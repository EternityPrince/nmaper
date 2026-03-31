package scanner

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"nmaper/internal/converter"
	"nmaper/internal/model"
	"nmaper/internal/parser"
)

type logger interface {
	Phasef(string, ...any)
	Infof(string, ...any)
	Waitf(string, ...any)
	OKf(string, ...any)
	Warnf(string, ...any)
}

type Scanner struct {
	nmapBin        string
	logger         logger
	sourceIdentity *SourceIdentity
	heartbeatEvery time.Duration
}

type Result struct {
	SessionName      string
	StartedAt        time.Time
	CompletedAt      time.Time
	SourceIdentity   SourceIdentity
	DiscoveryRun     parser.Run
	DiscoveryXML     string
	DiscoveryCommand []string
	DetailRuns       map[string]parser.Run
	DetailXML        map[string]string
	DetailCommands   map[string][]string
	DetailErrors     map[string]string
	Targets          []converter.DetailTarget
}

func New(log logger) *Scanner {
	nmapBin := os.Getenv("NMAPER_NMAP_BIN")
	if nmapBin == "" {
		nmapBin = "nmap"
	}
	return &Scanner{
		nmapBin:        nmapBin,
		logger:         log,
		heartbeatEvery: 15 * time.Second,
	}
}

func (s *Scanner) EnsureReady(ctx context.Context, opts model.Options) error {
	opts = effectiveOptions(opts)
	if _, err := exec.LookPath(s.nmapBin); err != nil {
		return fmt.Errorf("nmap not found in PATH: %w", err)
	}
	if opts.UseSudo {
		s.logger.Phasef("warming sudo credentials")
		cmd := exec.CommandContext(ctx, "sudo", "-v")
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("sudo -v failed: %w: %s", err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func BuildDiscoveryArgs(opts model.Options) []string {
	opts = effectiveOptions(opts)
	opts = discoveryPhaseOptions(opts)
	args := []string{}
	if usesHostDiscovery(opts) {
		args = append(args, "-sn")
	} else {
		if opts.UseSudo {
			args = append(args, "-sS")
		} else {
			args = append(args, "-sT")
		}
	}
	args = append(args, "-T", fmt.Sprintf("%d", opts.Timing), "-oX", "-")
	if opts.NoPing {
		args = append(args, "-Pn")
	}
	if !usesHostDiscovery(opts) {
		if opts.Ports != "" {
			args = append(args, "-p", opts.Ports)
		} else if opts.TopPorts > 0 {
			args = append(args, "--top-ports", fmt.Sprintf("%d", opts.TopPorts))
		}
	}
	if opts.SpoofMAC != "" {
		args = append(args, "--spoof-mac", opts.SpoofMAC)
	}
	args = append(args, opts.Target)
	return args
}

func BuildDetailArgs(ip string, ports []int, opts model.Options) []string {
	opts = effectiveOptions(opts)
	return buildDetailArgs(detailProfileContext{
		IP:       ip,
		Level:    opts.Level,
		TCPPorts: ports,
		UDPPorts: detailUDPPorts(opts),
	}, opts)
}

func (s *Scanner) Run(ctx context.Context, opts model.Options) (Result, error) {
	opts = effectiveOptions(opts)
	identity, err := s.ResolveSourceIdentity(opts.Target, opts.SpoofMAC)
	if err != nil {
		return Result{}, err
	}
	if identity.SpoofedMAC != "" {
		opts.SpoofMAC = identity.SpoofedMAC
	}

	sessionName := SessionName(opts)
	result := Result{
		SessionName:    sessionName,
		StartedAt:      time.Now(),
		SourceIdentity: identity,
		DetailRuns:     make(map[string]parser.Run),
		DetailXML:      make(map[string]string),
		DetailCommands: make(map[string][]string),
		DetailErrors:   make(map[string]string),
	}

	if opts.Save == model.SaveXML {
		if err := os.MkdirAll(filepath.Join(opts.OutputDir, sessionName, "xml"), 0o755); err != nil {
			return Result{}, fmt.Errorf("create xml output dir: %w", err)
		}
	}

	s.logger.Phasef("running discovery scan against %s", opts.Target)
	if shouldSuppressDiscoverySpoof(opts) {
		s.logger.Infof("suppressing MAC spoofing during subnet discovery so ARP host detection stays reliable")
	}
	discoveryArgs := BuildDiscoveryArgs(opts)
	discoveryXML, discoveryCommand, err := s.runXMLCommand(
		ctx,
		fmt.Sprintf("discovery scan for %s", opts.Target),
		discoveryArgs,
		opts.UseSudo,
	)
	if err != nil {
		return Result{}, err
	}
	result.DiscoveryCommand = discoveryCommand
	result.DiscoveryXML = discoveryXML

	if opts.Save == model.SaveXML {
		if err := os.WriteFile(filepath.Join(opts.OutputDir, sessionName, "xml", "discovery.xml"), []byte(discoveryXML), 0o644); err != nil {
			return Result{}, fmt.Errorf("write discovery xml: %w", err)
		}
	}

	discoveryRun, err := parser.Parse([]byte(discoveryXML))
	if err != nil {
		return Result{}, fmt.Errorf("parse discovery xml: %w", err)
	}
	result.DiscoveryRun = discoveryRun
	result.Targets = converter.DiscoveryToDetailTargets(discoveryRun)

	s.logger.OKf("discovery completed: %d hosts, %d live targets", len(discoveryRun.Hosts), len(result.Targets))
	if len(result.Targets) == 0 {
		result.CompletedAt = time.Now()
		return result, nil
	}

	s.logger.Phasef("running %d detail scans", len(result.Targets))
	sem := make(chan struct{}, opts.DetailWorkers)
	var wg sync.WaitGroup
	var mu sync.Mutex

	targets := append([]converter.DetailTarget(nil), result.Targets...)
	sort.Slice(targets, func(i, j int) bool { return targets[i].IP < targets[j].IP })

	for _, target := range targets {
		target := target
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			detailArgs := BuildDetailArgs(target.IP, target.Ports, opts)
			detailCtx := detailProfileContext{
				IP:       target.IP,
				Level:    opts.Level,
				TCPPorts: target.Ports,
				UDPPorts: detailUDPPorts(opts),
			}
			detailLabel := detailScanLabel(target, opts)
			if len(target.Ports) == 0 {
				detailLabel = fallbackDetailScanLabel(target, opts)
			}
			if discoveryHost, ok := findDiscoveryHost(result.DiscoveryRun, target.IP); ok && len(target.Ports) > 0 {
				detailArgs = BuildDetailArgsForHost(target.IP, target.Ports, discoveryHost, opts)
				detailCtx = detailContextForHost(target.IP, target.Ports, discoveryHost, opts)
			}
			var detailScripts []string
			if len(target.Ports) > 0 {
				detailScripts = effectiveDetailScripts(detailCtx)
			}
			label := detailLabel
			if len(detailScripts) > 0 {
				label += " using scripts " + strings.Join(detailScripts, ",")
			}
			xmlBody, wrappedCommand, runErr := s.runXMLCommand(ctx, label, detailArgs, opts.UseSudo)
			mu.Lock()
			result.DetailCommands[target.IP] = wrappedCommand
			mu.Unlock()
			if runErr != nil {
				mu.Lock()
				result.DetailErrors[target.IP] = runErr.Error()
				mu.Unlock()
				s.logger.Warnf("detail scan failed for %s: %v", target.IP, runErr)
				return
			}

			parsed, parseErr := parser.Parse([]byte(xmlBody))
			if parseErr != nil {
				mu.Lock()
				result.DetailErrors[target.IP] = parseErr.Error()
				mu.Unlock()
				s.logger.Warnf("detail xml parse failed for %s: %v", target.IP, parseErr)
				return
			}

			finalXML := xmlBody
			finalRun := parsed
			finalCommand := wrappedCommand
			if len(target.Ports) == 0 {
				probeHost, ok := findDiscoveryHost(parsed, target.IP)
				if ok {
					probePorts := openTCPPorts(probeHost)
					if len(probePorts) > 0 {
						enrichArgs := BuildDetailArgsForHost(target.IP, probePorts, probeHost, opts)
						enrichCtx := detailContextForHost(target.IP, probePorts, probeHost, opts)
						enrichLabel := fmt.Sprintf("enrichment scan for %s on ports %s", target.IP, joinProtocolPorts(probePorts, detailUDPPorts(opts)))
						if enrichScripts := effectiveDetailScripts(enrichCtx); len(enrichScripts) > 0 {
							enrichLabel += " using scripts " + strings.Join(enrichScripts, ",")
						}
						enrichXML, enrichCommand, enrichErr := s.runXMLCommand(ctx, enrichLabel, enrichArgs, opts.UseSudo)
						mu.Lock()
						result.DetailCommands[target.IP] = enrichCommand
						mu.Unlock()
						if enrichErr != nil {
							mu.Lock()
							result.DetailErrors[target.IP] = enrichErr.Error()
							mu.Unlock()
							s.logger.Warnf("enrichment scan failed for %s: %v", target.IP, enrichErr)
							return
						}
						enrichRun, enrichParseErr := parser.Parse([]byte(enrichXML))
						if enrichParseErr != nil {
							mu.Lock()
							result.DetailErrors[target.IP] = enrichParseErr.Error()
							mu.Unlock()
							s.logger.Warnf("enrichment xml parse failed for %s: %v", target.IP, enrichParseErr)
							return
						}
						finalXML = enrichXML
						finalRun = enrichRun
						finalCommand = enrichCommand
					}
				}
			}

			if opts.Save == model.SaveXML {
				fileName := fmt.Sprintf("host-%s.xml", strings.ReplaceAll(target.IP, ":", "_"))
				if err := os.WriteFile(filepath.Join(opts.OutputDir, sessionName, "xml", fileName), []byte(finalXML), 0o644); err != nil {
					mu.Lock()
					result.DetailErrors[target.IP] = err.Error()
					mu.Unlock()
					s.logger.Warnf("detail xml write failed for %s: %v", target.IP, err)
					return
				}
			}

			mu.Lock()
			result.DetailCommands[target.IP] = finalCommand
			result.DetailXML[target.IP] = finalXML
			result.DetailRuns[target.IP] = finalRun
			mu.Unlock()
		}()
	}
	wg.Wait()

	result.CompletedAt = time.Now()
	s.logger.OKf("detail phase finished: %d success, %d errors", len(result.DetailRuns), len(result.DetailErrors))
	return result, nil
}

func effectiveOptions(opts model.Options) model.Options {
	normalized, err := model.NormalizeScanOptions(opts)
	if err != nil {
		return opts
	}
	return normalized
}

func (s *Scanner) runXMLCommand(ctx context.Context, label string, nmapArgs []string, useSudo bool) (string, []string, error) {
	command := []string{s.nmapBin}
	name := s.nmapBin
	args := append([]string(nil), nmapArgs...)
	if useSudo {
		name = "sudo"
		command = []string{"sudo", "-n", s.nmapBin}
		args = append([]string{"-n", s.nmapBin}, nmapArgs...)
	}

	fullCommand := commandWithArgs(command, nmapArgs)
	s.logger.Phasef("%s started: %s", label, previewCommand(fullCommand))

	cmd := exec.CommandContext(ctx, name, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	startedAt := time.Now()
	stopWaiting := s.startCommandHeartbeat(label, fullCommand, startedAt)
	defer stopWaiting()
	if err := cmd.Run(); err != nil {
		return "", fullCommand, fmt.Errorf("command failed after %s: %w: %s", formatElapsed(time.Since(startedAt)), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), fullCommand, nil
}

func joinPorts(ports []int) string {
	values := make([]string, 0, len(ports))
	for _, port := range ports {
		values = append(values, fmt.Sprintf("%d", port))
	}
	return strings.Join(values, ",")
}

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func joinProtocolPorts(tcpPorts, udpPorts []int) string {
	sections := make([]string, 0, 2)
	if len(tcpPorts) > 0 {
		sections = append(sections, "T:"+joinPorts(tcpPorts))
	}
	if len(udpPorts) > 0 {
		sections = append(sections, "U:"+joinPorts(udpPorts))
	}
	if len(sections) == 0 {
		return ""
	}
	if len(sections) == 1 {
		return sections[0]
	}
	return strings.Join(sections, ",")
}

func isCIDRTarget(target string) bool {
	_, _, err := net.ParseCIDR(strings.TrimSpace(target))
	return err == nil
}

func usesHostDiscovery(opts model.Options) bool {
	return isCIDRTarget(opts.Target) && !opts.NoPing
}

func shouldSuppressDiscoverySpoof(opts model.Options) bool {
	return usesHostDiscovery(opts) && opts.SpoofMAC != ""
}

func discoveryPhaseOptions(opts model.Options) model.Options {
	if shouldSuppressDiscoverySpoof(opts) {
		opts.SpoofMAC = ""
	}
	return opts
}

func detailScanLabel(target converter.DetailTarget, opts model.Options) string {
	if len(target.Ports) > 0 {
		return fmt.Sprintf("detail scan for %s on ports %s", target.IP, joinProtocolPorts(target.Ports, detailUDPPorts(opts)))
	}
	return fallbackDetailScanLabel(target, opts)
}

func fallbackDetailScanLabel(target converter.DetailTarget, opts model.Options) string {
	if opts.Ports != "" {
		return fmt.Sprintf("port discovery scan for %s using explicit ports %s", target.IP, opts.Ports)
	}
	if opts.TopPorts > 0 {
		return fmt.Sprintf("port discovery scan for %s using top %d ports", target.IP, opts.TopPorts)
	}
	return fmt.Sprintf("port discovery scan for %s", target.IP)
}

func openTCPPorts(host parser.Host) []int {
	ports := make([]int, 0)
	for _, port := range host.OpenPorts() {
		if port.Protocol != "tcp" {
			continue
		}
		ports = append(ports, port.ID)
	}
	return ports
}

func SessionName(opts model.Options) string {
	if opts.Name != "" {
		return opts.Name
	}
	return fmt.Sprintf("scan-%s", time.Now().Format("20060102-150405"))
}

func commandWithArgs(prefix, args []string) []string {
	return append(append([]string(nil), prefix...), args...)
}

func findDiscoveryHost(run parser.Run, ip string) (parser.Host, bool) {
	for _, host := range run.Hosts {
		if host.PrimaryIP() == ip {
			return host, true
		}
	}
	return parser.Host{}, false
}

func (s *Scanner) startCommandHeartbeat(label string, command []string, startedAt time.Time) func() {
	interval := s.heartbeatEvery
	if interval <= 0 {
		return func() {}
	}

	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				s.logger.Waitf("%s still running after %s: %s", label, formatElapsed(time.Since(startedAt)), previewCommand(command))
			}
		}
	}()

	var once sync.Once
	return func() {
		once.Do(func() {
			close(done)
		})
	}
}

func previewCommand(command []string) string {
	parts := make([]string, 0, len(command))
	for _, arg := range command {
		if strings.ContainsAny(arg, " \t\n\"'") {
			parts = append(parts, strconv.Quote(arg))
			continue
		}
		parts = append(parts, arg)
	}
	text := strings.Join(parts, " ")
	if len(text) <= 220 {
		return text
	}
	return text[:217] + "..."
}

func formatElapsed(duration time.Duration) string {
	if duration < time.Second {
		return duration.Round(100 * time.Millisecond).String()
	}
	return duration.Round(time.Second).String()
}
