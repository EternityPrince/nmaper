package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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
		s.logger.Infof("suppressing MAC spoofing for local discovery so host detection stays reliable")
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
	if shouldSuppressDiscoverySpoof(opts) && shouldSuppressLocalDetailSpoof(result.Targets, opts) {
		result.SourceIdentity.SpoofedMAC = ""
	}

	s.logger.OKf("discovery completed: %d hosts, %d live targets", len(discoveryRun.Hosts), len(result.Targets))
	if len(result.Targets) == 0 {
		result.CompletedAt = time.Now()
		return result, nil
	}
	if shouldSuppressLocalDetailSpoof(result.Targets, opts) {
		s.logger.Infof("suppressing MAC spoofing during local detail scans so TCP replies stay reliable")
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

			label := detailScanLabel(target, opts)
			detailArgs := BuildPortProbeArgs(target.IP, opts)
			if len(target.Ports) > 0 {
				detailArgs = BuildDetailArgs(target.IP, target.Ports, opts)
				detailCtx := detailProfileContext{
					IP:       target.IP,
					Level:    opts.Level,
					TCPPorts: target.Ports,
					UDPPorts: detailUDPPorts(detailPhaseOptions(target.IP, opts)),
				}
				if discoveryHost, ok := findDiscoveryHost(result.DiscoveryRun, target.IP); ok {
					detailArgs = BuildDetailArgsForHost(target.IP, target.Ports, discoveryHost, opts)
					detailCtx = detailContextForHost(target.IP, target.Ports, discoveryHost, detailPhaseOptions(target.IP, opts))
				}
				if detailScripts := effectiveDetailScripts(detailCtx); len(detailScripts) > 0 {
					label += " using scripts " + strings.Join(detailScripts, ",")
				}
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
