package scanner

import (
	"bytes"
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
	OKf(string, ...any)
	Warnf(string, ...any)
}

type Scanner struct {
	nmapBin string
	logger  logger
}

type Result struct {
	SessionName      string
	StartedAt        time.Time
	CompletedAt      time.Time
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
		nmapBin: nmapBin,
		logger:  log,
	}
}

func (s *Scanner) EnsureReady(ctx context.Context, opts model.Options) error {
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
	args := []string{}
	if opts.UseSudo {
		args = append(args, "-sS")
	} else {
		args = append(args, "-sT")
	}
	args = append(args, opts.Target, "-T", fmt.Sprintf("%d", opts.Timing), "-oX", "-")
	if opts.NoPing {
		args = append(args, "-Pn")
	}
	if opts.Ports != "" {
		args = append(args, "-p", opts.Ports)
	}
	if opts.TopPorts > 0 {
		args = append(args, "--top-ports", fmt.Sprintf("%d", opts.TopPorts))
	}
	return args
}

func BuildDetailArgs(ip string, ports []int, opts model.Options) []string {
	args := []string{
		"-T", fmt.Sprintf("%d", opts.Timing),
		"-oX", "-",
		"-p", joinPorts(ports),
	}
	if !opts.ServiceVersion && !opts.OSDetect {
		args = append(args, "-A")
	} else {
		if opts.ServiceVersion {
			args = append(args, "-sV")
		}
		if opts.OSDetect {
			args = append(args, "-O")
		}
	}
	if opts.NoPing {
		args = append(args, "-Pn")
	}
	args = append(args, ip)
	return args
}

func (s *Scanner) Run(ctx context.Context, opts model.Options) (Result, error) {
	sessionName := SessionName(opts)
	result := Result{
		SessionName:    sessionName,
		StartedAt:      time.Now(),
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
	discoveryArgs := BuildDiscoveryArgs(opts)
	discoveryXML, discoveryCommand, err := s.runXMLCommand(ctx, discoveryArgs, opts.UseSudo)
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

			s.logger.Infof("detail scan for %s on ports %s", target.IP, joinPorts(target.Ports))
			xmlBody, wrappedCommand, runErr := s.runXMLCommand(ctx, BuildDetailArgs(target.IP, target.Ports, opts), opts.UseSudo)
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

			if opts.Save == model.SaveXML {
				fileName := fmt.Sprintf("host-%s.xml", strings.ReplaceAll(target.IP, ":", "_"))
				if err := os.WriteFile(filepath.Join(opts.OutputDir, sessionName, "xml", fileName), []byte(xmlBody), 0o644); err != nil {
					mu.Lock()
					result.DetailErrors[target.IP] = err.Error()
					mu.Unlock()
					s.logger.Warnf("detail xml write failed for %s: %v", target.IP, err)
					return
				}
			}

			mu.Lock()
			result.DetailXML[target.IP] = xmlBody
			result.DetailRuns[target.IP] = parsed
			mu.Unlock()
		}()
	}
	wg.Wait()

	result.CompletedAt = time.Now()
	s.logger.OKf("detail phase finished: %d success, %d errors", len(result.DetailRuns), len(result.DetailErrors))
	return result, nil
}

func (s *Scanner) runXMLCommand(ctx context.Context, nmapArgs []string, useSudo bool) (string, []string, error) {
	command := []string{s.nmapBin}
	name := s.nmapBin
	args := append([]string(nil), nmapArgs...)
	if useSudo {
		name = "sudo"
		command = []string{"sudo", "-n", s.nmapBin}
		args = append([]string{"-n", s.nmapBin}, nmapArgs...)
	}

	cmd := exec.CommandContext(ctx, name, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", commandWithArgs(command, nmapArgs), fmt.Errorf("command failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), commandWithArgs(command, nmapArgs), nil
}

func joinPorts(ports []int) string {
	values := make([]string, 0, len(ports))
	for _, port := range ports {
		values = append(values, fmt.Sprintf("%d", port))
	}
	return strings.Join(values, ",")
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
