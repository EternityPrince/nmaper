package scanner

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"nmaper/internal/model"
)

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

func formatElapsed(duration time.Duration) string {
	if duration < time.Second {
		return duration.Round(100 * time.Millisecond).String()
	}
	return duration.Round(time.Second).String()
}
