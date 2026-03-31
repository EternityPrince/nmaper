package cli

import (
	"strings"
	"testing"

	"nmaper/internal/model"
)

func TestParseScanMode(t *testing.T) {
	t.Parallel()

	opts, err := Parse([]string{"192.168.0.0/24", "--level", "high", "-p", "22,80,443", "--service-version", "--save", "xml", "-o", "./scans"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if opts.Mode != model.ModeScan {
		t.Fatalf("expected scan mode, got %q", opts.Mode)
	}
	if opts.Target != "192.168.0.0/24" {
		t.Fatalf("unexpected target: %q", opts.Target)
	}
	if opts.Ports != "22,80,443" {
		t.Fatalf("unexpected ports: %q", opts.Ports)
	}
	if opts.Save != model.SaveXML {
		t.Fatalf("unexpected save mode: %q", opts.Save)
	}
	if opts.Level != model.ScanLevelHigh {
		t.Fatalf("unexpected level: %q", opts.Level)
	}
}

func TestParseSessionHostFilter(t *testing.T) {
	t.Parallel()

	opts, err := Parse([]string{"--session", "12", "--host", "19216801"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if opts.Mode != model.ModeSession {
		t.Fatalf("expected session mode, got %q", opts.Mode)
	}
	if opts.SessionID == nil || *opts.SessionID != 12 {
		t.Fatalf("unexpected session id: %#v", opts.SessionID)
	}
	if opts.HostQuery != "19216801" {
		t.Fatalf("unexpected host query: %q", opts.HostQuery)
	}
}

func TestParseRejectsMultiplePrimaryModes(t *testing.T) {
	t.Parallel()

	if _, err := Parse([]string{"--sessions", "--timeline"}); err == nil {
		t.Fatalf("expected multiple primary modes validation error")
	}
}

func TestParseRejectsHostWithoutSessionID(t *testing.T) {
	t.Parallel()

	if _, err := Parse([]string{"--session", "--host", "router"}); err == nil {
		t.Fatalf("expected --host validation error")
	}
}

func TestParseSpoofMACRequiresSudo(t *testing.T) {
	t.Parallel()

	if _, err := Parse([]string{"192.168.0.0/24", "--spoof-mac", "random"}); err == nil {
		t.Fatalf("expected --spoof-mac validation error without --sudo")
	}

	opts, err := Parse([]string{"192.168.0.0/24", "--sudo", "--spoof-mac", "random"})
	if err != nil {
		t.Fatalf("expected spoof-mac parse to succeed, got %v", err)
	}
	if opts.SpoofMAC != "random" || !opts.UseSudo {
		t.Fatalf("unexpected spoof-mac opts: %#v", opts)
	}

	opts, err = Parse([]string{"192.168.0.0/24", "--level", "high", "--spoof-mac", "random"})
	if err != nil {
		t.Fatalf("expected level high to allow spoof-mac, got %v", err)
	}
	if opts.Level != model.ScanLevelHigh || opts.SpoofMAC != "random" {
		t.Fatalf("unexpected high-level spoof opts: %#v", opts)
	}
}

func TestParseDeleteAliases(t *testing.T) {
	t.Parallel()

	opts, err := Parse([]string{"--delete-session", "12"})
	if err != nil {
		t.Fatalf("expected delete-session parse to succeed, got %v", err)
	}
	if opts.Mode != model.ModeSession || opts.DeleteTarget == nil || *opts.DeleteTarget != 12 {
		t.Fatalf("unexpected delete-session opts: %#v", opts)
	}

	opts, err = Parse([]string{"--delete-all-sessions"})
	if err != nil {
		t.Fatalf("expected delete-all-sessions parse to succeed, got %v", err)
	}
	if opts.Mode != model.ModeSession || opts.DeleteTarget == nil || *opts.DeleteTarget != -1 {
		t.Fatalf("unexpected delete-all-sessions opts: %#v", opts)
	}
}

func TestUsageMentionsRichSnapshots(t *testing.T) {
	t.Parallel()

	usage := Usage()
	for _, want := range []string{
		"Safe service-aware NSE enrichment",
		"targeted UDP enrichment on higher scan levels",
		"--level <low|mid|high>",
		"--host <query>",
		"--out <mode>",
		"nmaper --delete-session 12",
	} {
		if !strings.Contains(usage, want) {
			t.Fatalf("usage missing %q:\n%s", want, usage)
		}
	}
}
