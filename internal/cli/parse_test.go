package cli

import (
	"testing"

	"nmaper/internal/model"
)

func TestParseScanMode(t *testing.T) {
	t.Parallel()

	opts, err := Parse([]string{"192.168.0.0/24", "-p", "22,80,443", "--service-version", "--save", "xml", "-o", "./scans"})
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
