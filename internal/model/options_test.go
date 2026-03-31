package model

import "testing"

func TestDefaultOptionsAndNeedsDatabase(t *testing.T) {
	t.Parallel()

	opts := DefaultOptions()
	if opts.Mode != ModeScan {
		t.Fatalf("expected default scan mode, got %q", opts.Mode)
	}
	if opts.Save != SaveDB {
		t.Fatalf("expected default save mode db, got %q", opts.Save)
	}
	if !opts.NeedsDatabase() {
		t.Fatalf("scan mode with db save should need database")
	}

	opts.Save = SaveXML
	if opts.NeedsDatabase() {
		t.Fatalf("xml scan mode should not need database")
	}

	opts.Mode = ModeSessions
	if !opts.NeedsDatabase() {
		t.Fatalf("history mode should need database")
	}

	opts.Mode = ModeCheck
	if opts.NeedsDatabase() {
		t.Fatalf("check mode should not need database")
	}
}
