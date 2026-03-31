package preflight

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureGofmt(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	formatted := []byte("package main\n\nfunc main() {}\n")
	if err := os.WriteFile(filepath.Join(root, "main.go"), formatted, 0o644); err != nil {
		t.Fatalf("write formatted file: %v", err)
	}
	if err := ensureGofmt(context.Background(), root); err != nil {
		t.Fatalf("ensureGofmt returned error for formatted file: %v", err)
	}
}

func TestEnsureGofmtReportsUnformattedFile(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	unformatted := []byte("package main\nfunc  main( ) {}\n")
	if err := os.WriteFile(filepath.Join(root, "main.go"), unformatted, 0o644); err != nil {
		t.Fatalf("write unformatted file: %v", err)
	}
	err := ensureGofmt(context.Background(), root)
	if err == nil {
		t.Fatalf("expected gofmt error for unformatted file")
	}
	if !strings.Contains(err.Error(), "main.go") {
		t.Fatalf("expected file name in error, got: %v", err)
	}
}

func TestRunCommandFailureIncludesOutput(t *testing.T) {
	t.Parallel()

	err := runCommand(context.Background(), t.TempDir(), "sh", "-c", "printf 'boom'; exit 1")
	if err == nil {
		t.Fatalf("expected runCommand failure")
	}
	if !strings.Contains(err.Error(), "sh failed") || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("unexpected error: %v", err)
	}
}
