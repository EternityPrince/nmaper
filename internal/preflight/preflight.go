package preflight

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

func Run(ctx context.Context, root string) error {
	if err := ensureGofmt(ctx, root); err != nil {
		return err
	}
	if err := runCommand(ctx, root, "go", "test", "./..."); err != nil {
		return err
	}
	return nil
}

func ensureGofmt(ctx context.Context, root string) error {
	cmd := exec.CommandContext(ctx, "gofmt", "-l", ".")
	cmd.Dir = root
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("gofmt failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if strings.TrimSpace(stdout.String()) != "" {
		return fmt.Errorf("gofmt reported unformatted files:\n%s", strings.TrimSpace(stdout.String()))
	}
	return nil
}

func runCommand(ctx context.Context, root string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = root
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w\n%s", name, err, strings.TrimSpace(out.String()))
	}
	return nil
}
