package termui

import (
	"bytes"
	"strings"
	"testing"
)

func TestLoggerRespectsVerboseFlag(t *testing.T) {
	t.Parallel()

	var quiet bytes.Buffer
	logger := New(&quiet, false)
	logger.Infof("hidden")
	logger.OKf("shown")
	if strings.Contains(quiet.String(), "hidden") {
		t.Fatalf("info log should be hidden when verbose=false: %q", quiet.String())
	}
	if !strings.Contains(quiet.String(), "shown") {
		t.Fatalf("expected ok log in output: %q", quiet.String())
	}

	var verbose bytes.Buffer
	logger = New(&verbose, true)
	logger.Phasef("phase")
	logger.Infof("info")
	logger.Warnf("warn")
	logger.Failf("fail")
	output := verbose.String()
	for _, part := range []string{"phase", "info", "warn", "fail"} {
		if !strings.Contains(output, part) {
			t.Fatalf("expected %q in output: %q", part, output)
		}
	}
}
