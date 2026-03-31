package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type captureLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *captureLogger) Phasef(format string, args ...any) {
	l.append(fmt.Sprintf(format, args...))
}

func (l *captureLogger) Infof(format string, args ...any) {
	l.append(fmt.Sprintf(format, args...))
}

func (l *captureLogger) Waitf(format string, args ...any) {
	l.append("WAIT " + fmt.Sprintf(format, args...))
}

func (l *captureLogger) OKf(format string, args ...any) {
	l.append(fmt.Sprintf(format, args...))
}

func (l *captureLogger) Warnf(format string, args ...any) {
	l.append(fmt.Sprintf(format, args...))
}

func (l *captureLogger) append(line string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, line)
}

func (l *captureLogger) joined() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func TestRunXMLCommandEmitsProgressForLongRunningCommand(t *testing.T) {
	tmpDir := t.TempDir()
	nmapPath := filepath.Join(tmpDir, "slow-nmap.sh")
	if err := os.WriteFile(nmapPath, []byte(slowNmapScript()), 0o755); err != nil {
		t.Fatalf("write fake nmap: %v", err)
	}

	log := &captureLogger{}
	sc := &Scanner{nmapBin: nmapPath, logger: log, heartbeatEvery: 10 * time.Millisecond}

	if _, _, err := sc.runXMLCommand(context.Background(), "slow detail scan", []string{"127.0.0.1"}, false); err != nil {
		t.Fatalf("runXMLCommand: %v", err)
	}

	output := log.joined()
	if !strings.Contains(output, "slow detail scan started") {
		t.Fatalf("expected command start log, got:\n%s", output)
	}
	if !strings.Contains(output, "still running after") {
		t.Fatalf("expected heartbeat log, got:\n%s", output)
	}
	if !strings.Contains(output, "WAIT ") {
		t.Fatalf("expected wait-level heartbeat log, got:\n%s", output)
	}
	if !strings.Contains(output, "127.0.0.1") {
		t.Fatalf("expected target in command log, got:\n%s", output)
	}
}

func slowNmapScript() string {
	return `#!/bin/sh
set -eu
sleep 0.05
cat <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="fake slow" start="1710000000" version="7.95">
  <runstats>
    <finished time="1710000001"/>
  </runstats>
</nmaprun>
EOF
`
}
