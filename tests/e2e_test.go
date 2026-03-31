package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"nmaper/internal/app"
	"nmaper/internal/history"
)

func TestEndToEndHistoryFlow(t *testing.T) {
	port1 := 18080
	port2 := 18443

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "nmaper.db")
	statePath := filepath.Join(tmpDir, "state.txt")
	if err := os.WriteFile(statePath, []byte("1"), 0o644); err != nil {
		t.Fatalf("write state: %v", err)
	}

	nmapPath := filepath.Join(tmpDir, "fake-nmap.sh")
	if err := os.WriteFile(nmapPath, []byte(fakeNmapScript()), 0o755); err != nil {
		t.Fatalf("write fake nmap: %v", err)
	}

	t.Setenv("NMAPER_NMAP_BIN", nmapPath)
	t.Setenv("NMAPER_STATE_FILE", statePath)
	t.Setenv("NMAPER_PORT1", fmt.Sprintf("%d", port1))
	t.Setenv("NMAPER_PORT2", fmt.Sprintf("%d", port2))

	runCLI(t, []string{"127.0.0.1", "-p", fmt.Sprintf("%d,%d", port1, port2), "--save", "db", "--db", dbPath, "--out", "json"})
	if err := os.WriteFile(statePath, []byte("2"), 0o644); err != nil {
		t.Fatalf("update state: %v", err)
	}
	runCLI(t, []string{"127.0.0.1", "-p", fmt.Sprintf("%d,%d", port1, port2), "--save", "db", "--db", dbPath, "--out", "json"})

	sessionsOut := runCLI(t, []string{"--sessions", "--db", dbPath, "--out", "json"})
	var sessions []history.SessionSummary
	if err := json.Unmarshal([]byte(sessionsOut), &sessions); err != nil {
		t.Fatalf("unmarshal sessions: %v\n%s", err, sessionsOut)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}

	diffOut := runCLI(t, []string{"--diff", strconv.FormatInt(sessions[1].ID, 10), strconv.FormatInt(sessions[0].ID, 10), "--db", dbPath, "--out", "json"})
	var diff history.DiffReport
	if err := json.Unmarshal([]byte(diffOut), &diff); err != nil {
		t.Fatalf("unmarshal diff: %v\n%s", err, diffOut)
	}
	if len(diff.ChangedHosts) != 1 {
		t.Fatalf("expected 1 changed host, got %d", len(diff.ChangedHosts))
	}
	if got := len(diff.ChangedHosts[0].After.OpenPorts); got != 2 {
		t.Fatalf("expected 2 open ports after second scan, got %d", got)
	}

	devicesOut := runCLI(t, []string{"--devices", "--ip-only", "--db", dbPath, "--out", "json"})
	var devices history.DeviceAnalyticsReport
	if err := json.Unmarshal([]byte(devicesOut), &devices); err != nil {
		t.Fatalf("unmarshal devices: %v\n%s", err, devicesOut)
	}
	if devices.UniqueDevices != 1 || devices.IPOnly != 1 {
		t.Fatalf("unexpected device analytics: %#v", devices)
	}

	timelineOut := runCLI(t, []string{"--timeline", "--db", dbPath, "--out", "json"})
	var timeline history.TimelineReport
	if err := json.Unmarshal([]byte(timelineOut), &timeline); err != nil {
		t.Fatalf("unmarshal timeline: %v\n%s", err, timelineOut)
	}
	if len(timeline.Entries) != 1 {
		t.Fatalf("expected 1 timeline entry, got %d", len(timeline.Entries))
	}
	if len(timeline.Entries[0].ChangedHosts) != 1 {
		t.Fatalf("expected 1 changed host in timeline, got %d", len(timeline.Entries[0].ChangedHosts))
	}
}

func runCLI(t *testing.T, args []string) string {
	t.Helper()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := app.Run(context.Background(), args, bytes.NewBuffer(nil), &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("app.Run failed with code %d\nstderr:\n%s\nstdout:\n%s", exitCode, stderr.String(), stdout.String())
	}
	return stdout.String()
}

func fakeNmapScript() string {
	return `#!/bin/sh
set -eu

state="$(cat "$NMAPER_STATE_FILE")"
ports=""
target=""
prev=""
mode="discovery"

for arg in "$@"; do
  if [ "$prev" = "-p" ]; then
    ports="$arg"
  fi
  case "$arg" in
    -A|-sV|-O)
      mode="detail"
      ;;
  esac
  prev="$arg"
  target="$arg"
done

emit_ports() {
  OLDIFS="$IFS"
  IFS=','
  for port in $1; do
    cat <<EOF
      <port protocol="tcp" portid="$port">
        <state state="open"/>
        <service name="http" product="test-service" version="1.0"/>
      </port>
EOF
  done
  IFS="$OLDIFS"
}

if [ "$mode" = "discovery" ]; then
  open_ports="$NMAPER_PORT1"
  if [ "$state" = "2" ]; then
    open_ports="$NMAPER_PORT1,$NMAPER_PORT2"
  fi
  cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="fake discovery" start="1710000000" version="7.95">
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
$(emit_ports "$open_ports")
    </ports>
  </host>
  <runstats>
    <finished time="1710000001"/>
  </runstats>
</nmaprun>
EOF
  exit 0
fi

cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="fake detail" start="1710000000" version="7.95">
  <host>
    <status state="up"/>
    <address addr="$target" addrtype="ipv4"/>
    <ports>
$(emit_ports "$ports")
    </ports>
    <os>
      <osmatch name="Linux test" accuracy="99">
        <osclass vendor="Linux" osfamily="Linux" osgen="6.X"/>
      </osmatch>
    </os>
  </host>
  <runstats>
    <finished time="1710000002"/>
  </runstats>
</nmaprun>
EOF
`
}
