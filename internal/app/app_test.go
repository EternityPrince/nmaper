package app

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"nmaper/internal/history"
	"nmaper/internal/testutil"
)

func TestRunHelpAndInvalidArgs(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Run(context.Background(), []string{"--help"}, bytes.NewBuffer(nil), &stdout, &stderr); code != 0 {
		t.Fatalf("expected help exit code 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("expected usage output, got: %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(context.Background(), []string{"--unknown-flag"}, bytes.NewBuffer(nil), &stdout, &stderr); code != 2 {
		t.Fatalf("expected parse error exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "unknown flag") {
		t.Fatalf("expected parse error in stderr, got: %q", stderr.String())
	}
}

func TestRunSessionsMode(t *testing.T) {
	t.Parallel()

	fixture := testutil.SeedHistoryDB(t)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run(
		context.Background(),
		[]string{"--sessions", "--db", fixture.DBPath, "--out", "json"},
		bytes.NewBuffer(nil),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected sessions mode to succeed, code=%d stderr=%s", code, stderr.String())
	}

	var sessions []history.SessionSummary
	if err := json.Unmarshal(stdout.Bytes(), &sessions); err != nil {
		t.Fatalf("unmarshal sessions: %v\n%s", err, stdout.String())
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}
}

func TestRunHistoryModes(t *testing.T) {
	t.Parallel()

	fixture := testutil.SeedHistoryDB(t)
	cases := []struct {
		name  string
		args  []string
		match string
	}{
		{"session", []string{"--session", strconv.FormatInt(fixture.Session1ID, 10), "--db", fixture.DBPath, "--out", "json"}, "\"hosts\""},
		{"diff", []string{"--diff", strconv.FormatInt(fixture.Session1ID, 10), strconv.FormatInt(fixture.Session2ID, 10), "--db", fixture.DBPath, "--out", "json"}, "\"changed_hosts\""},
		{"diff-global", []string{"--diff-global", "--db", fixture.DBPath, "--out", "json"}, "\"session_count\""},
		{"devices", []string{"--devices", "--db", fixture.DBPath, "--out", "json"}, "\"unique_devices\""},
		{"device", []string{"--device", "acme", "--db", fixture.DBPath, "--out", "json"}, "\"appearances\""},
		{"timeline", []string{"--timeline", "--db", fixture.DBPath, "--out", "json"}, "\"entries\""},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := Run(context.Background(), tc.args, bytes.NewBuffer(nil), &stdout, &stderr)
			if code != 0 {
				t.Fatalf("Run failed: code=%d stderr=%s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), tc.match) {
				t.Fatalf("expected %q in output, got: %s", tc.match, stdout.String())
			}
		})
	}
}

func TestConfirmDeletionRequiresTTY(t *testing.T) {
	t.Parallel()

	confirmed, err := confirmDeletion(bytes.NewBufferString("y\n"), &bytes.Buffer{}, 12)
	if err == nil || confirmed {
		t.Fatalf("expected TTY guard failure, confirmed=%v err=%v", confirmed, err)
	}
}

func TestRunScanPrintsHumanFriendlyProfile(t *testing.T) {
	tmpDir := t.TempDir()
	nmapPath := filepath.Join(tmpDir, "fake-nmap.sh")
	if err := os.WriteFile(nmapPath, []byte(fakeAppScannerScript()), 0o755); err != nil {
		t.Fatalf("write fake nmap: %v", err)
	}
	t.Setenv("NMAPER_NMAP_BIN", nmapPath)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(
		context.Background(),
		[]string{"127.0.0.1", "--level", "mid", "--save", "xml", "-o", filepath.Join(tmpDir, "out")},
		bytes.NewBuffer(nil),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected scan mode to succeed, code=%d stderr=%s", code, stderr.String())
	}

	out := stdout.String()
	for _, want := range []string{
		"Scan level: mid",
		"Profile: balanced TCP scan with richer service fingerprints",
		"Enabled: ",
		"service detection",
		"traceroute snapshots",
		"safe NSE enrichment",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in output, got:\n%s", want, out)
		}
	}
}

func fakeAppScannerScript() string {
	return `#!/usr/bin/env bash
set -euo pipefail

mode="discovery"
target=""
for arg in "$@"; do
  if [[ "$arg" == "-A" || "$arg" == "-sV" || "$arg" == "-O" || "$arg" == "--traceroute" ]]; then
    mode="detail"
  fi
  target="$arg"
done

if [[ "$mode" == "discovery" ]]; then
  cat <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="fake discovery" start="1710000000" version="7.95">
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
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
    <address addr="${target}" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.26"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1710000002"/>
  </runstats>
</nmaprun>
EOF
`
}
