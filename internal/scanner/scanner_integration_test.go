package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"nmaper/internal/model"
)

type noopLogger struct{}

func (noopLogger) Phasef(string, ...any) {}
func (noopLogger) Infof(string, ...any)  {}
func (noopLogger) Waitf(string, ...any)  {}
func (noopLogger) OKf(string, ...any)    {}
func (noopLogger) Warnf(string, ...any)  {}

func TestScannerRunAndEnsureReady(t *testing.T) {
	tmpDir := t.TempDir()
	nmapPath := filepath.Join(tmpDir, "fake-nmap.sh")
	if err := os.WriteFile(nmapPath, []byte(fakeScannerScript()), 0o755); err != nil {
		t.Fatalf("write fake nmap: %v", err)
	}
	t.Setenv("NMAPER_NMAP_BIN", nmapPath)

	opts := model.DefaultOptions()
	opts.Target = "127.0.0.1"
	opts.Save = model.SaveXML
	opts.OutputDir = filepath.Join(tmpDir, "out")
	opts.Name = "scanner-test"
	opts.DetailWorkers = 1

	sc := New(noopLogger{})
	if err := sc.EnsureReady(context.Background(), opts); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}

	result, err := sc.Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.SessionName != "scanner-test" {
		t.Fatalf("unexpected session name: %q", result.SessionName)
	}
	if len(result.DiscoveryRun.Hosts) != 1 || len(result.Targets) != 1 || len(result.DetailRuns) != 1 {
		t.Fatalf("unexpected scan result sizes: discovery=%d targets=%d detail=%d", len(result.DiscoveryRun.Hosts), len(result.Targets), len(result.DetailRuns))
	}
	if _, err := os.Stat(filepath.Join(opts.OutputDir, opts.Name, "xml", "discovery.xml")); err != nil {
		t.Fatalf("expected discovery xml artifact: %v", err)
	}
	if _, err := os.Stat(filepath.Join(opts.OutputDir, opts.Name, "xml", "host-127.0.0.1.xml")); err != nil {
		t.Fatalf("expected detail xml artifact: %v", err)
	}
	if got := result.DetailRuns["127.0.0.1"].Hosts[0].OpenPorts()[0].ID; got != 80 {
		t.Fatalf("unexpected open port in detail result: %d", got)
	}
}

func TestScannerRunPerformsEnrichmentAfterPortDiscoveryFallback(t *testing.T) {
	tmpDir := t.TempDir()
	nmapPath := filepath.Join(tmpDir, "fake-nmap-fallback.sh")
	if err := os.WriteFile(nmapPath, []byte(fakeFallbackScannerScript()), 0o755); err != nil {
		t.Fatalf("write fake fallback nmap: %v", err)
	}
	t.Setenv("NMAPER_NMAP_BIN", nmapPath)

	opts := model.DefaultOptions()
	opts.Target = "10.0.0.0/24"
	opts.Level = model.ScanLevelMid
	opts.DetailWorkers = 1

	sc := New(noopLogger{})
	result, err := sc.Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	run, ok := result.DetailRuns["10.0.0.10"]
	if !ok {
		t.Fatalf("expected detail result for 10.0.0.10")
	}
	host := run.Hosts[0]
	if got := host.OpenPorts()[0].ID; got != 80 {
		t.Fatalf("unexpected open port after enrichment: %d", got)
	}
	if len(host.OpenPorts()[0].Scripts) == 0 || host.OpenPorts()[0].Scripts[0].ID != "http-title" {
		t.Fatalf("expected enrichment script result, got %#v", host.OpenPorts()[0].Scripts)
	}
}

func fakeScannerScript() string {
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

func fakeFallbackScannerScript() string {
	return `#!/usr/bin/env bash
set -euo pipefail

if [[ "$*" == *"-sn"* ]]; then
  cat <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="fake discovery" start="1710000000" version="7.95">
  <host>
    <status state="up"/>
    <address addr="10.0.0.10" addrtype="ipv4"/>
  </host>
  <runstats>
    <finished time="1710000001"/>
  </runstats>
</nmaprun>
EOF
  exit 0
fi

if [[ "$*" == *"--script"* ]]; then
  cat <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="fake enrich" start="1710000002" version="7.95">
  <host>
    <status state="up"/>
    <address addr="10.0.0.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.26"/>
        <script id="http-title" output="Example device"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1710000003"/>
  </runstats>
</nmaprun>
EOF
  exit 0
fi

cat <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="fake probe" start="1710000001" version="7.95">
  <host>
    <status state="up"/>
    <address addr="10.0.0.10" addrtype="ipv4"/>
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
