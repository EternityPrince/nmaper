package parser

import "testing"

func TestParseXML(t *testing.T) {
	t.Parallel()

	xml := `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -oX -" start="1710000000" version="7.95">
  <host>
    <status state="up"/>
    <address addr="192.168.0.10" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Acme"/>
    <hostnames>
      <hostname name="router.local"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.25"/>
        <script id="http-title" output="Welcome"/>
      </port>
    </ports>
    <hostscript>
      <script id="broadcast-ping" output="ok"/>
    </hostscript>
    <os>
      <osmatch name="Linux 5.x" accuracy="98">
        <osclass vendor="Linux" osfamily="Linux" osgen="5.X"/>
      </osmatch>
    </os>
    <trace proto="tcp" port="80">
      <hop ttl="1" ipaddr="192.168.0.1" rtt="1.23" host="gateway"/>
    </trace>
  </host>
  <runstats>
    <finished time="1710000010"/>
  </runstats>
</nmaprun>`

	run, err := Parse([]byte(xml))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if run.Version != "7.95" {
		t.Fatalf("unexpected version: %q", run.Version)
	}
	if len(run.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(run.Hosts))
	}
	host := run.Hosts[0]
	if host.PrimaryIP() != "192.168.0.10" {
		t.Fatalf("unexpected primary ip: %q", host.PrimaryIP())
	}
	mac, vendor := host.MAC()
	if mac != "AA:BB:CC:DD:EE:FF" || vendor != "Acme" {
		t.Fatalf("unexpected mac/vendor: %q %q", mac, vendor)
	}
	if len(host.OpenPorts()) != 1 || host.OpenPorts()[0].Service.Name != "http" {
		t.Fatalf("unexpected open ports: %#v", host.OpenPorts())
	}
	if len(host.OSMatches) != 1 || host.OSMatches[0].Name != "Linux 5.x" {
		t.Fatalf("unexpected os matches: %#v", host.OSMatches)
	}
	if host.Trace == nil || len(host.Trace.Hops) != 1 {
		t.Fatalf("unexpected trace: %#v", host.Trace)
	}
}
