package scanner

import (
	"reflect"
	"testing"

	"nmaper/internal/model"
	"nmaper/internal/parser"
)

func TestBuildDiscoveryArgs(t *testing.T) {
	t.Parallel()

	opts := model.DefaultOptions()
	opts.Level = model.ScanLevelHigh
	opts.Target = "198.51.100.0/24"
	opts.UseSudo = true
	opts.NoPing = true
	opts.TopPorts = 100
	opts.TopPortsExplicit = true
	opts.Timing = 3
	opts.TimingExplicit = true
	opts.SpoofMAC = "AA:BB:CC:DD:EE:FF"
	opts.SpoofMACExplicit = true

	want := []string{"-sS", "-T", "3", "-oX", "-", "-Pn", "--top-ports", "100", "--spoof-mac", "AA:BB:CC:DD:EE:FF", "198.51.100.0/24"}
	if got := BuildDiscoveryArgs(opts); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected discovery args:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestBuildDiscoveryArgsCIDRUsesHostDiscovery(t *testing.T) {
	t.Parallel()

	opts := model.DefaultOptions()
	opts.Level = model.ScanLevelHigh
	opts.Target = "198.51.100.0/24"
	normalized, err := model.NormalizeScanOptions(opts)
	if err != nil {
		t.Fatalf("NormalizeScanOptions: %v", err)
	}

	want := []string{"-sn", "-T", "4", "-oX", "-", "198.51.100.0/24"}
	if got := BuildDiscoveryArgs(normalized); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected CIDR discovery args:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestBuildDiscoveryArgsSingleHostKeepsSpoofing(t *testing.T) {
	t.Parallel()

	opts := model.DefaultOptions()
	opts.Level = model.ScanLevelHigh
	opts.Target = "198.51.100.10"
	normalized, err := model.NormalizeScanOptions(opts)
	if err != nil {
		t.Fatalf("NormalizeScanOptions: %v", err)
	}

	want := []string{"-sS", "-T", "4", "-oX", "-", "--top-ports", "1000", "--spoof-mac", "random", "198.51.100.10"}
	if got := BuildDiscoveryArgs(normalized); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected single-host discovery args:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestBuildDiscoveryArgsLocalSingleHostSuppressesSpoofing(t *testing.T) {
	t.Parallel()

	opts := model.DefaultOptions()
	opts.Level = model.ScanLevelHigh
	opts.Target = "127.0.0.1"
	normalized, err := model.NormalizeScanOptions(opts)
	if err != nil {
		t.Fatalf("NormalizeScanOptions: %v", err)
	}

	want := []string{"-sS", "-T", "4", "-oX", "-", "--top-ports", "1000", "127.0.0.1"}
	if got := BuildDiscoveryArgs(normalized); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected local single-host discovery args:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestBuildDetailArgsDefaultAndSelective(t *testing.T) {
	t.Parallel()

	opts := model.DefaultOptions()
	opts.Level = model.ScanLevelMid
	normalized, err := model.NormalizeScanOptions(opts)
	if err != nil {
		t.Fatalf("NormalizeScanOptions: %v", err)
	}

	wantDefault := []string{"-sT", "-T", "4", "-oX", "-", "-p", "T:22,80", "-sV", "-Pn", "--script", "ssh-hostkey,ssh2-enum-algos,http-title,http-headers,http-server-header,http-enum,http-methods,http-auth,http-security-headers", "198.51.100.10"}
	if got := BuildDetailArgs("198.51.100.10", []int{22, 80}, normalized); !reflect.DeepEqual(got, wantDefault) {
		t.Fatalf("unexpected default detail args:\nwant %#v\ngot  %#v", wantDefault, got)
	}

	low := model.DefaultOptions()
	low.Level = model.ScanLevelLow
	normalizedLow, err := model.NormalizeScanOptions(low)
	if err != nil {
		t.Fatalf("NormalizeScanOptions low: %v", err)
	}
	wantLow := []string{"-sT", "-T", "3", "-oX", "-", "-p", "T:22,80", "-sV", "-Pn", "--script", "ssh-hostkey,http-title,http-headers,http-server-header", "198.51.100.10"}
	if got := BuildDetailArgs("198.51.100.10", []int{22, 80}, normalizedLow); !reflect.DeepEqual(got, wantLow) {
		t.Fatalf("unexpected low detail args:\nwant %#v\ngot  %#v", wantLow, got)
	}
}

func TestBuildDetailArgsHighProfile(t *testing.T) {
	t.Parallel()

	opts := model.DefaultOptions()
	opts.Level = model.ScanLevelHigh
	normalized, err := model.NormalizeScanOptions(opts)
	if err != nil {
		t.Fatalf("NormalizeScanOptions high: %v", err)
	}

	wantDefault := []string{"-sS", "-T", "4", "-oX", "-", "-p", "T:22,80,U:53,67,68,123,137,161,500,1900,5353", "-sU", "--version-light", "-sV", "-O", "--traceroute", "-Pn", "--spoof-mac", "random", "--script", "ssh-hostkey,ssh2-enum-algos,sshv1,http-title,http-headers,http-server-header,http-enum,http-methods,http-auth,http-security-headers,dns-nsid,dns-service-discovery,ntp-info,nbstat,snmp-info,ike-version,upnp-info", "198.51.100.10"}
	if got := BuildDetailArgs("198.51.100.10", []int{22, 80}, normalized); !reflect.DeepEqual(got, wantDefault) {
		t.Fatalf("unexpected default detail args:\nwant %#v\ngot  %#v", wantDefault, got)
	}
}

func TestBuildDetailArgsWithUDPProfile(t *testing.T) {
	t.Parallel()

	opts := model.DefaultOptions()
	opts.Target = "198.51.100.0/24"
	opts.Level = model.ScanLevelHigh
	normalized, err := model.NormalizeScanOptions(opts)
	if err != nil {
		t.Fatalf("NormalizeScanOptions: %v", err)
	}

	got := BuildDetailArgs("198.51.100.10", []int{443}, normalized)
	wantPrefix := []string{"-sS", "-T", "4", "-oX", "-", "-p", "T:443,U:53,67,68,123,137,161,500,1900,5353", "-sU", "--version-light", "-sV", "-O", "--traceroute", "-Pn"}
	if !reflect.DeepEqual(got[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("unexpected UDP detail args prefix:\nwant %#v\ngot  %#v", wantPrefix, got[:len(wantPrefix)])
	}
}

func TestBuildPortProbeArgsUsesTopPortsAndServiceVersion(t *testing.T) {
	t.Parallel()

	opts := model.DefaultOptions()
	opts.Target = "198.51.100.0/24"
	opts.Level = model.ScanLevelHigh
	normalized, err := model.NormalizeScanOptions(opts)
	if err != nil {
		t.Fatalf("NormalizeScanOptions: %v", err)
	}

	want := []string{"-sS", "-T", "4", "-oX", "-", "--top-ports", "1000", "-Pn", "-sV", "--spoof-mac", "random", "198.51.100.10"}
	if got := BuildPortProbeArgs("198.51.100.10", normalized); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected probe args:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestRecommendedScripts(t *testing.T) {
	t.Parallel()

	got := RecommendedScripts([]int{22, 443, 8443})
	want := []string{
		"ssh-hostkey",
		"ssh2-enum-algos",
		"sshv1",
		"ssl-cert",
		"ssl-enum-ciphers",
		"ssl-heartbleed",
		"http-title",
		"http-headers",
		"http-server-header",
		"http-enum",
		"http-methods",
		"http-auth",
		"http-security-headers",
		"dns-nsid",
		"dns-service-discovery",
		"ntp-info",
		"nbstat",
		"snmp-info",
		"ike-version",
		"upnp-info",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected recommended scripts:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestBuildDetailArgsForHostTargetsRTSPInsteadOfHTTP(t *testing.T) {
	t.Parallel()

	opts := model.DefaultOptions()
	opts.Level = model.ScanLevelHigh
	normalized, err := model.NormalizeScanOptions(opts)
	if err != nil {
		t.Fatalf("NormalizeScanOptions: %v", err)
	}

	host := parser.Host{
		Ports: []parser.Port{
			{
				ID:       5000,
				Protocol: "tcp",
				State:    "open",
				Service: parser.Service{
					Name:    "rtsp",
					Product: "AirTunes",
				},
			},
		},
	}

	got := BuildDetailArgsForHost("198.51.100.50", []int{5000}, host, normalized)
	want := []string{"-sS", "-T", "4", "-oX", "-", "-p", "T:5000,U:53,67,68,123,137,161,500,1900,5353", "-sU", "--version-light", "-sV", "-O", "--traceroute", "-Pn", "--spoof-mac", "random", "--script", "dns-nsid,dns-service-discovery,ntp-info,nbstat,snmp-info,ike-version,upnp-info,rtsp-methods", "198.51.100.50"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected RTSP detail args:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestBuildDetailArgsForHostAddsRicherHTTPScripts(t *testing.T) {
	t.Parallel()

	opts := model.DefaultOptions()
	opts.Level = model.ScanLevelHigh
	normalized, err := model.NormalizeScanOptions(opts)
	if err != nil {
		t.Fatalf("NormalizeScanOptions: %v", err)
	}

	host := parser.Host{
		Addresses: []parser.Address{{Type: "mac", Addr: "AA:BB:CC:DD:EE:FF", Vendor: "TP-Link Systems"}},
		Ports: []parser.Port{
			{
				ID:       80,
				Protocol: "tcp",
				State:    "open",
				Service: parser.Service{
					Name:    "http",
					Product: "Boa",
				},
			},
		},
	}

	got := BuildDetailArgsForHost("198.51.100.1", []int{80}, host, normalized)
	want := []string{"-sS", "-T", "4", "-oX", "-", "-p", "T:80,U:53,67,68,123,137,161,500,1900,5353", "-sU", "--version-light", "-sV", "-O", "--traceroute", "-Pn", "--spoof-mac", "random", "--script", "http-title,http-headers,http-server-header,http-enum,http-methods,http-auth,http-security-headers,dns-nsid,dns-service-discovery,ntp-info,nbstat,snmp-info,ike-version,upnp-info,http-favicon,http-date,http-generator,http-robots.txt,http-ntlm-info,http-auth-finder", "198.51.100.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected HTTP detail args:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestBuildPortProbeArgsSuppressesSpoofOnLocalTarget(t *testing.T) {
	t.Parallel()

	opts := model.DefaultOptions()
	opts.Level = model.ScanLevelHigh
	normalized, err := model.NormalizeScanOptions(opts)
	if err != nil {
		t.Fatalf("NormalizeScanOptions: %v", err)
	}

	want := []string{"-sS", "-T", "4", "-oX", "-", "--top-ports", "1000", "-Pn", "-sV", "127.0.0.1"}
	if got := BuildPortProbeArgs("127.0.0.1", normalized); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected local probe args:\nwant %#v\ngot  %#v", want, got)
	}
}
