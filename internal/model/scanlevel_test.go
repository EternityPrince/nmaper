package model

import "testing"

func TestNormalizeScanOptionsByLevel(t *testing.T) {
	t.Parallel()

	low, err := NormalizeScanOptions(DefaultOptions())
	if err != nil {
		t.Fatalf("normalize default opts: %v", err)
	}
	if low.Level != ScanLevelMid || !low.ServiceVersion || low.EnableUDP || low.EnableTraceroute || low.TopPorts != 1000 {
		t.Fatalf("unexpected mid defaults: %#v", low)
	}

	opts := DefaultOptions()
	opts.Level = ScanLevelLow
	opts.UseSudo = true
	normalized, err := NormalizeScanOptions(opts)
	if err != nil {
		t.Fatalf("normalize low opts: %v", err)
	}
	if normalized.UseSudo || normalized.EnableUDP || normalized.EnableTraceroute || normalized.TopPorts != 1000 || normalized.Timing != 3 {
		t.Fatalf("unexpected low profile: %#v", normalized)
	}

	opts = DefaultOptions()
	opts.Level = ScanLevelHigh
	normalized, err = NormalizeScanOptions(opts)
	if err != nil {
		t.Fatalf("normalize high opts: %v", err)
	}
	if !normalized.UseSudo || !normalized.EnableUDP || !normalized.EnableTraceroute || !normalized.OSDetect || normalized.SpoofMAC != "random" || normalized.TopPorts != 1000 {
		t.Fatalf("unexpected high profile: %#v", normalized)
	}
}

func TestNormalizeScanOptionsRejectsLowSpoof(t *testing.T) {
	t.Parallel()

	opts := DefaultOptions()
	opts.Level = ScanLevelLow
	opts.UseSudo = true
	opts.SpoofMAC = "random"
	opts.SpoofMACExplicit = true

	if _, err := NormalizeScanOptions(opts); err == nil {
		t.Fatalf("expected low spoof validation error")
	}
}

func TestScanLevelCapabilities(t *testing.T) {
	t.Parallel()

	opts := DefaultOptions()
	opts.Level = ScanLevelHigh
	normalized, err := NormalizeScanOptions(opts)
	if err != nil {
		t.Fatalf("NormalizeScanOptions: %v", err)
	}

	capabilities := ScanLevelCapabilities(normalized)
	for _, want := range []string{
		"privileged SYN scanning",
		"top 1000 ports",
		"service detection",
		"OS detection",
		"traceroute snapshots",
		"targeted UDP enrichment",
		"random MAC spoofing",
		"safe NSE enrichment",
		"6 parallel detail workers",
	} {
		if !containsString(capabilities, want) {
			t.Fatalf("capabilities missing %q: %#v", want, capabilities)
		}
	}
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
