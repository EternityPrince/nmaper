package scanner

import (
	"strings"
	"testing"
)

func TestResolveSpoofMAC(t *testing.T) {
	t.Parallel()

	got, err := resolveSpoofMAC("aa:bb:cc:dd:ee:ff")
	if err != nil {
		t.Fatalf("resolve explicit spoof mac: %v", err)
	}
	if got != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("unexpected normalized mac: %q", got)
	}

	random, err := resolveSpoofMAC("random")
	if err != nil {
		t.Fatalf("resolve random spoof mac: %v", err)
	}
	if len(strings.Split(random, ":")) != 6 {
		t.Fatalf("unexpected random mac format: %q", random)
	}
	if random == got {
		t.Fatalf("expected random mac to differ from explicit one")
	}
}

func TestRepresentativeDialTarget(t *testing.T) {
	t.Parallel()

	if got := representativeDialTarget("192.168.10.0/24"); got != "192.168.10.1" {
		t.Fatalf("unexpected cidr dial target: %q", got)
	}
	if got := representativeDialTarget("10.0.0.8"); got != "10.0.0.8" {
		t.Fatalf("unexpected ip dial target: %q", got)
	}
}
