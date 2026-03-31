package fuzzy

import "testing"

func TestNormalize(t *testing.T) {
	t.Parallel()

	got := Normalize("TP-Link Archer C6")
	if got != "tplinkarcherc6" {
		t.Fatalf("unexpected normalized value: %q", got)
	}
}

func TestMatch(t *testing.T) {
	t.Parallel()

	if !Match("192.168.0.1", "19216801") {
		t.Fatalf("expected fuzzy IP match")
	}
	if !Match("TP-Link Systems", "tplink") {
		t.Fatalf("expected vendor match")
	}
	if Match("Cisco", "mikrotik") {
		t.Fatalf("did not expect unrelated vendor match")
	}
}
