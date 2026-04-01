package app

import (
	"reflect"
	"testing"
	"time"

	"nmaper/internal/converter"
	"nmaper/internal/parser"
	"nmaper/internal/scanner"
)

func TestToCompletedScanCopiesScannerResultIntoStorageShape(t *testing.T) {
	t.Parallel()

	startedAt := time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC)
	completedAt := startedAt.Add(15 * time.Second)
	result := scanner.Result{
		SessionName: "scan-1",
		StartedAt:   startedAt,
		CompletedAt: completedAt,
		SourceIdentity: scanner.SourceIdentity{
			Interface:  "en0",
			RealMAC:    "AA:BB:CC:DD:EE:FF",
			SpoofedMAC: "11:22:33:44:55:66",
		},
		DiscoveryRun:     parser.Run{Version: "7.99"},
		DiscoveryCommand: []string{"nmap", "-sn", "10.0.0.0/24"},
		DetailRuns: map[string]parser.Run{
			"10.0.0.10": {Version: "7.99"},
		},
		DetailCommands: map[string][]string{
			"10.0.0.10": {"nmap", "-sV", "10.0.0.10"},
		},
		DetailErrors: map[string]string{
			"10.0.0.11": "timeout",
		},
		Targets: []converter.DetailTarget{
			{IP: "10.0.0.10", Ports: []int{80, 443}},
		},
	}

	converted := toCompletedScan(result)
	if converted.SessionName != result.SessionName || !converted.StartedAt.Equal(startedAt) || !converted.CompletedAt.Equal(completedAt) {
		t.Fatalf("unexpected top-level fields: %#v", converted)
	}
	if converted.SourceIdentity.Interface != "en0" || converted.SourceIdentity.RealMAC != "AA:BB:CC:DD:EE:FF" || converted.SourceIdentity.SpoofedMAC != "11:22:33:44:55:66" {
		t.Fatalf("unexpected source identity: %#v", converted.SourceIdentity)
	}
	if !reflect.DeepEqual(converted.DiscoveryCommand, result.DiscoveryCommand) {
		t.Fatalf("unexpected discovery command: %#v", converted.DiscoveryCommand)
	}
	if !reflect.DeepEqual(converted.DetailRuns, result.DetailRuns) {
		t.Fatalf("unexpected detail runs: %#v", converted.DetailRuns)
	}
	if !reflect.DeepEqual(converted.DetailCommands, result.DetailCommands) {
		t.Fatalf("unexpected detail commands: %#v", converted.DetailCommands)
	}
	if !reflect.DeepEqual(converted.DetailErrors, result.DetailErrors) {
		t.Fatalf("unexpected detail errors: %#v", converted.DetailErrors)
	}
	if !reflect.DeepEqual(converted.Targets, result.Targets) {
		t.Fatalf("unexpected targets: %#v", converted.Targets)
	}

	result.DetailCommands["10.0.0.10"][0] = "mutated"
	result.Targets[0].Ports[0] = 22
	if converted.DetailCommands["10.0.0.10"][0] != "nmap" {
		t.Fatalf("expected detail commands to be cloned, got %#v", converted.DetailCommands)
	}
	if converted.Targets[0].Ports[0] != 80 {
		t.Fatalf("expected targets to be cloned, got %#v", converted.Targets)
	}
}
