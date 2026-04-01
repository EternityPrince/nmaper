package history_test

import (
	"context"
	"strings"
	"testing"

	"nmaper/internal/history"
	"nmaper/internal/storage"
	"nmaper/internal/testutil"
)

func TestSessionReportAndDiff(t *testing.T) {
	t.Parallel()

	fixture := testutil.SeedHistoryDB(t)
	store, err := storage.Open(fixture.DBPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	service := history.New(store.DB())
	sessions, err := service.ListSessions(context.Background(), 10, "completed", "10.0.0")
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 2 || sessions[0].ID != fixture.Session2ID || sessions[1].ID != fixture.Session1ID {
		t.Fatalf("unexpected sessions order: %#v", sessions)
	}
	if sessions[0].ScanLevel != "mid" || sessions[1].ScanLevel != "mid" {
		t.Fatalf("expected persisted scan levels, got %#v", sessions)
	}

	report, err := service.SessionReport(context.Background(), fixture.Session1ID, "100011")
	if err != nil {
		t.Fatalf("SessionReport: %v", err)
	}
	if len(report.Hosts) != 1 || report.Hosts[0].PrimaryIP != "10.0.0.11" {
		t.Fatalf("unexpected filtered hosts: %#v", report.Hosts)
	}
	if len(report.Hosts[0].Services) != 1 || report.Hosts[0].Services[0].Port != 8080 {
		t.Fatalf("unexpected services for filtered host: %#v", report.Hosts[0].Services)
	}

	fullReport, err := service.SessionReport(context.Background(), fixture.Session1ID, "")
	if err != nil {
		t.Fatalf("SessionReport full: %v", err)
	}
	if len(fullReport.Hosts) != 2 || fullReport.Hosts[0].Trace == nil {
		t.Fatalf("expected trace and two hosts, got %#v", fullReport.Hosts)
	}
	if fullReport.Hosts[0].Services[0].HTTP == nil || fullReport.Hosts[0].Services[0].HTTP.Title == "" {
		t.Fatalf("expected normalized HTTP fingerprint, got %#v", fullReport.Hosts[0].Services[0])
	}

	diff, err := service.Diff(context.Background(), fixture.Session1ID, fixture.Session2ID)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(diff.NewHosts) != 1 || len(diff.MissingHosts) != 0 || len(diff.ChangedHosts) != 2 {
		t.Fatalf("unexpected diff summary: %#v", diff)
	}
	if diff.Summary.MovedHosts != 1 || diff.Summary.OpenedPorts != 2 || diff.Summary.ClosedPorts != 1 {
		t.Fatalf("unexpected diff summary counters: %#v", diff.Summary)
	}
	if diff.Summary.FingerprintChanges == 0 || diff.Summary.VulnerabilityChanges == 0 || diff.Summary.ManagementChanges == 0 {
		t.Fatalf("expected richer change counters, got %#v", diff.Summary)
	}
	if !containsAlert(diff.Alerts, "management_port_opened") || !containsAlert(diff.Alerts, "http_title_changed") || !containsAlert(diff.Alerts, "vulnerability_detected") {
		t.Fatalf("expected high-signal alerts, got %#v", diff.Alerts)
	}
	if diff.ChangedHosts[0].IP != "10.0.0.11" || !contains(diff.ChangedHosts[0].Reasons, "open_ports") || !contains(diff.ChangedHosts[0].Reasons, "management") {
		t.Fatalf("unexpected changed host: %#v", diff.ChangedHosts[0])
	}
	if diff.ChangedHosts[1].IP != "10.0.0.20" || !contains(diff.ChangedHosts[1].Reasons, "primary_ip") || len(diff.ChangedHosts[1].NewVulnerabilities) == 0 {
		t.Fatalf("expected host move to 10.0.0.20, got %#v", diff.ChangedHosts[1])
	}
}

func TestAnalyticsAndDevices(t *testing.T) {
	t.Parallel()

	fixture := testutil.SeedHistoryDB(t)
	store, err := storage.Open(fixture.DBPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	service := history.New(store.DB())

	global, err := service.GlobalDynamics(context.Background(), 10, "", "")
	if err != nil {
		t.Fatalf("GlobalDynamics: %v", err)
	}
	if global.UniqueHosts != 4 {
		t.Fatalf("unexpected unique hosts: %d", global.UniqueHosts)
	}
	if !contains(global.StableHosts, "10.0.0.11") || !contains(global.Volatile, "10.0.0.11") {
		t.Fatalf("unexpected stable/volatile hosts: %#v / %#v", global.StableHosts, global.Volatile)
	}
	if len(global.TopPorts) == 0 || global.TopPorts[0].Port != "80/tcp" || global.TopPorts[0].Count != 2 {
		t.Fatalf("unexpected top ports: %#v", global.TopPorts)
	}
	if !strings.Contains(global.LastMovement, "between session") || !strings.Contains(global.LastMovement, "->1 moved") || !strings.Contains(global.LastMovement, "fp:") {
		t.Fatalf("unexpected last movement: %q", global.LastMovement)
	}

	posture, err := service.Posture(context.Background(), "", "")
	if err != nil {
		t.Fatalf("Posture: %v", err)
	}
	if posture.ScopeHosts != 3 || posture.ManagementExposureHosts != 3 {
		t.Fatalf("unexpected posture scope/management: %#v", posture)
	}
	if posture.WeakTLSHosts != 1 || posture.ManagementOutdatedTLSOnlyHosts != 0 || posture.WeakSSHHosts != 1 || posture.LegacySMBHosts != 0 {
		t.Fatalf("unexpected posture weak/legacy counters: %#v", posture)
	}
	if posture.WebWithoutSecurityHeadersHosts != 1 || posture.MissingCoreSecurityHeadersHosts != 2 || posture.AuthSurfaceHosts != 2 {
		t.Fatalf("unexpected posture web/auth counters: %#v", posture)
	}
	if posture.UnstableIdentityOrPortDriftHosts != 2 || posture.SessionsAnalyzedForDrift != 2 {
		t.Fatalf("unexpected posture drift counters: %#v", posture)
	}

	filteredPosture, err := service.Posture(context.Background(), "acme", "10.0.0.0/28")
	if err != nil {
		t.Fatalf("Posture filtered: %v", err)
	}
	if filteredPosture.ScopeHosts != 0 {
		t.Fatalf("expected no hosts in filtered posture, got %#v", filteredPosture)
	}

	if _, err := service.Posture(context.Background(), "", "not-a-network"); err == nil {
		t.Fatalf("expected invalid network filter error")
	}

	devices, err := service.Devices(context.Background(), "acme", false, false)
	if err != nil {
		t.Fatalf("Devices: %v", err)
	}
	if devices.UniqueDevices != 1 || devices.MACBacked != 1 || devices.IPOnly != 0 {
		t.Fatalf("unexpected filtered device analytics: %#v", devices)
	}

	allDevices, err := service.Devices(context.Background(), "", false, false)
	if err != nil {
		t.Fatalf("Devices all: %v", err)
	}
	if allDevices.UniqueDevices != 3 || len(allDevices.MultiIP) != 1 {
		t.Fatalf("unexpected all-device analytics: %#v", allDevices)
	}

	deviceHistory, err := service.DeviceHistory(context.Background(), "acme", "", false, false)
	if err != nil {
		t.Fatalf("DeviceHistory: %v", err)
	}
	if len(deviceHistory.Devices) != 1 || len(deviceHistory.Devices[0].Appearances) != 2 {
		t.Fatalf("unexpected device history: %#v", deviceHistory)
	}

	timeline, err := service.Timeline(context.Background(), 10, "", "")
	if err != nil {
		t.Fatalf("Timeline: %v", err)
	}
	if len(timeline.Entries) != 1 || len(timeline.Entries[0].ChangedHosts) != 2 {
		t.Fatalf("unexpected timeline: %#v", timeline)
	}
	if timeline.Entries[0].Summary.MovedHosts != 1 || timeline.Entries[0].Summary.FingerprintChanges == 0 || timeline.Entries[0].Summary.HighSignalAlerts == 0 || len(timeline.Entries[0].Alerts) == 0 {
		t.Fatalf("expected one moved host in timeline, got %#v", timeline.Entries[0].Summary)
	}
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func containsAlert(items []history.DiffAlert, want string) bool {
	for _, item := range items {
		if item.Type == want {
			return true
		}
	}
	return false
}
