package output

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nmaper/internal/history"
)

type testLogger struct {
	warnings []string
}

func (l *testLogger) Warnf(format string, args ...any) {
	l.warnings = append(l.warnings, format)
}

func TestResolve(t *testing.T) {
	t.Parallel()

	cases := []struct {
		out      string
		mode     renderMode
		sink     sinkType
		pathPart string
	}{
		{"", modeTerminal, sinkClipboard, ""},
		{"terminal", modeTerminal, sinkStdout, ""},
		{"md", modeMarkdown, sinkStdout, ""},
		{"json", modeJSON, sinkStdout, ""},
		{"file:/tmp/report.md", modeMarkdown, sinkFile, "report.md"},
		{"file:/tmp/report.json", modeJSON, sinkFile, "report.json"},
		{"file:/tmp/report.txt", modeTerminal, sinkFile, "report.txt"},
	}

	for _, tc := range cases {
		mode, sink, path := Resolve(tc.out)
		if mode != tc.mode || sink != tc.sink || (tc.pathPart != "" && !strings.Contains(path, tc.pathPart)) {
			t.Fatalf("Resolve(%q) = (%q, %q, %q)", tc.out, mode, sink, path)
		}
	}
}

func TestEmitToStdoutAndFile(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	if err := Emit("hello", "terminal", &stdout, &testLogger{}); err != nil {
		t.Fatalf("Emit to stdout: %v", err)
	}
	if stdout.String() != "hello\n" {
		t.Fatalf("unexpected stdout content: %q", stdout.String())
	}

	target := filepath.Join(t.TempDir(), "nested", "report.txt")
	if err := Emit("saved", "file:"+target, &stdout, &testLogger{}); err != nil {
		t.Fatalf("Emit to file: %v", err)
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read emitted file: %v", err)
	}
	if string(body) != "saved" {
		t.Fatalf("unexpected file content: %q", string(body))
	}
}

func TestEmitStripsANSIForNonTTYAndFile(t *testing.T) {
	t.Parallel()

	colored := goodText("bright")

	var stdout bytes.Buffer
	if err := Emit(colored, "terminal", &stdout, &testLogger{}); err != nil {
		t.Fatalf("Emit colored terminal output: %v", err)
	}
	if stdout.String() != "bright\n" {
		t.Fatalf("expected ansi-stripped stdout, got %q", stdout.String())
	}

	target := filepath.Join(t.TempDir(), "report.txt")
	if err := Emit(colored, "file:"+target, &stdout, &testLogger{}); err != nil {
		t.Fatalf("Emit colored file output: %v", err)
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read ansi-stripped file: %v", err)
	}
	if string(body) != "bright" {
		t.Fatalf("expected ansi-stripped file, got %q", string(body))
	}
}

func TestRenderReports(t *testing.T) {
	t.Parallel()

	session := history.SessionSummary{
		ID:              2,
		Name:            "session-2",
		Status:          "completed",
		StartedAt:       time.Date(2026, 3, 2, 10, 0, 0, 0, time.UTC),
		Duration:        "30s",
		ScanLevel:       "high",
		Target:          "10.0.0.0/24",
		DiscoveredHosts: 3,
		LiveHosts:       3,
		NmapVersion:     "7.95",
	}
	host := history.HostSnapshot{
		PrimaryIP:         "10.0.0.20",
		Status:            "up",
		MAC:               "AA:BB:CC:DD:EE:FF",
		Vendor:            "Acme Networks",
		Hostnames:         []string{"router-b.local"},
		TopOS:             []string{"Linux 6.x"},
		NSEHits:           2,
		HostScriptHits:    0,
		ServiceScriptHits: 2,
		Services: []history.ServiceSnapshot{
			{Port: 80, Protocol: "tcp", State: "open", Name: "http", Product: "nginx", Version: "1.26", Scripts: []history.ScriptResult{{ID: "http-title", Output: "Router B"}, {ID: "http-headers", Output: "Server: nginx"}}},
		},
		Trace: &history.TraceSnapshot{
			Proto: "tcp",
			Port:  80,
			Hops:  []history.TraceHop{{TTL: 1, IP: "10.0.0.1", RTT: 0.91, Host: "gateway"}},
		},
	}

	sessionReport := history.SessionReport{Session: session, Hosts: []history.HostSnapshot{host}}
	diffReport := history.DiffReport{
		From:         history.SessionSummary{ID: 1},
		To:           history.SessionSummary{ID: 2},
		NewHosts:     []history.HostDiffSnapshot{{IP: "10.0.0.30", Status: "up", OpenPorts: []string{"22/tcp"}}},
		MissingHosts: []history.HostDiffSnapshot{{IP: "10.0.0.10", Status: "up", OpenPorts: []string{"80/tcp"}}},
		ChangedHosts: []history.ChangedHost{{IP: "10.0.0.11", Reasons: []string{"open_ports"}}},
	}
	globalReport := history.GlobalDynamicsReport{
		SessionCount: 2,
		UniqueHosts:  4,
		StableHosts:  []string{"10.0.0.11"},
		Transient:    []string{"10.0.0.30"},
		Volatile:     []string{"10.0.0.11"},
		LastMovement: "between session 1 and 2",
		TopPorts:     []history.PortFrequency{{Port: "80/tcp", Count: 2}},
	}
	deviceReport := history.DeviceAnalyticsReport{
		UniqueDevices: 3,
		MACBacked:     1,
		IPOnly:        2,
		TopDevices:    []history.DeviceStat{{Label: "AA:BB:CC:DD:EE:FF", Appearances: 2, Vendor: "Acme Networks", IPs: []string{"10.0.0.10", "10.0.0.20"}}},
		TopVendors:    []history.VendorStat{{Vendor: "Acme Networks", Count: 1}},
	}
	deviceHistory := history.DeviceHistoryReport{
		Query: "acme",
		Devices: []history.DeviceHistory{
			{
				Label:       "AA:BB:CC:DD:EE:FF",
				Vendor:      "Acme Networks",
				IPs:         []string{"10.0.0.10", "10.0.0.20"},
				Appearances: []history.DeviceAppearance{{Session: history.SessionSummary{ID: 1, StartedAt: session.StartedAt}, IP: "10.0.0.10", OpenPorts: []string{"80/tcp"}, TopOS: "Linux 6.x"}},
			},
		},
	}
	timelineReport := history.TimelineReport{Entries: []history.TimelineEntry{{From: history.SessionSummary{ID: 1}, To: history.SessionSummary{ID: 2}, ChangedHosts: []history.ChangedHost{{IP: "10.0.0.11"}}}}}
	postureReport := history.PostureSummary{
		SessionID:                        2,
		SessionStartedAt:                 ptrTime(session.StartedAt),
		ScopeHosts:                       3,
		ManagementExposureHosts:          3,
		WeakTLSHosts:                     1,
		ManagementOutdatedTLSOnlyHosts:   0,
		WeakSSHHosts:                     1,
		LegacySMBHosts:                   0,
		WebWithoutSecurityHeadersHosts:   1,
		MissingCoreSecurityHeadersHosts:  2,
		AuthSurfaceHosts:                 2,
		UnstableIdentityOrPortDriftHosts: 2,
		VendorFilter:                     "acme",
		NetworkFilter:                    "10.0.0.0/24",
		SessionsAnalyzedForDrift:         2,
	}

	outputs := []struct {
		name   string
		render func() (string, error)
		match  string
	}{
		{"sessions-terminal", func() (string, error) {
			return RenderSessionsView([]history.SessionSummary{session}, "terminal", "compact")
		}, "Summary"},
		{"session-terminal-full", func() (string, error) {
			return RenderSessionView(sessionReport, "terminal", "full")
		}, "Ports:"},
		{"session-md", func() (string, error) { return RenderSession(sessionReport, "md") }, "NSE hits"},
		{"session-json", func() (string, error) { return RenderSession(sessionReport, "json") }, "\"nse_hits\": 2"},
		{"diff-terminal", func() (string, error) { return RenderDiffView(diffReport, "terminal", "compact") }, "What needs attention"},
		{"global-md", func() (string, error) { return RenderGlobalView(globalReport, "md", "compact") }, "# Global Dynamics"},
		{"devices-terminal", func() (string, error) { return RenderDevicesView(deviceReport, "terminal", "compact") }, "Top changed hosts"},
		{"device-history-md", func() (string, error) { return RenderDeviceHistoryView(deviceHistory, "md", "full") }, "# Device History: acme"},
		{"timeline-json", func() (string, error) { return RenderTimelineView(timelineReport, "json", "compact") }, "\"changed_hosts\""},
		{"posture-terminal", func() (string, error) { return RenderPosture(postureReport, "terminal") }, "Risk Classes"},
		{"posture-md", func() (string, error) { return RenderPosture(postureReport, "md") }, "Security Posture Summary"},
	}

	for _, tc := range outputs {
		got, err := tc.render()
		if err != nil {
			t.Fatalf("%s render error: %v", tc.name, err)
		}
		if !strings.Contains(got, tc.match) {
			t.Fatalf("%s output missing %q:\n%s", tc.name, tc.match, got)
		}
	}
}

func ptrTime(value time.Time) *time.Time {
	return &value
}
