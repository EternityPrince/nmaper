package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"nmaper/internal/history"
)

type logger interface {
	Warnf(string, ...any)
}

type renderMode string

const (
	modeTerminal renderMode = "terminal"
	modeMarkdown renderMode = "markdown"
	modeJSON     renderMode = "json"
)

type sinkType string

const (
	sinkStdout    sinkType = "stdout"
	sinkClipboard sinkType = "clipboard"
	sinkFile      sinkType = "file"
)

func Resolve(out string) (renderMode, sinkType, string) {
	switch {
	case out == "", out == "clipboard":
		return modeTerminal, sinkClipboard, ""
	case out == "md":
		return modeMarkdown, sinkStdout, ""
	case out == "json":
		return modeJSON, sinkStdout, ""
	case out == "terminal":
		return modeTerminal, sinkStdout, ""
	case strings.HasPrefix(out, "file:"):
		path := strings.TrimPrefix(out, "file:")
		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".md", ".markdown":
			return modeMarkdown, sinkFile, path
		case ".json":
			return modeJSON, sinkFile, path
		default:
			return modeTerminal, sinkFile, path
		}
	default:
		return modeTerminal, sinkStdout, ""
	}
}

func Emit(text string, out string, stdout io.Writer, log logger) error {
	_, sink, path := Resolve(out)
	switch sink {
	case sinkFile:
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
			return err
		}
		return os.WriteFile(path, []byte(text), 0o644)
	case sinkClipboard:
		if _, err := io.WriteString(stdout, text); err != nil {
			return err
		}
		if !strings.HasSuffix(text, "\n") {
			if _, err := io.WriteString(stdout, "\n"); err != nil {
				return err
			}
		}
		if err := copyToClipboard(text); err != nil && log != nil {
			log.Warnf("clipboard copy failed: %v", err)
		}
		return nil
	default:
		if _, err := io.WriteString(stdout, text); err != nil {
			return err
		}
		if !strings.HasSuffix(text, "\n") {
			_, err := io.WriteString(stdout, "\n")
			return err
		}
		return nil
	}
}

func RenderSessions(items []history.SessionSummary, out string) (string, error) {
	mode, _, _ := Resolve(out)
	switch mode {
	case modeJSON:
		return asJSON(items)
	case modeMarkdown:
		var builder strings.Builder
		builder.WriteString("# Sessions\n\n")
		for _, item := range items {
			builder.WriteString(fmt.Sprintf("- `#%d` `%s` %s target `%s` duration `%s` live/discovered `%d/%d` nmap `%s`\n",
				item.ID, item.Status, item.StartedAt.Format(timeLayout), item.Target, item.Duration, item.LiveHosts, item.DiscoveredHosts, emptyDash(item.NmapVersion)))
		}
		return builder.String(), nil
	default:
		var builder strings.Builder
		builder.WriteString("Sessions\n")
		builder.WriteString(strings.Repeat("=", 8) + "\n")
		for _, item := range items {
			builder.WriteString(fmt.Sprintf("#%d  %-10s  %s  target=%s  duration=%s  live/discovered=%d/%d  nmap=%s\n",
				item.ID, item.Status, item.StartedAt.Format(timeLayout), item.Target, item.Duration, item.LiveHosts, item.DiscoveredHosts, emptyDash(item.NmapVersion)))
		}
		return builder.String(), nil
	}
}

func RenderSession(report history.SessionReport, out string) (string, error) {
	mode, _, _ := Resolve(out)
	switch mode {
	case modeJSON:
		return asJSON(report)
	case modeMarkdown:
		var builder strings.Builder
		builder.WriteString(fmt.Sprintf("# Session %d\n\n", report.Session.ID))
		builder.WriteString(renderSessionMetaMarkdown(report.Session))
		for _, host := range report.Hosts {
			builder.WriteString(renderHostMarkdown(host))
		}
		return builder.String(), nil
	default:
		var builder strings.Builder
		builder.WriteString(fmt.Sprintf("Session %d\n", report.Session.ID))
		builder.WriteString(strings.Repeat("=", 10) + "\n")
		builder.WriteString(renderSessionMetaTerminal(report.Session))
		for _, host := range report.Hosts {
			builder.WriteString(renderHostTerminal(host))
		}
		return builder.String(), nil
	}
}

func RenderDiff(report history.DiffReport, out string) (string, error) {
	mode, _, _ := Resolve(out)
	switch mode {
	case modeJSON:
		return asJSON(report)
	case modeMarkdown:
		var builder strings.Builder
		builder.WriteString(fmt.Sprintf("# Diff %d -> %d\n\n", report.From.ID, report.To.ID))
		builder.WriteString(renderDiffSectionsMarkdown(report))
		return builder.String(), nil
	default:
		var builder strings.Builder
		builder.WriteString(fmt.Sprintf("Diff %d -> %d\n", report.From.ID, report.To.ID))
		builder.WriteString(strings.Repeat("=", 12) + "\n")
		builder.WriteString(renderDiffSectionsTerminal(report))
		return builder.String(), nil
	}
}

func RenderGlobal(report history.GlobalDynamicsReport, out string) (string, error) {
	mode, _, _ := Resolve(out)
	switch mode {
	case modeJSON:
		return asJSON(report)
	case modeMarkdown:
		var builder strings.Builder
		builder.WriteString("# Global Dynamics\n\n")
		builder.WriteString(fmt.Sprintf("- Sessions analysed: `%d`\n", report.SessionCount))
		builder.WriteString(fmt.Sprintf("- Unique hosts: `%d`\n", report.UniqueHosts))
		builder.WriteString(fmt.Sprintf("- Stable hosts: %s\n", joinOrDash(report.StableHosts)))
		builder.WriteString(fmt.Sprintf("- Transient hosts: %s\n", joinOrDash(report.Transient)))
		builder.WriteString(fmt.Sprintf("- Volatile hosts: %s\n", joinOrDash(report.Volatile)))
		builder.WriteString(fmt.Sprintf("- Last movement: %s\n\n", emptyDash(report.LastMovement)))
		builder.WriteString("## Top Ports\n")
		for _, item := range report.TopPorts {
			builder.WriteString(fmt.Sprintf("- `%s` x %d\n", item.Port, item.Count))
		}
		return builder.String(), nil
	default:
		var builder strings.Builder
		builder.WriteString("Global Dynamics\n")
		builder.WriteString(strings.Repeat("=", 15) + "\n")
		builder.WriteString(fmt.Sprintf("Sessions analysed: %d\n", report.SessionCount))
		builder.WriteString(fmt.Sprintf("Unique hosts: %d\n", report.UniqueHosts))
		builder.WriteString(fmt.Sprintf("Stable hosts: %s\n", joinOrDash(report.StableHosts)))
		builder.WriteString(fmt.Sprintf("Transient hosts: %s\n", joinOrDash(report.Transient)))
		builder.WriteString(fmt.Sprintf("Volatile hosts: %s\n", joinOrDash(report.Volatile)))
		builder.WriteString(fmt.Sprintf("Last movement: %s\n", emptyDash(report.LastMovement)))
		builder.WriteString("\nTop ports:\n")
		for _, item := range report.TopPorts {
			builder.WriteString(fmt.Sprintf("  %s x %d\n", item.Port, item.Count))
		}
		return builder.String(), nil
	}
}

func RenderDevices(report history.DeviceAnalyticsReport, out string) (string, error) {
	mode, _, _ := Resolve(out)
	switch mode {
	case modeJSON:
		return asJSON(report)
	case modeMarkdown:
		var builder strings.Builder
		builder.WriteString("# Device Analytics\n\n")
		builder.WriteString(fmt.Sprintf("- Unique devices: `%d`\n", report.UniqueDevices))
		builder.WriteString(fmt.Sprintf("- MAC-backed: `%d`\n", report.MACBacked))
		builder.WriteString(fmt.Sprintf("- IP-only: `%d`\n\n", report.IPOnly))
		builder.WriteString("## Top Devices\n")
		for _, item := range report.TopDevices {
			builder.WriteString(fmt.Sprintf("- `%s` appearances `%d` vendor `%s` ips `%s`\n", item.Label, item.Appearances, emptyDash(item.Vendor), joinOrDash(item.IPs)))
		}
		builder.WriteString("\n## Top Vendors\n")
		for _, item := range report.TopVendors {
			builder.WriteString(fmt.Sprintf("- `%s` x %d\n", item.Vendor, item.Count))
		}
		return builder.String(), nil
	default:
		var builder strings.Builder
		builder.WriteString("Device Analytics\n")
		builder.WriteString(strings.Repeat("=", 16) + "\n")
		builder.WriteString(fmt.Sprintf("Unique devices: %d\nMAC-backed: %d\nIP-only: %d\n", report.UniqueDevices, report.MACBacked, report.IPOnly))
		builder.WriteString("\nTop devices:\n")
		for _, item := range report.TopDevices {
			builder.WriteString(fmt.Sprintf("  %s  appearances=%d  vendor=%s  ips=%s\n", item.Label, item.Appearances, emptyDash(item.Vendor), joinOrDash(item.IPs)))
		}
		builder.WriteString("\nTop vendors:\n")
		for _, item := range report.TopVendors {
			builder.WriteString(fmt.Sprintf("  %s x %d\n", item.Vendor, item.Count))
		}
		return builder.String(), nil
	}
}

func RenderDeviceHistory(report history.DeviceHistoryReport, out string) (string, error) {
	mode, _, _ := Resolve(out)
	switch mode {
	case modeJSON:
		return asJSON(report)
	case modeMarkdown:
		var builder strings.Builder
		builder.WriteString(fmt.Sprintf("# Device History: %s\n\n", report.Query))
		for _, device := range report.Devices {
			builder.WriteString(fmt.Sprintf("## %s\n\n", device.Label))
			builder.WriteString(fmt.Sprintf("- Vendor: `%s`\n", emptyDash(device.Vendor)))
			builder.WriteString(fmt.Sprintf("- IPs: %s\n", joinOrDash(device.IPs)))
			for _, appearance := range device.Appearances {
				builder.WriteString(fmt.Sprintf("- Session `%d` `%s` ip `%s` status `%s` ports `%s` top OS `%s`\n",
					appearance.Session.ID, appearance.Session.StartedAt.Format(timeLayout), appearance.IP, emptyDash(appearance.Status), joinOrDash(appearance.OpenPorts), emptyDash(appearance.TopOS)))
			}
			builder.WriteString("\n")
		}
		return builder.String(), nil
	default:
		var builder strings.Builder
		builder.WriteString(fmt.Sprintf("Device History: %s\n", report.Query))
		builder.WriteString(strings.Repeat("=", 16) + "\n")
		for _, device := range report.Devices {
			builder.WriteString(fmt.Sprintf("%s  vendor=%s  ips=%s\n", device.Label, emptyDash(device.Vendor), joinOrDash(device.IPs)))
			for _, appearance := range device.Appearances {
				builder.WriteString(fmt.Sprintf("  session=%d  time=%s  ip=%s  status=%s  ports=%s  top-os=%s\n",
					appearance.Session.ID, appearance.Session.StartedAt.Format(timeLayout), appearance.IP, emptyDash(appearance.Status), joinOrDash(appearance.OpenPorts), emptyDash(appearance.TopOS)))
			}
			builder.WriteString("\n")
		}
		return builder.String(), nil
	}
}

func RenderTimeline(report history.TimelineReport, out string) (string, error) {
	mode, _, _ := Resolve(out)
	switch mode {
	case modeJSON:
		return asJSON(report)
	case modeMarkdown:
		var builder strings.Builder
		builder.WriteString("# Timeline\n\n")
		for _, entry := range report.Entries {
			builder.WriteString(fmt.Sprintf("## %d -> %d\n\n", entry.From.ID, entry.To.ID))
			builder.WriteString(renderTimelineEntryMarkdown(entry))
		}
		return builder.String(), nil
	default:
		var builder strings.Builder
		builder.WriteString("Timeline\n")
		builder.WriteString(strings.Repeat("=", 8) + "\n")
		for _, entry := range report.Entries {
			builder.WriteString(fmt.Sprintf("%d -> %d\n", entry.From.ID, entry.To.ID))
			builder.WriteString(renderTimelineEntryTerminal(entry))
			builder.WriteString("\n")
		}
		return builder.String(), nil
	}
}

func asJSON(value any) (string, error) {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func renderSessionMetaTerminal(session history.SessionSummary) string {
	return fmt.Sprintf("Status: %s\nStarted: %s\nDuration: %s\nTarget: %s\nLive/discovered: %d/%d\nNmap: %s\n\n",
		session.Status,
		session.StartedAt.Format(timeLayout),
		session.Duration,
		session.Target,
		session.LiveHosts,
		session.DiscoveredHosts,
		emptyDash(session.NmapVersion),
	)
}

func renderSessionMetaMarkdown(session history.SessionSummary) string {
	return fmt.Sprintf("- Status: `%s`\n- Started: `%s`\n- Duration: `%s`\n- Target: `%s`\n- Live/discovered: `%d/%d`\n- Nmap: `%s`\n\n",
		session.Status,
		session.StartedAt.Format(timeLayout),
		session.Duration,
		session.Target,
		session.LiveHosts,
		session.DiscoveredHosts,
		emptyDash(session.NmapVersion),
	)
}

func renderHostTerminal(host history.HostSnapshot) string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("Host %s\n", host.PrimaryIP))
	builder.WriteString(fmt.Sprintf("  status=%s  mac=%s  vendor=%s\n", emptyDash(host.Status), emptyDash(host.MAC), emptyDash(host.Vendor)))
	builder.WriteString(fmt.Sprintf("  hostnames=%s\n", joinOrDash(host.Hostnames)))
	builder.WriteString(fmt.Sprintf("  top-os=%s\n", joinOrDash(host.TopOS)))
	if len(host.Services) > 0 {
		builder.WriteString("  services:\n")
		for _, service := range host.Services {
			builder.WriteString(fmt.Sprintf("    %d/%s  %-7s  %s %s %s\n",
				service.Port,
				service.Protocol,
				emptyDash(service.State),
				emptyDash(service.Name),
				emptyDash(service.Product),
				emptyDash(service.Version),
			))
		}
	}
	if host.Trace != nil && len(host.Trace.Hops) > 0 {
		builder.WriteString("  trace:\n")
		for _, hop := range host.Trace.Hops {
			builder.WriteString(fmt.Sprintf("    ttl=%d ip=%s rtt=%.2f host=%s\n", hop.TTL, emptyDash(hop.IP), hop.RTT, emptyDash(hop.Host)))
		}
	}
	builder.WriteString("\n")
	return builder.String()
}

func renderHostMarkdown(host history.HostSnapshot) string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("## %s\n\n", host.PrimaryIP))
	builder.WriteString(fmt.Sprintf("- Status: `%s`\n", emptyDash(host.Status)))
	builder.WriteString(fmt.Sprintf("- MAC: `%s`\n", emptyDash(host.MAC)))
	builder.WriteString(fmt.Sprintf("- Vendor: `%s`\n", emptyDash(host.Vendor)))
	builder.WriteString(fmt.Sprintf("- Hostnames: %s\n", joinOrDash(host.Hostnames)))
	builder.WriteString(fmt.Sprintf("- Top OS: %s\n", joinOrDash(host.TopOS)))
	if len(host.Services) > 0 {
		builder.WriteString("- Services:\n")
		for _, service := range host.Services {
			builder.WriteString(fmt.Sprintf("  - `%d/%s` `%s` `%s %s %s`\n",
				service.Port, service.Protocol, emptyDash(service.State), emptyDash(service.Name), emptyDash(service.Product), emptyDash(service.Version)))
		}
	}
	if host.Trace != nil && len(host.Trace.Hops) > 0 {
		builder.WriteString("- Trace:\n")
		for _, hop := range host.Trace.Hops {
			builder.WriteString(fmt.Sprintf("  - ttl `%d` ip `%s` rtt `%.2f` host `%s`\n", hop.TTL, emptyDash(hop.IP), hop.RTT, emptyDash(hop.Host)))
		}
	}
	builder.WriteString("\n")
	return builder.String()
}

func renderDiffSectionsTerminal(report history.DiffReport) string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("From: %d  To: %d\n\n", report.From.ID, report.To.ID))
	builder.WriteString("New hosts:\n")
	for _, host := range report.NewHosts {
		builder.WriteString("  " + renderHostDiffLine(host) + "\n")
	}
	builder.WriteString("Missing hosts:\n")
	for _, host := range report.MissingHosts {
		builder.WriteString("  " + renderHostDiffLine(host) + "\n")
	}
	builder.WriteString("Changed hosts:\n")
	for _, host := range report.ChangedHosts {
		builder.WriteString(fmt.Sprintf("  %s  reasons=%s  before=[%s]  after=[%s]\n",
			host.IP, strings.Join(host.Reasons, ","), renderHostDiffLine(host.Before), renderHostDiffLine(host.After)))
	}
	return builder.String()
}

func renderDiffSectionsMarkdown(report history.DiffReport) string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("- From: `%d`\n- To: `%d`\n\n", report.From.ID, report.To.ID))
	builder.WriteString("## New Hosts\n")
	for _, host := range report.NewHosts {
		builder.WriteString("- " + renderHostDiffLine(host) + "\n")
	}
	builder.WriteString("\n## Missing Hosts\n")
	for _, host := range report.MissingHosts {
		builder.WriteString("- " + renderHostDiffLine(host) + "\n")
	}
	builder.WriteString("\n## Changed Hosts\n")
	for _, host := range report.ChangedHosts {
		builder.WriteString(fmt.Sprintf("- `%s` reasons `%s` before `%s` after `%s`\n",
			host.IP, strings.Join(host.Reasons, ","), renderHostDiffLine(host.Before), renderHostDiffLine(host.After)))
	}
	return builder.String()
}

func renderTimelineEntryTerminal(entry history.TimelineEntry) string {
	return fmt.Sprintf("  new=%d missing=%d changed=%d\n", len(entry.NewHosts), len(entry.MissingHosts), len(entry.ChangedHosts))
}

func renderTimelineEntryMarkdown(entry history.TimelineEntry) string {
	return fmt.Sprintf("- New: `%d`\n- Missing: `%d`\n- Changed: `%d`\n\n", len(entry.NewHosts), len(entry.MissingHosts), len(entry.ChangedHosts))
}

func renderHostDiffLine(host history.HostDiffSnapshot) string {
	return fmt.Sprintf("%s status=%s ports=%s top-os=%s vendor=%s",
		host.IP, emptyDash(host.Status), joinOrDash(host.OpenPorts), emptyDash(host.TopOS), emptyDash(host.Vendor))
}

func joinOrDash(items []string) string {
	if len(items) == 0 {
		return "-"
	}
	sorted := append([]string(nil), items...)
	sort.Strings(sorted)
	return strings.Join(sorted, ", ")
}

func emptyDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func copyToClipboard(text string) error {
	if _, err := exec.LookPath("pbcopy"); err != nil {
		return err
	}
	cmd := exec.Command("pbcopy")
	cmd.Stdin = bytes.NewBufferString(text)
	return cmd.Run()
}

const timeLayout = "2006-01-02 15:04:05"
