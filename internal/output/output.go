package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"nmaper/internal/history"
	"nmaper/internal/snapshot"
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
	mode, sink, path := Resolve(out)
	visibleText := text
	persistedText := text
	if mode == modeTerminal {
		persistedText = stripANSI(text)
		if !isTTYWriter(stdout) {
			visibleText = persistedText
		}
	}
	switch sink {
	case sinkFile:
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
			return err
		}
		return os.WriteFile(path, []byte(persistedText), 0o644)
	case sinkClipboard:
		if _, err := io.WriteString(stdout, visibleText); err != nil {
			return err
		}
		if !strings.HasSuffix(visibleText, "\n") {
			if _, err := io.WriteString(stdout, "\n"); err != nil {
				return err
			}
		}
		if err := copyToClipboard(persistedText); err != nil && log != nil {
			log.Warnf("clipboard copy failed: %v", err)
		}
		return nil
	default:
		if _, err := io.WriteString(stdout, visibleText); err != nil {
			return err
		}
		if !strings.HasSuffix(visibleText, "\n") {
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
			builder.WriteString(fmt.Sprintf("- `#%d` `%s` %s level `%s` target `%s` duration `%s` live/discovered `%d/%d` nmap `%s`\n",
				item.ID, item.Status, item.StartedAt.Format(timeLayout), emptyDash(item.ScanLevel), item.Target, item.Duration, item.LiveHosts, item.DiscoveredHosts, emptyDash(item.NmapVersion)))
		}
		return builder.String(), nil
	default:
		var builder strings.Builder
		builder.WriteString(terminalTitle("Sessions"))
		for _, item := range items {
			builder.WriteString(fmt.Sprintf("%s  %s  %s\n",
				highlight(fmt.Sprintf("#%d", item.ID)),
				statusBadge(item.Status),
				style(item.StartedAt.Format(timeLayout), ansiDim),
			))
			builder.WriteString(summaryLine("Level", accent(emptyDash(item.ScanLevel))))
			builder.WriteString(summaryLine("Target", highlight(item.Target)))
			builder.WriteString(summaryLine("Duration", accent(item.Duration)))
			builder.WriteString(summaryLine("Live/Discovered", fmt.Sprintf("%s/%s", accent(fmt.Sprintf("%d", item.LiveHosts)), accent(fmt.Sprintf("%d", item.DiscoveredHosts)))))
			builder.WriteString(summaryLine("Nmap", accent(emptyDash(item.NmapVersion))))
			builder.WriteString("\n")
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
		builder.WriteString(terminalTitle(fmt.Sprintf("Session %d", report.Session.ID)))
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
		builder.WriteString(terminalTitle(fmt.Sprintf("Diff %d -> %d", report.From.ID, report.To.ID)))
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
		builder.WriteString(terminalTitle("Global Dynamics"))
		builder.WriteString(summaryLine("Sessions analysed", accent(fmt.Sprintf("%d", report.SessionCount))))
		builder.WriteString(summaryLine("Unique hosts", accent(fmt.Sprintf("%d", report.UniqueHosts))))
		builder.WriteString(summaryLine("Stable hosts", highlight(joinOrDash(report.StableHosts))))
		builder.WriteString(summaryLine("Transient hosts", warnText(joinOrDash(report.Transient))))
		builder.WriteString(summaryLine("Volatile hosts", warnText(joinOrDash(report.Volatile))))
		builder.WriteString(summaryLine("Last movement", accent(emptyDash(report.LastMovement))))
		builder.WriteString(terminalSection("Top ports"))
		for _, item := range report.TopPorts {
			builder.WriteString(fmt.Sprintf("  %s  x %s\n", highlight(item.Port), accent(fmt.Sprintf("%d", item.Count))))
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
		builder.WriteString(terminalTitle("Device Analytics"))
		builder.WriteString(summaryLine("Unique devices", accent(fmt.Sprintf("%d", report.UniqueDevices))))
		builder.WriteString(summaryLine("MAC-backed", accent(fmt.Sprintf("%d", report.MACBacked))))
		builder.WriteString(summaryLine("IP-only", accent(fmt.Sprintf("%d", report.IPOnly))))
		builder.WriteString(terminalSection("Top devices"))
		for _, item := range report.TopDevices {
			builder.WriteString(fmt.Sprintf("  %s  %s  vendor=%s  ips=%s\n", highlight(item.Label), accent(fmt.Sprintf("x%d", item.Appearances)), accent(emptyDash(item.Vendor)), joinOrDash(item.IPs)))
		}
		builder.WriteString(terminalSection("Top vendors"))
		for _, item := range report.TopVendors {
			builder.WriteString(fmt.Sprintf("  %s  x %s\n", highlight(item.Vendor), accent(fmt.Sprintf("%d", item.Count))))
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
		builder.WriteString(terminalTitle(fmt.Sprintf("Device History: %s", report.Query)))
		for _, device := range report.Devices {
			builder.WriteString(fmt.Sprintf("%s  vendor=%s  ips=%s\n", highlight(device.Label), accent(emptyDash(device.Vendor)), joinOrDash(device.IPs)))
			for _, appearance := range device.Appearances {
				builder.WriteString(fmt.Sprintf("  session=%s  time=%s  ip=%s  status=%s  ports=%s  top-os=%s\n",
					highlight(fmt.Sprintf("%d", appearance.Session.ID)),
					style(appearance.Session.StartedAt.Format(timeLayout), ansiDim),
					highlight(appearance.IP),
					statusBadge(appearance.Status),
					accent(joinOrDash(appearance.OpenPorts)),
					accent(emptyDash(appearance.TopOS)),
				))
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
		builder.WriteString(terminalTitle("Timeline"))
		for _, entry := range report.Entries {
			builder.WriteString(fmt.Sprintf("%s -> %s\n", highlight(fmt.Sprintf("%d", entry.From.ID)), highlight(fmt.Sprintf("%d", entry.To.ID))))
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
	var builder strings.Builder
	builder.WriteString(summaryLine("Status", statusBadge(session.Status)))
	builder.WriteString(summaryLine("Started", style(session.StartedAt.Format(timeLayout), ansiDim)))
	builder.WriteString(summaryLine("Duration", accent(session.Duration)))
	builder.WriteString(summaryLine("Level", accent(emptyDash(session.ScanLevel))))
	builder.WriteString(summaryLine("Target", highlight(session.Target)))
	builder.WriteString(summaryLine("Live/Discovered", fmt.Sprintf("%s/%s", accent(fmt.Sprintf("%d", session.LiveHosts)), accent(fmt.Sprintf("%d", session.DiscoveredHosts)))))
	builder.WriteString(summaryLine("Nmap", accent(emptyDash(session.NmapVersion))))
	if session.ScannerInterface != "" {
		builder.WriteString(summaryLine("Scanner Interface", accent(session.ScannerInterface)))
	}
	if session.ScannerRealMAC != "" {
		builder.WriteString(summaryLine("Scanner Real MAC", accent(session.ScannerRealMAC)))
	}
	if session.ScannerSpoofedMAC != "" {
		builder.WriteString(summaryLine("Scanner Spoofed MAC", warnText(session.ScannerSpoofedMAC)))
	}
	builder.WriteString("\n")
	return builder.String()
}

func renderSessionMetaMarkdown(session history.SessionSummary) string {
	return fmt.Sprintf("- Status: `%s`\n- Started: `%s`\n- Duration: `%s`\n- Level: `%s`\n- Target: `%s`\n- Live/discovered: `%d/%d`\n- Nmap: `%s`\n- Scanner interface: `%s`\n- Scanner real MAC: `%s`\n- Scanner spoofed MAC: `%s`\n\n",
		session.Status,
		session.StartedAt.Format(timeLayout),
		session.Duration,
		emptyDash(session.ScanLevel),
		session.Target,
		session.LiveHosts,
		session.DiscoveredHosts,
		emptyDash(session.NmapVersion),
		emptyDash(session.ScannerInterface),
		emptyDash(session.ScannerRealMAC),
		emptyDash(session.ScannerSpoofedMAC),
	)
}

func renderHostTerminal(host history.HostSnapshot) string {
	var builder strings.Builder
	builder.WriteString(terminalSection(fmt.Sprintf("Host %s", host.PrimaryIP)))
	builder.WriteString(summaryLine("Status", statusBadge(host.Status)))
	builder.WriteString(summaryLine("MAC", accent(emptyDash(host.MAC))))
	builder.WriteString(summaryLine("Vendor", accent(emptyDash(host.Vendor))))
	builder.WriteString(summaryLine("Hostnames", highlight(joinOrDash(host.Hostnames))))
	builder.WriteString(summaryLine("Top OS", accent(joinOrDash(host.TopOS))))
	builder.WriteString(summaryLine("NSE hits", renderNSEHits(host)))
	if len(host.Scripts) > 0 {
		builder.WriteString(style("  Host scripts:\n", ansiBlue))
		for _, script := range host.Scripts {
			builder.WriteString(fmt.Sprintf("    %s  %s\n",
				highlight(script.ID),
				style(previewText(emptyDash(script.Output), 96), ansiDim),
			))
		}
	}
	if len(host.Management) > 0 {
		builder.WriteString(style("  Management:\n", ansiBlue))
		builder.WriteString(renderManagementTerminal(host.Management, "    "))
	}
	if len(host.Vulnerabilities) > 0 {
		builder.WriteString(style("  Vulnerabilities:\n", ansiBlue))
		builder.WriteString(renderVulnerabilitiesTerminal(host.Vulnerabilities, "    "))
	}
	if len(host.Services) > 0 {
		builder.WriteString(style("  Services:\n", ansiBlue))
		for _, service := range host.Services {
			builder.WriteString(fmt.Sprintf("    %s  %s  %s %s %s\n",
				highlight(fmt.Sprintf("%d/%s", service.Port, service.Protocol)),
				statusBadge(service.State),
				accent(emptyDash(service.Name)),
				style(emptyDash(service.Product), ansiDim),
				style(emptyDash(service.Version), ansiDim),
			))
			for _, script := range service.Scripts {
				builder.WriteString(fmt.Sprintf("      script=%s  %s\n",
					highlight(script.ID),
					style(previewText(emptyDash(script.Output), 88), ansiDim),
				))
			}
			builder.WriteString(renderServiceProfilesTerminal(service))
		}
	}
	if host.Trace != nil && len(host.Trace.Hops) > 0 {
		builder.WriteString(style("  Trace:\n", ansiBlue))
		for _, hop := range host.Trace.Hops {
			builder.WriteString(fmt.Sprintf("    ttl=%s ip=%s rtt=%s host=%s\n",
				accent(fmt.Sprintf("%d", hop.TTL)),
				highlight(emptyDash(hop.IP)),
				style(fmt.Sprintf("%.2f", hop.RTT), ansiDim),
				accent(emptyDash(hop.Host)),
			))
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
	builder.WriteString(fmt.Sprintf("- NSE hits: `%s`\n", renderNSEHitsPlain(host)))
	if len(host.Scripts) > 0 {
		builder.WriteString("- Host scripts:\n")
		for _, script := range host.Scripts {
			builder.WriteString(fmt.Sprintf("  - `%s` `%s`\n", script.ID, previewText(emptyDash(script.Output), 96)))
		}
	}
	if len(host.Management) > 0 {
		builder.WriteString("- Management:\n")
		builder.WriteString(renderManagementMarkdown(host.Management, "  "))
	}
	if len(host.Vulnerabilities) > 0 {
		builder.WriteString("- Vulnerabilities:\n")
		builder.WriteString(renderVulnerabilitiesMarkdown(host.Vulnerabilities, "  "))
	}
	if len(host.Services) > 0 {
		builder.WriteString("- Services:\n")
		for _, service := range host.Services {
			builder.WriteString(fmt.Sprintf("  - `%d/%s` `%s` `%s %s %s`\n",
				service.Port, service.Protocol, emptyDash(service.State), emptyDash(service.Name), emptyDash(service.Product), emptyDash(service.Version)))
			for _, script := range service.Scripts {
				builder.WriteString(fmt.Sprintf("    - script `%s` `%s`\n", script.ID, previewText(emptyDash(script.Output), 88)))
			}
			builder.WriteString(renderServiceProfilesMarkdown(service, "    "))
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
	builder.WriteString(summaryLine("From", highlight(fmt.Sprintf("%d", report.From.ID))))
	builder.WriteString(summaryLine("To", highlight(fmt.Sprintf("%d", report.To.ID))))
	builder.WriteString(summaryLine("New/Missing/Changed", fmt.Sprintf("%s/%s/%s",
		goodText(fmt.Sprintf("%d", report.Summary.NewHosts)),
		badText(fmt.Sprintf("%d", report.Summary.MissingHosts)),
		warnText(fmt.Sprintf("%d", report.Summary.ChangedHosts)),
	)))
	builder.WriteString(summaryLine("Moved hosts", accent(fmt.Sprintf("%d", report.Summary.MovedHosts))))
	builder.WriteString(summaryLine("Ports +/-", fmt.Sprintf("%s/%s",
		goodText(fmt.Sprintf("%d", report.Summary.OpenedPorts)),
		badText(fmt.Sprintf("%d", report.Summary.ClosedPorts)),
	)))
	builder.WriteString(summaryLine("Service changes", accent(fmt.Sprintf("%d", report.Summary.ServiceChanges))))
	builder.WriteString(summaryLine("Script changes", accent(fmt.Sprintf("%d", report.Summary.ScriptChanges))))
	builder.WriteString(summaryLine("Fingerprint changes", accent(fmt.Sprintf("%d", report.Summary.FingerprintChanges))))
	builder.WriteString(summaryLine("Vulnerability changes", warnText(fmt.Sprintf("%d", report.Summary.VulnerabilityChanges))))
	builder.WriteString(summaryLine("Management changes", warnText(fmt.Sprintf("%d", report.Summary.ManagementChanges))))
	builder.WriteString(summaryLine("Trace changes", accent(fmt.Sprintf("%d", report.Summary.TraceChanges))))
	builder.WriteString(summaryLine("High-signal alerts", warnText(fmt.Sprintf("%d", report.Summary.HighSignalAlerts))))
	builder.WriteString(terminalSection("New hosts"))
	for _, host := range report.NewHosts {
		builder.WriteString("  " + goodText("+") + " " + renderHostDiffLine(host) + "\n")
	}
	builder.WriteString(terminalSection("Missing hosts"))
	for _, host := range report.MissingHosts {
		builder.WriteString("  " + badText("-") + " " + renderHostDiffLine(host) + "\n")
	}
	builder.WriteString(terminalSection("Changed hosts"))
	for _, host := range report.ChangedHosts {
		builder.WriteString(fmt.Sprintf("  %s %s  match=%s  reasons=%s\n",
			warnText("~"),
			highlight(renderChangedHostLabel(host)),
			accent(emptyDash(host.MatchBy)),
			accent(strings.Join(host.Reasons, ", ")),
		))
		builder.WriteString(fmt.Sprintf("    before: %s\n", renderHostDiffLine(host.Before)))
		builder.WriteString(fmt.Sprintf("    after:  %s\n", renderHostDiffLine(host.After)))
		builder.WriteString(renderChangedHostDetailsTerminal(host))
	}
	builder.WriteString(renderDiffAlertsTerminal(report.Alerts))
	return builder.String()
}

func renderDiffSectionsMarkdown(report history.DiffReport) string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("- From: `%d`\n- To: `%d`\n", report.From.ID, report.To.ID))
	builder.WriteString(fmt.Sprintf("- Summary: new `%d`, missing `%d`, changed `%d`, moved `%d`, ports `+%d/-%d`, services `%d`, scripts `%d`\n\n",
		report.Summary.NewHosts,
		report.Summary.MissingHosts,
		report.Summary.ChangedHosts,
		report.Summary.MovedHosts,
		report.Summary.OpenedPorts,
		report.Summary.ClosedPorts,
		report.Summary.ServiceChanges,
		report.Summary.ScriptChanges,
	))
	builder.WriteString(fmt.Sprintf("- Fingerprints changed: `%d`\n- Vulnerability changes: `%d`\n- Management changes: `%d`\n- Trace changes: `%d`\n",
		report.Summary.FingerprintChanges,
		report.Summary.VulnerabilityChanges,
		report.Summary.ManagementChanges,
		report.Summary.TraceChanges,
	))
	builder.WriteString(fmt.Sprintf("- High-signal alerts: `%d`\n\n", report.Summary.HighSignalAlerts))
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
		builder.WriteString(fmt.Sprintf("- `%s` match `%s` reasons `%s`\n",
			renderChangedHostLabel(host), emptyDash(host.MatchBy), strings.Join(host.Reasons, ",")))
		builder.WriteString(fmt.Sprintf("  - before `%s`\n", stripANSI(renderHostDiffLine(host.Before))))
		builder.WriteString(fmt.Sprintf("  - after `%s`\n", stripANSI(renderHostDiffLine(host.After))))
		builder.WriteString(renderChangedHostDetailsMarkdown(host))
	}
	builder.WriteString(renderDiffAlertsMarkdown(report.Alerts))
	return builder.String()
}

func renderTimelineEntryTerminal(entry history.TimelineEntry) string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("  new=%s  missing=%s  changed=%s  moved=%s  ports=%s/%s  services=%s  scripts=%s  alerts=%s\n",
		goodText(fmt.Sprintf("%d", entry.Summary.NewHosts)),
		badText(fmt.Sprintf("%d", entry.Summary.MissingHosts)),
		warnText(fmt.Sprintf("%d", entry.Summary.ChangedHosts)),
		accent(fmt.Sprintf("%d", entry.Summary.MovedHosts)),
		goodText(fmt.Sprintf("%d", entry.Summary.OpenedPorts)),
		badText(fmt.Sprintf("%d", entry.Summary.ClosedPorts)),
		accent(fmt.Sprintf("%d", entry.Summary.ServiceChanges)),
		accent(fmt.Sprintf("%d", entry.Summary.ScriptChanges)),
		warnText(fmt.Sprintf("%d", entry.Summary.HighSignalAlerts)),
	))
	builder.WriteString(fmt.Sprintf("  fingerprints=%s  vulns=%s  mgmt=%s  trace=%s\n",
		accent(fmt.Sprintf("%d", entry.Summary.FingerprintChanges)),
		warnText(fmt.Sprintf("%d", entry.Summary.VulnerabilityChanges)),
		warnText(fmt.Sprintf("%d", entry.Summary.ManagementChanges)),
		accent(fmt.Sprintf("%d", entry.Summary.TraceChanges)),
	))
	for _, alert := range entry.Alerts {
		builder.WriteString(fmt.Sprintf("    %s %s  host=%s  detail=%s\n",
			warnText("!"),
			highlight(alert.Title),
			accent(alert.Host),
			style(emptyDash(alert.Detail), ansiDim),
		))
	}
	return builder.String()
}

func renderTimelineEntryMarkdown(entry history.TimelineEntry) string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("- New: `%d`\n- Missing: `%d`\n- Changed: `%d`\n- Moved: `%d`\n- Ports: `+%d/-%d`\n- Services changed: `%d`\n- Scripts changed: `%d`\n- High-signal alerts: `%d`\n",
		entry.Summary.NewHosts,
		entry.Summary.MissingHosts,
		entry.Summary.ChangedHosts,
		entry.Summary.MovedHosts,
		entry.Summary.OpenedPorts,
		entry.Summary.ClosedPorts,
		entry.Summary.ServiceChanges,
		entry.Summary.ScriptChanges,
		entry.Summary.HighSignalAlerts,
	))
	builder.WriteString(fmt.Sprintf("- Fingerprints changed: `%d`\n- Vulnerability changes: `%d`\n- Management changes: `%d`\n- Trace changes: `%d`\n",
		entry.Summary.FingerprintChanges,
		entry.Summary.VulnerabilityChanges,
		entry.Summary.ManagementChanges,
		entry.Summary.TraceChanges,
	))
	for _, alert := range entry.Alerts {
		builder.WriteString(fmt.Sprintf("  - alert `%s` host `%s` detail `%s`\n", alert.Title, alert.Host, emptyDash(alert.Detail)))
	}
	builder.WriteString("\n")
	return builder.String()
}

func renderHostDiffLine(host history.HostDiffSnapshot) string {
	parts := []string{
		fmt.Sprintf("%s status=%s", highlight(host.IP), statusBadge(host.Status)),
		fmt.Sprintf("ports=%s", accent(joinOrDash(host.OpenPorts))),
		fmt.Sprintf("services=%s", accent(joinOrDash(host.Services))),
		fmt.Sprintf("top-os=%s", accent(emptyDash(host.TopOS))),
		fmt.Sprintf("vendor=%s", accent(emptyDash(host.Vendor))),
	}
	if host.MAC != "" {
		parts = append(parts, fmt.Sprintf("mac=%s", accent(host.MAC)))
	}
	if len(host.Hostnames) > 0 {
		parts = append(parts, fmt.Sprintf("hostnames=%s", highlight(joinOrDash(host.Hostnames))))
	}
	return strings.Join(parts, " ")
}

func renderNSEHits(host history.HostSnapshot) string {
	total := fmt.Sprintf("%d", host.NSEHits)
	hostHits := fmt.Sprintf("%d", host.HostScriptHits)
	serviceHits := fmt.Sprintf("%d", host.ServiceScriptHits)
	if host.NSEHits > 0 {
		return fmt.Sprintf("%s  (%s host, %s service)", goodText(total), accent(hostHits), accent(serviceHits))
	}
	return fmt.Sprintf("%s  (%s host, %s service)", warnText(total), accent(hostHits), accent(serviceHits))
}

func renderNSEHitsPlain(host history.HostSnapshot) string {
	return fmt.Sprintf("%d (host %d, service %d)", host.NSEHits, host.HostScriptHits, host.ServiceScriptHits)
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

func renderChangedHostLabel(host history.ChangedHost) string {
	if host.Before.IP != "" && host.Before.IP != host.After.IP {
		return host.Before.IP + " -> " + host.After.IP
	}
	if host.After.IP != "" {
		return host.After.IP
	}
	return host.IP
}

func renderChangedHostDetailsTerminal(host history.ChangedHost) string {
	var builder strings.Builder
	if len(host.OpenedPorts) > 0 {
		builder.WriteString(fmt.Sprintf("    opened ports: %s\n", goodText(strings.Join(host.OpenedPorts, ", "))))
	}
	if len(host.ClosedPorts) > 0 {
		builder.WriteString(fmt.Sprintf("    closed ports: %s\n", badText(strings.Join(host.ClosedPorts, ", "))))
	}
	if len(host.HostnamesAdded) > 0 {
		builder.WriteString(fmt.Sprintf("    hostnames +: %s\n", goodText(strings.Join(host.HostnamesAdded, ", "))))
	}
	if len(host.HostnamesRemoved) > 0 {
		builder.WriteString(fmt.Sprintf("    hostnames -: %s\n", badText(strings.Join(host.HostnamesRemoved, ", "))))
	}
	if len(host.ServiceChanges) > 0 {
		builder.WriteString("    service changes:\n")
		for _, change := range host.ServiceChanges {
			builder.WriteString(fmt.Sprintf("      %s  %s -> %s\n",
				highlight(change.Port),
				accent(previewText(emptyDash(change.Before), 72)),
				accent(previewText(emptyDash(change.After), 72)),
			))
		}
	}
	if len(host.ScriptChanges) > 0 {
		builder.WriteString("    script changes:\n")
		for _, change := range host.ScriptChanges {
			builder.WriteString(fmt.Sprintf("      %s/%s  %s -> %s\n",
				accent(change.Scope),
				highlight(change.ID),
				style(previewText(emptyDash(change.Before), 52), ansiDim),
				style(previewText(emptyDash(change.After), 52), ansiDim),
			))
		}
	}
	if len(host.FingerprintChanges) > 0 {
		builder.WriteString(fmt.Sprintf("    fingerprint changes: %s\n", warnText(strings.Join(host.FingerprintChanges, ", "))))
	}
	if len(host.NewVulnerabilities) > 0 {
		builder.WriteString("    vulnerabilities +:\n")
		builder.WriteString(renderVulnerabilitiesTerminal(host.NewVulnerabilities, "      "))
	}
	if len(host.ResolvedVulnerabilities) > 0 {
		builder.WriteString("    vulnerabilities -:\n")
		builder.WriteString(renderVulnerabilitiesTerminal(host.ResolvedVulnerabilities, "      "))
	}
	if len(host.ManagementAdded) > 0 {
		builder.WriteString("    management +:\n")
		builder.WriteString(renderManagementTerminal(host.ManagementAdded, "      "))
	}
	if len(host.ManagementRemoved) > 0 {
		builder.WriteString("    management -:\n")
		builder.WriteString(renderManagementTerminal(host.ManagementRemoved, "      "))
	}
	if host.TraceChanged {
		builder.WriteString(fmt.Sprintf("    trace: %s\n", warnText("route changed")))
	}
	return builder.String()
}

func renderChangedHostDetailsMarkdown(host history.ChangedHost) string {
	var builder strings.Builder
	if len(host.OpenedPorts) > 0 {
		builder.WriteString(fmt.Sprintf("  - opened ports `%s`\n", strings.Join(host.OpenedPorts, ", ")))
	}
	if len(host.ClosedPorts) > 0 {
		builder.WriteString(fmt.Sprintf("  - closed ports `%s`\n", strings.Join(host.ClosedPorts, ", ")))
	}
	if len(host.HostnamesAdded) > 0 {
		builder.WriteString(fmt.Sprintf("  - hostnames added `%s`\n", strings.Join(host.HostnamesAdded, ", ")))
	}
	if len(host.HostnamesRemoved) > 0 {
		builder.WriteString(fmt.Sprintf("  - hostnames removed `%s`\n", strings.Join(host.HostnamesRemoved, ", ")))
	}
	for _, change := range host.ServiceChanges {
		builder.WriteString(fmt.Sprintf("  - service `%s`: `%s` -> `%s`\n",
			change.Port,
			previewText(emptyDash(change.Before), 72),
			previewText(emptyDash(change.After), 72),
		))
	}
	for _, change := range host.ScriptChanges {
		builder.WriteString(fmt.Sprintf("  - script `%s/%s`: `%s` -> `%s`\n",
			change.Scope,
			change.ID,
			previewText(emptyDash(change.Before), 52),
			previewText(emptyDash(change.After), 52),
		))
	}
	if len(host.FingerprintChanges) > 0 {
		builder.WriteString(fmt.Sprintf("  - fingerprints `%s`\n", strings.Join(host.FingerprintChanges, ", ")))
	}
	if len(host.NewVulnerabilities) > 0 {
		builder.WriteString("  - vulnerabilities added:\n")
		builder.WriteString(renderVulnerabilitiesMarkdown(host.NewVulnerabilities, "    "))
	}
	if len(host.ResolvedVulnerabilities) > 0 {
		builder.WriteString("  - vulnerabilities resolved:\n")
		builder.WriteString(renderVulnerabilitiesMarkdown(host.ResolvedVulnerabilities, "    "))
	}
	if len(host.ManagementAdded) > 0 {
		builder.WriteString("  - management added:\n")
		builder.WriteString(renderManagementMarkdown(host.ManagementAdded, "    "))
	}
	if len(host.ManagementRemoved) > 0 {
		builder.WriteString("  - management removed:\n")
		builder.WriteString(renderManagementMarkdown(host.ManagementRemoved, "    "))
	}
	if host.TraceChanged {
		builder.WriteString("  - trace changed\n")
	}
	return builder.String()
}

func renderDiffAlertsTerminal(alerts []history.DiffAlert) string {
	if len(alerts) == 0 {
		return ""
	}
	var builder strings.Builder
	builder.WriteString(terminalSection("High-signal alerts"))
	for _, alert := range alerts {
		builder.WriteString(fmt.Sprintf("  %s %s  host=%s  detail=%s\n",
			warnText("!"),
			highlight(alert.Title),
			accent(alert.Host),
			style(emptyDash(alert.Detail), ansiDim),
		))
	}
	return builder.String()
}

func renderDiffAlertsMarkdown(alerts []history.DiffAlert) string {
	if len(alerts) == 0 {
		return ""
	}
	var builder strings.Builder
	builder.WriteString("\n## High-Signal Alerts\n")
	for _, alert := range alerts {
		builder.WriteString(fmt.Sprintf("- `%s` host `%s` detail `%s`\n", alert.Title, alert.Host, emptyDash(alert.Detail)))
	}
	return builder.String()
}

func previewText(text string, limit int) string {
	normalized := strings.Join(strings.Fields(strings.TrimSpace(text)), " ")
	if normalized == "" {
		return "-"
	}
	if len(normalized) <= limit {
		return normalized
	}
	if limit <= 3 {
		return normalized[:limit]
	}
	return normalized[:limit-3] + "..."
}

func renderServiceProfilesTerminal(service history.ServiceSnapshot) string {
	var builder strings.Builder
	if service.TLS != nil {
		builder.WriteString(fmt.Sprintf("      tls  subject=%s  issuer=%s  versions=%s  weak=%s\n",
			accent(emptyDash(previewText(service.TLS.Subject, 40))),
			style(previewText(emptyDash(service.TLS.Issuer), 32), ansiDim),
			accent(joinOrDash(service.TLS.Versions)),
			warnText(joinOrDash(service.TLS.WeakCiphers)),
		))
	}
	if service.SSH != nil {
		builder.WriteString(fmt.Sprintf("      ssh  hostkeys=%s  weak=%s\n",
			accent(fmt.Sprintf("%d", len(service.SSH.HostKeys))),
			warnText(joinOrDash(service.SSH.WeakAlgorithms)),
		))
	}
	if service.HTTP != nil {
		builder.WriteString(fmt.Sprintf("      http title=%s  server=%s  methods=%s  auth=%s\n",
			highlight(emptyDash(previewText(service.HTTP.Title, 36))),
			accent(emptyDash(previewText(service.HTTP.Server, 28))),
			accent(joinOrDash(service.HTTP.Methods)),
			warnText(joinOrDash(service.HTTP.AuthSchemes)),
		))
	}
	if service.SMB != nil {
		builder.WriteString(fmt.Sprintf("      smb  os=%s  protocols=%s  shares=%s\n",
			accent(emptyDash(previewText(service.SMB.OS, 32))),
			accent(joinOrDash(service.SMB.Protocols)),
			accent(joinOrDash(service.SMB.Shares)),
		))
	}
	if len(service.Management) > 0 {
		builder.WriteString("      management:\n")
		builder.WriteString(renderManagementTerminal(service.Management, "        "))
	}
	if len(service.Vulnerabilities) > 0 {
		builder.WriteString("      vulnerabilities:\n")
		builder.WriteString(renderVulnerabilitiesTerminal(service.Vulnerabilities, "        "))
	}
	return builder.String()
}

func renderServiceProfilesMarkdown(service history.ServiceSnapshot, indent string) string {
	var builder strings.Builder
	if service.TLS != nil {
		builder.WriteString(fmt.Sprintf("%s- tls subject `%s` issuer `%s` versions `%s` weak `%s`\n",
			indent,
			previewText(emptyDash(service.TLS.Subject), 40),
			previewText(emptyDash(service.TLS.Issuer), 32),
			joinOrDash(service.TLS.Versions),
			joinOrDash(service.TLS.WeakCiphers),
		))
	}
	if service.SSH != nil {
		builder.WriteString(fmt.Sprintf("%s- ssh hostkeys `%d` weak `%s`\n", indent, len(service.SSH.HostKeys), joinOrDash(service.SSH.WeakAlgorithms)))
	}
	if service.HTTP != nil {
		builder.WriteString(fmt.Sprintf("%s- http title `%s` server `%s` methods `%s` auth `%s`\n",
			indent,
			previewText(emptyDash(service.HTTP.Title), 36),
			previewText(emptyDash(service.HTTP.Server), 28),
			joinOrDash(service.HTTP.Methods),
			joinOrDash(service.HTTP.AuthSchemes),
		))
	}
	if service.SMB != nil {
		builder.WriteString(fmt.Sprintf("%s- smb os `%s` protocols `%s` shares `%s`\n",
			indent,
			previewText(emptyDash(service.SMB.OS), 32),
			joinOrDash(service.SMB.Protocols),
			joinOrDash(service.SMB.Shares),
		))
	}
	if len(service.Management) > 0 {
		builder.WriteString(indent + "- management:\n")
		builder.WriteString(renderManagementMarkdown(service.Management, indent+"  "))
	}
	if len(service.Vulnerabilities) > 0 {
		builder.WriteString(indent + "- vulnerabilities:\n")
		builder.WriteString(renderVulnerabilitiesMarkdown(service.Vulnerabilities, indent+"  "))
	}
	return builder.String()
}

func renderVulnerabilitiesTerminal(findings []snapshot.VulnerabilityFinding, indent string) string {
	var builder strings.Builder
	for _, finding := range findings {
		builder.WriteString(fmt.Sprintf("%s%s  %s  %s\n",
			indent,
			warnText("!"),
			highlight(previewText(emptyDash(firstNonEmpty(finding.Identifier, finding.Title, finding.ScriptID)), 48)),
			style(previewText(emptyDash(firstNonEmpty(finding.Evidence, finding.State)), 72), ansiDim),
		))
	}
	return builder.String()
}

func renderVulnerabilitiesMarkdown(findings []snapshot.VulnerabilityFinding, indent string) string {
	var builder strings.Builder
	for _, finding := range findings {
		builder.WriteString(fmt.Sprintf("%s- `%s` `%s`\n",
			indent,
			previewText(emptyDash(firstNonEmpty(finding.Identifier, finding.Title, finding.ScriptID)), 48),
			previewText(emptyDash(firstNonEmpty(finding.Evidence, finding.State)), 72),
		))
	}
	return builder.String()
}

func renderManagementTerminal(items []snapshot.ManagementSurface, indent string) string {
	var builder strings.Builder
	for _, item := range items {
		builder.WriteString(fmt.Sprintf("%s%s  %s on %d/%s  %s\n",
			indent,
			warnText("+"),
			highlight(emptyDash(firstNonEmpty(item.Label, item.Category))),
			item.Port,
			item.Protocol,
			style(previewText(emptyDash(firstNonEmpty(item.Detail, item.Exposure)), 64), ansiDim),
		))
	}
	return builder.String()
}

func renderManagementMarkdown(items []snapshot.ManagementSurface, indent string) string {
	var builder strings.Builder
	for _, item := range items {
		builder.WriteString(fmt.Sprintf("%s- `%s` on `%d/%s` `%s`\n",
			indent,
			emptyDash(firstNonEmpty(item.Label, item.Category)),
			item.Port,
			item.Protocol,
			previewText(emptyDash(firstNonEmpty(item.Detail, item.Exposure)), 64),
		))
	}
	return builder.String()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
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

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiBlue   = "\033[34m"
	ansiCyan   = "\033[36m"
)

func terminalTitle(title string) string {
	line := strings.Repeat("=", maxInt(len(title), 12))
	return style(title, ansiBold, ansiCyan) + "\n" + style(line, ansiDim) + "\n"
}

func terminalSection(title string) string {
	line := strings.Repeat("-", maxInt(len(title), 8))
	return "\n" + style(title, ansiBold, ansiBlue) + "\n" + style(line, ansiDim) + "\n"
}

func summaryLine(label, value string) string {
	return fmt.Sprintf("%s %s\n", style(label+":", ansiDim), value)
}

func statusBadge(status string) string {
	normalized := strings.ToLower(strings.TrimSpace(status))
	switch normalized {
	case "completed", "up", "open":
		return style("["+strings.ToUpper(emptyDash(status))+"]", ansiBold, ansiGreen)
	case "running":
		return style("["+strings.ToUpper(emptyDash(status))+"]", ansiBold, ansiCyan)
	case "failed", "down", "closed":
		return style("["+strings.ToUpper(emptyDash(status))+"]", ansiBold, ansiRed)
	default:
		return style("["+strings.ToUpper(emptyDash(status))+"]", ansiBold, ansiYellow)
	}
}

func accent(value string) string {
	return style(value, ansiBold, ansiCyan)
}

func highlight(value string) string {
	return style(value, ansiBold)
}

func goodText(value string) string {
	return style(value, ansiBold, ansiGreen)
}

func warnText(value string) string {
	return style(value, ansiBold, ansiYellow)
}

func badText(value string) string {
	return style(value, ansiBold, ansiRed)
}

func style(text string, codes ...string) string {
	if text == "" {
		return ""
	}
	var builder strings.Builder
	for _, code := range codes {
		builder.WriteString(code)
	}
	builder.WriteString(text)
	builder.WriteString(ansiReset)
	return builder.String()
}

func stripANSI(text string) string {
	return ansiPattern.ReplaceAllString(text, "")
}

func isTTYWriter(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}
