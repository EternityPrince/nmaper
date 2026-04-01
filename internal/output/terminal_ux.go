package output

import (
	"fmt"
	"sort"
	"strings"

	"nmaper/internal/history"
	"nmaper/internal/snapshot"
)

type terminalView string

const (
	viewCompact terminalView = "compact"
	viewFull    terminalView = "full"
)

type hostRisk struct {
	Host     history.HostSnapshot
	Score    int
	Level    string
	Reasons  []string
	Evidence []string
}

type sessionAlert struct {
	Host     string
	Title    string
	Why      string
	Evidence string
	Score    int
}

type changedImpact struct {
	Host   history.ChangedHost
	Score  int
	Level  string
	Reason string
	HostIP string
	Alerts []history.DiffAlert
}

func normalizeTerminalView(raw string) terminalView {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(viewCompact):
		return viewCompact
	default:
		return viewFull
	}
}

func renderSessionsTerminalUX(items []history.SessionSummary, view terminalView) string {
	var builder strings.Builder
	builder.WriteString(terminalTitle("Sessions"))
	builder.WriteString(terminalSection("Summary"))
	builder.WriteString(summaryLine("History", accent(fmt.Sprintf("%d sessions", len(items)))))

	completed := 0
	running := 0
	failed := 0
	for _, item := range items {
		switch strings.ToLower(item.Status) {
		case "completed":
			completed++
		case "running":
			running++
		case "failed":
			failed++
		}
	}
	builder.WriteString(summaryLine("Completed", goodText(fmt.Sprintf("%d", completed))))
	builder.WriteString(summaryLine("Running", warnText(fmt.Sprintf("%d", running))))
	builder.WriteString(summaryLine("Failed", badText(fmt.Sprintf("%d", failed))))

	builder.WriteString(terminalSection("History"))
	for _, item := range items {
		builder.WriteString(fmt.Sprintf("  %s  %s  level=%s  target=%s  live/discovered=%s/%s  time=%s\n",
			highlight(fmt.Sprintf("#%d", item.ID)),
			statusBadge(item.Status),
			accent(emptyDash(item.ScanLevel)),
			highlight(item.Target),
			accent(fmt.Sprintf("%d", item.LiveHosts)),
			accent(fmt.Sprintf("%d", item.DiscoveredHosts)),
			style(item.StartedAt.Format(timeLayout), ansiDim),
		))
		if view == viewFull {
			builder.WriteString(fmt.Sprintf("    duration=%s  nmap=%s\n", accent(item.Duration), accent(emptyDash(item.NmapVersion))))
		}
	}
	return builder.String()
}

func renderSessionTerminalUX(report history.SessionReport, view terminalView) string {
	risks := rankSessionHosts(report.Hosts)
	alerts := collectSessionAlerts(risks)

	var builder strings.Builder
	builder.WriteString(terminalTitle(fmt.Sprintf("Session %d", report.Session.ID)))
	builder.WriteString(terminalSection("Summary"))
	builder.WriteString(summaryLine("Status", statusBadge(report.Session.Status)))
	builder.WriteString(summaryLine("History", fmt.Sprintf("started=%s  duration=%s", style(report.Session.StartedAt.Format(timeLayout), ansiDim), accent(report.Session.Duration))))
	builder.WriteString(summaryLine("Exposure", fmt.Sprintf("hosts=%s  live/discovered=%s/%s", accent(fmt.Sprintf("%d", len(report.Hosts))), accent(fmt.Sprintf("%d", report.Session.LiveHosts)), accent(fmt.Sprintf("%d", report.Session.DiscoveredHosts)))))
	builder.WriteString(summaryLine("High-signal alerts", warnText(fmt.Sprintf("%d", len(alerts)))))
	builder.WriteString(summaryLine("Top changed hosts", accent(fmt.Sprintf("%d", minInt(3, len(risks))))))

	renderSessionAlertsSection(&builder, alerts, view)
	renderSessionTopRiskSection(&builder, risks, view)

	if view == viewFull {
		builder.WriteString(terminalSection("Host cards"))
		for _, risk := range risks {
			builder.WriteString(renderSessionHostCard(risk))
		}
	}
	return builder.String()
}

func renderDiffTerminalUX(report history.DiffReport, view terminalView) string {
	impacts := rankChangedHosts(report)

	var builder strings.Builder
	builder.WriteString(terminalTitle(fmt.Sprintf("Diff %d -> %d", report.From.ID, report.To.ID)))
	builder.WriteString(terminalSection("Summary"))
	builder.WriteString(summaryLine("History", fmt.Sprintf("from=%s  to=%s", highlight(fmt.Sprintf("%d", report.From.ID)), highlight(fmt.Sprintf("%d", report.To.ID)))))
	builder.WriteString(summaryLine("Exposure", fmt.Sprintf("new=%s  missing=%s  changed=%s  moved=%s", goodText(fmt.Sprintf("%d", report.Summary.NewHosts)), badText(fmt.Sprintf("%d", report.Summary.MissingHosts)), warnText(fmt.Sprintf("%d", report.Summary.ChangedHosts)), warnText(fmt.Sprintf("%d", report.Summary.MovedHosts)))))
	builder.WriteString(summaryLine("Identity", fmt.Sprintf("ports +/-%s/%s  fingerprints=%s  mgmt=%s", goodText(fmt.Sprintf("%d", report.Summary.OpenedPorts)), badText(fmt.Sprintf("%d", report.Summary.ClosedPorts)), warnText(fmt.Sprintf("%d", report.Summary.FingerprintChanges)), warnText(fmt.Sprintf("%d", report.Summary.ManagementChanges)))))
	builder.WriteString(summaryLine("High-signal alerts", warnText(fmt.Sprintf("%d", report.Summary.HighSignalAlerts))))

	builder.WriteString(terminalSection("What needs attention"))
	for _, line := range buildDiffAttention(report, impacts) {
		builder.WriteString(fmt.Sprintf("  %s\n", line))
	}

	builder.WriteString(terminalSection("High-signal alerts"))
	if len(report.Alerts) == 0 {
		builder.WriteString("  - none\n")
	} else {
		for _, alert := range report.Alerts {
			builder.WriteString(fmt.Sprintf("  %s %s  host=%s\n", warnText("!"), highlight(alert.Title), accent(alert.Host)))
			builder.WriteString(fmt.Sprintf("    why: %s\n", style(alertImportance(alert.Type), ansiDim)))
			if alert.Detail != "" {
				builder.WriteString(fmt.Sprintf("    evidence: %s\n", style(previewText(alert.Detail, 100), ansiDim)))
			}
		}
	}

	builder.WriteString(terminalSection("Top changed hosts"))
	if len(impacts) == 0 {
		builder.WriteString("  - none\n")
	} else {
		limit := len(impacts)
		if view == viewCompact {
			limit = minInt(limit, 8)
		}
		for _, item := range impacts[:limit] {
			builder.WriteString(fmt.Sprintf("  %s %s reasons=%s impact=%s\n",
				warnText("~"),
				highlight(renderChangedHostLabel(item.Host)),
				accent(strings.Join(item.Host.Reasons, ",")),
				riskBadge(item.Level, item.Score),
			))
			builder.WriteString(fmt.Sprintf("    why: %s\n", style(item.Reason, ansiDim)))
		}
	}

	if view == viewFull {
		renderDiffHostEventSections(&builder, report, impacts)
	}
	return builder.String()
}

func renderDiffHostEventSections(builder *strings.Builder, report history.DiffReport, impacts []changedImpact) {
	builder.WriteString(terminalSection("Moved hosts"))
	moved := 0
	for _, item := range impacts {
		if item.Host.Before.IP == item.Host.After.IP {
			continue
		}
		moved++
		builder.WriteString(fmt.Sprintf("  %s %s -> %s  match=%s\n",
			warnText("->"),
			highlight(item.Host.Before.IP),
			highlight(item.Host.After.IP),
			accent(emptyDash(item.Host.MatchBy)),
		))
	}
	if moved == 0 {
		builder.WriteString("  - none\n")
	}

	builder.WriteString(terminalSection("New hosts"))
	if len(report.NewHosts) == 0 {
		builder.WriteString("  - none\n")
	} else {
		for _, host := range report.NewHosts {
			builder.WriteString("  " + goodText("+") + " " + renderHostDiffLine(host) + "\n")
		}
	}

	builder.WriteString(terminalSection("Missing hosts"))
	if len(report.MissingHosts) == 0 {
		builder.WriteString("  - none\n")
	} else {
		for _, host := range report.MissingHosts {
			builder.WriteString("  " + badText("-") + " " + renderHostDiffLine(host) + "\n")
		}
	}

	builder.WriteString(terminalSection("Host cards"))
	for _, item := range impacts {
		builder.WriteString(fmt.Sprintf("  %s  impact=%s\n", highlight(renderChangedHostLabel(item.Host)), riskBadge(item.Level, item.Score)))
		builder.WriteString(summaryLine("Identity", fmt.Sprintf("match=%s  reasons=%s", accent(emptyDash(item.Host.MatchBy)), accent(strings.Join(item.Host.Reasons, ", ")))))
		builder.WriteString(summaryLine("Exposure", fmt.Sprintf("opened=%s  closed=%s", goodText(strings.Join(item.Host.OpenedPorts, ", ")), badText(strings.Join(item.Host.ClosedPorts, ", ")))))
		builder.WriteString(summaryLine("Fingerprints", warnText(joinOrDash(item.Host.FingerprintChanges))))
		builder.WriteString(renderChangedHostDetailsTerminal(item.Host))
	}
}

func renderTimelineTerminalUX(report history.TimelineReport, view terminalView) string {
	var builder strings.Builder
	builder.WriteString(terminalTitle("Timeline"))
	builder.WriteString(terminalSection("Summary"))
	builder.WriteString(summaryLine("History", accent(fmt.Sprintf("%d transitions", len(report.Entries)))))

	totalAlerts := 0
	totalChanged := 0
	for _, entry := range report.Entries {
		totalAlerts += len(entry.Alerts)
		totalChanged += len(entry.ChangedHosts)
	}
	builder.WriteString(summaryLine("High-signal alerts", warnText(fmt.Sprintf("%d", totalAlerts))))
	builder.WriteString(summaryLine("Top changed hosts", warnText(fmt.Sprintf("%d", totalChanged))))

	builder.WriteString(terminalSection("History"))
	for _, entry := range report.Entries {
		builder.WriteString(fmt.Sprintf("  %s -> %s  changed=%s  alerts=%s  moved=%s\n",
			highlight(fmt.Sprintf("%d", entry.From.ID)),
			highlight(fmt.Sprintf("%d", entry.To.ID)),
			warnText(fmt.Sprintf("%d", entry.Summary.ChangedHosts)),
			warnText(fmt.Sprintf("%d", entry.Summary.HighSignalAlerts)),
			warnText(fmt.Sprintf("%d", entry.Summary.MovedHosts)),
		))
		events := timelineTopEvents(entry)
		limit := len(events)
		if view == viewCompact {
			limit = minInt(limit, 3)
		}
		for _, event := range events[:limit] {
			builder.WriteString(fmt.Sprintf("    %s\n", event))
		}
		if view == viewFull {
			builder.WriteString(fmt.Sprintf("    exposure: ports +/-%d/%d, mgmt=%d, vulns=%d, fingerprints=%d\n",
				entry.Summary.OpenedPorts,
				entry.Summary.ClosedPorts,
				entry.Summary.ManagementChanges,
				entry.Summary.VulnerabilityChanges,
				entry.Summary.FingerprintChanges,
			))
		}
	}
	return builder.String()
}

func renderDevicesTerminalUX(report history.DeviceAnalyticsReport, view terminalView) string {
	var builder strings.Builder
	builder.WriteString(terminalTitle("Device Analytics"))
	builder.WriteString(terminalSection("Summary"))
	builder.WriteString(summaryLine("Identity", fmt.Sprintf("unique=%s  mac-backed=%s  ip-only=%s", accent(fmt.Sprintf("%d", report.UniqueDevices)), accent(fmt.Sprintf("%d", report.MACBacked)), accent(fmt.Sprintf("%d", report.IPOnly)))))
	builder.WriteString(summaryLine("High-signal alerts", warnText(fmt.Sprintf("%d unstable identities", len(report.MultiIP)))))

	builder.WriteString(terminalSection("Top changed hosts"))
	if len(report.MultiIP) == 0 {
		builder.WriteString("  - none\n")
	} else {
		limit := len(report.MultiIP)
		if view == viewCompact {
			limit = minInt(limit, 10)
		}
		for _, item := range report.MultiIP[:limit] {
			builder.WriteString(fmt.Sprintf("  %s  appearances=%s  ips=%s  vendor=%s\n",
				highlight(item.Label),
				accent(fmt.Sprintf("%d", item.Appearances)),
				warnText(fmt.Sprintf("%d", len(item.IPs))),
				accent(emptyDash(item.Vendor)),
			))
		}
	}

	builder.WriteString(terminalSection("Identity"))
	for _, item := range report.TopDevices {
		stability := "stable"
		if len(item.IPs) > 1 {
			stability = "drift"
		}
		builder.WriteString(fmt.Sprintf("  %s  x%s  stability=%s  vendor=%s\n",
			highlight(item.Label),
			accent(fmt.Sprintf("%d", item.Appearances)),
			riskBadge(stabilityLevel(stability), len(item.IPs)),
			accent(emptyDash(item.Vendor)),
		))
		if view == viewFull {
			builder.WriteString(fmt.Sprintf("    ips=%s\n", style(joinOrDash(item.IPs), ansiDim)))
		}
	}

	if view == viewFull {
		builder.WriteString(terminalSection("History"))
		for _, item := range report.TopVendors {
			builder.WriteString(fmt.Sprintf("  %s  x%s\n", highlight(item.Vendor), accent(fmt.Sprintf("%d", item.Count))))
		}
	}
	return builder.String()
}

func renderDeviceHistoryTerminalUX(report history.DeviceHistoryReport, view terminalView) string {
	var builder strings.Builder
	builder.WriteString(terminalTitle(fmt.Sprintf("Device History: %s", report.Query)))
	builder.WriteString(terminalSection("Summary"))
	builder.WriteString(summaryLine("Identity", accent(fmt.Sprintf("%d devices", len(report.Devices)))))

	totalAppearances := 0
	for _, device := range report.Devices {
		totalAppearances += len(device.Appearances)
	}
	builder.WriteString(summaryLine("History", accent(fmt.Sprintf("%d appearances", totalAppearances))))

	builder.WriteString(terminalSection("Host cards"))
	for _, device := range report.Devices {
		stats := computeDeviceHistoryStats(device)
		builder.WriteString(fmt.Sprintf("  %s  stability=%s\n", highlight(device.Label), riskBadge(stats.Level, stats.Score)))
		builder.WriteString(summaryLine("Identity", fmt.Sprintf("vendor=%s  ips=%s", accent(emptyDash(device.Vendor)), accent(fmt.Sprintf("%d", len(device.IPs))))))
		builder.WriteString(summaryLine("Exposure", fmt.Sprintf("typical ports=%s", accent(joinOrDash(stats.TopPorts)))))
		builder.WriteString(summaryLine("History", fmt.Sprintf("appearances=%s  ip-changes=%s  port-drift=%s", accent(fmt.Sprintf("%d", len(device.Appearances))), warnText(fmt.Sprintf("%d", stats.IPChanges)), warnText(fmt.Sprintf("%d", stats.PortDrift)))))
		if len(stats.Why) > 0 {
			builder.WriteString(summaryLine("Evidence", style(strings.Join(stats.Why, "; "), ansiDim)))
		}
		if view == viewFull {
			for _, appearance := range device.Appearances {
				builder.WriteString(fmt.Sprintf("    session=%s  time=%s  ip=%s  status=%s  ports=%s  top-os=%s\n",
					highlight(fmt.Sprintf("%d", appearance.Session.ID)),
					style(appearance.Session.StartedAt.Format(timeLayout), ansiDim),
					highlight(appearance.IP),
					statusBadge(appearance.Status),
					accent(joinOrDash(appearance.OpenPorts)),
					accent(emptyDash(appearance.TopOS)),
				))
			}
		}
		builder.WriteString("\n")
	}
	return builder.String()
}

func rankSessionHosts(hosts []history.HostSnapshot) []hostRisk {
	items := make([]hostRisk, 0, len(hosts))
	for _, host := range hosts {
		items = append(items, evaluateHostRisk(host))
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Score == items[j].Score {
			return items[i].Host.PrimaryIP < items[j].Host.PrimaryIP
		}
		return items[i].Score > items[j].Score
	})
	return items
}

func evaluateHostRisk(host history.HostSnapshot) hostRisk {
	findings := allHostFindings(host)
	score := 0
	reasons := make([]string, 0)
	evidence := make([]string, 0)

	managementCount := len(host.Management)
	for _, service := range host.Services {
		managementCount += len(service.Management)
	}
	if managementCount > 0 {
		score += 3
		reasons = append(reasons, "management surface exposure")
	}
	authSurface := false
	for _, service := range host.Services {
		if service.HTTP != nil && len(service.HTTP.AuthSchemes) > 0 {
			authSurface = true
			break
		}
	}
	if authSurface {
		score += 2
		reasons = append(reasons, "authentication surface detected")
	}
	for _, finding := range findings {
		score += findingSeverityScore(finding.Severity)
		if label := findingImpactLabel(finding); label != "" {
			reasons = append(reasons, label)
		}
		if ev := strings.TrimSpace(firstNonEmpty(finding.Evidence, finding.Title, finding.Identifier)); ev != "" {
			evidence = append(evidence, ev)
		}
	}

	reasons = uniqueStrings(reasons)
	evidence = uniqueStrings(evidence)
	if len(evidence) > 4 {
		evidence = evidence[:4]
	}
	return hostRisk{
		Host:     host,
		Score:    score,
		Level:    scoreToLevel(score),
		Reasons:  reasons,
		Evidence: evidence,
	}
}

func collectSessionAlerts(risks []hostRisk) []sessionAlert {
	alerts := make([]sessionAlert, 0)
	for _, risk := range risks {
		if risk.Level == "low" && len(risk.Reasons) == 0 {
			continue
		}
		title := "Host shows security-relevant drift or exposure"
		if len(risk.Reasons) > 0 {
			title = strings.Title(risk.Reasons[0])
		}
		alerts = append(alerts, sessionAlert{
			Host:     risk.Host.PrimaryIP,
			Title:    title,
			Why:      hostRiskWhy(risk),
			Evidence: firstOrDash(risk.Evidence),
			Score:    risk.Score,
		})
	}
	sort.Slice(alerts, func(i, j int) bool {
		if alerts[i].Score == alerts[j].Score {
			return alerts[i].Host < alerts[j].Host
		}
		return alerts[i].Score > alerts[j].Score
	})
	if len(alerts) > 12 {
		alerts = alerts[:12]
	}
	return alerts
}

func renderSessionAlertsSection(builder *strings.Builder, alerts []sessionAlert, view terminalView) {
	builder.WriteString(terminalSection("High-signal alerts"))
	if len(alerts) == 0 {
		builder.WriteString("  - none\n")
		return
	}
	limit := len(alerts)
	if view == viewCompact {
		limit = minInt(limit, 8)
	}
	for _, alert := range alerts[:limit] {
		builder.WriteString(fmt.Sprintf("  %s %s  host=%s\n", warnText("!"), highlight(alert.Title), accent(alert.Host)))
		builder.WriteString(fmt.Sprintf("    why: %s\n", style(previewText(alert.Why, 120), ansiDim)))
		builder.WriteString(fmt.Sprintf("    evidence: %s\n", style(previewText(alert.Evidence, 96), ansiDim)))
	}
}

func renderSessionTopRiskSection(builder *strings.Builder, risks []hostRisk, view terminalView) {
	builder.WriteString(terminalSection("Top changed hosts"))
	if len(risks) == 0 {
		builder.WriteString("  - none\n")
		return
	}
	limit := len(risks)
	if view == viewCompact {
		limit = minInt(limit, 8)
	}
	for _, item := range risks[:limit] {
		builder.WriteString(fmt.Sprintf("  %s status=%s risk=%s\n",
			highlight(item.Host.PrimaryIP),
			statusBadge(item.Host.Status),
			riskBadge(item.Level, item.Score),
		))
		builder.WriteString(fmt.Sprintf("    why: %s\n", style(previewText(hostRiskWhy(item), 120), ansiDim)))
	}
}

func renderSessionHostCard(risk hostRisk) string {
	host := risk.Host
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("%s\n", highlight(host.PrimaryIP)))
	builder.WriteString(summaryLine("Identity", fmt.Sprintf("status=%s  vendor=%s  mac=%s", statusBadge(host.Status), accent(emptyDash(host.Vendor)), accent(emptyDash(host.MAC)))))
	builder.WriteString(summaryLine("Exposure", fmt.Sprintf("open-ports=%s  management=%s", accent(joinOrDash(hostOpenPorts(host))), warnText(fmt.Sprintf("%d", countHostManagement(host))))))
	builder.WriteString(summaryLine("Fingerprints", fmt.Sprintf("tls=%s ssh=%s http=%s smb=%s", accent(fmt.Sprintf("%d", countTLS(host))), accent(fmt.Sprintf("%d", countSSH(host))), accent(fmt.Sprintf("%d", countHTTP(host))), accent(fmt.Sprintf("%d", countSMB(host))))))
	builder.WriteString(summaryLine("Risk", riskBadge(risk.Level, risk.Score)))
	builder.WriteString(summaryLine("Evidence", style(previewText(firstOrDash(risk.Evidence), 120), ansiDim)))
	builder.WriteString(summaryLine("History", fmt.Sprintf("nse=%s", renderNSEHits(host))))
	builder.WriteString("\n")
	return builder.String()
}

func rankChangedHosts(report history.DiffReport) []changedImpact {
	alertsByHost := mapDiffAlertsByHost(report.Alerts)
	impacts := make([]changedImpact, 0, len(report.ChangedHosts))
	for _, host := range report.ChangedHosts {
		hostIP := host.After.IP
		if hostIP == "" {
			hostIP = host.IP
		}
		score := 0
		score += len(host.NewVulnerabilities) * 6
		score += len(host.ManagementAdded) * 5
		score += len(host.FingerprintChanges) * 4
		score += len(host.OpenedPorts) * 2
		score += len(host.ServiceChanges) * 2
		score += len(host.ScriptChanges)
		if host.Before.IP != host.After.IP {
			score += 4
		}
		if host.TraceChanged {
			score += 2
		}
		score += len(alertsByHost[hostIP]) * 4
		if score == 0 {
			score = len(host.Reasons)
		}
		impacts = append(impacts, changedImpact{
			Host:   host,
			Score:  score,
			Level:  scoreToLevel(score),
			Reason: changedHostWhy(host),
			HostIP: hostIP,
			Alerts: alertsByHost[hostIP],
		})
	}
	sort.Slice(impacts, func(i, j int) bool {
		if impacts[i].Score == impacts[j].Score {
			return renderChangedHostLabel(impacts[i].Host) < renderChangedHostLabel(impacts[j].Host)
		}
		return impacts[i].Score > impacts[j].Score
	})
	return impacts
}

func buildDiffAttention(report history.DiffReport, impacts []changedImpact) []string {
	lines := make([]string, 0)
	if report.Summary.HighSignalAlerts > 0 {
		lines = append(lines, fmt.Sprintf("%s high-signal alerts require review", warnText(fmt.Sprintf("%d", report.Summary.HighSignalAlerts))))
	}
	if report.Summary.ManagementChanges > 0 {
		lines = append(lines, fmt.Sprintf("%s management surface changes expand control-plane exposure", warnText(fmt.Sprintf("%d", report.Summary.ManagementChanges))))
	}
	if report.Summary.VulnerabilityChanges > 0 {
		lines = append(lines, fmt.Sprintf("%s vulnerability signal changes may indicate new risk", warnText(fmt.Sprintf("%d", report.Summary.VulnerabilityChanges))))
	}
	if report.Summary.MovedHosts > 0 {
		lines = append(lines, fmt.Sprintf("%s identity moves observed; verify DHCP/reprovisioning intent", warnText(fmt.Sprintf("%d", report.Summary.MovedHosts))))
	}
	if len(impacts) > 0 {
		top := impacts[0]
		lines = append(lines, fmt.Sprintf("top host %s impact=%s (%s)", highlight(renderChangedHostLabel(top.Host)), riskBadge(top.Level, top.Score), style(previewText(top.Reason, 80), ansiDim)))
	}
	if len(lines) == 0 {
		lines = append(lines, "no high-priority drift detected")
	}
	return lines
}

func mapDiffAlertsByHost(alerts []history.DiffAlert) map[string][]history.DiffAlert {
	out := make(map[string][]history.DiffAlert)
	for _, alert := range alerts {
		host := strings.TrimSpace(alert.Host)
		if host == "" {
			continue
		}
		out[host] = append(out[host], alert)
	}
	return out
}

func alertImportance(alertType string) string {
	switch strings.ToLower(strings.TrimSpace(alertType)) {
	case "management_port_opened", "management_surface_added":
		return "New management surface: expands administrative attack surface and should be justified."
	case "tls_certificate_changed":
		return "Certificate changed: possible service replacement, reprovisioning, or unauthorized cert rotation."
	case "tls_issuer_changed":
		return "Issuer changed: trust chain drift may indicate PKI reconfiguration or interception risk."
	case "tls_key_fingerprint_changed":
		return "TLS key fingerprint changed: verify expected key rotation or service replacement."
	case "ssh_hostkey_rotated":
		return "SSH host key rotated: confirm intentional rebuild/rekey and update trust anchors."
	case "http_title_changed":
		return "HTTP UI changed: possible application swap, firmware update, or service drift."
	case "vulnerability_detected":
		return "New vulnerability signal detected: prioritize validation and remediation planning."
	case "smb_appeared", "rdp_appeared":
		return "Remote access surface appeared: review exposure and access controls."
	default:
		return "This event may indicate exposure, identity drift, or configuration change requiring validation."
	}
}

func timelineTopEvents(entry history.TimelineEntry) []string {
	events := make([]string, 0)
	for _, alert := range entry.Alerts {
		events = append(events, fmt.Sprintf("%s %s host=%s", warnText("!"), alert.Title, emptyDash(alert.Host)))
	}
	if entry.Summary.MovedHosts > 0 {
		events = append(events, fmt.Sprintf("%s %d moved host(s) (identity drift)", warnText("->"), entry.Summary.MovedHosts))
	}
	if entry.Summary.ManagementChanges > 0 {
		events = append(events, fmt.Sprintf("%s %d management changes (exposure drift)", warnText("+"), entry.Summary.ManagementChanges))
	}
	if entry.Summary.VulnerabilityChanges > 0 {
		events = append(events, fmt.Sprintf("%s %d vulnerability changes", warnText("!"), entry.Summary.VulnerabilityChanges))
	}
	if len(events) == 0 {
		events = append(events, "no notable high-signal events")
	}
	return events
}

type deviceHistoryStats struct {
	TopPorts  []string
	IPChanges int
	PortDrift int
	Score     int
	Level     string
	Why       []string
}

func computeDeviceHistoryStats(device history.DeviceHistory) deviceHistoryStats {
	portFrequency := make(map[string]int)
	ipChanges := 0
	portDrift := 0
	lastIP := ""
	lastPorts := ""

	for _, appearance := range device.Appearances {
		if lastIP != "" && lastIP != appearance.IP {
			ipChanges++
		}
		lastIP = appearance.IP

		openPorts := append([]string(nil), appearance.OpenPorts...)
		sort.Strings(openPorts)
		currentPorts := strings.Join(openPorts, ",")
		if lastPorts != "" && lastPorts != currentPorts {
			portDrift++
		}
		lastPorts = currentPorts
		for _, port := range appearance.OpenPorts {
			portFrequency[port]++
		}
	}

	type portCount struct {
		port  string
		count int
	}
	var top []portCount
	for port, count := range portFrequency {
		top = append(top, portCount{port: port, count: count})
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].count == top[j].count {
			return top[i].port < top[j].port
		}
		return top[i].count > top[j].count
	})
	topPorts := make([]string, 0, minInt(3, len(top)))
	for _, item := range top[:minInt(3, len(top))] {
		topPorts = append(topPorts, fmt.Sprintf("%s(x%d)", item.port, item.count))
	}

	score := ipChanges*2 + portDrift*2
	if len(device.IPs) > 1 {
		score += len(device.IPs)
	}
	why := make([]string, 0)
	if ipChanges > 0 {
		why = append(why, fmt.Sprintf("%d IP change(s)", ipChanges))
	}
	if portDrift > 0 {
		why = append(why, fmt.Sprintf("%d port-profile drift event(s)", portDrift))
	}
	if len(why) == 0 {
		why = append(why, "stable identity profile")
	}
	return deviceHistoryStats{
		TopPorts:  topPorts,
		IPChanges: ipChanges,
		PortDrift: portDrift,
		Score:     score,
		Level:     scoreToLevel(score),
		Why:       why,
	}
}

func changedHostWhy(host history.ChangedHost) string {
	reasons := make([]string, 0)
	if len(host.ManagementAdded) > 0 {
		reasons = append(reasons, "new management surface")
	}
	if len(host.NewVulnerabilities) > 0 {
		reasons = append(reasons, "new vulnerability signal")
	}
	if len(host.FingerprintChanges) > 0 {
		reasons = append(reasons, "fingerprint drift")
	}
	if host.Before.IP != host.After.IP {
		reasons = append(reasons, "identity moved")
	}
	if len(host.OpenedPorts) > 0 {
		reasons = append(reasons, "new exposed ports")
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "configuration drift observed")
	}
	return strings.Join(uniqueStrings(reasons), "; ")
}

func hostRiskWhy(risk hostRisk) string {
	reasons := risk.Reasons
	if len(reasons) == 0 {
		return "notable service or identity change"
	}
	return strings.Join(reasons, "; ")
}

func allHostFindings(host history.HostSnapshot) []snapshot.VulnerabilityFinding {
	findings := append([]snapshot.VulnerabilityFinding(nil), host.Vulnerabilities...)
	for _, service := range host.Services {
		findings = append(findings, service.Vulnerabilities...)
	}
	return findings
}

func findingSeverityScore(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 6
	case "high":
		return 4
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func findingImpactLabel(finding snapshot.VulnerabilityFinding) string {
	identifier := strings.ToLower(strings.TrimSpace(finding.Identifier))
	switch identifier {
	case "weak-tls-cipher", "tls-outdated-protocol-only", "management-ui-outdated-tls-only":
		return "weak or outdated TLS exposure"
	case "weak-ssh-algorithm":
		return "weak SSH cryptography"
	case "legacy-smbv1":
		return "legacy SMB protocol enabled"
	case "missing-core-security-headers":
		return "missing core HTTP security headers"
	case "dangerous-http-methods":
		return "dangerous HTTP methods exposed"
	case "www-authenticate-without-tls":
		return "credentials challenged on plaintext HTTP"
	case "exposed-admin-paths":
		return "admin/login paths exposed"
	case "tls-certificate-expiring-soon", "tls-certificate-expired":
		return "TLS certificate lifecycle risk"
	}
	title := strings.TrimSpace(finding.Title)
	if title != "" {
		return strings.ToLower(title)
	}
	return ""
}

func hostOpenPorts(host history.HostSnapshot) []string {
	ports := make([]string, 0)
	for _, service := range host.Services {
		if strings.EqualFold(service.State, "open") {
			ports = append(ports, fmt.Sprintf("%d/%s", service.Port, service.Protocol))
		}
	}
	sort.Strings(ports)
	return ports
}

func countHostManagement(host history.HostSnapshot) int {
	total := len(host.Management)
	for _, service := range host.Services {
		total += len(service.Management)
	}
	return total
}

func countTLS(host history.HostSnapshot) int {
	total := 0
	for _, service := range host.Services {
		if service.TLS != nil {
			total++
		}
	}
	return total
}

func countSSH(host history.HostSnapshot) int {
	total := 0
	for _, service := range host.Services {
		if service.SSH != nil {
			total++
		}
	}
	return total
}

func countHTTP(host history.HostSnapshot) int {
	total := 0
	for _, service := range host.Services {
		if service.HTTP != nil {
			total++
		}
	}
	return total
}

func countSMB(host history.HostSnapshot) int {
	total := 0
	for _, service := range host.Services {
		if service.SMB != nil {
			total++
		}
	}
	return total
}

func scoreToLevel(score int) string {
	switch {
	case score >= 12:
		return "high"
	case score >= 5:
		return "medium"
	default:
		return "low"
	}
}

func stabilityLevel(label string) string {
	switch label {
	case "drift":
		return "medium"
	default:
		return "low"
	}
}

func riskBadge(level string, score int) string {
	switch level {
	case "high":
		return badText(fmt.Sprintf("%s(%d)", strings.ToUpper(level), score))
	case "medium":
		return warnText(fmt.Sprintf("%s(%d)", strings.ToUpper(level), score))
	default:
		return goodText(fmt.Sprintf("%s(%d)", strings.ToUpper(level), score))
	}
}

func uniqueStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func firstOrDash(items []string) string {
	if len(items) == 0 {
		return "-"
	}
	return items[0]
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
