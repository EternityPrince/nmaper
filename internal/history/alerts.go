package history

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"nmaper/internal/snapshot"
)

var managementPortLabels = map[int]string{
	22:    "SSH",
	23:    "Telnet",
	161:   "SNMP",
	445:   "SMB",
	3389:  "RDP",
	5900:  "VNC",
	5985:  "WinRM",
	5986:  "WinRM TLS",
	8080:  "HTTP admin",
	8081:  "HTTP admin",
	8443:  "HTTPS admin",
	9090:  "Admin UI",
	9443:  "HTTPS admin",
	10000: "Webmin",
	2375:  "Docker API",
	2376:  "Docker TLS API",
	6443:  "Kubernetes API",
	15672: "RabbitMQ UI",
}

func buildHighSignalAlerts(report DiffReport) []DiffAlert {
	alerts := make([]DiffAlert, 0)
	seen := make(map[string]struct{})

	appendAlert := func(alert DiffAlert) {
		key := strings.Join([]string{alert.Type, alert.Host, alert.Title, alert.Detail}, "|")
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		alerts = append(alerts, alert)
	}

	for _, host := range report.NewHosts {
		for _, alert := range alertsFromNewHost(host) {
			appendAlert(alert)
		}
	}
	for _, host := range report.ChangedHosts {
		for _, alert := range alertsFromChangedHost(host) {
			appendAlert(alert)
		}
	}

	sort.Slice(alerts, func(i, j int) bool {
		if alerts[i].Host == alerts[j].Host {
			return alerts[i].Type < alerts[j].Type
		}
		return alerts[i].Host < alerts[j].Host
	})
	return alerts
}

func alertsFromNewHost(host HostDiffSnapshot) []DiffAlert {
	alerts := make([]DiffAlert, 0)
	for _, port := range host.OpenPorts {
		switch parsePortNumber(port) {
		case 445:
			alerts = append(alerts, DiffAlert{
				Type:     "smb_appeared",
				Severity: "high",
				Host:     host.IP,
				Title:    "SMB appeared on a newly discovered host",
				Detail:   "open port " + port,
			})
		case 3389:
			alerts = append(alerts, DiffAlert{
				Type:     "rdp_appeared",
				Severity: "high",
				Host:     host.IP,
				Title:    "RDP appeared on a newly discovered host",
				Detail:   "open port " + port,
			})
		default:
			if label := managementPortLabel(port); label != "" {
				alerts = append(alerts, DiffAlert{
					Type:     "management_port_opened",
					Severity: "high",
					Host:     host.IP,
					Title:    "New management surface detected",
					Detail:   fmt.Sprintf("%s on %s", label, port),
				})
			}
		}
	}
	return alerts
}

func alertsFromChangedHost(host ChangedHost) []DiffAlert {
	alerts := make([]DiffAlert, 0)
	hostIP := host.After.IP
	if hostIP == "" {
		hostIP = host.IP
	}

	for _, port := range host.OpenedPorts {
		switch parsePortNumber(port) {
		case 445:
			alerts = append(alerts, DiffAlert{
				Type:     "smb_appeared",
				Severity: "high",
				Host:     hostIP,
				Title:    "SMB appeared",
				Detail:   "new open port " + port,
			})
		case 3389:
			alerts = append(alerts, DiffAlert{
				Type:     "rdp_appeared",
				Severity: "high",
				Host:     hostIP,
				Title:    "RDP appeared",
				Detail:   "new open port " + port,
			})
		default:
			if label := managementPortLabel(port); label != "" {
				alerts = append(alerts, DiffAlert{
					Type:     "management_port_opened",
					Severity: "high",
					Host:     hostIP,
					Title:    "New management surface detected",
					Detail:   fmt.Sprintf("%s on %s", label, port),
				})
			}
		}
	}
	for _, surface := range host.ManagementAdded {
		if label := strings.TrimSpace(surface.Label); label != "" {
			alerts = append(alerts, DiffAlert{
				Type:     "management_surface_added",
				Severity: "high",
				Host:     hostIP,
				Title:    "New management surface detected",
				Detail:   fmt.Sprintf("%s on %d/%s", label, surface.Port, surface.Protocol),
			})
		}
	}

	beforeCerts, afterCerts := aggregateScriptOutputs(host.ScriptChanges, "ssl-cert")
	if len(beforeCerts) > 0 && len(afterCerts) > 0 && strings.Join(beforeCerts, "|") != strings.Join(afterCerts, "|") {
		alerts = append(alerts, DiffAlert{
			Type:     "tls_certificate_changed",
			Severity: "high",
			Host:     hostIP,
			Title:    "TLS certificate changed",
			Detail:   fmt.Sprintf("%s -> %s", previewOutputs(beforeCerts), previewOutputs(afterCerts)),
		})
		beforeIssuer := extractTLSCertField(beforeCerts, "issuer:")
		afterIssuer := extractTLSCertField(afterCerts, "issuer:")
		if beforeIssuer != "" && afterIssuer != "" && beforeIssuer != afterIssuer {
			alerts = append(alerts, DiffAlert{
				Type:     "tls_issuer_changed",
				Severity: "high",
				Host:     hostIP,
				Title:    "TLS issuer changed",
				Detail:   fmt.Sprintf("%s -> %s", beforeIssuer, afterIssuer),
			})
		}
		beforeSHA := extractTLSCertField(beforeCerts, "sha256:", "fingerprint-256:", "sha-256:")
		afterSHA := extractTLSCertField(afterCerts, "sha256:", "fingerprint-256:", "sha-256:")
		if beforeSHA != "" && afterSHA != "" && beforeSHA != afterSHA {
			alerts = append(alerts, DiffAlert{
				Type:     "tls_key_fingerprint_changed",
				Severity: "high",
				Host:     hostIP,
				Title:    "TLS certificate key fingerprint changed",
				Detail:   fmt.Sprintf("%s -> %s", beforeSHA, afterSHA),
			})
		}
	}

	beforeSSH, afterSSH := aggregateScriptOutputs(host.ScriptChanges, "ssh-hostkey")
	if len(beforeSSH) > 0 && len(afterSSH) > 0 && strings.Join(beforeSSH, "|") != strings.Join(afterSSH, "|") {
		alerts = append(alerts, DiffAlert{
			Type:     "ssh_hostkey_rotated",
			Severity: "high",
			Host:     hostIP,
			Title:    "SSH host key rotated",
			Detail:   fmt.Sprintf("%s -> %s", previewOutputs(beforeSSH), previewOutputs(afterSSH)),
		})
	}

	beforeTitles, afterTitles := aggregateScriptOutputs(host.ScriptChanges, "http-title")
	if (len(beforeTitles) > 0 || len(afterTitles) > 0) && strings.Join(beforeTitles, "|") != strings.Join(afterTitles, "|") {
		alerts = append(alerts, DiffAlert{
			Type:     "http_title_changed",
			Severity: "high",
			Host:     hostIP,
			Title:    "HTTP title changed",
			Detail:   fmt.Sprintf("%s -> %s", previewOutputs(beforeTitles), previewOutputs(afterTitles)),
		})
	}
	for _, finding := range host.NewVulnerabilities {
		if !findingSignalsRisk(finding) {
			continue
		}
		title := "New vulnerability signal detected"
		if finding.Title != "" {
			title = finding.Title
		}
		severity := finding.Severity
		if severity == "" {
			severity = "high"
		}
		alerts = append(alerts, DiffAlert{
			Type:     "vulnerability_detected",
			Severity: severity,
			Host:     hostIP,
			Title:    title,
			Detail:   firstNonEmpty(finding.Identifier, finding.Evidence, finding.ScriptID),
		})
	}

	return alerts
}

func aggregateScriptOutputs(changes []ScriptDelta, scriptID string) ([]string, []string) {
	before := make(map[string]struct{})
	after := make(map[string]struct{})
	for _, change := range changes {
		if change.ID != scriptID {
			continue
		}
		if strings.TrimSpace(change.Before) != "" {
			before[strings.TrimSpace(change.Before)] = struct{}{}
		}
		if strings.TrimSpace(change.After) != "" {
			after[strings.TrimSpace(change.After)] = struct{}{}
		}
	}
	return mapKeys(before), mapKeys(after)
}

func previewOutputs(values []string) string {
	if len(values) == 0 {
		return "-"
	}
	preview := append([]string(nil), values...)
	sort.Strings(preview)
	if len(preview) > 2 {
		preview = preview[:2]
	}
	for index, value := range preview {
		if len(value) > 48 {
			preview[index] = value[:45] + "..."
		}
	}
	return strings.Join(preview, "; ")
}

func findingSignalsRisk(finding snapshot.VulnerabilityFinding) bool {
	switch strings.ToLower(finding.State) {
	case "vulnerable", "likely_vulnerable", "present", "observed":
		return true
	default:
		return false
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func mapKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func extractTLSCertField(outputs []string, prefixes ...string) string {
	for _, output := range outputs {
		for _, line := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
			trimmed := strings.TrimSpace(line)
			lower := strings.ToLower(trimmed)
			for _, prefix := range prefixes {
				if strings.HasPrefix(lower, strings.ToLower(prefix)) {
					return strings.TrimSpace(trimmed[len(prefix):])
				}
			}
		}
	}
	return ""
}

func managementPortLabel(port string) string {
	number := parsePortNumber(port)
	switch number {
	case 445, 3389:
		return ""
	default:
		return managementPortLabels[number]
	}
}

func parsePortNumber(port string) int {
	value := port
	if cut := strings.Index(value, "/"); cut >= 0 {
		value = value[:cut]
	}
	number, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return number
}
