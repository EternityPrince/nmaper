package snapshot

import (
	"strings"

	"nmaper/internal/parser"
)

func vulnerabilitiesFromScript(script parser.ScriptResult) []VulnerabilityFinding {
	output := normalizeWhitespace(script.Output)
	lowerID := strings.ToLower(script.ID)
	if output == "" {
		return nil
	}

	if !strings.Contains(lowerID, "vuln") && lowerID != "ssl-heartbleed" && lowerID != "sshv1" {
		return nil
	}

	identifiers := extractIdentifiers(output + " " + script.RawXML)
	if len(identifiers) == 0 {
		identifiers = []string{script.ID}
	}

	findings := make([]VulnerabilityFinding, 0, len(identifiers))
	for _, identifier := range identifiers {
		findings = append(findings, VulnerabilityFinding{
			ScriptID:   script.ID,
			Identifier: identifier,
			Title:      humanizeFindingTitle(script.ID, output),
			Severity:   detectSeverity(script.ID, output),
			State:      detectState(output),
			Evidence:   previewEvidence(output),
		})
	}
	return findings
}

func humanizeFindingTitle(scriptID, output string) string {
	switch strings.ToLower(scriptID) {
	case "ssl-heartbleed":
		return "Heartbleed exposure detected"
	case "smb-vuln-ms17-010":
		return "MS17-010 exposure detected"
	case "rdp-vuln-ms12-020":
		return "MS12-020 exposure detected"
	case "sshv1":
		return "Legacy SSHv1 support detected"
	}
	if line := firstMeaningfulLine(output); line != "" {
		return line
	}
	return strings.ReplaceAll(scriptID, "-", " ")
}

func detectSeverity(scriptID, output string) string {
	lower := strings.ToLower(output + " " + scriptID)
	switch {
	case strings.Contains(lower, "critical"), strings.Contains(lower, "heartbleed"), strings.Contains(lower, "ms17-010"):
		return "critical"
	case strings.Contains(lower, "high"), strings.Contains(lower, "vulnerable"), strings.Contains(lower, "ms12-020"):
		return "high"
	case strings.Contains(lower, "medium"):
		return "medium"
	case strings.Contains(lower, "low"):
		return "low"
	default:
		return "info"
	}
}

func detectState(output string) string {
	lower := strings.ToLower(output)
	switch {
	case strings.Contains(lower, "not vulnerable"), strings.Contains(lower, "safe"):
		return "not_vulnerable"
	case strings.Contains(lower, "likely vulnerable"):
		return "likely_vulnerable"
	case strings.Contains(lower, "vulnerable"), strings.Contains(lower, "open to"), strings.Contains(lower, "supports sshv1"):
		return "vulnerable"
	default:
		return "observed"
	}
}

func previewEvidence(output string) string {
	if output == "" {
		return ""
	}
	normalized := normalizeWhitespace(output)
	if len(normalized) <= 160 {
		return normalized
	}
	return normalized[:157] + "..."
}
