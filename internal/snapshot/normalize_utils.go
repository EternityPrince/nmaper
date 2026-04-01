package snapshot

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"nmaper/internal/parser"
)

func extractIdentifiers(text string) []string {
	matches := reIdentifier.FindAllString(strings.ToUpper(text), -1)
	return uniqueSorted(matches)
}

func extractAfterPrefixes(text string, prefixes ...string) string {
	for _, line := range splitLines(text) {
		trimmed := strings.TrimSpace(line)
		for _, prefix := range prefixes {
			if strings.HasPrefix(strings.ToLower(trimmed), strings.ToLower(prefix)) {
				return strings.TrimSpace(trimmed[len(prefix):])
			}
		}
	}
	return ""
}

func extractRegexGroup(text string, re *regexp.Regexp) string {
	match := re.FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func splitLines(text string) []string {
	return strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
}

func splitTokens(line string) []string {
	replacer := strings.NewReplacer(",", " ", ";", " ", "(", " ", ")", " ", "[", " ", "]", " ")
	return strings.Fields(replacer.Replace(line))
}

func startsWithDigit(value string) bool {
	if value == "" {
		return false
	}
	return value[0] >= '0' && value[0] <= '9'
}

func isCipherLine(line string) bool {
	trimmed := strings.TrimLeft(line, "|_ ")
	return strings.Contains(trimmed, "TLS_") || strings.Contains(trimmed, "ECDHE") || strings.Contains(trimmed, "DHE_") || strings.Contains(trimmed, "RSA_")
}

func normalizeCipher(line string) string {
	trimmed := strings.TrimSpace(strings.TrimLeft(line, "|_ "))
	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func normalizeVersion(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}

func looksLikeSSHAlgorithm(token string) bool {
	return strings.Contains(token, "-") && (strings.HasPrefix(token, "diffie-") || strings.HasPrefix(token, "curve") || strings.HasPrefix(token, "ecdh-") || strings.HasPrefix(token, "aes") || strings.HasPrefix(token, "chacha20") || strings.HasPrefix(token, "hmac-") || strings.HasPrefix(token, "ssh-"))
}

func isWeakCipher(cipher string) bool {
	upper := strings.ToUpper(cipher)
	for _, marker := range weakTLSMarkers {
		if strings.Contains(upper, strings.ToUpper(marker)) {
			return true
		}
	}
	return false
}

func isWeakSSHAlgorithm(algorithm string) bool {
	lower := strings.ToLower(algorithm)
	for _, marker := range weakSSHMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func sanitizeLine(text string) string {
	return normalizeWhitespace(firstMeaningfulLine(text))
}

func firstMeaningfulLine(text string) string {
	for _, line := range splitLines(text) {
		trimmed := strings.TrimSpace(strings.TrimLeft(line, "|_ "))
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func normalizeWhitespace(text string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(text)), " ")
}

func uniqueSorted(items []string) []string {
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
	sort.Strings(out)
	return out
}

func uniqueFindings(items []VulnerabilityFinding) []VulnerabilityFinding {
	seen := make(map[string]struct{}, len(items))
	out := make([]VulnerabilityFinding, 0, len(items))
	for _, item := range items {
		key := fmt.Sprintf("%s|%s|%s|%s|%s", item.ScriptID, item.Identifier, item.Title, item.Severity, item.State)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity == out[j].Severity {
			if out[i].Identifier == out[j].Identifier {
				return out[i].ScriptID < out[j].ScriptID
			}
			return out[i].Identifier < out[j].Identifier
		}
		return out[i].Severity > out[j].Severity
	})
	return out
}

func uniqueManagement(items []ManagementSurface) []ManagementSurface {
	seen := make(map[string]struct{}, len(items))
	out := make([]ManagementSurface, 0, len(items))
	for _, item := range items {
		key := fmt.Sprintf("%s|%d|%s|%s|%s", item.Category, item.Port, item.Protocol, item.Label, item.Detail)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port == out[j].Port {
			return out[i].Category < out[j].Category
		}
		return out[i].Port < out[j].Port
	})
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func containsAny(items []string, wants ...string) bool {
	for _, item := range items {
		for _, want := range wants {
			if strings.EqualFold(item, want) {
				return true
			}
		}
	}
	return false
}

func containsAnySubstring(items []string, wants ...string) bool {
	for _, item := range items {
		lowerItem := strings.ToLower(item)
		for _, want := range wants {
			if strings.Contains(lowerItem, strings.ToLower(want)) {
				return true
			}
		}
	}
	return false
}

func isHTTPService(port parser.Port) bool {
	name := strings.ToLower(port.Service.Name)
	return strings.Contains(name, "http")
}
