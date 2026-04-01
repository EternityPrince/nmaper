package snapshot

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"nmaper/internal/parser"
)

var (
	coreSecurityHeaders = []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
	}
	dangerousHTTPMethods = []string{"PUT", "DELETE", "TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "PATCH"}
	adminPathTokens      = []string{"/admin", "/login", "/console", "/manager", "/dashboard", "/wp-admin", "/phpmyadmin", "/setup", "/install", "/webadmin", "/cgi-bin"}
	vendorPanelTokens    = []string{"tp-link", "netgear", "d-link", "mikrotik", "routeros", "synology", "qnap", "ubiquiti", "openwrt", "fritz", "draytek", "hikvision", "dahua", "fortinet", "pfsense"}
	privateCATokens      = []string{"internal", "private", "local", "lab", "corp", "home", "dev", "staging", "root ca", "issuing ca"}
	publicCATokens       = []string{"let's encrypt", "digicert", "globalsign", "sectigo", "geotrust", "godaddy", "amazon", "cloudflare", "buypass", "entrust", "comodo", "google trust services", "isrg", "zerossl"}
	reCommonName         = regexp.MustCompile(`(?i)\bCN\s*=\s*([^,/\n]+)`)
	reSANDNS             = regexp.MustCompile(`(?i)\bDNS\s*:\s*([A-Za-z0-9*._-]+)`)
)

func enrichTLSSecurityFindings(profile *ServiceProfile, port parser.Port, certOutputs []string) {
	if profile == nil || profile.TLS == nil {
		return
	}

	switch classifyTLSIssuer(profile.TLS.Subject, profile.TLS.Issuer) {
	case "self-signed":
		profile.Vulnerabilities = append(profile.Vulnerabilities, VulnerabilityFinding{
			ScriptID:   "ssl-cert",
			Identifier: "tls-self-signed",
			Title:      "Self-signed TLS certificate detected",
			Severity:   "medium",
			State:      "present",
			Evidence:   firstNonEmpty(profile.TLS.Subject, profile.TLS.Issuer),
		})
	case "private-ca":
		profile.Vulnerabilities = append(profile.Vulnerabilities, VulnerabilityFinding{
			ScriptID:   "ssl-cert",
			Identifier: "tls-private-ca",
			Title:      "Private/internal TLS CA detected",
			Severity:   "low",
			State:      "observed",
			Evidence:   firstNonEmpty(profile.TLS.Issuer, profile.TLS.Subject),
		})
	case "public-ca":
		profile.Vulnerabilities = append(profile.Vulnerabilities, VulnerabilityFinding{
			ScriptID:   "ssl-cert",
			Identifier: "tls-public-ca",
			Title:      "Public CA issued certificate detected",
			Severity:   "info",
			State:      "observed",
			Evidence:   firstNonEmpty(profile.TLS.Issuer, profile.TLS.Subject),
		})
	}

	if notAfter, ok := parseCertificateDate(profile.TLS.NotAfter); ok {
		daysLeft := int(time.Until(notAfter).Hours() / 24)
		switch {
		case daysLeft < 0:
			profile.Vulnerabilities = append(profile.Vulnerabilities, VulnerabilityFinding{
				ScriptID:   "ssl-cert",
				Identifier: "tls-certificate-expired",
				Title:      "TLS certificate has expired",
				Severity:   "high",
				State:      "present",
				Evidence:   profile.TLS.NotAfter,
			})
		case daysLeft <= 30:
			profile.Vulnerabilities = append(profile.Vulnerabilities, VulnerabilityFinding{
				ScriptID:   "ssl-cert",
				Identifier: "tls-certificate-expiring-soon",
				Title:      "TLS certificate is expiring soon",
				Severity:   "medium",
				State:      "observed",
				Evidence:   profile.TLS.NotAfter,
			})
		}
	}

	if cn := parseCommonName(profile.TLS.Subject); cn != "" {
		sans := parseSubjectAltNames(certOutputs)
		if len(sans) == 0 {
			profile.Vulnerabilities = append(profile.Vulnerabilities, VulnerabilityFinding{
				ScriptID:   "ssl-cert",
				Identifier: "tls-missing-san",
				Title:      "TLS certificate SAN extension missing",
				Severity:   "medium",
				State:      "observed",
				Evidence:   "CN=" + cn,
			})
		}
	}

	if hasOnlyLegacyTLSVersions(profile.TLS.Versions) {
		profile.Vulnerabilities = append(profile.Vulnerabilities, VulnerabilityFinding{
			ScriptID:   "ssl-enum-ciphers",
			Identifier: "tls-outdated-protocol-only",
			Title:      "TLS endpoint only supports outdated protocol versions",
			Severity:   "high",
			State:      "present",
			Evidence:   strings.Join(profile.TLS.Versions, ", "),
		})
		if label, _ := managementDescriptor(port, *profile); label != "" {
			profile.Vulnerabilities = append(profile.Vulnerabilities, VulnerabilityFinding{
				ScriptID:   "ssl-enum-ciphers",
				Identifier: "management-ui-outdated-tls-only",
				Title:      "Management UI uses outdated TLS only",
				Severity:   "high",
				State:      "present",
				Evidence:   strings.Join(profile.TLS.Versions, ", "),
			})
		}
	}
}

func enrichHTTPSecurityFindings(profile *ServiceProfile, port parser.Port, headerOutputs, enumOutputs []string) {
	if profile == nil || profile.HTTP == nil {
		return
	}

	missingCore := missingCoreHeaders(profile.HTTP.SecurityHeaders)
	if len(missingCore) > 0 {
		profile.Vulnerabilities = append(profile.Vulnerabilities, VulnerabilityFinding{
			ScriptID:   "http-security-headers",
			Identifier: "missing-core-security-headers",
			Title:      "Missing core HTTP security headers",
			Severity:   "medium",
			State:      "observed",
			Evidence:   strings.Join(missingCore, ", "),
		})
	}

	if dangerous := presentDangerousMethods(profile.HTTP.Methods); len(dangerous) > 0 {
		profile.Vulnerabilities = append(profile.Vulnerabilities, VulnerabilityFinding{
			ScriptID:   "http-methods",
			Identifier: "dangerous-http-methods",
			Title:      "Dangerous HTTP methods exposed",
			Severity:   "medium",
			State:      "present",
			Evidence:   strings.Join(dangerous, ", "),
		})
	}

	if hasAdminPaths(profile.HTTP.Paths) {
		profile.Vulnerabilities = append(profile.Vulnerabilities, VulnerabilityFinding{
			ScriptID:   "http-enum",
			Identifier: "exposed-admin-paths",
			Title:      "Exposed admin/login HTTP paths detected",
			Severity:   "medium",
			State:      "observed",
			Evidence:   strings.Join(profile.HTTP.Paths, ", "),
		})
	}

	if hasDirectoryListingHints(profile.HTTP, enumOutputs) {
		profile.Vulnerabilities = append(profile.Vulnerabilities, VulnerabilityFinding{
			ScriptID:   "http-enum",
			Identifier: "directory-listing-hints",
			Title:      "Directory listing hints detected on HTTP surface",
			Severity:   "low",
			State:      "observed",
			Evidence:   firstNonEmpty(profile.HTTP.Title, strings.Join(enumOutputs, " | ")),
		})
	}

	if looksLikeVendorDefaultPanel(profile.HTTP) {
		profile.Vulnerabilities = append(profile.Vulnerabilities, VulnerabilityFinding{
			ScriptID:   "http-title",
			Identifier: "default-vendor-panel-heuristic",
			Title:      "Possible default vendor admin panel detected",
			Severity:   "low",
			State:      "observed",
			Evidence:   firstNonEmpty(profile.HTTP.Title, profile.HTTP.Server),
		})
	}

	redirectToHTTPS := detectHTTPSRedirect(headerOutputs)
	if isHTTPService(port) && !isHTTPSTransport(port, profile) {
		if redirectToHTTPS {
			profile.Vulnerabilities = append(profile.Vulnerabilities, VulnerabilityFinding{
				ScriptID:   "http-headers",
				Identifier: "http-redirects-to-https",
				Title:      "HTTP surface redirects to HTTPS",
				Severity:   "info",
				State:      "observed",
				Evidence:   "Location: https://...",
			})
		} else {
			profile.Vulnerabilities = append(profile.Vulnerabilities, VulnerabilityFinding{
				ScriptID:   "http-headers",
				Identifier: "http-no-https-redirect",
				Title:      "HTTP surface does not redirect to HTTPS",
				Severity:   "medium",
				State:      "present",
				Evidence:   firstNonEmpty(profile.HTTP.Title, profile.HTTP.Server),
			})
		}
	}

	if hasWWWAuthenticateHeader(headerOutputs) && !isHTTPSTransport(port, profile) {
		profile.Vulnerabilities = append(profile.Vulnerabilities, VulnerabilityFinding{
			ScriptID:   "http-auth",
			Identifier: "www-authenticate-without-tls",
			Title:      "WWW-Authenticate exposed over non-TLS HTTP",
			Severity:   "high",
			State:      "present",
			Evidence:   "WWW-Authenticate header on plaintext HTTP",
		})
	}
}

func classifyTLSIssuer(subject, issuer string) string {
	s := strings.ToLower(strings.TrimSpace(subject))
	i := strings.ToLower(strings.TrimSpace(issuer))
	if s == "" && i == "" {
		return ""
	}
	if s != "" && i != "" && s == i {
		return "self-signed"
	}
	for _, marker := range privateCATokens {
		if strings.Contains(i, marker) {
			return "private-ca"
		}
	}
	for _, marker := range publicCATokens {
		if strings.Contains(i, marker) {
			return "public-ca"
		}
	}
	if i != "" {
		return "private-ca"
	}
	return ""
}

func parseCertificateDate(value string) (time.Time, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return time.Time{}, false
	}
	layouts := []string{
		"2006-01-02",
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"Jan 2 15:04:05 2006 MST",
		"Jan 2 15:04:05 2006",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, trimmed); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func parseCommonName(subject string) string {
	match := reCommonName.FindStringSubmatch(subject)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func parseSubjectAltNames(certOutputs []string) []string {
	sans := make([]string, 0)
	for _, output := range certOutputs {
		for _, match := range reSANDNS.FindAllStringSubmatch(output, -1) {
			if len(match) < 2 {
				continue
			}
			sans = append(sans, strings.TrimSpace(match[1]))
		}
	}
	return uniqueSorted(sans)
}

func hasOnlyLegacyTLSVersions(versions []string) bool {
	if len(versions) == 0 {
		return false
	}
	for _, version := range versions {
		normalized := strings.ToUpper(strings.TrimSpace(version))
		if normalized == "" {
			continue
		}
		switch normalized {
		case "SSLV2", "SSLV3", "TLSV1", "TLSV1.0", "TLSV1.1":
		default:
			return false
		}
	}
	return true
}

func missingCoreHeaders(securityHeaders []string) []string {
	missing := make([]string, 0, len(coreSecurityHeaders))
	for _, header := range coreSecurityHeaders {
		if !containsAny(securityHeaders, header) {
			missing = append(missing, header)
		}
	}
	return missing
}

func presentDangerousMethods(methods []string) []string {
	present := make([]string, 0)
	for _, method := range methods {
		if slices.Contains(dangerousHTTPMethods, strings.ToUpper(strings.TrimSpace(method))) {
			present = append(present, strings.ToUpper(strings.TrimSpace(method)))
		}
	}
	return uniqueSorted(present)
}

func hasAdminPaths(paths []string) bool {
	for _, path := range paths {
		lower := strings.ToLower(strings.TrimSpace(path))
		for _, token := range adminPathTokens {
			if strings.Contains(lower, token) {
				return true
			}
		}
	}
	return false
}

func hasDirectoryListingHints(http *HTTPFingerprint, enumOutputs []string) bool {
	if http != nil {
		lowerTitle := strings.ToLower(http.Title)
		if strings.Contains(lowerTitle, "index of /") || strings.Contains(lowerTitle, "directory listing") {
			return true
		}
	}
	for _, output := range enumOutputs {
		lower := strings.ToLower(output)
		if strings.Contains(lower, "index of /") || strings.Contains(lower, "directory listing") || strings.Contains(lower, "autoindex") {
			return true
		}
	}
	return false
}

func looksLikeVendorDefaultPanel(http *HTTPFingerprint) bool {
	if http == nil {
		return false
	}
	combined := strings.ToLower(strings.Join([]string{http.Title, http.Server, strings.Join(http.Paths, " ")}, " "))
	if !strings.Contains(combined, "admin") && !strings.Contains(combined, "login") && !strings.Contains(combined, "router") && !strings.Contains(combined, "panel") {
		return false
	}
	for _, token := range vendorPanelTokens {
		if strings.Contains(combined, token) {
			return true
		}
	}
	return false
}

func detectHTTPSRedirect(headerOutputs []string) bool {
	for _, output := range headerOutputs {
		for _, line := range splitLines(output) {
			trimmed := strings.TrimSpace(strings.ToLower(line))
			if strings.HasPrefix(trimmed, "location:") && strings.Contains(trimmed, "https://") {
				return true
			}
			if strings.Contains(trimmed, " 301 ") && strings.Contains(trimmed, "https://") {
				return true
			}
			if strings.Contains(trimmed, " 302 ") && strings.Contains(trimmed, "https://") {
				return true
			}
			if strings.Contains(trimmed, " 308 ") && strings.Contains(trimmed, "https://") {
				return true
			}
		}
	}
	return false
}

func hasWWWAuthenticateHeader(headerOutputs []string) bool {
	for _, output := range headerOutputs {
		if strings.Contains(strings.ToLower(output), "www-authenticate:") {
			return true
		}
	}
	return false
}

func isHTTPSTransport(port parser.Port, profile *ServiceProfile) bool {
	if strings.EqualFold(port.Service.Tunnel, "ssl") {
		return true
	}
	if strings.Contains(strings.ToLower(port.Service.Name), "https") {
		return true
	}
	if port.ID == 443 || port.ID == 8443 || port.ID == 9443 {
		return true
	}
	return profile != nil && profile.TLS != nil
}

func parsePortFromScope(scope string) int {
	parts := strings.SplitN(scope, "/", 2)
	if len(parts) == 0 {
		return 0
	}
	port, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
	return port
}
