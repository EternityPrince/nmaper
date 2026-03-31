package snapshot

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"nmaper/internal/parser"
)

var (
	reHTTPPath        = regexp.MustCompile(`(?m)(/[A-Za-z0-9._~!$&'()*+,;=:@%-]+(?:/[A-Za-z0-9._~!$&'()*+,;=:@%-]+)*)`)
	reIdentifier      = regexp.MustCompile(`(?i)\b(CVE-\d{4}-\d+|CWE-\d+|MS\d{2}-\d+)\b`)
	reTLSVersion      = regexp.MustCompile(`(?i)\b(?:SSLv\d|TLSv1(?:\.[0-3])?)\b`)
	reHashFingerprint = regexp.MustCompile(`(?i)\b(?:sha-?256|fingerprint-?256)\s*[:=]?\s*([A-F0-9:]{32,})\b`)
	reShareName       = regexp.MustCompile(`(?m)^\s*([A-Za-z0-9$_. -]{1,64})\s*(?:-|$)`)
)

var (
	httpMethodTokens = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL"}
	securityHeaders  = []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Referrer-Policy",
		"Permissions-Policy",
		"Cross-Origin-Opener-Policy",
		"Cross-Origin-Resource-Policy",
	}
	weakTLSMarkers = []string{"RC4", "3DES", "DES", "MD5", "NULL", "EXPORT", "CBC", "anon", "RSA_WITH_3DES", "RSA_WITH_RC4"}
	weakSSHMarkers = []string{"diffie-hellman-group1-sha1", "ssh-dss", "cbc", "hmac-md5", "arcfour"}
)

func AnalyzeHost(host parser.Host) HostProfile {
	profile := HostProfile{}
	for _, script := range host.Scripts {
		profile.Vulnerabilities = append(profile.Vulnerabilities, vulnerabilitiesFromScript(script)...)
	}
	profile.Vulnerabilities = uniqueFindings(profile.Vulnerabilities)
	profile.Management = uniqueManagement(profile.Management)
	return profile
}

func AnalyzeService(port parser.Port) ServiceProfile {
	profile := ServiceProfile{}
	for _, script := range port.Scripts {
		switch script.ID {
		case "ssl-cert":
			profile.TLS = mergeTLS(profile.TLS, parseSSLCert(script.Output))
		case "ssl-enum-ciphers":
			profile.TLS = mergeTLS(profile.TLS, parseSSLCiphers(script.Output))
		case "ssh-hostkey":
			profile.SSH = mergeSSH(profile.SSH, parseSSHHostKeys(script.Output))
		case "ssh2-enum-algos":
			profile.SSH = mergeSSH(profile.SSH, parseSSHAlgorithms(script.Output))
		case "http-title":
			profile.HTTP = mergeHTTP(profile.HTTP, &HTTPFingerprint{Title: sanitizeLine(script.Output)})
		case "http-server-header":
			profile.HTTP = mergeHTTP(profile.HTTP, &HTTPFingerprint{Server: sanitizeLine(script.Output)})
		case "http-headers":
			profile.HTTP = mergeHTTP(profile.HTTP, parseHTTPHeaders(script.Output))
		case "http-methods":
			profile.HTTP = mergeHTTP(profile.HTTP, parseHTTPMethods(script.Output))
		case "http-auth":
			profile.HTTP = mergeHTTP(profile.HTTP, parseHTTPAuth(script.Output))
		case "http-security-headers":
			profile.HTTP = mergeHTTP(profile.HTTP, parseHTTPSecurityHeaders(script.Output))
		case "http-enum":
			profile.HTTP = mergeHTTP(profile.HTTP, parseHTTPPaths(script.Output))
		case "smb-os-discovery":
			profile.SMB = mergeSMB(profile.SMB, parseSMBOS(script.Output))
		case "smb-protocols":
			profile.SMB = mergeSMB(profile.SMB, parseSMBProtocols(script.Output))
		case "smb-enum-shares":
			profile.SMB = mergeSMB(profile.SMB, parseSMBShares(script.Output))
		}

		profile.Vulnerabilities = append(profile.Vulnerabilities, vulnerabilitiesFromScript(script)...)
	}

	if profile.TLS != nil && len(profile.TLS.WeakCiphers) > 0 {
		profile.Vulnerabilities = append(profile.Vulnerabilities, VulnerabilityFinding{
			ScriptID:   "ssl-enum-ciphers",
			Identifier: "weak-tls-cipher",
			Title:      "Weak TLS ciphers enabled",
			Severity:   "medium",
			State:      "present",
			Evidence:   strings.Join(profile.TLS.WeakCiphers, ", "),
		})
	}
	if profile.SSH != nil && len(profile.SSH.WeakAlgorithms) > 0 {
		profile.Vulnerabilities = append(profile.Vulnerabilities, VulnerabilityFinding{
			ScriptID:   "ssh2-enum-algos",
			Identifier: "weak-ssh-algorithm",
			Title:      "Weak SSH algorithms enabled",
			Severity:   "medium",
			State:      "present",
			Evidence:   strings.Join(profile.SSH.WeakAlgorithms, ", "),
		})
	}
	if profile.SMB != nil && containsAnySubstring(profile.SMB.Protocols, "SMBv1", "SMB 1.0", "NT LM 0.12") {
		profile.Vulnerabilities = append(profile.Vulnerabilities, VulnerabilityFinding{
			ScriptID:   "smb-protocols",
			Identifier: "legacy-smbv1",
			Title:      "Legacy SMBv1 enabled",
			Severity:   "high",
			State:      "present",
			Evidence:   strings.Join(profile.SMB.Protocols, ", "),
		})
	}

	profile.Management = deriveManagement(port, profile)
	profile.Vulnerabilities = uniqueFindings(profile.Vulnerabilities)
	profile.Management = uniqueManagement(profile.Management)
	return profile
}

func parseSSLCert(output string) *TLSFingerprint {
	if strings.TrimSpace(output) == "" {
		return nil
	}
	fp := &TLSFingerprint{
		Subject:   extractAfterPrefixes(output, "Subject:", "subject="),
		Issuer:    extractAfterPrefixes(output, "Issuer:", "issuer="),
		NotBefore: extractAfterPrefixes(output, "Not valid before:", "Not before:", "valid from:"),
		NotAfter:  extractAfterPrefixes(output, "Not valid after:", "Not after:", "valid to:"),
		SHA256:    extractRegexGroup(output, reHashFingerprint),
	}
	return nilIfEmptyTLS(fp)
}

func parseSSLCiphers(output string) *TLSFingerprint {
	if strings.TrimSpace(output) == "" {
		return nil
	}
	fp := &TLSFingerprint{}
	lines := splitLines(output)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if version := reTLSVersion.FindString(trimmed); version != "" {
			fp.Versions = append(fp.Versions, normalizeVersion(version))
			continue
		}
		if isCipherLine(trimmed) {
			cipher := normalizeCipher(trimmed)
			if cipher == "" {
				continue
			}
			fp.Ciphers = append(fp.Ciphers, cipher)
			if isWeakCipher(cipher) {
				fp.WeakCiphers = append(fp.WeakCiphers, cipher)
			}
		}
	}
	fp.Versions = uniqueSorted(fp.Versions)
	fp.Ciphers = uniqueSorted(fp.Ciphers)
	fp.WeakCiphers = uniqueSorted(fp.WeakCiphers)
	return nilIfEmptyTLS(fp)
}

func parseSSHHostKeys(output string) *SSHFingerprint {
	if strings.TrimSpace(output) == "" {
		return nil
	}
	fp := &SSHFingerprint{}
	for _, line := range splitLines(output) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "bits") || strings.Contains(trimmed, "ssh-") || strings.Contains(trimmed, "ecdsa-") || startsWithDigit(trimmed) {
			fp.HostKeys = append(fp.HostKeys, trimmed)
		}
	}
	fp.HostKeys = uniqueSorted(fp.HostKeys)
	return nilIfEmptySSH(fp)
}

func parseSSHAlgorithms(output string) *SSHFingerprint {
	if strings.TrimSpace(output) == "" {
		return nil
	}
	fp := &SSHFingerprint{}
	for _, line := range splitLines(output) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		for _, token := range splitTokens(trimmed) {
			if !looksLikeSSHAlgorithm(token) {
				continue
			}
			fp.Algorithms = append(fp.Algorithms, token)
			if isWeakSSHAlgorithm(token) {
				fp.WeakAlgorithms = append(fp.WeakAlgorithms, token)
			}
		}
	}
	fp.Algorithms = uniqueSorted(fp.Algorithms)
	fp.WeakAlgorithms = uniqueSorted(fp.WeakAlgorithms)
	return nilIfEmptySSH(fp)
}

func parseHTTPHeaders(output string) *HTTPFingerprint {
	if strings.TrimSpace(output) == "" {
		return nil
	}
	fp := &HTTPFingerprint{}
	for _, line := range splitLines(output) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if parts := strings.SplitN(trimmed, ":", 2); len(parts) == 2 {
			header := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			fp.Headers = append(fp.Headers, header)
			if strings.EqualFold(header, "Server") && fp.Server == "" {
				fp.Server = value
			}
			for _, securityHeader := range securityHeaders {
				if strings.EqualFold(header, securityHeader) {
					fp.SecurityHeaders = append(fp.SecurityHeaders, securityHeader)
				}
			}
		}
	}
	fp.Headers = uniqueSorted(fp.Headers)
	fp.SecurityHeaders = uniqueSorted(fp.SecurityHeaders)
	return nilIfEmptyHTTP(fp)
}

func parseHTTPMethods(output string) *HTTPFingerprint {
	if strings.TrimSpace(output) == "" {
		return nil
	}
	fp := &HTTPFingerprint{}
	upper := strings.ToUpper(output)
	for _, method := range httpMethodTokens {
		if strings.Contains(upper, method) {
			fp.Methods = append(fp.Methods, method)
		}
	}
	fp.Methods = uniqueSorted(fp.Methods)
	return nilIfEmptyHTTP(fp)
}

func parseHTTPAuth(output string) *HTTPFingerprint {
	if strings.TrimSpace(output) == "" {
		return nil
	}
	fp := &HTTPFingerprint{}
	for _, scheme := range []string{"Basic", "Digest", "NTLM", "Bearer", "Negotiate"} {
		if strings.Contains(strings.ToLower(output), strings.ToLower(scheme)) {
			fp.AuthSchemes = append(fp.AuthSchemes, scheme)
		}
	}
	fp.AuthSchemes = uniqueSorted(fp.AuthSchemes)
	return nilIfEmptyHTTP(fp)
}

func parseHTTPSecurityHeaders(output string) *HTTPFingerprint {
	if strings.TrimSpace(output) == "" {
		return nil
	}
	fp := &HTTPFingerprint{}
	for _, header := range securityHeaders {
		if strings.Contains(strings.ToLower(output), strings.ToLower(header)) {
			fp.SecurityHeaders = append(fp.SecurityHeaders, header)
		}
	}
	fp.SecurityHeaders = uniqueSorted(fp.SecurityHeaders)
	return nilIfEmptyHTTP(fp)
}

func parseHTTPPaths(output string) *HTTPFingerprint {
	if strings.TrimSpace(output) == "" {
		return nil
	}
	fp := &HTTPFingerprint{}
	for _, match := range reHTTPPath.FindAllString(output, -1) {
		if strings.HasPrefix(match, "/") {
			fp.Paths = append(fp.Paths, match)
		}
	}
	fp.Paths = uniqueSorted(fp.Paths)
	return nilIfEmptyHTTP(fp)
}

func parseSMBOS(output string) *SMBFingerprint {
	if strings.TrimSpace(output) == "" {
		return nil
	}
	fp := &SMBFingerprint{
		OS:        extractAfterPrefixes(output, "OS:", "Native OS:"),
		Workgroup: extractAfterPrefixes(output, "Workgroup:", "Domain name:"),
	}
	return nilIfEmptySMB(fp)
}

func parseSMBProtocols(output string) *SMBFingerprint {
	if strings.TrimSpace(output) == "" {
		return nil
	}
	fp := &SMBFingerprint{}
	for _, line := range splitLines(output) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "SMB") || strings.Contains(trimmed, "NT LM 0.12") {
			fp.Protocols = append(fp.Protocols, normalizeWhitespace(trimmed))
		}
	}
	fp.Protocols = uniqueSorted(fp.Protocols)
	return nilIfEmptySMB(fp)
}

func parseSMBShares(output string) *SMBFingerprint {
	if strings.TrimSpace(output) == "" {
		return nil
	}
	fp := &SMBFingerprint{}
	for _, match := range reShareName.FindAllStringSubmatch(output, -1) {
		name := strings.TrimSpace(match[1])
		if name == "" {
			continue
		}
		if strings.Contains(strings.ToLower(name), "warning") || strings.Contains(strings.ToLower(name), "account_used") {
			continue
		}
		fp.Shares = append(fp.Shares, name)
	}
	fp.Shares = uniqueSorted(fp.Shares)
	return nilIfEmptySMB(fp)
}

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

func deriveManagement(port parser.Port, profile ServiceProfile) []ManagementSurface {
	label, category := managementDescriptor(port, profile)
	if label == "" && category == "" {
		return nil
	}

	detail := serviceDetail(port, profile)
	return []ManagementSurface{{
		Category: category,
		Label:    label,
		Port:     port.ID,
		Protocol: port.Protocol,
		Exposure: port.Service.Name,
		Detail:   detail,
	}}
}

func managementDescriptor(port parser.Port, profile ServiceProfile) (string, string) {
	switch port.ID {
	case 22, 2222:
		return "SSH", "ssh"
	case 23:
		return "Telnet", "telnet"
	case 53:
		return "DNS", "dns"
	case 137:
		return "NetBIOS", "netbios"
	case 161:
		return "SNMP", "snmp"
	case 445, 139:
		return "SMB", "smb"
	case 3389:
		return "RDP", "rdp"
	case 5900:
		return "VNC", "vnc"
	case 5985, 5986:
		return "WinRM", "winrm"
	case 8080, 8081, 8443, 9090, 9443, 10000, 15672:
		return "Admin UI", "http-admin"
	case 2375, 2376:
		return "Docker API", "docker"
	case 6443:
		return "Kubernetes API", "kubernetes"
	case 1900:
		return "UPnP", "upnp"
	}

	if isHTTPService(port) {
		title := ""
		if profile.HTTP != nil {
			title = strings.ToLower(profile.HTTP.Title)
		}
		if strings.Contains(title, "admin") || strings.Contains(title, "login") || strings.Contains(title, "console") || strings.Contains(title, "dashboard") || strings.Contains(title, "router") || strings.Contains(title, "nas") {
			return "Admin UI", "http-admin"
		}
	}
	return "", ""
}

func serviceDetail(port parser.Port, profile ServiceProfile) string {
	if profile.HTTP != nil && profile.HTTP.Title != "" {
		return profile.HTTP.Title
	}
	if profile.HTTP != nil && profile.HTTP.Server != "" {
		return profile.HTTP.Server
	}
	if profile.SMB != nil && profile.SMB.OS != "" {
		return profile.SMB.OS
	}
	if port.Service.Product != "" {
		return strings.TrimSpace(strings.Join([]string{port.Service.Product, port.Service.Version}, " "))
	}
	return port.Service.Name
}

func mergeTLS(base, next *TLSFingerprint) *TLSFingerprint {
	if next == nil {
		return base
	}
	if base == nil {
		copy := *next
		copy.Versions = uniqueSorted(copy.Versions)
		copy.Ciphers = uniqueSorted(copy.Ciphers)
		copy.WeakCiphers = uniqueSorted(copy.WeakCiphers)
		return &copy
	}
	if base.Subject == "" {
		base.Subject = next.Subject
	}
	if base.Issuer == "" {
		base.Issuer = next.Issuer
	}
	if base.NotBefore == "" {
		base.NotBefore = next.NotBefore
	}
	if base.NotAfter == "" {
		base.NotAfter = next.NotAfter
	}
	if base.SHA256 == "" {
		base.SHA256 = next.SHA256
	}
	base.Versions = append(base.Versions, next.Versions...)
	base.Ciphers = append(base.Ciphers, next.Ciphers...)
	base.WeakCiphers = append(base.WeakCiphers, next.WeakCiphers...)
	base.Versions = uniqueSorted(base.Versions)
	base.Ciphers = uniqueSorted(base.Ciphers)
	base.WeakCiphers = uniqueSorted(base.WeakCiphers)
	return base
}

func mergeSSH(base, next *SSHFingerprint) *SSHFingerprint {
	if next == nil {
		return base
	}
	if base == nil {
		copy := *next
		copy.HostKeys = uniqueSorted(copy.HostKeys)
		copy.Algorithms = uniqueSorted(copy.Algorithms)
		copy.WeakAlgorithms = uniqueSorted(copy.WeakAlgorithms)
		return &copy
	}
	base.HostKeys = uniqueSorted(append(base.HostKeys, next.HostKeys...))
	base.Algorithms = uniqueSorted(append(base.Algorithms, next.Algorithms...))
	base.WeakAlgorithms = uniqueSorted(append(base.WeakAlgorithms, next.WeakAlgorithms...))
	return base
}

func mergeHTTP(base, next *HTTPFingerprint) *HTTPFingerprint {
	if next == nil {
		return base
	}
	if base == nil {
		copy := *next
		copy.Methods = uniqueSorted(copy.Methods)
		copy.AuthSchemes = uniqueSorted(copy.AuthSchemes)
		copy.Paths = uniqueSorted(copy.Paths)
		copy.SecurityHeaders = uniqueSorted(copy.SecurityHeaders)
		copy.Headers = uniqueSorted(copy.Headers)
		return &copy
	}
	if base.Title == "" {
		base.Title = next.Title
	}
	if base.Server == "" {
		base.Server = next.Server
	}
	base.Methods = uniqueSorted(append(base.Methods, next.Methods...))
	base.AuthSchemes = uniqueSorted(append(base.AuthSchemes, next.AuthSchemes...))
	base.Paths = uniqueSorted(append(base.Paths, next.Paths...))
	base.SecurityHeaders = uniqueSorted(append(base.SecurityHeaders, next.SecurityHeaders...))
	base.Headers = uniqueSorted(append(base.Headers, next.Headers...))
	return base
}

func mergeSMB(base, next *SMBFingerprint) *SMBFingerprint {
	if next == nil {
		return base
	}
	if base == nil {
		copy := *next
		copy.Protocols = uniqueSorted(copy.Protocols)
		copy.Shares = uniqueSorted(copy.Shares)
		return &copy
	}
	if base.OS == "" {
		base.OS = next.OS
	}
	if base.Workgroup == "" {
		base.Workgroup = next.Workgroup
	}
	base.Protocols = uniqueSorted(append(base.Protocols, next.Protocols...))
	base.Shares = uniqueSorted(append(base.Shares, next.Shares...))
	return base
}

func nilIfEmptyTLS(fp *TLSFingerprint) *TLSFingerprint {
	if fp == nil {
		return nil
	}
	if fp.Subject == "" && fp.Issuer == "" && fp.NotBefore == "" && fp.NotAfter == "" && fp.SHA256 == "" && len(fp.Versions) == 0 && len(fp.Ciphers) == 0 && len(fp.WeakCiphers) == 0 {
		return nil
	}
	return fp
}

func nilIfEmptySSH(fp *SSHFingerprint) *SSHFingerprint {
	if fp == nil {
		return nil
	}
	if len(fp.HostKeys) == 0 && len(fp.Algorithms) == 0 && len(fp.WeakAlgorithms) == 0 {
		return nil
	}
	return fp
}

func nilIfEmptyHTTP(fp *HTTPFingerprint) *HTTPFingerprint {
	if fp == nil {
		return nil
	}
	if fp.Title == "" && fp.Server == "" && len(fp.Methods) == 0 && len(fp.AuthSchemes) == 0 && len(fp.Paths) == 0 && len(fp.SecurityHeaders) == 0 && len(fp.Headers) == 0 {
		return nil
	}
	return fp
}

func nilIfEmptySMB(fp *SMBFingerprint) *SMBFingerprint {
	if fp == nil {
		return nil
	}
	if fp.OS == "" && fp.Workgroup == "" && len(fp.Protocols) == 0 && len(fp.Shares) == 0 {
		return nil
	}
	return fp
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
