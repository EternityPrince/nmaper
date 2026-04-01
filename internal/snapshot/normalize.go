package snapshot

import (
	"regexp"
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
	var sslCertOutputs []string
	var httpHeaderOutputs []string
	var httpEnumOutputs []string
	for _, script := range port.Scripts {
		switch script.ID {
		case "ssl-cert":
			profile.TLS = mergeTLS(profile.TLS, parseSSLCert(script.Output))
			sslCertOutputs = append(sslCertOutputs, script.Output)
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
			httpHeaderOutputs = append(httpHeaderOutputs, script.Output)
		case "http-methods":
			profile.HTTP = mergeHTTP(profile.HTTP, parseHTTPMethods(script.Output))
		case "http-auth":
			profile.HTTP = mergeHTTP(profile.HTTP, parseHTTPAuth(script.Output))
		case "http-security-headers":
			profile.HTTP = mergeHTTP(profile.HTTP, parseHTTPSecurityHeaders(script.Output))
		case "http-enum":
			profile.HTTP = mergeHTTP(profile.HTTP, parseHTTPPaths(script.Output))
			httpEnumOutputs = append(httpEnumOutputs, script.Output)
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

	enrichTLSSecurityFindings(&profile, port, sslCertOutputs)
	enrichHTTPSecurityFindings(&profile, port, httpHeaderOutputs, httpEnumOutputs)

	profile.Management = deriveManagement(port, profile)
	profile.Vulnerabilities = uniqueFindings(profile.Vulnerabilities)
	profile.Management = uniqueManagement(profile.Management)
	return profile
}
