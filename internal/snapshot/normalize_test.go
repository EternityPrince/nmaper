package snapshot

import (
	"testing"
	"time"

	"nmaper/internal/parser"
)

func TestAnalyzeServiceBuildsProfiles(t *testing.T) {
	t.Parallel()

	port := parser.Port{
		ID:       443,
		Protocol: "tcp",
		State:    "open",
		Service:  parser.Service{Name: "https", Product: "nginx", Version: "1.26"},
		Scripts: []parser.ScriptResult{
			{ID: "ssl-cert", Output: "Subject: CN=router.local\nIssuer: CN=Acme Root\nNot valid before: 2026-01-01\nNot valid after: 2027-01-01\nSHA256: AA:BB:CC:DD"},
			{ID: "ssl-enum-ciphers", Output: "TLSv1.2:\n  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\n  TLS_RSA_WITH_3DES_EDE_CBC_SHA\nTLSv1.3:\n  TLS_AES_128_GCM_SHA256"},
			{ID: "http-title", Output: "Router Admin Console"},
			{ID: "http-headers", Output: "Server: nginx\nStrict-Transport-Security: max-age=63072000"},
			{ID: "http-methods", Output: "Supported Methods: GET HEAD POST OPTIONS"},
			{ID: "http-auth", Output: "Basic realm=admin"},
			{ID: "http-enum", Output: "/admin\n/login"},
			{ID: "ssl-heartbleed", Output: "VULNERABLE: The Heartbleed Bug is present"},
		},
	}

	profile := AnalyzeService(port)
	if profile.TLS == nil || profile.TLS.Subject != "CN=router.local" {
		t.Fatalf("expected TLS fingerprint, got %#v", profile.TLS)
	}
	if len(profile.TLS.WeakCiphers) == 0 {
		t.Fatalf("expected weak TLS cipher detection, got %#v", profile.TLS)
	}
	if profile.HTTP == nil || profile.HTTP.Title != "Router Admin Console" || len(profile.HTTP.Methods) == 0 {
		t.Fatalf("expected HTTP fingerprint, got %#v", profile.HTTP)
	}
	if len(profile.Vulnerabilities) < 2 {
		t.Fatalf("expected vulnerability findings, got %#v", profile.Vulnerabilities)
	}
	if len(profile.Management) != 1 || profile.Management[0].Category != "http-admin" {
		t.Fatalf("expected admin management surface, got %#v", profile.Management)
	}
}

func TestAnalyzeServiceParsesSMBandSSH(t *testing.T) {
	t.Parallel()

	ssh := AnalyzeService(parser.Port{
		ID:       22,
		Protocol: "tcp",
		State:    "open",
		Service:  parser.Service{Name: "ssh"},
		Scripts: []parser.ScriptResult{
			{ID: "ssh-hostkey", Output: "2048 aa:bb:ssh rsa"},
			{ID: "ssh2-enum-algos", Output: "diffie-hellman-group1-sha1\naes128-ctr\nssh-dss"},
		},
	})
	if ssh.SSH == nil || len(ssh.SSH.HostKeys) != 1 || len(ssh.SSH.WeakAlgorithms) == 0 {
		t.Fatalf("expected SSH fingerprint, got %#v", ssh.SSH)
	}

	smb := AnalyzeService(parser.Port{
		ID:       445,
		Protocol: "tcp",
		State:    "open",
		Service:  parser.Service{Name: "microsoft-ds"},
		Scripts: []parser.ScriptResult{
			{ID: "smb-os-discovery", Output: "OS: Windows 11 Pro\nWorkgroup: WORKGROUP"},
			{ID: "smb-protocols", Output: "SMBv1 enabled\nSMBv3 enabled"},
			{ID: "smb-enum-shares", Output: "ADMIN$ - Remote Admin\nIPC$ - Remote IPC\nUsers - Shared Users"},
		},
	})
	if smb.SMB == nil || smb.SMB.OS != "Windows 11 Pro" || len(smb.SMB.Shares) == 0 {
		t.Fatalf("expected SMB fingerprint, got %#v", smb.SMB)
	}
	if len(smb.Vulnerabilities) == 0 {
		t.Fatalf("expected SMBv1 vulnerability signal, got %#v", smb.Vulnerabilities)
	}
}

func TestAnalyzeServiceAddsRichTLSSecurityFindings(t *testing.T) {
	t.Parallel()

	port := parser.Port{
		ID:       8443,
		Protocol: "tcp",
		State:    "open",
		Service:  parser.Service{Name: "https", Tunnel: "ssl"},
		Scripts: []parser.ScriptResult{
			{
				ID: "ssl-cert",
				Output: "Subject: CN=router.local\n" +
					"Issuer: CN=router.local\n" +
					"Not valid after: " + time.Now().Add(10*24*time.Hour).UTC().Format("2006-01-02") + "\n" +
					"SHA256: AA:BB:CC:DD",
			},
			{ID: "ssl-enum-ciphers", Output: "TLSv1.0:\n  TLS_RSA_WITH_3DES_EDE_CBC_SHA\nTLSv1.1:\n  TLS_RSA_WITH_AES_128_CBC_SHA"},
		},
	}

	profile := AnalyzeService(port)
	for _, identifier := range []string{
		"tls-self-signed",
		"tls-certificate-expiring-soon",
		"tls-missing-san",
		"tls-outdated-protocol-only",
		"management-ui-outdated-tls-only",
	} {
		if !hasFindingIdentifier(profile.Vulnerabilities, identifier) {
			t.Fatalf("expected finding %q, got %#v", identifier, profile.Vulnerabilities)
		}
	}
}

func TestAnalyzeServiceAddsRichHTTPSecurityFindings(t *testing.T) {
	t.Parallel()

	port := parser.Port{
		ID:       80,
		Protocol: "tcp",
		State:    "open",
		Service:  parser.Service{Name: "http"},
		Scripts: []parser.ScriptResult{
			{ID: "http-title", Output: "TP-Link Admin Login"},
			{ID: "http-headers", Output: "Server: lighttpd\nWWW-Authenticate: Basic realm=router"},
			{ID: "http-methods", Output: "Supported Methods: GET HEAD POST PUT DELETE TRACE"},
			{ID: "http-auth", Output: "Basic realm=router"},
			{ID: "http-enum", Output: "/admin\n/login\n/images\nIndex of /backup"},
		},
	}

	profile := AnalyzeService(port)
	for _, identifier := range []string{
		"missing-core-security-headers",
		"dangerous-http-methods",
		"exposed-admin-paths",
		"directory-listing-hints",
		"default-vendor-panel-heuristic",
		"http-no-https-redirect",
		"www-authenticate-without-tls",
	} {
		if !hasFindingIdentifier(profile.Vulnerabilities, identifier) {
			t.Fatalf("expected finding %q, got %#v", identifier, profile.Vulnerabilities)
		}
	}
}

func hasFindingIdentifier(findings []VulnerabilityFinding, identifier string) bool {
	for _, finding := range findings {
		if finding.Identifier == identifier {
			return true
		}
	}
	return false
}
