package snapshot

import "strings"

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
