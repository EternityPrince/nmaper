package snapshot

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
