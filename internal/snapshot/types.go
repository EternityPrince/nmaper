package snapshot

type TLSFingerprint struct {
	Subject     string   `json:"subject,omitempty"`
	Issuer      string   `json:"issuer,omitempty"`
	NotBefore   string   `json:"not_before,omitempty"`
	NotAfter    string   `json:"not_after,omitempty"`
	SHA256      string   `json:"sha256,omitempty"`
	Versions    []string `json:"versions,omitempty"`
	Ciphers     []string `json:"ciphers,omitempty"`
	WeakCiphers []string `json:"weak_ciphers,omitempty"`
}

type SSHFingerprint struct {
	HostKeys       []string `json:"host_keys,omitempty"`
	Algorithms     []string `json:"algorithms,omitempty"`
	WeakAlgorithms []string `json:"weak_algorithms,omitempty"`
}

type HTTPFingerprint struct {
	Title           string   `json:"title,omitempty"`
	Server          string   `json:"server,omitempty"`
	Methods         []string `json:"methods,omitempty"`
	AuthSchemes     []string `json:"auth_schemes,omitempty"`
	Paths           []string `json:"paths,omitempty"`
	SecurityHeaders []string `json:"security_headers,omitempty"`
	Headers         []string `json:"headers,omitempty"`
}

type SMBFingerprint struct {
	OS        string   `json:"os,omitempty"`
	Workgroup string   `json:"workgroup,omitempty"`
	Protocols []string `json:"protocols,omitempty"`
	Shares    []string `json:"shares,omitempty"`
}

type VulnerabilityFinding struct {
	ScriptID   string `json:"script_id"`
	Identifier string `json:"identifier,omitempty"`
	Title      string `json:"title,omitempty"`
	Severity   string `json:"severity,omitempty"`
	State      string `json:"state,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
}

type ManagementSurface struct {
	Category string `json:"category"`
	Label    string `json:"label,omitempty"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Exposure string `json:"exposure,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

type HostProfile struct {
	Vulnerabilities []VulnerabilityFinding `json:"vulnerabilities,omitempty"`
	Management      []ManagementSurface    `json:"management,omitempty"`
}

type ServiceProfile struct {
	TLS             *TLSFingerprint        `json:"tls,omitempty"`
	SSH             *SSHFingerprint        `json:"ssh,omitempty"`
	HTTP            *HTTPFingerprint       `json:"http,omitempty"`
	SMB             *SMBFingerprint        `json:"smb,omitempty"`
	Vulnerabilities []VulnerabilityFinding `json:"vulnerabilities,omitempty"`
	Management      []ManagementSurface    `json:"management,omitempty"`
}
