package history

import (
	"time"

	"nmaper/internal/snapshot"
)

type SessionSummary struct {
	ID                int64      `json:"id"`
	Name              string     `json:"name,omitempty"`
	Status            string     `json:"status"`
	StartedAt         time.Time  `json:"started_at"`
	CompletedAt       *time.Time `json:"completed_at,omitempty"`
	Duration          string     `json:"duration"`
	Target            string     `json:"target"`
	DiscoveredHosts   int        `json:"discovered_hosts"`
	LiveHosts         int        `json:"live_hosts"`
	NmapVersion       string     `json:"nmap_version,omitempty"`
	ScanLevel         string     `json:"scan_level,omitempty"`
	ScannerInterface  string     `json:"scanner_interface,omitempty"`
	ScannerRealMAC    string     `json:"scanner_real_mac,omitempty"`
	ScannerSpoofedMAC string     `json:"scanner_spoofed_mac,omitempty"`
}

type ScriptResult struct {
	ID     string `json:"id"`
	Output string `json:"output,omitempty"`
}

type ServiceSnapshot struct {
	Port            int                             `json:"port"`
	Protocol        string                          `json:"protocol"`
	State           string                          `json:"state"`
	Name            string                          `json:"name,omitempty"`
	Product         string                          `json:"product,omitempty"`
	Version         string                          `json:"version,omitempty"`
	ExtraInfo       string                          `json:"extra_info,omitempty"`
	Tunnel          string                          `json:"tunnel,omitempty"`
	Scripts         []ScriptResult                  `json:"scripts,omitempty"`
	TLS             *snapshot.TLSFingerprint        `json:"tls,omitempty"`
	SSH             *snapshot.SSHFingerprint        `json:"ssh,omitempty"`
	HTTP            *snapshot.HTTPFingerprint       `json:"http,omitempty"`
	SMB             *snapshot.SMBFingerprint        `json:"smb,omitempty"`
	Vulnerabilities []snapshot.VulnerabilityFinding `json:"vulnerabilities,omitempty"`
	Management      []snapshot.ManagementSurface    `json:"management,omitempty"`
}

type TraceHop struct {
	TTL  int     `json:"ttl"`
	IP   string  `json:"ip,omitempty"`
	RTT  float64 `json:"rtt,omitempty"`
	Host string  `json:"host,omitempty"`
}

type TraceSnapshot struct {
	Proto string     `json:"proto,omitempty"`
	Port  int        `json:"port,omitempty"`
	Hops  []TraceHop `json:"hops,omitempty"`
}

type HostSnapshot struct {
	PrimaryIP         string                          `json:"primary_ip"`
	Status            string                          `json:"status"`
	MAC               string                          `json:"mac,omitempty"`
	Vendor            string                          `json:"vendor,omitempty"`
	Hostnames         []string                        `json:"hostnames,omitempty"`
	TopOS             []string                        `json:"top_os,omitempty"`
	NSEHits           int                             `json:"nse_hits"`
	HostScriptHits    int                             `json:"host_script_hits"`
	ServiceScriptHits int                             `json:"service_script_hits"`
	Scripts           []ScriptResult                  `json:"scripts,omitempty"`
	Services          []ServiceSnapshot               `json:"services,omitempty"`
	Vulnerabilities   []snapshot.VulnerabilityFinding `json:"vulnerabilities,omitempty"`
	Management        []snapshot.ManagementSurface    `json:"management,omitempty"`
	Trace             *TraceSnapshot                  `json:"trace,omitempty"`
}

type SessionReport struct {
	Session SessionSummary `json:"session"`
	Hosts   []HostSnapshot `json:"hosts"`
}

type HostDiffSnapshot struct {
	IP        string   `json:"ip"`
	Status    string   `json:"status,omitempty"`
	MAC       string   `json:"mac,omitempty"`
	Vendor    string   `json:"vendor,omitempty"`
	Hostnames []string `json:"hostnames,omitempty"`
	OpenPorts []string `json:"open_ports,omitempty"`
	Services  []string `json:"services,omitempty"`
	TopOS     string   `json:"top_os,omitempty"`
}

type ServiceDelta struct {
	Port   string `json:"port"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

type ScriptDelta struct {
	Scope  string `json:"scope"`
	ID     string `json:"id"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

type DiffSummary struct {
	NewHosts             int `json:"new_hosts"`
	MissingHosts         int `json:"missing_hosts"`
	ChangedHosts         int `json:"changed_hosts"`
	MovedHosts           int `json:"moved_hosts"`
	OpenedPorts          int `json:"opened_ports"`
	ClosedPorts          int `json:"closed_ports"`
	ServiceChanges       int `json:"service_changes"`
	ScriptChanges        int `json:"script_changes"`
	FingerprintChanges   int `json:"fingerprint_changes"`
	VulnerabilityChanges int `json:"vulnerability_changes"`
	ManagementChanges    int `json:"management_changes"`
	TraceChanges         int `json:"trace_changes"`
	HighSignalAlerts     int `json:"high_signal_alerts"`
}

type DiffAlert struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Host     string `json:"host"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
}

type ChangedHost struct {
	IP                      string                          `json:"ip"`
	MatchBy                 string                          `json:"match_by,omitempty"`
	Before                  HostDiffSnapshot                `json:"before"`
	After                   HostDiffSnapshot                `json:"after"`
	Reasons                 []string                        `json:"reasons"`
	OpenedPorts             []string                        `json:"opened_ports,omitempty"`
	ClosedPorts             []string                        `json:"closed_ports,omitempty"`
	HostnamesAdded          []string                        `json:"hostnames_added,omitempty"`
	HostnamesRemoved        []string                        `json:"hostnames_removed,omitempty"`
	ServiceChanges          []ServiceDelta                  `json:"service_changes,omitempty"`
	ScriptChanges           []ScriptDelta                   `json:"script_changes,omitempty"`
	FingerprintChanges      []string                        `json:"fingerprint_changes,omitempty"`
	NewVulnerabilities      []snapshot.VulnerabilityFinding `json:"new_vulnerabilities,omitempty"`
	ResolvedVulnerabilities []snapshot.VulnerabilityFinding `json:"resolved_vulnerabilities,omitempty"`
	ManagementAdded         []snapshot.ManagementSurface    `json:"management_added,omitempty"`
	ManagementRemoved       []snapshot.ManagementSurface    `json:"management_removed,omitempty"`
	TraceChanged            bool                            `json:"trace_changed,omitempty"`
}

type DiffReport struct {
	From         SessionSummary     `json:"from"`
	To           SessionSummary     `json:"to"`
	NewHosts     []HostDiffSnapshot `json:"new_hosts"`
	MissingHosts []HostDiffSnapshot `json:"missing_hosts"`
	ChangedHosts []ChangedHost      `json:"changed_hosts"`
	Summary      DiffSummary        `json:"summary"`
	Alerts       []DiffAlert        `json:"alerts,omitempty"`
}

type RecurringHost struct {
	IP          string `json:"ip"`
	Appearances int    `json:"appearances"`
}

type PortFrequency struct {
	Port  string `json:"port"`
	Count int    `json:"count"`
}

type GlobalDynamicsReport struct {
	Sessions     []SessionSummary `json:"sessions"`
	SessionCount int              `json:"session_count"`
	UniqueHosts  int              `json:"unique_hosts"`
	StableHosts  []string         `json:"stable_hosts"`
	Transient    []string         `json:"transient_hosts"`
	Recurring    []RecurringHost  `json:"recurring_hosts"`
	Volatile     []string         `json:"volatile_hosts"`
	TopPorts     []PortFrequency  `json:"top_ports"`
	LastMovement string           `json:"last_movement,omitempty"`
}

type DeviceStat struct {
	DeviceID    int64    `json:"device_id"`
	Label       string   `json:"label"`
	MAC         string   `json:"mac,omitempty"`
	Vendor      string   `json:"vendor,omitempty"`
	Appearances int      `json:"appearances"`
	IPs         []string `json:"ips,omitempty"`
}

type VendorStat struct {
	Vendor string `json:"vendor"`
	Count  int    `json:"count"`
}

type DeviceAnalyticsReport struct {
	UniqueDevices int          `json:"unique_devices"`
	MACBacked     int          `json:"mac_backed"`
	IPOnly        int          `json:"ip_only"`
	TopDevices    []DeviceStat `json:"top_devices"`
	TopVendors    []VendorStat `json:"top_vendors"`
	MultiIP       []DeviceStat `json:"multi_ip_devices"`
}

type DeviceAppearance struct {
	Session   SessionSummary `json:"session"`
	IP        string         `json:"ip"`
	Status    string         `json:"status,omitempty"`
	OpenPorts []string       `json:"open_ports,omitempty"`
	TopOS     string         `json:"top_os,omitempty"`
}

type DeviceHistory struct {
	DeviceID    int64              `json:"device_id"`
	Label       string             `json:"label"`
	MAC         string             `json:"mac,omitempty"`
	Vendor      string             `json:"vendor,omitempty"`
	IPs         []string           `json:"ips,omitempty"`
	Appearances []DeviceAppearance `json:"appearances"`
}

type DeviceHistoryReport struct {
	Query   string          `json:"query"`
	Devices []DeviceHistory `json:"devices"`
}

type TimelineEntry struct {
	From         SessionSummary     `json:"from"`
	To           SessionSummary     `json:"to"`
	NewHosts     []HostDiffSnapshot `json:"new_hosts"`
	MissingHosts []HostDiffSnapshot `json:"missing_hosts"`
	ChangedHosts []ChangedHost      `json:"changed_hosts"`
	Summary      DiffSummary        `json:"summary"`
	Alerts       []DiffAlert        `json:"alerts,omitempty"`
}

type TimelineReport struct {
	Entries []TimelineEntry `json:"entries"`
}
