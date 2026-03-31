package history

import "time"

type SessionSummary struct {
	ID              int64      `json:"id"`
	Name            string     `json:"name,omitempty"`
	Status          string     `json:"status"`
	StartedAt       time.Time  `json:"started_at"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
	Duration        string     `json:"duration"`
	Target          string     `json:"target"`
	DiscoveredHosts int        `json:"discovered_hosts"`
	LiveHosts       int        `json:"live_hosts"`
	NmapVersion     string     `json:"nmap_version,omitempty"`
}

type ScriptResult struct {
	ID     string `json:"id"`
	Output string `json:"output,omitempty"`
}

type ServiceSnapshot struct {
	Port      int            `json:"port"`
	Protocol  string         `json:"protocol"`
	State     string         `json:"state"`
	Name      string         `json:"name,omitempty"`
	Product   string         `json:"product,omitempty"`
	Version   string         `json:"version,omitempty"`
	ExtraInfo string         `json:"extra_info,omitempty"`
	Tunnel    string         `json:"tunnel,omitempty"`
	Scripts   []ScriptResult `json:"scripts,omitempty"`
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
	PrimaryIP string            `json:"primary_ip"`
	Status    string            `json:"status"`
	MAC       string            `json:"mac,omitempty"`
	Vendor    string            `json:"vendor,omitempty"`
	Hostnames []string          `json:"hostnames,omitempty"`
	TopOS     []string          `json:"top_os,omitempty"`
	Scripts   []ScriptResult    `json:"scripts,omitempty"`
	Services  []ServiceSnapshot `json:"services,omitempty"`
	Trace     *TraceSnapshot    `json:"trace,omitempty"`
}

type SessionReport struct {
	Session SessionSummary `json:"session"`
	Hosts   []HostSnapshot `json:"hosts"`
}

type HostDiffSnapshot struct {
	IP        string   `json:"ip"`
	Status    string   `json:"status,omitempty"`
	OpenPorts []string `json:"open_ports,omitempty"`
	TopOS     string   `json:"top_os,omitempty"`
	Vendor    string   `json:"vendor,omitempty"`
}

type ChangedHost struct {
	IP      string           `json:"ip"`
	Before  HostDiffSnapshot `json:"before"`
	After   HostDiffSnapshot `json:"after"`
	Reasons []string         `json:"reasons"`
}

type DiffReport struct {
	From         SessionSummary     `json:"from"`
	To           SessionSummary     `json:"to"`
	NewHosts     []HostDiffSnapshot `json:"new_hosts"`
	MissingHosts []HostDiffSnapshot `json:"missing_hosts"`
	ChangedHosts []ChangedHost      `json:"changed_hosts"`
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
}

type TimelineReport struct {
	Entries []TimelineEntry `json:"entries"`
}
