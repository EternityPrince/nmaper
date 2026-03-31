package parser

import (
	"sort"
)

type Run struct {
	Scanner string `json:"scanner"`
	Args    string `json:"args"`
	Version string `json:"version"`
	Start   int64  `json:"start_unix"`
	End     int64  `json:"end_unix"`
	Hosts   []Host `json:"hosts"`
}

type Host struct {
	Status    string         `json:"status"`
	Addresses []Address      `json:"addresses"`
	Hostnames []string       `json:"hostnames,omitempty"`
	Ports     []Port         `json:"ports,omitempty"`
	Scripts   []ScriptResult `json:"scripts,omitempty"`
	OSMatches []OSMatch      `json:"os_matches,omitempty"`
	Trace     *Trace         `json:"trace,omitempty"`
}

type Address struct {
	Type   string `json:"type"`
	Addr   string `json:"addr"`
	Vendor string `json:"vendor,omitempty"`
}

type Port struct {
	ID       int            `json:"id"`
	Protocol string         `json:"protocol"`
	State    string         `json:"state"`
	Service  Service        `json:"service"`
	Scripts  []ScriptResult `json:"scripts,omitempty"`
}

type Service struct {
	Name      string `json:"name,omitempty"`
	Product   string `json:"product,omitempty"`
	Version   string `json:"version,omitempty"`
	ExtraInfo string `json:"extra_info,omitempty"`
	Tunnel    string `json:"tunnel,omitempty"`
}

type ScriptResult struct {
	ID     string `json:"id"`
	Output string `json:"output,omitempty"`
}

type OSMatch struct {
	Name     string   `json:"name"`
	Accuracy int      `json:"accuracy"`
	Classes  []string `json:"classes,omitempty"`
}

type Trace struct {
	Proto string     `json:"proto,omitempty"`
	Port  int        `json:"port,omitempty"`
	Hops  []TraceHop `json:"hops,omitempty"`
}

type TraceHop struct {
	TTL  int     `json:"ttl"`
	IP   string  `json:"ip,omitempty"`
	RTT  float64 `json:"rtt,omitempty"`
	Host string  `json:"host,omitempty"`
}

func (h Host) PrimaryIP() string {
	var fallback string
	for _, address := range h.Addresses {
		switch address.Type {
		case "ipv4":
			return address.Addr
		case "ipv6":
			if fallback == "" {
				fallback = address.Addr
			}
		}
	}
	return fallback
}

func (h Host) MAC() (string, string) {
	for _, address := range h.Addresses {
		if address.Type == "mac" {
			return address.Addr, address.Vendor
		}
	}
	return "", ""
}

func (h Host) OpenPorts() []Port {
	ports := make([]Port, 0, len(h.Ports))
	for _, port := range h.Ports {
		if port.State == "open" {
			ports = append(ports, port)
		}
	}
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Protocol == ports[j].Protocol {
			return ports[i].ID < ports[j].ID
		}
		return ports[i].Protocol < ports[j].Protocol
	})
	return ports
}
