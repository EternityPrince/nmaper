package parser

import (
	"encoding/xml"
	"strconv"
	"strings"
)

type xmlRun struct {
	Scanner  string      `xml:"scanner,attr"`
	Args     string      `xml:"args,attr"`
	Version  string      `xml:"version,attr"`
	Start    string      `xml:"start,attr"`
	Hosts    []xmlHost   `xml:"host"`
	RunStats xmlRunStats `xml:"runstats"`
}

type xmlRunStats struct {
	Finished xmlFinished `xml:"finished"`
}

type xmlFinished struct {
	Time string `xml:"time,attr"`
}

type xmlHost struct {
	Status    xmlStatus    `xml:"status"`
	Addresses []xmlAddress `xml:"address"`
	Hostnames xmlHostnames `xml:"hostnames"`
	Ports     xmlPorts     `xml:"ports"`
	Scripts   []xmlScript  `xml:"hostscript>script"`
	OS        xmlOS        `xml:"os"`
	Trace     *xmlTrace    `xml:"trace"`
}

type xmlStatus struct {
	State string `xml:"state,attr"`
}

type xmlAddress struct {
	Type   string `xml:"addrtype,attr"`
	Addr   string `xml:"addr,attr"`
	Vendor string `xml:"vendor,attr"`
}

type xmlHostnames struct {
	Items []xmlHostname `xml:"hostname"`
}

type xmlHostname struct {
	Name string `xml:"name,attr"`
}

type xmlPorts struct {
	Items []xmlPort `xml:"port"`
}

type xmlPort struct {
	Protocol string       `xml:"protocol,attr"`
	PortID   int          `xml:"portid,attr"`
	State    xmlPortState `xml:"state"`
	Service  *xmlService  `xml:"service"`
	Scripts  []xmlScript  `xml:"script"`
}

type xmlPortState struct {
	State string `xml:"state,attr"`
}

type xmlService struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
	Tunnel    string `xml:"tunnel,attr"`
}

type xmlScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
	Inner  string `xml:",innerxml"`
}

type xmlOS struct {
	Matches []xmlOSMatch `xml:"osmatch"`
}

type xmlOSMatch struct {
	Name     string       `xml:"name,attr"`
	Accuracy string       `xml:"accuracy,attr"`
	Classes  []xmlOSClass `xml:"osclass"`
}

type xmlOSClass struct {
	Type   string `xml:"type,attr"`
	Vendor string `xml:"vendor,attr"`
	Family string `xml:"osfamily,attr"`
	Gen    string `xml:"osgen,attr"`
}

type xmlTrace struct {
	Proto string   `xml:"proto,attr"`
	Port  int      `xml:"port,attr"`
	Hops  []xmlHop `xml:"hop"`
}

type xmlHop struct {
	TTL  int    `xml:"ttl,attr"`
	IP   string `xml:"ipaddr,attr"`
	RTT  string `xml:"rtt,attr"`
	Host string `xml:"host,attr"`
}

func Parse(data []byte) (Run, error) {
	var raw xmlRun
	if err := xml.Unmarshal(data, &raw); err != nil {
		return Run{}, err
	}

	run := Run{
		Scanner: raw.Scanner,
		Args:    raw.Args,
		Version: raw.Version,
		Start:   parseUnix(raw.Start),
		End:     parseUnix(raw.RunStats.Finished.Time),
		Hosts:   make([]Host, 0, len(raw.Hosts)),
	}

	for _, host := range raw.Hosts {
		parsedHost := Host{
			Status:    host.Status.State,
			Addresses: make([]Address, 0, len(host.Addresses)),
			Hostnames: make([]string, 0, len(host.Hostnames.Items)),
			Ports:     make([]Port, 0, len(host.Ports.Items)),
			Scripts:   make([]ScriptResult, 0, len(host.Scripts)),
			OSMatches: make([]OSMatch, 0, len(host.OS.Matches)),
		}

		for _, address := range host.Addresses {
			parsedHost.Addresses = append(parsedHost.Addresses, Address{
				Type:   address.Type,
				Addr:   address.Addr,
				Vendor: address.Vendor,
			})
		}
		for _, hostname := range host.Hostnames.Items {
			if hostname.Name != "" {
				parsedHost.Hostnames = append(parsedHost.Hostnames, hostname.Name)
			}
		}
		for _, script := range host.Scripts {
			parsedHost.Scripts = append(parsedHost.Scripts, ScriptResult{
				ID:     script.ID,
				Output: script.Output,
				RawXML: strings.TrimSpace(script.Inner),
			})
		}
		for _, match := range host.OS.Matches {
			parsedHost.OSMatches = append(parsedHost.OSMatches, OSMatch{
				Name:     match.Name,
				Accuracy: int(parseUnix(match.Accuracy)),
				Classes:  collectClasses(match.Classes),
			})
		}
		for _, port := range host.Ports.Items {
			parsedPort := Port{
				ID:       port.PortID,
				Protocol: port.Protocol,
				State:    port.State.State,
			}
			if port.Service != nil {
				parsedPort.Service = Service{
					Name:      port.Service.Name,
					Product:   port.Service.Product,
					Version:   port.Service.Version,
					ExtraInfo: port.Service.ExtraInfo,
					Tunnel:    port.Service.Tunnel,
				}
			}
			for _, script := range port.Scripts {
				parsedPort.Scripts = append(parsedPort.Scripts, ScriptResult{
					ID:     script.ID,
					Output: script.Output,
					RawXML: strings.TrimSpace(script.Inner),
				})
			}
			parsedHost.Ports = append(parsedHost.Ports, parsedPort)
		}
		if host.Trace != nil {
			trace := &Trace{
				Proto: host.Trace.Proto,
				Port:  host.Trace.Port,
				Hops:  make([]TraceHop, 0, len(host.Trace.Hops)),
			}
			for _, hop := range host.Trace.Hops {
				trace.Hops = append(trace.Hops, TraceHop{
					TTL:  hop.TTL,
					IP:   hop.IP,
					RTT:  parseFloat(hop.RTT),
					Host: hop.Host,
				})
			}
			parsedHost.Trace = trace
		}
		run.Hosts = append(run.Hosts, parsedHost)
	}

	return run, nil
}

func parseUnix(value string) int64 {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func parseFloat(value string) float64 {
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func collectClasses(classes []xmlOSClass) []string {
	out := make([]string, 0, len(classes))
	for _, class := range classes {
		var label string
		switch {
		case class.Vendor != "" && class.Family != "":
			label = class.Vendor + " " + class.Family
		case class.Family != "":
			label = class.Family
		case class.Type != "":
			label = class.Type
		}
		if class.Gen != "" {
			if label != "" {
				label += " " + class.Gen
			} else {
				label = class.Gen
			}
		}
		if label != "" {
			out = append(out, label)
		}
	}
	return out
}
