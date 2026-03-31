package converter

import (
	"sort"
	"strings"

	"nmaper/internal/parser"
)

type DetailTarget struct {
	IP    string
	Ports []int
}

func DiscoveryToDetailTargets(run parser.Run) []DetailTarget {
	targets := make([]DetailTarget, 0)
	for _, host := range run.Hosts {
		ip := host.PrimaryIP()
		if ip == "" {
			continue
		}
		status := strings.ToLower(strings.TrimSpace(host.Status))
		ports := make([]int, 0)
		for _, port := range host.OpenPorts() {
			if port.Protocol != "tcp" {
				continue
			}
			ports = append(ports, port.ID)
		}
		if len(ports) == 0 && status != "up" {
			continue
		}
		targets = append(targets, DetailTarget{IP: ip, Ports: ports})
	}

	sort.Slice(targets, func(i, j int) bool {
		return targets[i].IP < targets[j].IP
	})
	return targets
}
