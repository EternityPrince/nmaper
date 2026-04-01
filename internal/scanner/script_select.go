package scanner

import (
	"strings"

	"nmaper/internal/model"
	"nmaper/internal/parser"
)

func effectiveDetailScripts(ctx detailProfileContext) []string {
	if len(ctx.TCPPorts) == 0 && len(ctx.UDPPorts) == 0 {
		return nil
	}
	return effectiveRecommendedScripts(ctx)
}

func effectiveRecommendedScripts(ctx detailProfileContext) []string {
	return filterAvailableScripts(mergeScripts(recommendedScripts(ctx), targetedScripts(ctx)))
}

func recommendedScripts(ctx detailProfileContext) []string {
	seen := make(map[string]struct{})
	selected := make([]string, 0)
	for _, rule := range defaultScriptRules {
		if ctx.Level.Rank() < rule.MinLevel.Rank() {
			continue
		}
		if !rule.matches(ctx) {
			continue
		}
		for _, script := range rule.Scripts {
			if _, ok := seen[script]; ok {
				continue
			}
			seen[script] = struct{}{}
			selected = append(selected, script)
		}
	}
	return selected
}

func targetedScripts(ctx detailProfileContext) []string {
	seen := make(map[string]struct{})
	selected := make([]string, 0)
	for _, rule := range serviceAwareScriptRules {
		if ctx.Level.Rank() < rule.MinLevel.Rank() {
			continue
		}
		if !rule.matches(ctx) {
			continue
		}
		for _, script := range rule.Scripts {
			if _, ok := seen[script]; ok {
				continue
			}
			seen[script] = struct{}{}
			selected = append(selected, script)
		}
	}
	return selected
}

func (r scriptRule) matches(ctx detailProfileContext) bool {
	if len(r.TCPPorts) > 0 || len(r.UDPPorts) > 0 {
		tcpMatch := len(r.TCPPorts) > 0 && matchesAnyPort(r.TCPPorts, ctx.TCPPorts)
		udpMatch := len(r.UDPPorts) > 0 && matchesAnyPort(r.UDPPorts, ctx.UDPPorts)
		if !tcpMatch && !udpMatch {
			return false
		}
	}
	if len(r.HostnameContains) > 0 && !matchesAnyHostname(r.HostnameContains, ctx.Hostnames) {
		return false
	}
	if len(r.VendorContains) > 0 && !matchesSubstring(ctx.Vendor, r.VendorContains) {
		return false
	}
	if len(r.ServiceContains) > 0 {
		if len(ctx.Services) == 0 || !matchesAnyHint(ctx.Services, r.ServiceContains) {
			return false
		}
	}
	if len(r.ProductContains) > 0 {
		if len(ctx.Products) == 0 || !matchesAnyHint(ctx.Products, r.ProductContains) {
			return false
		}
	}
	return true
}

func mergeScripts(groups ...[]string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, group := range groups {
		for _, script := range group {
			if _, ok := seen[script]; ok {
				continue
			}
			seen[script] = struct{}{}
			out = append(out, script)
		}
	}
	return out
}

func matchesAnyPort(rulePorts, targetPorts []int) bool {
	available := make(map[int]struct{}, len(targetPorts))
	for _, port := range targetPorts {
		available[port] = struct{}{}
	}
	for _, port := range rulePorts {
		if _, ok := available[port]; ok {
			return true
		}
	}
	return false
}

func matchesAnyHostname(patterns, hostnames []string) bool {
	for _, hostname := range hostnames {
		if matchesSubstring(hostname, patterns) {
			return true
		}
	}
	return false
}

func matchesSubstring(value string, patterns []string) bool {
	normalized := strings.ToLower(value)
	for _, pattern := range patterns {
		if strings.Contains(normalized, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

func matchesAnyHint(values, patterns []string) bool {
	for _, value := range values {
		if matchesSubstring(value, patterns) {
			return true
		}
	}
	return false
}

func detailContextForHost(ip string, ports []int, host parser.Host, opts model.Options) detailProfileContext {
	_, vendor := host.MAC()
	return detailProfileContext{
		IP:        ip,
		Level:     opts.Level,
		TCPPorts:  ports,
		UDPPorts:  detailUDPPorts(opts),
		Hostnames: append([]string(nil), host.Hostnames...),
		Vendor:    vendor,
		Services:  openServiceNames(host),
		Products:  openServiceProducts(host),
	}
}

func openServiceNames(host parser.Host) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, port := range host.OpenPorts() {
		for _, value := range []string{port.Service.Name, port.Service.Tunnel, port.Service.ExtraInfo} {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			key := strings.ToLower(value)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, value)
		}
	}
	return out
}

func openServiceProducts(host parser.Host) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, port := range host.OpenPorts() {
		for _, value := range []string{port.Service.Product, port.Service.Version} {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			key := strings.ToLower(value)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, value)
		}
	}
	return out
}
