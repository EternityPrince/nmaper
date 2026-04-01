package history

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"

	"nmaper/internal/fuzzy"
)

func (s *Service) Posture(ctx context.Context, vendor, network string) (PostureSummary, error) {
	report := PostureSummary{
		VendorFilter:  vendor,
		NetworkFilter: strings.TrimSpace(network),
	}

	networkMatcher, err := compileNetworkMatcher(network)
	if err != nil {
		return PostureSummary{}, err
	}

	sessions, err := s.ListSessions(ctx, 0, "completed", "")
	if err != nil {
		return PostureSummary{}, err
	}
	if len(sessions) == 0 {
		return report, nil
	}
	report.SessionsAnalyzedForDrift = len(sessions)

	latestSummary, latestHosts, err := s.loadSnapshot(ctx, sessions[0].ID)
	if err != nil {
		return PostureSummary{}, err
	}
	report.SessionID = latestSummary.ID
	report.SessionStartedAt = &latestSummary.StartedAt

	latestHosts = filterHostsByScope(latestHosts, vendor, networkMatcher)
	report.ScopeHosts = len(latestHosts)
	for _, host := range latestHosts {
		if hostHasManagementExposure(host) {
			report.ManagementExposureHosts++
		}
		if hostHasWeakTLS(host) {
			report.WeakTLSHosts++
		}
		if hostHasVulnerabilityIdentifier(host, "management-ui-outdated-tls-only") {
			report.ManagementOutdatedTLSOnlyHosts++
		}
		if hostHasWeakSSH(host) {
			report.WeakSSHHosts++
		}
		if hostHasLegacySMB(host) {
			report.LegacySMBHosts++
		}
		if hostHasWebWithoutSecurityHeaders(host) {
			report.WebWithoutSecurityHeadersHosts++
		}
		if hostHasVulnerabilityIdentifier(host, "missing-core-security-headers") {
			report.MissingCoreSecurityHeadersHosts++
		}
		if hostHasAuthSurface(host) {
			report.AuthSurfaceHosts++
		}
	}

	if len(sessions) < 2 || len(latestHosts) == 0 {
		return report, nil
	}

	currentKeys := make(map[string]struct{}, len(latestHosts))
	for _, host := range latestHosts {
		currentKeys[postureIdentityKey(host, host)] = struct{}{}
	}

	var snapshots [][]HostSnapshot
	for _, session := range sessions {
		_, hosts, err := s.loadSnapshot(ctx, session.ID)
		if err != nil {
			return PostureSummary{}, err
		}
		snapshots = append(snapshots, filterHostsByScope(hosts, vendor, networkMatcher))
	}

	driftKeys := make(map[string]struct{})
	for i := len(snapshots) - 1; i > 0; i-- {
		pairs, _, _ := matchHosts(snapshots[i], snapshots[i-1])
		for _, pair := range pairs {
			if pair.left.PrimaryIP != pair.right.PrimaryIP || !slices.Equal(openPortStrings(pair.left), openPortStrings(pair.right)) {
				driftKeys[postureIdentityKey(pair.left, pair.right)] = struct{}{}
			}
		}
	}
	for key := range driftKeys {
		if _, ok := currentKeys[key]; ok {
			report.UnstableIdentityOrPortDriftHosts++
		}
	}

	return report, nil
}

func compileNetworkMatcher(raw string) (func(string) bool, error) {
	filter := strings.TrimSpace(raw)
	if filter == "" {
		return func(string) bool { return true }, nil
	}
	if ip := net.ParseIP(filter); ip != nil {
		return func(candidate string) bool {
			return net.ParseIP(strings.TrimSpace(candidate)).Equal(ip)
		}, nil
	}
	_, network, err := net.ParseCIDR(filter)
	if err != nil {
		return nil, fmt.Errorf("--network expects CIDR or IP, got %q", raw)
	}
	return func(candidate string) bool {
		ip := net.ParseIP(strings.TrimSpace(candidate))
		return ip != nil && network.Contains(ip)
	}, nil
}

func filterHostsByScope(hosts []HostSnapshot, vendor string, networkMatcher func(string) bool) []HostSnapshot {
	filtered := make([]HostSnapshot, 0, len(hosts))
	for _, host := range hosts {
		if vendor != "" && !fuzzy.Match(host.Vendor, vendor) {
			continue
		}
		if !networkMatcher(host.PrimaryIP) {
			continue
		}
		filtered = append(filtered, host)
	}
	return filtered
}

func hostHasManagementExposure(host HostSnapshot) bool {
	if len(host.Management) > 0 {
		return true
	}
	for _, service := range host.Services {
		if len(service.Management) > 0 {
			return true
		}
	}
	return false
}

func hostHasWeakTLS(host HostSnapshot) bool {
	for _, service := range host.Services {
		if service.TLS != nil && len(service.TLS.WeakCiphers) > 0 {
			return true
		}
	}
	return false
}

func hostHasWeakSSH(host HostSnapshot) bool {
	for _, service := range host.Services {
		if service.SSH != nil && len(service.SSH.WeakAlgorithms) > 0 {
			return true
		}
	}
	return false
}

func hostHasLegacySMB(host HostSnapshot) bool {
	for _, service := range host.Services {
		if service.SMB == nil {
			continue
		}
		for _, protocol := range service.SMB.Protocols {
			normalized := strings.ToLower(strings.TrimSpace(protocol))
			if strings.Contains(normalized, "smbv1") || strings.Contains(normalized, "smb 1.0") || strings.Contains(normalized, "nt lm 0.12") {
				return true
			}
		}
	}
	return false
}

func hostHasWebWithoutSecurityHeaders(host HostSnapshot) bool {
	for _, service := range host.Services {
		if service.HTTP == nil {
			continue
		}
		if len(service.HTTP.SecurityHeaders) == 0 {
			return true
		}
	}
	return false
}

func hostHasAuthSurface(host HostSnapshot) bool {
	for _, service := range host.Services {
		if service.HTTP != nil && len(service.HTTP.AuthSchemes) > 0 {
			return true
		}
		switch service.Port {
		case 22, 23, 139, 445, 3389, 5900, 5985, 5986:
			if service.State == "open" {
				return true
			}
		}
	}
	return false
}

func hostHasVulnerabilityIdentifier(host HostSnapshot, identifier string) bool {
	for _, finding := range host.Vulnerabilities {
		if strings.EqualFold(strings.TrimSpace(finding.Identifier), identifier) {
			return true
		}
	}
	for _, service := range host.Services {
		for _, finding := range service.Vulnerabilities {
			if strings.EqualFold(strings.TrimSpace(finding.Identifier), identifier) {
				return true
			}
		}
	}
	return false
}

func postureIdentityKey(left, right HostSnapshot) string {
	if mac := normalizedMAC(firstNonEmpty(left.MAC, right.MAC)); mac != "" {
		return "mac:" + mac
	}
	if right.PrimaryIP != "" {
		return "ip:" + right.PrimaryIP
	}
	return "ip:" + left.PrimaryIP
}
