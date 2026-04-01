package history

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"nmaper/internal/fuzzy"
	"nmaper/internal/snapshot"
)

func matchesHost(host HostSnapshot, query string) bool {
	if fuzzy.Match(host.PrimaryIP, query) || fuzzy.Match(host.MAC, query) || fuzzy.Match(host.Vendor, query) {
		return true
	}
	for _, hostname := range host.Hostnames {
		if fuzzy.Match(hostname, query) {
			return true
		}
	}
	return false
}

type matchedHostPair struct {
	left    HostSnapshot
	right   HostSnapshot
	matchBy string
}

func compareHosts(leftSession SessionSummary, leftHosts []HostSnapshot, rightSession SessionSummary, rightHosts []HostSnapshot) DiffReport {
	report := DiffReport{From: leftSession, To: rightSession}

	pairs, leftOnly, rightOnly := matchHosts(leftHosts, rightHosts)
	for _, host := range rightOnly {
		report.NewHosts = append(report.NewHosts, diffSnapshot(host))
	}
	for _, host := range leftOnly {
		report.MissingHosts = append(report.MissingHosts, diffSnapshot(host))
	}
	for _, pair := range pairs {
		changed := buildChangedHost(pair.left, pair.right, pair.matchBy)
		if changed == nil {
			continue
		}
		report.ChangedHosts = append(report.ChangedHosts, *changed)
		accumulateDiffSummary(&report.Summary, *changed)
	}

	sort.Slice(report.NewHosts, func(i, j int) bool { return report.NewHosts[i].IP < report.NewHosts[j].IP })
	sort.Slice(report.MissingHosts, func(i, j int) bool { return report.MissingHosts[i].IP < report.MissingHosts[j].IP })
	sort.Slice(report.ChangedHosts, func(i, j int) bool { return report.ChangedHosts[i].After.IP < report.ChangedHosts[j].After.IP })

	report.Summary.NewHosts = len(report.NewHosts)
	report.Summary.MissingHosts = len(report.MissingHosts)
	report.Summary.ChangedHosts = len(report.ChangedHosts)
	report.Alerts = buildHighSignalAlerts(report)
	report.Summary.HighSignalAlerts = len(report.Alerts)
	return report
}

func buildChangedHost(left, right HostSnapshot, matchBy string) *ChangedHost {
	openedPorts, closedPorts := diffStringSlices(openPortStrings(left), openPortStrings(right))
	hostnamesAdded, hostnamesRemoved := diffStringSlices(left.Hostnames, right.Hostnames)
	serviceChanges := diffServiceChanges(left, right)
	scriptChanges := diffScriptChanges(left, right)
	fingerprintChanges := diffFingerprintChanges(left, right)
	newVulnerabilities, resolvedVulnerabilities := diffVulnerabilityChanges(left, right)
	managementAdded, managementRemoved := diffManagementChanges(left, right)
	traceChanged := traceFingerprint(left.Trace) != traceFingerprint(right.Trace)
	reasons := composeDiffReasons(
		left,
		right,
		openedPorts,
		closedPorts,
		hostnamesAdded,
		hostnamesRemoved,
		serviceChanges,
		scriptChanges,
		fingerprintChanges,
		newVulnerabilities,
		resolvedVulnerabilities,
		managementAdded,
		managementRemoved,
		traceChanged,
	)
	if len(reasons) == 0 {
		return nil
	}

	return &ChangedHost{
		IP:                      right.PrimaryIP,
		MatchBy:                 matchBy,
		Before:                  diffSnapshot(left),
		After:                   diffSnapshot(right),
		Reasons:                 reasons,
		OpenedPorts:             openedPorts,
		ClosedPorts:             closedPorts,
		HostnamesAdded:          hostnamesAdded,
		HostnamesRemoved:        hostnamesRemoved,
		ServiceChanges:          serviceChanges,
		ScriptChanges:           scriptChanges,
		FingerprintChanges:      fingerprintChanges,
		NewVulnerabilities:      newVulnerabilities,
		ResolvedVulnerabilities: resolvedVulnerabilities,
		ManagementAdded:         managementAdded,
		ManagementRemoved:       managementRemoved,
		TraceChanged:            traceChanged,
	}
}

func composeDiffReasons(left, right HostSnapshot, openedPorts, closedPorts, hostnamesAdded, hostnamesRemoved []string, serviceChanges []ServiceDelta, scriptChanges []ScriptDelta, fingerprintChanges []string, newVulnerabilities, resolvedVulnerabilities []snapshot.VulnerabilityFinding, managementAdded, managementRemoved []snapshot.ManagementSurface, traceChanged bool) []string {
	var reasons []string
	if left.PrimaryIP != right.PrimaryIP {
		reasons = append(reasons, "primary_ip")
	}
	if normalizedMAC(left.MAC) != normalizedMAC(right.MAC) {
		reasons = append(reasons, "mac")
	}
	if left.Status != right.Status {
		reasons = append(reasons, "status")
	}
	if len(openedPorts) > 0 || len(closedPorts) > 0 {
		reasons = append(reasons, "open_ports")
	}
	if len(hostnamesAdded) > 0 || len(hostnamesRemoved) > 0 {
		reasons = append(reasons, "hostnames")
	}
	if left.Vendor != right.Vendor {
		reasons = append(reasons, "vendor")
	}
	if hostTopOS(left) != hostTopOS(right) {
		reasons = append(reasons, "top_os")
	}
	if len(serviceChanges) > 0 {
		reasons = append(reasons, "services")
	}
	if len(scriptChanges) > 0 {
		reasons = append(reasons, "scripts")
	}
	if len(fingerprintChanges) > 0 {
		reasons = append(reasons, "fingerprints")
	}
	if len(newVulnerabilities) > 0 || len(resolvedVulnerabilities) > 0 {
		reasons = append(reasons, "vulnerabilities")
	}
	if len(managementAdded) > 0 || len(managementRemoved) > 0 {
		reasons = append(reasons, "management")
	}
	if traceChanged {
		reasons = append(reasons, "trace")
	}
	return reasons
}

func accumulateDiffSummary(summary *DiffSummary, changed ChangedHost) {
	if changed.Before.IP != changed.After.IP {
		summary.MovedHosts++
	}
	summary.OpenedPorts += len(changed.OpenedPorts)
	summary.ClosedPorts += len(changed.ClosedPorts)
	summary.ServiceChanges += len(changed.ServiceChanges)
	summary.ScriptChanges += len(changed.ScriptChanges)
	summary.FingerprintChanges += len(changed.FingerprintChanges)
	summary.VulnerabilityChanges += len(changed.NewVulnerabilities) + len(changed.ResolvedVulnerabilities)
	summary.ManagementChanges += len(changed.ManagementAdded) + len(changed.ManagementRemoved)
	if changed.TraceChanged {
		summary.TraceChanges++
	}
}

func matchHosts(leftHosts, rightHosts []HostSnapshot) ([]matchedHostPair, []HostSnapshot, []HostSnapshot) {
	leftByIP := make(map[string]HostSnapshot, len(leftHosts))
	rightByIP := make(map[string]HostSnapshot, len(rightHosts))
	leftMACs := make(map[string]string)
	rightMACs := make(map[string]string)
	for _, host := range leftHosts {
		leftByIP[host.PrimaryIP] = host
		if mac := normalizedMAC(host.MAC); mac != "" {
			leftMACs[mac] = host.PrimaryIP
		}
	}
	for _, host := range rightHosts {
		rightByIP[host.PrimaryIP] = host
		if mac := normalizedMAC(host.MAC); mac != "" {
			rightMACs[mac] = host.PrimaryIP
		}
	}

	matchedLeftIPs := make(map[string]struct{})
	matchedRightIPs := make(map[string]struct{})
	pairs := make([]matchedHostPair, 0)

	for mac, rightIP := range rightMACs {
		leftIP, ok := leftMACs[mac]
		if !ok {
			continue
		}
		pairs = append(pairs, matchedHostPair{
			left:    leftByIP[leftIP],
			right:   rightByIP[rightIP],
			matchBy: "mac",
		})
		matchedLeftIPs[leftIP] = struct{}{}
		matchedRightIPs[rightIP] = struct{}{}
	}

	for ip, right := range rightByIP {
		if _, ok := matchedRightIPs[ip]; ok {
			continue
		}
		left, ok := leftByIP[ip]
		if !ok {
			continue
		}
		if _, ok := matchedLeftIPs[ip]; ok {
			continue
		}
		pairs = append(pairs, matchedHostPair{
			left:    left,
			right:   right,
			matchBy: "ip",
		})
		matchedLeftIPs[ip] = struct{}{}
		matchedRightIPs[ip] = struct{}{}
	}

	leftOnly := make([]HostSnapshot, 0)
	for _, host := range leftHosts {
		if _, ok := matchedLeftIPs[host.PrimaryIP]; ok {
			continue
		}
		leftOnly = append(leftOnly, host)
	}

	rightOnly := make([]HostSnapshot, 0)
	for _, host := range rightHosts {
		if _, ok := matchedRightIPs[host.PrimaryIP]; ok {
			continue
		}
		rightOnly = append(rightOnly, host)
	}

	return pairs, leftOnly, rightOnly
}

func diffSnapshot(host HostSnapshot) HostDiffSnapshot {
	return HostDiffSnapshot{
		IP:        host.PrimaryIP,
		Status:    host.Status,
		MAC:       host.MAC,
		Vendor:    host.Vendor,
		Hostnames: sortedStrings(host.Hostnames),
		OpenPorts: openPortStrings(host),
		Services:  openServiceFingerprints(host),
		TopOS:     hostTopOS(host),
	}
}

func hostSignature(host HostSnapshot) string {
	return strings.Join([]string{
		host.Status,
		normalizedMAC(host.MAC),
		host.Vendor,
		strings.Join(sortedStrings(host.Hostnames), ","),
		strings.Join(openPortStrings(host), ","),
		strings.Join(openServiceFingerprints(host), ","),
		hostTopOS(host),
	}, "|")
}

func hostTopOS(host HostSnapshot) string {
	if len(host.TopOS) == 0 {
		return ""
	}
	return host.TopOS[0]
}

func openServiceFingerprints(host HostSnapshot) []string {
	fingerprints := make([]string, 0, len(host.Services))
	for _, service := range host.Services {
		if service.State != "open" {
			continue
		}
		fingerprints = append(fingerprints, fmt.Sprintf("%s=%s", serviceKey(service), serviceDisplay(service)))
	}
	sort.Strings(fingerprints)
	return fingerprints
}

func diffServiceChanges(left, right HostSnapshot) []ServiceDelta {
	leftMap := serviceSnapshotMap(left.Services)
	rightMap := serviceSnapshotMap(right.Services)
	keys := make([]string, 0, len(leftMap)+len(rightMap))
	seen := make(map[string]struct{})
	for key := range leftMap {
		keys = append(keys, key)
		seen[key] = struct{}{}
	}
	for key := range rightMap {
		if _, ok := seen[key]; ok {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	changes := make([]ServiceDelta, 0)
	for _, key := range keys {
		leftService, leftOK := leftMap[key]
		rightService, rightOK := rightMap[key]
		if !leftOK || !rightOK {
			continue
		}
		if serviceFingerprint(leftService) == serviceFingerprint(rightService) {
			continue
		}
		changes = append(changes, ServiceDelta{
			Port:   key,
			Before: serviceDisplay(leftService),
			After:  serviceDisplay(rightService),
		})
	}
	return changes
}

func diffScriptChanges(left, right HostSnapshot) []ScriptDelta {
	changes := scriptDiffsForScope("host", left.Scripts, right.Scripts)
	leftServices := serviceSnapshotMap(left.Services)
	rightServices := serviceSnapshotMap(right.Services)

	keys := make([]string, 0, len(leftServices)+len(rightServices))
	seen := make(map[string]struct{})
	for key := range leftServices {
		keys = append(keys, key)
		seen[key] = struct{}{}
	}
	for key := range rightServices {
		if _, ok := seen[key]; ok {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		changes = append(changes, scriptDiffsForScope(key, leftServices[key].Scripts, rightServices[key].Scripts)...)
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Scope == changes[j].Scope {
			return changes[i].ID < changes[j].ID
		}
		return changes[i].Scope < changes[j].Scope
	})
	return changes
}

func diffFingerprintChanges(left, right HostSnapshot) []string {
	leftServices := serviceSnapshotMap(left.Services)
	rightServices := serviceSnapshotMap(right.Services)
	keys := unionKeys(leftServices, rightServices)
	changes := make([]string, 0)
	for _, key := range keys {
		leftService, leftOK := leftServices[key]
		rightService, rightOK := rightServices[key]
		if !leftOK || !rightOK {
			continue
		}
		if !sameFingerprint(leftService.TLS, rightService.TLS) {
			changes = append(changes, key+"/tls")
		}
		if !sameFingerprint(leftService.SSH, rightService.SSH) {
			changes = append(changes, key+"/ssh")
		}
		if !sameFingerprint(leftService.HTTP, rightService.HTTP) {
			changes = append(changes, key+"/http")
		}
		if !sameFingerprint(leftService.SMB, rightService.SMB) {
			changes = append(changes, key+"/smb")
		}
	}
	sort.Strings(changes)
	return changes
}

func diffVulnerabilityChanges(left, right HostSnapshot) ([]snapshot.VulnerabilityFinding, []snapshot.VulnerabilityFinding) {
	leftMap := vulnerabilityMap(flattenVulnerabilities(left))
	rightMap := vulnerabilityMap(flattenVulnerabilities(right))
	addedKeys, removedKeys := diffStringSlices(mapKeysFindings(leftMap), mapKeysFindings(rightMap))
	added := make([]snapshot.VulnerabilityFinding, 0, len(addedKeys))
	removed := make([]snapshot.VulnerabilityFinding, 0, len(removedKeys))
	for _, key := range addedKeys {
		added = append(added, rightMap[key])
	}
	for _, key := range removedKeys {
		removed = append(removed, leftMap[key])
	}
	return added, removed
}

func diffManagementChanges(left, right HostSnapshot) ([]snapshot.ManagementSurface, []snapshot.ManagementSurface) {
	leftMap := managementMap(flattenManagement(left))
	rightMap := managementMap(flattenManagement(right))
	addedKeys, removedKeys := diffStringSlices(mapKeysFindings(leftMap), mapKeysFindings(rightMap))
	added := make([]snapshot.ManagementSurface, 0, len(addedKeys))
	removed := make([]snapshot.ManagementSurface, 0, len(removedKeys))
	for _, key := range addedKeys {
		added = append(added, rightMap[key])
	}
	for _, key := range removedKeys {
		removed = append(removed, leftMap[key])
	}
	return added, removed
}

func scriptDiffsForScope(scope string, left, right []ScriptResult) []ScriptDelta {
	leftMap := make(map[string]string, len(left))
	rightMap := make(map[string]string, len(right))
	for _, script := range left {
		leftMap[script.ID] = script.Output
	}
	for _, script := range right {
		rightMap[script.ID] = script.Output
	}

	keys := make([]string, 0, len(leftMap)+len(rightMap))
	seen := make(map[string]struct{})
	for key := range leftMap {
		keys = append(keys, key)
		seen[key] = struct{}{}
	}
	for key := range rightMap {
		if _, ok := seen[key]; ok {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	changes := make([]ScriptDelta, 0)
	for _, key := range keys {
		if leftMap[key] == rightMap[key] {
			continue
		}
		changes = append(changes, ScriptDelta{
			Scope:  scope,
			ID:     key,
			Before: leftMap[key],
			After:  rightMap[key],
		})
	}
	return changes
}

func serviceSnapshotMap(services []ServiceSnapshot) map[string]ServiceSnapshot {
	mapped := make(map[string]ServiceSnapshot, len(services))
	for _, service := range services {
		mapped[serviceKey(service)] = service
	}
	return mapped
}

func unionKeys(left, right map[string]ServiceSnapshot) []string {
	keys := make([]string, 0, len(left)+len(right))
	seen := make(map[string]struct{}, len(left)+len(right))
	for key := range left {
		keys = append(keys, key)
		seen[key] = struct{}{}
	}
	for key := range right {
		if _, ok := seen[key]; ok {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func serviceKey(service ServiceSnapshot) string {
	return fmt.Sprintf("%d/%s", service.Port, service.Protocol)
}

func serviceFingerprint(service ServiceSnapshot) string {
	return strings.Join([]string{
		service.State,
		service.Name,
		service.Product,
		service.Version,
		service.ExtraInfo,
		service.Tunnel,
	}, "|")
}

func serviceDisplay(service ServiceSnapshot) string {
	parts := []string{emptyIfDash(service.State)}
	if service.Name != "" {
		parts = append(parts, service.Name)
	}
	if service.Product != "" {
		parts = append(parts, service.Product)
	}
	if service.Version != "" {
		parts = append(parts, service.Version)
	}
	if service.ExtraInfo != "" {
		parts = append(parts, service.ExtraInfo)
	}
	if service.Tunnel != "" {
		parts = append(parts, service.Tunnel)
	}
	return strings.Join(filterEmpty(parts), " ")
}

func sameFingerprint(left, right any) bool {
	return comparableValue(left) == comparableValue(right)
}

func comparableValue(value any) string {
	if value == nil {
		return ""
	}
	body, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%v", value)
	}
	return string(body)
}

func traceFingerprint(trace *TraceSnapshot) string {
	return comparableValue(trace)
}

func flattenVulnerabilities(host HostSnapshot) []snapshot.VulnerabilityFinding {
	items := append([]snapshot.VulnerabilityFinding(nil), host.Vulnerabilities...)
	for _, service := range host.Services {
		items = append(items, service.Vulnerabilities...)
	}
	return items
}

func vulnerabilityMap(items []snapshot.VulnerabilityFinding) map[string]snapshot.VulnerabilityFinding {
	out := make(map[string]snapshot.VulnerabilityFinding, len(items))
	for _, item := range items {
		key := strings.Join([]string{item.ScriptID, item.Identifier, item.Title, item.Severity, item.State}, "|")
		out[key] = item
	}
	return out
}

func mapKeysFindings[T any](items map[string]T) []string {
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func flattenManagement(host HostSnapshot) []snapshot.ManagementSurface {
	items := append([]snapshot.ManagementSurface(nil), host.Management...)
	for _, service := range host.Services {
		items = append(items, service.Management...)
	}
	return items
}

func managementMap(items []snapshot.ManagementSurface) map[string]snapshot.ManagementSurface {
	out := make(map[string]snapshot.ManagementSurface, len(items))
	for _, item := range items {
		key := strings.Join([]string{item.Category, strconv.Itoa(item.Port), item.Protocol, item.Label, item.Detail}, "|")
		out[key] = item
	}
	return out
}

func diffStringSlices(left, right []string) ([]string, []string) {
	leftSet := make(map[string]struct{}, len(left))
	rightSet := make(map[string]struct{}, len(right))
	for _, item := range left {
		if item == "" {
			continue
		}
		leftSet[item] = struct{}{}
	}
	for _, item := range right {
		if item == "" {
			continue
		}
		rightSet[item] = struct{}{}
	}

	added := make([]string, 0)
	removed := make([]string, 0)
	for item := range rightSet {
		if _, ok := leftSet[item]; ok {
			continue
		}
		added = append(added, item)
	}
	for item := range leftSet {
		if _, ok := rightSet[item]; ok {
			continue
		}
		removed = append(removed, item)
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func sortedStrings(items []string) []string {
	out := append([]string(nil), items...)
	sort.Strings(out)
	return out
}

func normalizedMAC(mac string) string {
	return strings.ToUpper(strings.TrimSpace(mac))
}

func filterEmpty(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if item == "" {
			continue
		}
		out = append(out, item)
	}
	return out
}

func emptyIfDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func openPortStrings(host HostSnapshot) []string {
	var ports []string
	for _, service := range host.Services {
		if service.State == "open" {
			ports = append(ports, fmt.Sprintf("%d/%s", service.Port, service.Protocol))
		}
	}
	sort.Strings(ports)
	return ports
}
