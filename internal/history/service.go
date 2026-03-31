package history

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"nmaper/internal/fuzzy"
)

type Service struct {
	db *sql.DB
}

func New(db *sql.DB) *Service {
	return &Service{db: db}
}

func (s *Service) ListSessions(ctx context.Context, limit int, status, targetFilter string) ([]SessionSummary, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT id, COALESCE(name, ''), status, started_at, completed_at, target, duration_ms, discovered_hosts, live_hosts, COALESCE(nmap_version, '')
		 FROM scan_sessions
		 WHERE (? = '' OR status = ?)
		 ORDER BY started_at DESC`,
		status,
		status,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []SessionSummary
	for rows.Next() {
		summary, err := scanSessionSummary(rows)
		if err != nil {
			return nil, err
		}
		if !fuzzy.Match(summary.Target, targetFilter) && !fuzzy.Match(summary.Name, targetFilter) {
			continue
		}
		sessions = append(sessions, summary)
		if limit > 0 && len(sessions) >= limit {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return sessions, nil
}

func (s *Service) SessionReport(ctx context.Context, sessionID int64, hostQuery string) (SessionReport, error) {
	summary, hosts, err := s.loadSnapshot(ctx, sessionID)
	if err != nil {
		return SessionReport{}, err
	}
	if hostQuery != "" {
		filtered := make([]HostSnapshot, 0, len(hosts))
		for _, host := range hosts {
			if matchesHost(host, hostQuery) {
				filtered = append(filtered, host)
			}
		}
		hosts = filtered
	}
	return SessionReport{Session: summary, Hosts: hosts}, nil
}

func (s *Service) Diff(ctx context.Context, leftID, rightID int64) (DiffReport, error) {
	leftSummary, leftHosts, err := s.loadSnapshot(ctx, leftID)
	if err != nil {
		return DiffReport{}, err
	}
	rightSummary, rightHosts, err := s.loadSnapshot(ctx, rightID)
	if err != nil {
		return DiffReport{}, err
	}
	diff := compareHosts(leftSummary, leftHosts, rightSummary, rightHosts)
	return diff, nil
}

func (s *Service) GlobalDynamics(ctx context.Context, limit int, status, targetFilter string) (GlobalDynamicsReport, error) {
	sessions, err := s.ListSessions(ctx, limit, status, targetFilter)
	if err != nil {
		return GlobalDynamicsReport{}, err
	}
	report := GlobalDynamicsReport{
		Sessions:     sessions,
		SessionCount: len(sessions),
	}
	if len(sessions) == 0 {
		return report, nil
	}

	hostCounts := make(map[string]int)
	hostSignatures := make(map[string]map[string]struct{})
	portCounts := make(map[string]int)
	snapshots := make([]SessionReport, 0, len(sessions))

	for _, session := range sessions {
		summary, hosts, err := s.loadSnapshot(ctx, session.ID)
		if err != nil {
			return GlobalDynamicsReport{}, err
		}
		snapshot := SessionReport{Session: summary, Hosts: hosts}
		snapshots = append(snapshots, snapshot)
		for _, host := range hosts {
			hostCounts[host.PrimaryIP]++
			if _, ok := hostSignatures[host.PrimaryIP]; !ok {
				hostSignatures[host.PrimaryIP] = make(map[string]struct{})
			}
			hostSignatures[host.PrimaryIP][hostSignature(host)] = struct{}{}
			for _, port := range openPortStrings(host) {
				portCounts[port]++
			}
		}
	}

	report.UniqueHosts = len(hostCounts)
	for ip, count := range hostCounts {
		switch {
		case count == len(snapshots):
			report.StableHosts = append(report.StableHosts, ip)
		case count == 1:
			report.Transient = append(report.Transient, ip)
		default:
			report.Recurring = append(report.Recurring, RecurringHost{IP: ip, Appearances: count})
		}
		if len(hostSignatures[ip]) > 1 {
			report.Volatile = append(report.Volatile, ip)
		}
	}
	for port, count := range portCounts {
		report.TopPorts = append(report.TopPorts, PortFrequency{Port: port, Count: count})
	}

	sort.Strings(report.StableHosts)
	sort.Strings(report.Transient)
	sort.Strings(report.Volatile)
	sort.Slice(report.Recurring, func(i, j int) bool {
		if report.Recurring[i].Appearances == report.Recurring[j].Appearances {
			return report.Recurring[i].IP < report.Recurring[j].IP
		}
		return report.Recurring[i].Appearances > report.Recurring[j].Appearances
	})
	sort.Slice(report.TopPorts, func(i, j int) bool {
		if report.TopPorts[i].Count == report.TopPorts[j].Count {
			return report.TopPorts[i].Port < report.TopPorts[j].Port
		}
		return report.TopPorts[i].Count > report.TopPorts[j].Count
	})

	if len(snapshots) >= 2 {
		diff := compareHosts(snapshots[1].Session, snapshots[1].Hosts, snapshots[0].Session, snapshots[0].Hosts)
		report.LastMovement = fmt.Sprintf(
			"between session %d and %d: +%d new / -%d gone / ~%d changed",
			diff.From.ID,
			diff.To.ID,
			len(diff.NewHosts),
			len(diff.MissingHosts),
			len(diff.ChangedHosts),
		)
	}
	return report, nil
}

func (s *Service) Timeline(ctx context.Context, limit int, status, targetFilter string) (TimelineReport, error) {
	sessions, err := s.ListSessions(ctx, limit, status, targetFilter)
	if err != nil {
		return TimelineReport{}, err
	}
	if len(sessions) < 2 {
		return TimelineReport{}, nil
	}
	reverseSessions(sessions)

	snapshots := make([]SessionReport, 0, len(sessions))
	for _, session := range sessions {
		summary, hosts, err := s.loadSnapshot(ctx, session.ID)
		if err != nil {
			return TimelineReport{}, err
		}
		snapshots = append(snapshots, SessionReport{Session: summary, Hosts: hosts})
	}

	report := TimelineReport{Entries: make([]TimelineEntry, 0, len(snapshots)-1)}
	for i := 1; i < len(snapshots); i++ {
		diff := compareHosts(snapshots[i-1].Session, snapshots[i-1].Hosts, snapshots[i].Session, snapshots[i].Hosts)
		report.Entries = append(report.Entries, TimelineEntry{
			From:         diff.From,
			To:           diff.To,
			NewHosts:     diff.NewHosts,
			MissingHosts: diff.MissingHosts,
			ChangedHosts: diff.ChangedHosts,
		})
	}
	return report, nil
}

func (s *Service) loadSnapshot(ctx context.Context, sessionID int64) (SessionSummary, []HostSnapshot, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT id, COALESCE(name, ''), status, started_at, completed_at, target, duration_ms, discovered_hosts, live_hosts, COALESCE(nmap_version, '')
		 FROM scan_sessions
		 WHERE id = ?`,
		sessionID,
	)
	summary, err := scanSingleSessionSummary(row)
	if err != nil {
		return SessionSummary{}, nil, err
	}

	hostRows, err := s.db.QueryContext(
		ctx,
		`SELECT id, primary_ip, COALESCE(status, ''), COALESCE(mac, ''), COALESCE(vendor, ''), hostnames_json
		 FROM host_observations
		 WHERE session_id = ?
		 ORDER BY primary_ip`,
		sessionID,
	)
	if err != nil {
		return SessionSummary{}, nil, err
	}
	defer hostRows.Close()

	var hosts []HostSnapshot
	for hostRows.Next() {
		var hostID int64
		var host HostSnapshot
		var hostnamesJSON string
		if err := hostRows.Scan(&hostID, &host.PrimaryIP, &host.Status, &host.MAC, &host.Vendor, &hostnamesJSON); err != nil {
			return SessionSummary{}, nil, err
		}
		if err := json.Unmarshal([]byte(hostnamesJSON), &host.Hostnames); err != nil {
			return SessionSummary{}, nil, err
		}
		host.TopOS, err = s.loadOSMatches(ctx, hostID)
		if err != nil {
			return SessionSummary{}, nil, err
		}
		host.Scripts, err = s.loadHostScripts(ctx, hostID)
		if err != nil {
			return SessionSummary{}, nil, err
		}
		host.Services, err = s.loadServices(ctx, hostID)
		if err != nil {
			return SessionSummary{}, nil, err
		}
		host.Trace, err = s.loadTrace(ctx, hostID)
		if err != nil {
			return SessionSummary{}, nil, err
		}
		hosts = append(hosts, host)
	}
	if err := hostRows.Err(); err != nil {
		return SessionSummary{}, nil, err
	}
	return summary, hosts, nil
}

func (s *Service) loadOSMatches(ctx context.Context, hostID int64) ([]string, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT name FROM os_matches WHERE host_observation_id = ? ORDER BY accuracy DESC, id ASC`,
		hostID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var matches []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		matches = append(matches, name)
	}
	return matches, rows.Err()
}

func (s *Service) loadHostScripts(ctx context.Context, hostID int64) ([]ScriptResult, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT script_id, COALESCE(output, '') FROM script_results
		 WHERE host_observation_id = ? AND service_observation_id IS NULL
		 ORDER BY script_id`,
		hostID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var scripts []ScriptResult
	for rows.Next() {
		var script ScriptResult
		if err := rows.Scan(&script.ID, &script.Output); err != nil {
			return nil, err
		}
		scripts = append(scripts, script)
	}
	return scripts, rows.Err()
}

func (s *Service) loadServices(ctx context.Context, hostID int64) ([]ServiceSnapshot, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT id, port, protocol, COALESCE(state, ''), COALESCE(service_name, ''), COALESCE(product, ''),
		        COALESCE(version, ''), COALESCE(extra_info, ''), COALESCE(tunnel, '')
		 FROM service_observations
		 WHERE host_observation_id = ?
		 ORDER BY port, protocol`,
		hostID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var services []ServiceSnapshot
	for rows.Next() {
		var serviceID int64
		var service ServiceSnapshot
		if err := rows.Scan(
			&serviceID,
			&service.Port,
			&service.Protocol,
			&service.State,
			&service.Name,
			&service.Product,
			&service.Version,
			&service.ExtraInfo,
			&service.Tunnel,
		); err != nil {
			return nil, err
		}
		service.Scripts, err = s.loadServiceScripts(ctx, serviceID)
		if err != nil {
			return nil, err
		}
		services = append(services, service)
	}
	return services, rows.Err()
}

func (s *Service) loadServiceScripts(ctx context.Context, serviceID int64) ([]ScriptResult, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT script_id, COALESCE(output, '') FROM script_results
		 WHERE service_observation_id = ?
		 ORDER BY script_id`,
		serviceID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var scripts []ScriptResult
	for rows.Next() {
		var script ScriptResult
		if err := rows.Scan(&script.ID, &script.Output); err != nil {
			return nil, err
		}
		scripts = append(scripts, script)
	}
	return scripts, rows.Err()
}

func (s *Service) loadTrace(ctx context.Context, hostID int64) (*TraceSnapshot, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT id, COALESCE(proto, ''), COALESCE(port, 0) FROM traces WHERE host_observation_id = ? LIMIT 1`,
		hostID,
	)
	var traceID int64
	var trace TraceSnapshot
	if err := row.Scan(&traceID, &trace.Proto, &trace.Port); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT ttl, COALESCE(ip_address, ''), COALESCE(rtt, 0), COALESCE(host, '')
		 FROM trace_hops
		 WHERE trace_id = ?
		 ORDER BY ttl`,
		traceID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var hop TraceHop
		if err := rows.Scan(&hop.TTL, &hop.IP, &hop.RTT, &hop.Host); err != nil {
			return nil, err
		}
		trace.Hops = append(trace.Hops, hop)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &trace, nil
}

func scanSessionSummary(rows *sql.Rows) (SessionSummary, error) {
	var (
		summary        SessionSummary
		startedAtRaw   string
		completedAtRaw sql.NullString
		durationMS     int64
	)
	if err := rows.Scan(
		&summary.ID,
		&summary.Name,
		&summary.Status,
		&startedAtRaw,
		&completedAtRaw,
		&summary.Target,
		&durationMS,
		&summary.DiscoveredHosts,
		&summary.LiveHosts,
		&summary.NmapVersion,
	); err != nil {
		return SessionSummary{}, err
	}
	startedAt, err := time.Parse(time.RFC3339Nano, startedAtRaw)
	if err != nil {
		return SessionSummary{}, err
	}
	summary.StartedAt = startedAt
	summary.Duration = (time.Duration(durationMS) * time.Millisecond).String()
	if completedAtRaw.Valid && completedAtRaw.String != "" {
		completedAt, err := time.Parse(time.RFC3339Nano, completedAtRaw.String)
		if err != nil {
			return SessionSummary{}, err
		}
		summary.CompletedAt = &completedAt
	}
	return summary, nil
}

func scanSingleSessionSummary(row *sql.Row) (SessionSummary, error) {
	var (
		summary        SessionSummary
		startedAtRaw   string
		completedAtRaw sql.NullString
		durationMS     int64
	)
	if err := row.Scan(
		&summary.ID,
		&summary.Name,
		&summary.Status,
		&startedAtRaw,
		&completedAtRaw,
		&summary.Target,
		&durationMS,
		&summary.DiscoveredHosts,
		&summary.LiveHosts,
		&summary.NmapVersion,
	); err != nil {
		if err == sql.ErrNoRows {
			return SessionSummary{}, fmt.Errorf("session not found")
		}
		return SessionSummary{}, err
	}
	startedAt, err := time.Parse(time.RFC3339Nano, startedAtRaw)
	if err != nil {
		return SessionSummary{}, err
	}
	summary.StartedAt = startedAt
	summary.Duration = (time.Duration(durationMS) * time.Millisecond).String()
	if completedAtRaw.Valid && completedAtRaw.String != "" {
		completedAt, err := time.Parse(time.RFC3339Nano, completedAtRaw.String)
		if err != nil {
			return SessionSummary{}, err
		}
		summary.CompletedAt = &completedAt
	}
	return summary, nil
}

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

func compareHosts(leftSession SessionSummary, leftHosts []HostSnapshot, rightSession SessionSummary, rightHosts []HostSnapshot) DiffReport {
	leftMap := make(map[string]HostSnapshot, len(leftHosts))
	rightMap := make(map[string]HostSnapshot, len(rightHosts))
	for _, host := range leftHosts {
		leftMap[host.PrimaryIP] = host
	}
	for _, host := range rightHosts {
		rightMap[host.PrimaryIP] = host
	}

	report := DiffReport{From: leftSession, To: rightSession}
	seen := make(map[string]struct{})
	for ip, right := range rightMap {
		seen[ip] = struct{}{}
		left, ok := leftMap[ip]
		if !ok {
			report.NewHosts = append(report.NewHosts, diffSnapshot(right))
			continue
		}
		reasons := diffReasons(left, right)
		if len(reasons) > 0 {
			report.ChangedHosts = append(report.ChangedHosts, ChangedHost{
				IP:      ip,
				Before:  diffSnapshot(left),
				After:   diffSnapshot(right),
				Reasons: reasons,
			})
		}
	}
	for ip, left := range leftMap {
		if _, ok := seen[ip]; ok {
			continue
		}
		report.MissingHosts = append(report.MissingHosts, diffSnapshot(left))
	}

	sort.Slice(report.NewHosts, func(i, j int) bool { return report.NewHosts[i].IP < report.NewHosts[j].IP })
	sort.Slice(report.MissingHosts, func(i, j int) bool { return report.MissingHosts[i].IP < report.MissingHosts[j].IP })
	sort.Slice(report.ChangedHosts, func(i, j int) bool { return report.ChangedHosts[i].IP < report.ChangedHosts[j].IP })
	return report
}

func diffSnapshot(host HostSnapshot) HostDiffSnapshot {
	topOS := ""
	if len(host.TopOS) > 0 {
		topOS = host.TopOS[0]
	}
	return HostDiffSnapshot{
		IP:        host.PrimaryIP,
		Status:    host.Status,
		OpenPorts: openPortStrings(host),
		TopOS:     topOS,
		Vendor:    host.Vendor,
	}
}

func diffReasons(left, right HostSnapshot) []string {
	var reasons []string
	if left.Status != right.Status {
		reasons = append(reasons, "status")
	}
	if strings.Join(openPortStrings(left), ",") != strings.Join(openPortStrings(right), ",") {
		reasons = append(reasons, "open_ports")
	}
	leftOS, rightOS := "", ""
	if len(left.TopOS) > 0 {
		leftOS = left.TopOS[0]
	}
	if len(right.TopOS) > 0 {
		rightOS = right.TopOS[0]
	}
	if leftOS != rightOS {
		reasons = append(reasons, "top_os")
	}
	return reasons
}

func hostSignature(host HostSnapshot) string {
	topOS := ""
	if len(host.TopOS) > 0 {
		topOS = host.TopOS[0]
	}
	return host.Status + "|" + strings.Join(openPortStrings(host), ",") + "|" + topOS
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

func reverseSessions(items []SessionSummary) {
	for left, right := 0, len(items)-1; left < right; left, right = left+1, right-1 {
		items[left], items[right] = items[right], items[left]
	}
}
