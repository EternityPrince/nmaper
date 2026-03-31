package history

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"nmaper/internal/fuzzy"
	"nmaper/internal/snapshot"
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
		`SELECT id, COALESCE(name, ''), status, started_at, completed_at, target, duration_ms, discovered_hosts, live_hosts, COALESCE(nmap_version, ''),
		        COALESCE(scan_level, 'mid'), COALESCE(scanner_interface, ''), COALESCE(scanner_real_mac, ''), COALESCE(scanner_spoofed_mac, '')
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
			"between session %d and %d: +%d new / -%d gone / ~%d changed / ->%d moved / +%d ports / -%d ports / fp:%d / vuln:%d / mgmt:%d / !%d alerts",
			diff.From.ID,
			diff.To.ID,
			diff.Summary.NewHosts,
			diff.Summary.MissingHosts,
			diff.Summary.ChangedHosts,
			diff.Summary.MovedHosts,
			diff.Summary.OpenedPorts,
			diff.Summary.ClosedPorts,
			diff.Summary.FingerprintChanges,
			diff.Summary.VulnerabilityChanges,
			diff.Summary.ManagementChanges,
			diff.Summary.HighSignalAlerts,
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
			Summary:      diff.Summary,
			Alerts:       diff.Alerts,
		})
	}
	return report, nil
}

func (s *Service) loadSnapshot(ctx context.Context, sessionID int64) (SessionSummary, []HostSnapshot, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT id, COALESCE(name, ''), status, started_at, completed_at, target, duration_ms, discovered_hosts, live_hosts, COALESCE(nmap_version, ''),
		        COALESCE(scan_level, 'mid'), COALESCE(scanner_interface, ''), COALESCE(scanner_real_mac, ''), COALESCE(scanner_spoofed_mac, '')
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
		host.Vulnerabilities, err = s.loadVulnerabilities(ctx, hostID, nil)
		if err != nil {
			return SessionSummary{}, nil, err
		}
		host.Management, err = s.loadManagement(ctx, hostID, nil)
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
		populateHostNSEMetrics(&host)
		hosts = append(hosts, host)
	}
	if err := hostRows.Err(); err != nil {
		return SessionSummary{}, nil, err
	}
	return summary, hosts, nil
}

func populateHostNSEMetrics(host *HostSnapshot) {
	if host == nil {
		return
	}
	host.HostScriptHits = len(host.Scripts)
	host.ServiceScriptHits = 0
	for _, service := range host.Services {
		host.ServiceScriptHits += len(service.Scripts)
	}
	host.NSEHits = host.HostScriptHits + host.ServiceScriptHits
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
		service.TLS, err = s.loadTLSFingerprint(ctx, serviceID)
		if err != nil {
			return nil, err
		}
		service.SSH, err = s.loadSSHFingerprint(ctx, serviceID)
		if err != nil {
			return nil, err
		}
		service.HTTP, err = s.loadHTTPFingerprint(ctx, serviceID)
		if err != nil {
			return nil, err
		}
		service.SMB, err = s.loadSMBFingerprint(ctx, serviceID)
		if err != nil {
			return nil, err
		}
		service.Vulnerabilities, err = s.loadVulnerabilities(ctx, hostID, &serviceID)
		if err != nil {
			return nil, err
		}
		service.Management, err = s.loadManagement(ctx, hostID, &serviceID)
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

func (s *Service) loadTLSFingerprint(ctx context.Context, serviceID int64) (*snapshot.TLSFingerprint, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT COALESCE(subject, ''), COALESCE(issuer, ''), COALESCE(not_before, ''), COALESCE(not_after, ''),
		        COALESCE(sha256, ''), versions_json, ciphers_json, weak_ciphers_json
		 FROM tls_fingerprints
		 WHERE service_observation_id = ?`,
		serviceID,
	)
	var (
		fp       snapshot.TLSFingerprint
		versions string
		ciphers  string
		weak     string
	)
	if err := row.Scan(&fp.Subject, &fp.Issuer, &fp.NotBefore, &fp.NotAfter, &fp.SHA256, &versions, &ciphers, &weak); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if err := unmarshalStrings(versions, &fp.Versions); err != nil {
		return nil, err
	}
	if err := unmarshalStrings(ciphers, &fp.Ciphers); err != nil {
		return nil, err
	}
	if err := unmarshalStrings(weak, &fp.WeakCiphers); err != nil {
		return nil, err
	}
	return &fp, nil
}

func (s *Service) loadSSHFingerprint(ctx context.Context, serviceID int64) (*snapshot.SSHFingerprint, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT host_keys_json, algorithms_json, weak_algorithms_json
		 FROM ssh_fingerprints
		 WHERE service_observation_id = ?`,
		serviceID,
	)
	var (
		fp         snapshot.SSHFingerprint
		hostKeys   string
		algorithms string
		weak       string
	)
	if err := row.Scan(&hostKeys, &algorithms, &weak); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if err := unmarshalStrings(hostKeys, &fp.HostKeys); err != nil {
		return nil, err
	}
	if err := unmarshalStrings(algorithms, &fp.Algorithms); err != nil {
		return nil, err
	}
	if err := unmarshalStrings(weak, &fp.WeakAlgorithms); err != nil {
		return nil, err
	}
	return &fp, nil
}

func (s *Service) loadHTTPFingerprint(ctx context.Context, serviceID int64) (*snapshot.HTTPFingerprint, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT COALESCE(title, ''), COALESCE(server, ''), methods_json, auth_schemes_json, paths_json, security_headers_json, headers_json
		 FROM http_fingerprints
		 WHERE service_observation_id = ?`,
		serviceID,
	)
	var (
		fp       snapshot.HTTPFingerprint
		methods  string
		auth     string
		paths    string
		security string
		headers  string
	)
	if err := row.Scan(&fp.Title, &fp.Server, &methods, &auth, &paths, &security, &headers); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if err := unmarshalStrings(methods, &fp.Methods); err != nil {
		return nil, err
	}
	if err := unmarshalStrings(auth, &fp.AuthSchemes); err != nil {
		return nil, err
	}
	if err := unmarshalStrings(paths, &fp.Paths); err != nil {
		return nil, err
	}
	if err := unmarshalStrings(security, &fp.SecurityHeaders); err != nil {
		return nil, err
	}
	if err := unmarshalStrings(headers, &fp.Headers); err != nil {
		return nil, err
	}
	return &fp, nil
}

func (s *Service) loadSMBFingerprint(ctx context.Context, serviceID int64) (*snapshot.SMBFingerprint, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT COALESCE(os, ''), COALESCE(workgroup, ''), protocols_json, shares_json
		 FROM smb_fingerprints
		 WHERE service_observation_id = ?`,
		serviceID,
	)
	var (
		fp        snapshot.SMBFingerprint
		protocols string
		shares    string
	)
	if err := row.Scan(&fp.OS, &fp.Workgroup, &protocols, &shares); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if err := unmarshalStrings(protocols, &fp.Protocols); err != nil {
		return nil, err
	}
	if err := unmarshalStrings(shares, &fp.Shares); err != nil {
		return nil, err
	}
	return &fp, nil
}

func (s *Service) loadVulnerabilities(ctx context.Context, hostID int64, serviceID *int64) ([]snapshot.VulnerabilityFinding, error) {
	query := `SELECT COALESCE(script_id, ''), COALESCE(identifier, ''), COALESCE(title, ''), COALESCE(severity, ''), COALESCE(state, ''), COALESCE(evidence, '')
		FROM vulnerability_findings
		WHERE host_observation_id = ?`
	args := []any{hostID}
	if serviceID == nil {
		query += ` AND service_observation_id IS NULL`
	} else {
		query += ` AND service_observation_id = ?`
		args = append(args, *serviceID)
	}
	query += ` ORDER BY severity DESC, identifier, script_id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var findings []snapshot.VulnerabilityFinding
	for rows.Next() {
		var finding snapshot.VulnerabilityFinding
		if err := rows.Scan(&finding.ScriptID, &finding.Identifier, &finding.Title, &finding.Severity, &finding.State, &finding.Evidence); err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}

func (s *Service) loadManagement(ctx context.Context, hostID int64, serviceID *int64) ([]snapshot.ManagementSurface, error) {
	query := `SELECT COALESCE(category, ''), COALESCE(label, ''), port, COALESCE(protocol, ''), COALESCE(exposure, ''), COALESCE(detail, '')
		FROM management_surfaces
		WHERE host_observation_id = ?`
	args := []any{hostID}
	if serviceID == nil {
		query += ` AND service_observation_id IS NULL`
	} else {
		query += ` AND service_observation_id = ?`
		args = append(args, *serviceID)
	}
	query += ` ORDER BY port, category`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var surfaces []snapshot.ManagementSurface
	for rows.Next() {
		var surface snapshot.ManagementSurface
		if err := rows.Scan(&surface.Category, &surface.Label, &surface.Port, &surface.Protocol, &surface.Exposure, &surface.Detail); err != nil {
			return nil, err
		}
		surfaces = append(surfaces, surface)
	}
	return surfaces, rows.Err()
}

func unmarshalStrings(raw string, target *[]string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return json.Unmarshal([]byte(raw), target)
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
		&summary.ScanLevel,
		&summary.ScannerInterface,
		&summary.ScannerRealMAC,
		&summary.ScannerSpoofedMAC,
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
		&summary.ScanLevel,
		&summary.ScannerInterface,
		&summary.ScannerRealMAC,
		&summary.ScannerSpoofedMAC,
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

var managementPortLabels = map[int]string{
	22:    "SSH",
	23:    "Telnet",
	161:   "SNMP",
	445:   "SMB",
	3389:  "RDP",
	5900:  "VNC",
	5985:  "WinRM",
	5986:  "WinRM TLS",
	8080:  "HTTP admin",
	8081:  "HTTP admin",
	8443:  "HTTPS admin",
	9090:  "Admin UI",
	9443:  "HTTPS admin",
	10000: "Webmin",
	2375:  "Docker API",
	2376:  "Docker TLS API",
	6443:  "Kubernetes API",
	15672: "RabbitMQ UI",
}

func buildHighSignalAlerts(report DiffReport) []DiffAlert {
	alerts := make([]DiffAlert, 0)
	seen := make(map[string]struct{})

	appendAlert := func(alert DiffAlert) {
		key := strings.Join([]string{alert.Type, alert.Host, alert.Title, alert.Detail}, "|")
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		alerts = append(alerts, alert)
	}

	for _, host := range report.NewHosts {
		for _, alert := range alertsFromNewHost(host) {
			appendAlert(alert)
		}
	}
	for _, host := range report.ChangedHosts {
		for _, alert := range alertsFromChangedHost(host) {
			appendAlert(alert)
		}
	}

	sort.Slice(alerts, func(i, j int) bool {
		if alerts[i].Host == alerts[j].Host {
			return alerts[i].Type < alerts[j].Type
		}
		return alerts[i].Host < alerts[j].Host
	})
	return alerts
}

func alertsFromNewHost(host HostDiffSnapshot) []DiffAlert {
	alerts := make([]DiffAlert, 0)
	for _, port := range host.OpenPorts {
		switch parsePortNumber(port) {
		case 445:
			alerts = append(alerts, DiffAlert{
				Type:     "smb_appeared",
				Severity: "high",
				Host:     host.IP,
				Title:    "SMB appeared on a newly discovered host",
				Detail:   "open port " + port,
			})
		case 3389:
			alerts = append(alerts, DiffAlert{
				Type:     "rdp_appeared",
				Severity: "high",
				Host:     host.IP,
				Title:    "RDP appeared on a newly discovered host",
				Detail:   "open port " + port,
			})
		default:
			if label := managementPortLabel(port); label != "" {
				alerts = append(alerts, DiffAlert{
					Type:     "management_port_opened",
					Severity: "high",
					Host:     host.IP,
					Title:    "New management surface detected",
					Detail:   fmt.Sprintf("%s on %s", label, port),
				})
			}
		}
	}
	return alerts
}

func alertsFromChangedHost(host ChangedHost) []DiffAlert {
	alerts := make([]DiffAlert, 0)
	hostIP := host.After.IP
	if hostIP == "" {
		hostIP = host.IP
	}

	for _, port := range host.OpenedPorts {
		switch parsePortNumber(port) {
		case 445:
			alerts = append(alerts, DiffAlert{
				Type:     "smb_appeared",
				Severity: "high",
				Host:     hostIP,
				Title:    "SMB appeared",
				Detail:   "new open port " + port,
			})
		case 3389:
			alerts = append(alerts, DiffAlert{
				Type:     "rdp_appeared",
				Severity: "high",
				Host:     hostIP,
				Title:    "RDP appeared",
				Detail:   "new open port " + port,
			})
		default:
			if label := managementPortLabel(port); label != "" {
				alerts = append(alerts, DiffAlert{
					Type:     "management_port_opened",
					Severity: "high",
					Host:     hostIP,
					Title:    "New management surface detected",
					Detail:   fmt.Sprintf("%s on %s", label, port),
				})
			}
		}
	}
	for _, surface := range host.ManagementAdded {
		if label := strings.TrimSpace(surface.Label); label != "" {
			alerts = append(alerts, DiffAlert{
				Type:     "management_surface_added",
				Severity: "high",
				Host:     hostIP,
				Title:    "New management surface detected",
				Detail:   fmt.Sprintf("%s on %d/%s", label, surface.Port, surface.Protocol),
			})
		}
	}

	beforeCerts, afterCerts := aggregateScriptOutputs(host.ScriptChanges, "ssl-cert")
	if len(beforeCerts) > 0 && len(afterCerts) > 0 && strings.Join(beforeCerts, "|") != strings.Join(afterCerts, "|") {
		alerts = append(alerts, DiffAlert{
			Type:     "tls_certificate_changed",
			Severity: "high",
			Host:     hostIP,
			Title:    "TLS certificate changed",
			Detail:   fmt.Sprintf("%s -> %s", previewOutputs(beforeCerts), previewOutputs(afterCerts)),
		})
	}

	beforeSSH, afterSSH := aggregateScriptOutputs(host.ScriptChanges, "ssh-hostkey")
	if len(beforeSSH) > 0 && len(afterSSH) > 0 && strings.Join(beforeSSH, "|") != strings.Join(afterSSH, "|") {
		alerts = append(alerts, DiffAlert{
			Type:     "ssh_hostkey_rotated",
			Severity: "high",
			Host:     hostIP,
			Title:    "SSH host key rotated",
			Detail:   fmt.Sprintf("%s -> %s", previewOutputs(beforeSSH), previewOutputs(afterSSH)),
		})
	}

	beforeTitles, afterTitles := aggregateScriptOutputs(host.ScriptChanges, "http-title")
	if (len(beforeTitles) > 0 || len(afterTitles) > 0) && strings.Join(beforeTitles, "|") != strings.Join(afterTitles, "|") {
		alerts = append(alerts, DiffAlert{
			Type:     "http_title_changed",
			Severity: "high",
			Host:     hostIP,
			Title:    "HTTP title changed",
			Detail:   fmt.Sprintf("%s -> %s", previewOutputs(beforeTitles), previewOutputs(afterTitles)),
		})
	}
	for _, finding := range host.NewVulnerabilities {
		if !findingSignalsRisk(finding) {
			continue
		}
		title := "New vulnerability signal detected"
		if finding.Title != "" {
			title = finding.Title
		}
		severity := finding.Severity
		if severity == "" {
			severity = "high"
		}
		alerts = append(alerts, DiffAlert{
			Type:     "vulnerability_detected",
			Severity: severity,
			Host:     hostIP,
			Title:    title,
			Detail:   firstNonEmpty(finding.Identifier, finding.Evidence, finding.ScriptID),
		})
	}

	return alerts
}

func aggregateScriptOutputs(changes []ScriptDelta, scriptID string) ([]string, []string) {
	before := make(map[string]struct{})
	after := make(map[string]struct{})
	for _, change := range changes {
		if change.ID != scriptID {
			continue
		}
		if strings.TrimSpace(change.Before) != "" {
			before[strings.TrimSpace(change.Before)] = struct{}{}
		}
		if strings.TrimSpace(change.After) != "" {
			after[strings.TrimSpace(change.After)] = struct{}{}
		}
	}
	return mapKeys(before), mapKeys(after)
}

func previewOutputs(values []string) string {
	if len(values) == 0 {
		return "-"
	}
	preview := append([]string(nil), values...)
	sort.Strings(preview)
	if len(preview) > 2 {
		preview = preview[:2]
	}
	for index, value := range preview {
		if len(value) > 48 {
			preview[index] = value[:45] + "..."
		}
	}
	return strings.Join(preview, "; ")
}

func findingSignalsRisk(finding snapshot.VulnerabilityFinding) bool {
	switch strings.ToLower(finding.State) {
	case "vulnerable", "likely_vulnerable", "present", "observed":
		return true
	default:
		return false
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func mapKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func managementPortLabel(port string) string {
	number := parsePortNumber(port)
	switch number {
	case 445, 3389:
		return ""
	default:
		return managementPortLabels[number]
	}
}

func parsePortNumber(port string) int {
	value := port
	if cut := strings.Index(value, "/"); cut >= 0 {
		value = value[:cut]
	}
	number, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return number
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
