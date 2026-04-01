package history

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"nmaper/internal/snapshot"
)

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
