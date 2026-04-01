package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"nmaper/internal/model"
	"nmaper/internal/parser"
	"nmaper/internal/snapshot"
)

func (s *Store) BeginSession(ctx context.Context, opts model.Options, sessionName string, startedAt time.Time) (int64, error) {
	res, err := s.db.ExecContext(
		ctx,
		`INSERT INTO scan_sessions (name, target, save_mode, started_at, status, scan_level)
		 VALUES (?, ?, ?, ?, 'running', ?)`,
		sessionName,
		opts.Target,
		string(opts.Save),
		startedAt.UTC().Format(time.RFC3339Nano),
		string(opts.Level),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) AttachSourceIdentity(ctx context.Context, sessionID int64, identity SourceIdentity) error {
	_, err := s.db.ExecContext(
		ctx,
		`UPDATE scan_sessions
		 SET scanner_interface = ?,
		     scanner_real_mac = ?,
		     scanner_spoofed_mac = ?
		 WHERE id = ?`,
		nullString(identity.Interface),
		nullString(identity.RealMAC),
		nullString(identity.SpoofedMAC),
		sessionID,
	)
	return err
}

func (s *Store) MarkSessionFailed(ctx context.Context, sessionID int64, sessionErr error) error {
	_, err := s.db.ExecContext(
		ctx,
		`UPDATE scan_sessions
		 SET status = 'failed',
		     error_text = ?,
		     completed_at = ?,
		     duration_ms = CASE
		         WHEN started_at IS NOT NULL THEN CAST((julianday(?) - julianday(started_at)) * 86400000 AS INTEGER)
		         ELSE duration_ms
		     END
		 WHERE id = ?`,
		sessionErr.Error(),
		time.Now().UTC().Format(time.RFC3339Nano),
		time.Now().UTC().Format(time.RFC3339Nano),
		sessionID,
	)
	return err
}

func (s *Store) PersistCompletedSession(ctx context.Context, sessionID int64, opts model.Options, result CompletedScan) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	discoveredHosts := len(result.DiscoveryRun.Hosts)
	liveHosts := len(result.Targets)

	networkID, networkErr := ensureNetwork(tx, opts.Target)
	if networkErr != nil {
		return networkErr
	}
	if networkID != nil {
		if _, err = tx.ExecContext(
			ctx,
			`INSERT INTO session_networks (session_id, network_id, discovered_hosts, live_hosts)
			 VALUES (?, ?, ?, ?)
			 ON CONFLICT(session_id, network_id) DO UPDATE SET
			     discovered_hosts = excluded.discovered_hosts,
			     live_hosts = excluded.live_hosts`,
			sessionID,
			*networkID,
			discoveredHosts,
			liveHosts,
		); err != nil {
			return err
		}
	}

	detailByIP := make(map[string]parser.Host)
	for ip, run := range result.DetailRuns {
		if len(run.Hosts) == 0 {
			continue
		}
		detailByIP[ip] = run.Hosts[0]
	}

	for _, host := range result.DiscoveryRun.Hosts {
		selected := host
		if detailed, ok := detailByIP[host.PrimaryIP()]; ok {
			selected = mergeHost(host, detailed)
		}
		if selected.PrimaryIP() == "" {
			continue
		}
		if err = persistHost(ctx, tx, sessionID, result.CompletedAt, networkID, selected); err != nil {
			return err
		}
	}

	version := result.DiscoveryRun.Version
	if version == "" {
		for _, run := range result.DetailRuns {
			if run.Version != "" {
				version = run.Version
				break
			}
		}
	}

	_, err = tx.ExecContext(
		ctx,
		`UPDATE scan_sessions
		 SET status = 'completed',
		     completed_at = ?,
		     duration_ms = ?,
		     nmap_version = ?,
		     scan_level = ?,
		     scanner_interface = ?,
		     scanner_real_mac = ?,
		     scanner_spoofed_mac = ?,
		     discovery_command = ?,
		     detail_command_template = ?,
		     discovered_hosts = ?,
		     live_hosts = ?,
		     detail_scans = ?,
		     detail_errors = ?
		 WHERE id = ?`,
		result.CompletedAt.UTC().Format(time.RFC3339Nano),
		result.CompletedAt.Sub(result.StartedAt).Milliseconds(),
		version,
		string(opts.Level),
		nullString(result.SourceIdentity.Interface),
		nullString(result.SourceIdentity.RealMAC),
		nullString(result.SourceIdentity.SpoofedMAC),
		strings.Join(result.DiscoveryCommand, " "),
		firstDetailCommand(result.DetailCommands),
		discoveredHosts,
		liveHosts,
		len(result.DetailRuns),
		len(result.DetailErrors),
		sessionID,
	)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func persistHost(ctx context.Context, tx *sql.Tx, sessionID int64, observedAt time.Time, networkID *int64, host parser.Host) error {
	deviceID, primaryIP, mac, vendor, err := resolveDevice(ctx, tx, sessionID, observedAt, networkID, host)
	if err != nil {
		return err
	}

	hostnamesJSON, err := json.Marshal(host.Hostnames)
	if err != nil {
		return err
	}

	res, err := tx.ExecContext(
		ctx,
		`INSERT INTO host_observations (session_id, device_id, primary_ip, status, mac, vendor, hostnames_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(session_id, primary_ip) DO UPDATE SET
		     device_id = excluded.device_id,
		     status = excluded.status,
		     mac = excluded.mac,
		     vendor = excluded.vendor,
		     hostnames_json = excluded.hostnames_json`,
		sessionID,
		deviceID,
		primaryIP,
		host.Status,
		nullString(mac),
		nullString(vendor),
		string(hostnamesJSON),
	)
	if err != nil {
		return err
	}
	hostObservationID, err := res.LastInsertId()
	if err != nil || hostObservationID == 0 {
		if lookupErr := tx.QueryRowContext(
			ctx,
			`SELECT id FROM host_observations WHERE session_id = ? AND primary_ip = ?`,
			sessionID,
			primaryIP,
		).Scan(&hostObservationID); lookupErr != nil {
			return lookupErr
		}
	}

	if _, err = tx.ExecContext(ctx, `DELETE FROM os_matches WHERE host_observation_id = ?`, hostObservationID); err != nil {
		return err
	}
	for _, match := range host.OSMatches {
		if _, err = tx.ExecContext(
			ctx,
			`INSERT INTO os_matches (host_observation_id, name, accuracy, os_class) VALUES (?, ?, ?, ?)`,
			hostObservationID,
			match.Name,
			match.Accuracy,
			strings.Join(match.Classes, ", "),
		); err != nil {
			return err
		}
	}

	if _, err = tx.ExecContext(ctx, `DELETE FROM script_results WHERE host_observation_id = ? AND service_observation_id IS NULL`, hostObservationID); err != nil {
		return err
	}
	for _, script := range host.Scripts {
		if _, err = tx.ExecContext(
			ctx,
			`INSERT INTO script_results (host_observation_id, script_id, output) VALUES (?, ?, ?)`,
			hostObservationID,
			script.ID,
			script.Output,
		); err != nil {
			return err
		}
	}
	if err = persistHostProfile(ctx, tx, hostObservationID, snapshot.AnalyzeHost(host)); err != nil {
		return err
	}

	if _, err = tx.ExecContext(ctx, `DELETE FROM service_observations WHERE host_observation_id = ?`, hostObservationID); err != nil {
		return err
	}
	for _, port := range host.Ports {
		if _, err = tx.ExecContext(
			ctx,
			`INSERT INTO ports (port, protocol) VALUES (?, ?)
			 ON CONFLICT(port, protocol) DO NOTHING`,
			port.ID,
			port.Protocol,
		); err != nil {
			return err
		}

		res, execErr := tx.ExecContext(
			ctx,
			`INSERT INTO service_observations
			 (host_observation_id, port, protocol, state, service_name, product, version, extra_info, tunnel)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			hostObservationID,
			port.ID,
			port.Protocol,
			port.State,
			nullString(port.Service.Name),
			nullString(port.Service.Product),
			nullString(port.Service.Version),
			nullString(port.Service.ExtraInfo),
			nullString(port.Service.Tunnel),
		)
		if execErr != nil {
			return execErr
		}
		serviceObservationID, execErr := res.LastInsertId()
		if execErr != nil {
			return execErr
		}
		for _, script := range port.Scripts {
			if _, err = tx.ExecContext(
				ctx,
				`INSERT INTO script_results (service_observation_id, script_id, output) VALUES (?, ?, ?)`,
				serviceObservationID,
				script.ID,
				script.Output,
			); err != nil {
				return err
			}
		}
		if err = persistServiceProfile(ctx, tx, hostObservationID, serviceObservationID, snapshot.AnalyzeService(port)); err != nil {
			return err
		}
	}

	if _, err = tx.ExecContext(ctx, `DELETE FROM traces WHERE host_observation_id = ?`, hostObservationID); err != nil {
		return err
	}
	if host.Trace != nil {
		res, traceErr := tx.ExecContext(
			ctx,
			`INSERT INTO traces (host_observation_id, proto, port) VALUES (?, ?, ?)`,
			hostObservationID,
			nullString(host.Trace.Proto),
			host.Trace.Port,
		)
		if traceErr != nil {
			return traceErr
		}
		traceID, traceErr := res.LastInsertId()
		if traceErr != nil {
			return traceErr
		}
		for _, hop := range host.Trace.Hops {
			if _, err = tx.ExecContext(
				ctx,
				`INSERT INTO trace_hops (trace_id, ttl, ip_address, rtt, host) VALUES (?, ?, ?, ?, ?)`,
				traceID,
				hop.TTL,
				nullString(hop.IP),
				hop.RTT,
				nullString(hop.Host),
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func resolveDevice(ctx context.Context, tx *sql.Tx, sessionID int64, observedAt time.Time, networkID *int64, host parser.Host) (int64, string, string, string, error) {
	primaryIP := host.PrimaryIP()
	if primaryIP == "" {
		return 0, "", "", "", fmt.Errorf("host has no primary ip")
	}

	mac, vendor := host.MAC()
	deviceID, found, err := findDeviceByMAC(ctx, tx, mac)
	if err != nil {
		return 0, "", "", "", err
	}

	if !found && primaryIP != "" {
		deviceID, found, err = findDeviceByIP(ctx, tx, primaryIP)
		if err != nil {
			return 0, "", "", "", err
		}
	}
	if !found && mac == "" {
		deviceID, found, err = findDeviceByFallback(ctx, tx, "ip:"+primaryIP)
		if err != nil {
			return 0, "", "", "", err
		}
	}

	timestamp := observedAt.UTC().Format(time.RFC3339Nano)
	if !found {
		res, execErr := tx.ExecContext(
			ctx,
			`INSERT INTO devices (mac, fallback_key, vendor, first_seen_session_id, last_seen_session_id, first_seen_at, last_seen_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			nullString(mac),
			fallbackKey(mac, primaryIP),
			nullString(vendor),
			sessionID,
			sessionID,
			timestamp,
			timestamp,
		)
		if execErr != nil {
			return 0, "", "", "", execErr
		}
		deviceID, err = res.LastInsertId()
		if err != nil {
			return 0, "", "", "", err
		}
	} else {
		_, err = tx.ExecContext(
			ctx,
			`UPDATE devices
			 SET mac = CASE WHEN (mac IS NULL OR mac = '') AND ? <> '' THEN ? ELSE mac END,
			     fallback_key = CASE WHEN (? <> '') THEN fallback_key ELSE COALESCE(fallback_key, ?) END,
			     vendor = CASE WHEN (vendor IS NULL OR vendor = '') AND ? <> '' THEN ? ELSE vendor END,
			     last_seen_session_id = ?,
			     last_seen_at = ?
			 WHERE id = ?`,
			mac,
			mac,
			mac,
			fallbackKey(mac, primaryIP),
			vendor,
			vendor,
			sessionID,
			timestamp,
			deviceID,
		)
		if err != nil {
			return 0, "", "", "", err
		}
	}

	_, err = tx.ExecContext(
		ctx,
		`INSERT INTO device_ip_addresses
		 (device_id, ip_address, ip_version, network_id, first_seen_session_id, last_seen_session_id, first_seen_at, last_seen_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(device_id, ip_address) DO UPDATE SET
		     network_id = COALESCE(excluded.network_id, device_ip_addresses.network_id),
		     last_seen_session_id = excluded.last_seen_session_id,
		     last_seen_at = excluded.last_seen_at`,
		deviceID,
		primaryIP,
		ipVersion(primaryIP),
		nullableInt64(networkID),
		sessionID,
		sessionID,
		timestamp,
		timestamp,
	)
	if err != nil {
		return 0, "", "", "", err
	}

	return deviceID, primaryIP, mac, vendor, nil
}

func findDeviceByMAC(ctx context.Context, tx *sql.Tx, mac string) (int64, bool, error) {
	if mac == "" {
		return 0, false, nil
	}
	var id int64
	err := tx.QueryRowContext(ctx, `SELECT id FROM devices WHERE mac = ?`, mac).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return id, true, nil
}

func findDeviceByIP(ctx context.Context, tx *sql.Tx, ip string) (int64, bool, error) {
	var id int64
	err := tx.QueryRowContext(
		ctx,
		`SELECT device_id
		 FROM device_ip_addresses
		 WHERE ip_address = ?
		 ORDER BY last_seen_session_id DESC
		 LIMIT 1`,
		ip,
	).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return id, true, nil
}

func findDeviceByFallback(ctx context.Context, tx *sql.Tx, fallback string) (int64, bool, error) {
	var id int64
	err := tx.QueryRowContext(ctx, `SELECT id FROM devices WHERE fallback_key = ?`, fallback).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return id, true, nil
}

func ensureNetwork(tx *sql.Tx, target string) (*int64, error) {
	if _, _, err := net.ParseCIDR(target); err != nil {
		return nil, nil
	}
	if _, err := tx.Exec(`INSERT INTO networks (cidr) VALUES (?) ON CONFLICT(cidr) DO NOTHING`, target); err != nil {
		return nil, err
	}
	var id int64
	if err := tx.QueryRow(`SELECT id FROM networks WHERE cidr = ?`, target).Scan(&id); err != nil {
		return nil, err
	}
	return &id, nil
}

func mergeHost(discovery parser.Host, detail parser.Host) parser.Host {
	merged := detail
	if merged.Status == "" {
		merged.Status = discovery.Status
	}
	if len(merged.Addresses) == 0 {
		merged.Addresses = discovery.Addresses
	}
	if len(merged.Hostnames) == 0 {
		merged.Hostnames = discovery.Hostnames
	}
	if len(merged.OSMatches) == 0 {
		merged.OSMatches = discovery.OSMatches
	}
	if len(merged.Ports) == 0 {
		merged.Ports = discovery.Ports
	}
	if merged.Trace == nil {
		merged.Trace = discovery.Trace
	}
	if len(merged.Scripts) == 0 {
		merged.Scripts = discovery.Scripts
	}
	return merged
}

func firstDetailCommand(commands map[string][]string) string {
	if len(commands) == 0 {
		return ""
	}
	keys := make([]string, 0, len(commands))
	for key := range commands {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return strings.Join(commands[keys[0]], " ")
}

func fallbackKey(mac, ip string) any {
	if mac != "" {
		return nil
	}
	return "ip:" + ip
}

func ipVersion(ip string) int {
	if strings.Contains(ip, ":") {
		return 6
	}
	return 4
}

func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableInt64(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}
