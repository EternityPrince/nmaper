package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"nmaper/internal/parser"
	"nmaper/internal/snapshot"
)

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
