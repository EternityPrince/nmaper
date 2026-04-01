package storage

import (
	"context"
	"strings"
	"time"

	"nmaper/internal/model"
	"nmaper/internal/parser"
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
