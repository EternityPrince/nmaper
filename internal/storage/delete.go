package storage

import (
	"context"
	"database/sql"
	"fmt"
)

func (s *Store) DeleteSession(ctx context.Context, sessionID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	res, err := tx.ExecContext(ctx, `DELETE FROM scan_sessions WHERE id = ?`, sessionID)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("session %d not found", sessionID)
	}

	if err = rebuildMetadata(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteAll(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	statements := []string{
		`DELETE FROM trace_hops`,
		`DELETE FROM traces`,
		`DELETE FROM script_results`,
		`DELETE FROM service_observations`,
		`DELETE FROM os_matches`,
		`DELETE FROM host_observations`,
		`DELETE FROM device_ip_addresses`,
		`DELETE FROM devices`,
		`DELETE FROM session_networks`,
		`DELETE FROM networks`,
		`DELETE FROM ports`,
		`DELETE FROM scan_sessions`,
	}
	for _, statement := range statements {
		if _, err = tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func rebuildMetadata(ctx context.Context, tx *sql.Tx) error {
	deviceRows, err := tx.QueryContext(ctx, `SELECT id FROM devices`)
	if err != nil {
		return err
	}
	defer deviceRows.Close()

	var deviceIDs []int64
	for deviceRows.Next() {
		var id int64
		if err := deviceRows.Scan(&id); err != nil {
			return err
		}
		deviceIDs = append(deviceIDs, id)
	}
	if err := deviceRows.Err(); err != nil {
		return err
	}

	for _, deviceID := range deviceIDs {
		var firstID, lastID sql.NullInt64
		var firstAt, lastAt sql.NullString
		if err := tx.QueryRowContext(
			ctx,
			`SELECT MIN(ho.session_id), MAX(ho.session_id), MIN(s.started_at), MAX(s.started_at)
			 FROM host_observations ho
			 JOIN scan_sessions s ON s.id = ho.session_id
			 WHERE ho.device_id = ?`,
			deviceID,
		).Scan(&firstID, &lastID, &firstAt, &lastAt); err != nil {
			return err
		}
		if !firstID.Valid {
			if _, err := tx.ExecContext(ctx, `DELETE FROM device_ip_addresses WHERE device_id = ?`, deviceID); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM devices WHERE id = ?`, deviceID); err != nil {
				return err
			}
			continue
		}
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE devices
			 SET first_seen_session_id = ?, last_seen_session_id = ?, first_seen_at = ?, last_seen_at = ?
			 WHERE id = ?`,
			firstID.Int64,
			lastID.Int64,
			firstAt.String,
			lastAt.String,
			deviceID,
		); err != nil {
			return err
		}
	}

	ipRows, err := tx.QueryContext(ctx, `SELECT id, device_id, ip_address FROM device_ip_addresses`)
	if err != nil {
		return err
	}
	defer ipRows.Close()

	type ipRecord struct {
		ID       int64
		DeviceID int64
		IP       string
	}
	var ips []ipRecord
	for ipRows.Next() {
		var item ipRecord
		if err := ipRows.Scan(&item.ID, &item.DeviceID, &item.IP); err != nil {
			return err
		}
		ips = append(ips, item)
	}
	if err := ipRows.Err(); err != nil {
		return err
	}

	for _, item := range ips {
		var firstID, lastID sql.NullInt64
		var firstAt, lastAt sql.NullString
		if err := tx.QueryRowContext(
			ctx,
			`SELECT MIN(ho.session_id), MAX(ho.session_id), MIN(s.started_at), MAX(s.started_at)
			 FROM host_observations ho
			 JOIN scan_sessions s ON s.id = ho.session_id
			 WHERE ho.device_id = ? AND ho.primary_ip = ?`,
			item.DeviceID,
			item.IP,
		).Scan(&firstID, &lastID, &firstAt, &lastAt); err != nil {
			return err
		}
		if !firstID.Valid {
			if _, err := tx.ExecContext(ctx, `DELETE FROM device_ip_addresses WHERE id = ?`, item.ID); err != nil {
				return err
			}
			continue
		}
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE device_ip_addresses
			 SET first_seen_session_id = ?, last_seen_session_id = ?, first_seen_at = ?, last_seen_at = ?
			 WHERE id = ?`,
			firstID.Int64,
			lastID.Int64,
			firstAt.String,
			lastAt.String,
			item.ID,
		); err != nil {
			return err
		}
	}

	_, err = tx.ExecContext(ctx, `DELETE FROM networks WHERE id NOT IN (SELECT DISTINCT network_id FROM session_networks WHERE network_id IS NOT NULL)`)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM ports WHERE NOT EXISTS (SELECT 1 FROM service_observations so WHERE so.port = ports.port AND so.protocol = ports.protocol)`)
	return err
}
