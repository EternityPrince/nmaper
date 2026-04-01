package storage

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strings"
	"time"

	"nmaper/internal/parser"
)

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
