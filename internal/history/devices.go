package history

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"nmaper/internal/fuzzy"
)

type deviceRow struct {
	ID          int64
	MAC         string
	Vendor      string
	FallbackKey string
	Appearances int
	IPs         []string
}

func (s *Service) Devices(ctx context.Context, vendor string, macOnly, ipOnly bool) (DeviceAnalyticsReport, error) {
	devices, err := s.loadDevices(ctx)
	if err != nil {
		return DeviceAnalyticsReport{}, err
	}
	filtered := filterDevices(devices, "", vendor, macOnly, ipOnly)

	report := DeviceAnalyticsReport{UniqueDevices: len(filtered)}
	vendorCounts := make(map[string]int)
	for _, device := range filtered {
		stat := DeviceStat{
			DeviceID:    device.ID,
			Label:       deviceLabel(device),
			MAC:         device.MAC,
			Vendor:      device.Vendor,
			Appearances: device.Appearances,
			IPs:         append([]string(nil), device.IPs...),
		}
		report.TopDevices = append(report.TopDevices, stat)
		if device.MAC != "" {
			report.MACBacked++
		} else {
			report.IPOnly++
		}
		if device.Vendor != "" {
			vendorCounts[device.Vendor]++
		}
		if len(device.IPs) > 1 {
			report.MultiIP = append(report.MultiIP, stat)
		}
	}

	for vendorName, count := range vendorCounts {
		report.TopVendors = append(report.TopVendors, VendorStat{Vendor: vendorName, Count: count})
	}
	sort.Slice(report.TopDevices, func(i, j int) bool {
		if report.TopDevices[i].Appearances == report.TopDevices[j].Appearances {
			return report.TopDevices[i].Label < report.TopDevices[j].Label
		}
		return report.TopDevices[i].Appearances > report.TopDevices[j].Appearances
	})
	sort.Slice(report.MultiIP, func(i, j int) bool {
		if len(report.MultiIP[i].IPs) == len(report.MultiIP[j].IPs) {
			return report.MultiIP[i].Label < report.MultiIP[j].Label
		}
		return len(report.MultiIP[i].IPs) > len(report.MultiIP[j].IPs)
	})
	sort.Slice(report.TopVendors, func(i, j int) bool {
		if report.TopVendors[i].Count == report.TopVendors[j].Count {
			return report.TopVendors[i].Vendor < report.TopVendors[j].Vendor
		}
		return report.TopVendors[i].Count > report.TopVendors[j].Count
	})
	if len(report.TopDevices) > 10 {
		report.TopDevices = report.TopDevices[:10]
	}
	if len(report.MultiIP) > 10 {
		report.MultiIP = report.MultiIP[:10]
	}
	if len(report.TopVendors) > 10 {
		report.TopVendors = report.TopVendors[:10]
	}
	return report, nil
}

func (s *Service) DeviceHistory(ctx context.Context, query, vendor string, macOnly, ipOnly bool) (DeviceHistoryReport, error) {
	devices, err := s.loadDevices(ctx)
	if err != nil {
		return DeviceHistoryReport{}, err
	}
	filtered := filterDevices(devices, query, vendor, macOnly, ipOnly)
	report := DeviceHistoryReport{Query: query}

	for _, device := range filtered {
		appearances, err := s.loadDeviceAppearances(ctx, device.ID)
		if err != nil {
			return DeviceHistoryReport{}, err
		}
		report.Devices = append(report.Devices, DeviceHistory{
			DeviceID:    device.ID,
			Label:       deviceLabel(device),
			MAC:         device.MAC,
			Vendor:      device.Vendor,
			IPs:         append([]string(nil), device.IPs...),
			Appearances: appearances,
		})
	}
	sort.Slice(report.Devices, func(i, j int) bool {
		return report.Devices[i].Label < report.Devices[j].Label
	})
	return report, nil
}

func (s *Service) loadDevices(ctx context.Context) ([]deviceRow, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT d.id, COALESCE(d.mac, ''), COALESCE(d.vendor, ''), COALESCE(d.fallback_key, ''), COUNT(DISTINCT ho.session_id)
		 FROM devices d
		 LEFT JOIN host_observations ho ON ho.device_id = d.id
		 GROUP BY d.id
		 ORDER BY d.id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []deviceRow
	for rows.Next() {
		var device deviceRow
		if err := rows.Scan(&device.ID, &device.MAC, &device.Vendor, &device.FallbackKey, &device.Appearances); err != nil {
			return nil, err
		}
		device.IPs, err = s.loadDeviceIPs(ctx, device.ID)
		if err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}
	return devices, rows.Err()
}

func (s *Service) loadDeviceIPs(ctx context.Context, deviceID int64) ([]string, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT ip_address FROM device_ip_addresses WHERE device_id = ? ORDER BY ip_address`,
		deviceID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, rows.Err()
}

func (s *Service) loadDeviceAppearances(ctx context.Context, deviceID int64) ([]DeviceAppearance, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT ho.id, ho.primary_ip, COALESCE(ho.status, ''),
		        s.id, COALESCE(s.name, ''), s.status, s.started_at, s.completed_at, s.target, s.duration_ms, s.discovered_hosts, s.live_hosts, COALESCE(s.nmap_version, '')
		 FROM host_observations ho
		 JOIN scan_sessions s ON s.id = ho.session_id
		 WHERE ho.device_id = ?
		 ORDER BY s.started_at`,
		deviceID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var appearances []DeviceAppearance
	for rows.Next() {
		var (
			hostObservationID int64
			ip                string
			status            string
			session           SessionSummary
			startedAtRaw      string
			completedAtRaw    sql.NullString
			durationMS        int64
		)
		if err := rows.Scan(
			&hostObservationID,
			&ip,
			&status,
			&session.ID,
			&session.Name,
			&session.Status,
			&startedAtRaw,
			&completedAtRaw,
			&session.Target,
			&durationMS,
			&session.DiscoveredHosts,
			&session.LiveHosts,
			&session.NmapVersion,
		); err != nil {
			return nil, err
		}
		startedAt, err := time.Parse(time.RFC3339Nano, startedAtRaw)
		if err != nil {
			return nil, err
		}
		session.StartedAt = startedAt
		session.Duration = (time.Duration(durationMS) * time.Millisecond).String()
		if completedAtRaw.Valid && completedAtRaw.String != "" {
			completedAt, err := time.Parse(time.RFC3339Nano, completedAtRaw.String)
			if err != nil {
				return nil, err
			}
			session.CompletedAt = &completedAt
		}

		openPorts, err := s.loadOpenPortsByHostObservation(ctx, hostObservationID)
		if err != nil {
			return nil, err
		}
		topOS, err := s.loadTopOS(ctx, hostObservationID)
		if err != nil {
			return nil, err
		}
		appearances = append(appearances, DeviceAppearance{
			Session:   session,
			IP:        ip,
			Status:    status,
			OpenPorts: openPorts,
			TopOS:     topOS,
		})
	}
	return appearances, rows.Err()
}

func (s *Service) loadOpenPortsByHostObservation(ctx context.Context, hostObservationID int64) ([]string, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT port, protocol FROM service_observations
		 WHERE host_observation_id = ? AND state = 'open'
		 ORDER BY port, protocol`,
		hostObservationID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var port int
		var protocol string
		if err := rows.Scan(&port, &protocol); err != nil {
			return nil, err
		}
		out = append(out, fmt.Sprintf("%d/%s", port, protocol))
	}
	return out, rows.Err()
}

func (s *Service) loadTopOS(ctx context.Context, hostObservationID int64) (string, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT COALESCE(name, '') FROM os_matches
		 WHERE host_observation_id = ?
		 ORDER BY accuracy DESC, id ASC
		 LIMIT 1`,
		hostObservationID,
	)
	var name string
	if err := row.Scan(&name); err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return name, nil
}

func filterDevices(devices []deviceRow, query, vendor string, macOnly, ipOnly bool) []deviceRow {
	filtered := make([]deviceRow, 0, len(devices))
	for _, device := range devices {
		if macOnly && device.MAC == "" {
			continue
		}
		if ipOnly && device.MAC != "" {
			continue
		}
		if vendor != "" && !fuzzy.Match(device.Vendor, vendor) {
			continue
		}
		if query != "" {
			match := fuzzy.Match(device.MAC, query) || fuzzy.Match(device.Vendor, query) || fuzzy.Match(device.FallbackKey, query)
			if !match {
				for _, ip := range device.IPs {
					if fuzzy.Match(ip, query) {
						match = true
						break
					}
				}
			}
			if !match {
				continue
			}
		}
		filtered = append(filtered, device)
	}
	return filtered
}

func deviceLabel(device deviceRow) string {
	if device.MAC != "" {
		return device.MAC
	}
	if strings.HasPrefix(device.FallbackKey, "ip:") {
		return strings.TrimPrefix(device.FallbackKey, "ip:")
	}
	return device.FallbackKey
}
