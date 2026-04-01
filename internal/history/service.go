package history

import (
	"context"
	"database/sql"
	"fmt"
	"sort"

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
	return compareHosts(leftSummary, leftHosts, rightSummary, rightHosts), nil
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

func reverseSessions(items []SessionSummary) {
	for left, right := 0, len(items)-1; left < right; left, right = left+1, right-1 {
		items[left], items[right] = items[right], items[left]
	}
}
