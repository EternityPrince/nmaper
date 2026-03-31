package storage_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"nmaper/internal/model"
	"nmaper/internal/storage"
	"nmaper/internal/testutil"
)

func TestPersistCompletedSessionStoresFacts(t *testing.T) {
	t.Parallel()

	fixture := testutil.SeedHistoryDB(t)
	store, err := storage.Open(fixture.DBPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ok, err := store.HasSession(context.Background(), fixture.Session1ID)
	if err != nil {
		t.Fatalf("HasSession: %v", err)
	}
	if !ok {
		t.Fatalf("expected session %d to exist", fixture.Session1ID)
	}

	assertCount(t, store, "scan_sessions", 2)
	assertCount(t, store, "devices", 3)
	assertCount(t, store, "host_observations", 5)
	assertCount(t, store, "service_observations", 6)
	assertCount(t, store, "device_ip_addresses", 4)
	assertCount(t, store, "traces", 2)
	assertCount(t, store, "script_results", 16)
	assertCount(t, store, "tls_fingerprints", 2)
	assertCount(t, store, "ssh_fingerprints", 1)
	assertCount(t, store, "http_fingerprints", 4)
	assertCount(t, store, "vulnerability_findings", 3)
	assertCount(t, store, "management_surfaces", 5)

	var status string
	var scanLevel string
	var discoveredHosts int
	var liveHosts int
	err = store.DB().QueryRowContext(
		context.Background(),
		`SELECT status, COALESCE(scan_level, ''), discovered_hosts, live_hosts FROM scan_sessions WHERE id = ?`,
		fixture.Session2ID,
	).Scan(&status, &scanLevel, &discoveredHosts, &liveHosts)
	if err != nil {
		t.Fatalf("query session: %v", err)
	}
	if status != "completed" || scanLevel != "mid" || discoveredHosts != 3 || liveHosts != 3 {
		t.Fatalf("unexpected session aggregate: status=%s level=%s discovered=%d live=%d", status, scanLevel, discoveredHosts, liveHosts)
	}
}

func TestDeleteSessionRebuildsMetadata(t *testing.T) {
	t.Parallel()

	fixture := testutil.SeedHistoryDB(t)
	store, err := storage.Open(fixture.DBPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if err := store.DeleteSession(context.Background(), fixture.Session1ID); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	assertCount(t, store, "scan_sessions", 1)
	assertCount(t, store, "device_ip_addresses", 3)

	var firstSeen int64
	var lastSeen int64
	err = store.DB().QueryRowContext(
		context.Background(),
		`SELECT first_seen_session_id, last_seen_session_id FROM devices WHERE mac = ?`,
		fixture.DeviceMAC,
	).Scan(&firstSeen, &lastSeen)
	if err != nil {
		t.Fatalf("query device metadata: %v", err)
	}
	if firstSeen != fixture.Session2ID || lastSeen != fixture.Session2ID {
		t.Fatalf("unexpected metadata after delete: first=%d last=%d", firstSeen, lastSeen)
	}

	var count int
	err = store.DB().QueryRowContext(
		context.Background(),
		`SELECT COUNT(1) FROM device_ip_addresses WHERE ip_address = '10.0.0.10'`,
	).Scan(&count)
	if err != nil {
		t.Fatalf("query deleted ip: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected deleted IP metadata to be removed, got %d rows", count)
	}
}

func TestDeleteAllAndMarkFailed(t *testing.T) {
	t.Parallel()

	store, err := storage.Open(filepathDB(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	opts := model.DefaultOptions()
	opts.Target = "127.0.0.1"
	sessionID, err := store.BeginSession(context.Background(), opts, "failed-session", testTime())
	if err != nil {
		t.Fatalf("BeginSession: %v", err)
	}
	if err := store.MarkSessionFailed(context.Background(), sessionID, errors.New("boom")); err != nil {
		t.Fatalf("MarkSessionFailed: %v", err)
	}

	var status string
	var errorText string
	err = store.DB().QueryRowContext(
		context.Background(),
		`SELECT status, error_text FROM scan_sessions WHERE id = ?`,
		sessionID,
	).Scan(&status, &errorText)
	if err != nil {
		t.Fatalf("query failed session: %v", err)
	}
	if status != "failed" || errorText != "boom" {
		t.Fatalf("unexpected failed session state: status=%s error=%s", status, errorText)
	}

	fixture := testutil.SeedHistoryDB(t)
	store2, err := storage.Open(fixture.DBPath)
	if err != nil {
		t.Fatalf("open seeded store: %v", err)
	}
	defer store2.Close()

	if err := store2.DeleteAll(context.Background()); err != nil {
		t.Fatalf("DeleteAll: %v", err)
	}
	assertCount(t, store2, "scan_sessions", 0)
	assertCount(t, store2, "devices", 0)
}

func assertCount(t *testing.T, store *storage.Store, table string, want int) {
	t.Helper()

	var got int
	err := store.DB().QueryRowContext(context.Background(), `SELECT COUNT(1) FROM `+table).Scan(&got)
	if err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	if got != want {
		t.Fatalf("unexpected row count for %s: want %d got %d", table, want, got)
	}
}

func filepathDB(t *testing.T) string {
	t.Helper()
	return t.TempDir() + "/failed.db"
}

func testTime() time.Time {
	return time.Date(2026, 3, 3, 10, 0, 0, 0, time.UTC)
}
