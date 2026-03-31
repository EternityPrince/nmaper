package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	if err := applyMigrations(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply migrations: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) DB() *sql.DB {
	return s.db
}

func (s *Store) HasSession(ctx context.Context, id int64) (bool, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM scan_sessions WHERE id = ?`, id).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func applyMigrations(db *sql.DB) error {
	if err := ensureColumn(db, "scan_sessions", "name", "TEXT"); err != nil {
		return err
	}
	if err := ensureColumn(db, "scan_sessions", "target", "TEXT"); err != nil {
		return err
	}
	if err := ensureColumn(db, "scan_sessions", "save_mode", "TEXT"); err != nil {
		return err
	}
	if err := ensureColumn(db, "scan_sessions", "completed_at", "TEXT"); err != nil {
		return err
	}
	if err := ensureColumn(db, "scan_sessions", "duration_ms", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureColumn(db, "scan_sessions", "error_text", "TEXT"); err != nil {
		return err
	}
	if err := ensureColumn(db, "scan_sessions", "scan_level", "TEXT"); err != nil {
		return err
	}
	if err := ensureColumn(db, "scan_sessions", "scanner_interface", "TEXT"); err != nil {
		return err
	}
	if err := ensureColumn(db, "scan_sessions", "scanner_real_mac", "TEXT"); err != nil {
		return err
	}
	if err := ensureColumn(db, "scan_sessions", "scanner_spoofed_mac", "TEXT"); err != nil {
		return err
	}
	if err := ensureColumn(db, "scan_sessions", "discovery_command", "TEXT"); err != nil {
		return err
	}
	if err := ensureColumn(db, "scan_sessions", "detail_command_template", "TEXT"); err != nil {
		return err
	}
	if err := ensureColumn(db, "scan_sessions", "discovered_hosts", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureColumn(db, "scan_sessions", "live_hosts", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureColumn(db, "scan_sessions", "detail_scans", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureColumn(db, "scan_sessions", "detail_errors", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := backfillLegacyScanSessionColumns(db); err != nil {
		return err
	}
	return nil
}

func backfillLegacyScanSessionColumns(db *sql.DB) error {
	if has, err := hasColumn(db, "scan_sessions", "target_input"); err != nil {
		return err
	} else if has {
		if _, err := db.Exec(`UPDATE scan_sessions SET target = COALESCE(NULLIF(target, ''), target_input)`); err != nil {
			return err
		}
	}
	if has, err := hasColumn(db, "scan_sessions", "finished_at"); err != nil {
		return err
	} else if has {
		if _, err := db.Exec(`UPDATE scan_sessions SET completed_at = COALESCE(NULLIF(completed_at, ''), finished_at)`); err != nil {
			return err
		}
	}
	if has, err := hasColumn(db, "scan_sessions", "duration_seconds"); err != nil {
		return err
	} else if has {
		if _, err := db.Exec(`UPDATE scan_sessions SET duration_ms = CASE WHEN duration_ms = 0 AND duration_seconds IS NOT NULL THEN CAST(duration_seconds * 1000 AS INTEGER) ELSE duration_ms END`); err != nil {
			return err
		}
	}
	if has, err := hasColumn(db, "scan_sessions", "nmap_command"); err != nil {
		return err
	} else if has {
		if _, err := db.Exec(`UPDATE scan_sessions SET discovery_command = COALESCE(NULLIF(discovery_command, ''), nmap_command)`); err != nil {
			return err
		}
	}
	if has, err := hasColumn(db, "scan_sessions", "notes"); err != nil {
		return err
	} else if has {
		if _, err := db.Exec(`UPDATE scan_sessions SET error_text = COALESCE(NULLIF(error_text, ''), notes)`); err != nil {
			return err
		}
	}
	if _, err := db.Exec(`UPDATE scan_sessions SET save_mode = COALESCE(NULLIF(save_mode, ''), 'db')`); err != nil {
		return err
	}
	if _, err := db.Exec(`UPDATE scan_sessions SET target = COALESCE(target, '')`); err != nil {
		return err
	}
	return nil
}

func hasColumn(db *sql.DB, tableName, columnName string) (bool, error) {
	rows, err := db.Query(`PRAGMA table_info(` + tableName + `)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid        int
			name       string
			kind       string
			notNull    int
			defaultVal sql.NullString
			primaryKey int
		)
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultVal, &primaryKey); err != nil {
			return false, err
		}
		if name == columnName {
			return true, nil
		}
	}
	return false, rows.Err()
}

func ensureColumn(db *sql.DB, tableName, columnName, columnType string) error {
	rows, err := db.Query(`PRAGMA table_info(` + tableName + `)`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid        int
			name       string
			kind       string
			notNull    int
			defaultVal sql.NullString
			primaryKey int
		)
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultVal, &primaryKey); err != nil {
			return err
		}
		if name == columnName {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	_, err = db.Exec(`ALTER TABLE ` + tableName + ` ADD COLUMN ` + columnName + ` ` + columnType)
	return err
}
