// Package store wraps the SQLite database that holds scan jobs and findings.
// v1 uses a single-file SQLite DB on the persistent volume (no Postgres) — see
// docs/codescan-v1-plan.md §3.
package store

import (
	"database/sql"
	_ "embed"
	"fmt"

	_ "modernc.org/sqlite" // pure-Go driver, no cgo (registers "sqlite")
)

//go:embed schema.sql
var schemaSQL string

// Store owns the SQLite connection pool.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the SQLite database at dbPath and applies the
// schema idempotently. The schema is safe to re-run on every startup.
func Open(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", dbPath, err)
	}
	// SQLite is a single-writer store; one connection keeps v1 free of
	// SQLITE_BUSY without a connection-pool retry layer.
	db.SetMaxOpenConns(1)

	for _, pragma := range []string{
		"PRAGMA busy_timeout = 5000;",
		"PRAGMA journal_mode = WAL;",
		"PRAGMA foreign_keys = ON;",
	} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("pragma %q: %w", pragma, err)
		}
	}

	if _, err := db.Exec(schemaSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	// Schema evolution for DBs created before a column existed. CREATE TABLE IF
	// NOT EXISTS above does NOT add columns to an existing table, so add them
	// idempotently here (keeps existing scan history intact).
	for _, col := range []string{"relationship", "usage"} {
		if err := addColumnIfMissing(db, "findings", col, "TEXT"); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	return &Store{db: db}, nil
}

// addColumnIfMissing runs ALTER TABLE ... ADD COLUMN only when the column is not
// already present, so it is safe to call on every startup.
func addColumnIfMissing(db *sql.DB, table, column, typ string) error {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return fmt.Errorf("inspect %s: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid, notnull, pk int
			name, ctype      string
			dflt             sql.NullString
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == column {
			return nil // already present
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if _, err := db.Exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + typ); err != nil {
		return fmt.Errorf("add column %s.%s: %w", table, column, err)
	}
	return nil
}

// DB exposes the underlying handle for query code in other files/packages.
func (s *Store) DB() *sql.DB { return s.db }

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }
