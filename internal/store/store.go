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
	return &Store{db: db}, nil
}

// DB exposes the underlying handle for query code in other files/packages.
func (s *Store) DB() *sql.DB { return s.db }

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }
