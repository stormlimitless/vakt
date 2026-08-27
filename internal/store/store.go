package store

import (
	"database/sql"
	"path/filepath"

	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

type scanner interface{ Scan(...any) error }

const schema = `
CREATE TABLE IF NOT EXISTS sites (
	id INTEGER PRIMARY KEY,
	host TEXT NOT NULL UNIQUE,
	upstream TEXT NOT NULL,
	methods TEXT NOT NULL DEFAULT '',
	pin_hash TEXT,
	password_hash TEXT,
	session_ttl_seconds INTEGER NOT NULL DEFAULT 604800,
	allowlist TEXT NOT NULL DEFAULT '[]',
	require_totp INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY,
	username TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	totp_secret_enc BLOB,
	totp_last_used INTEGER NOT NULL DEFAULT 0,
	role TEXT NOT NULL CHECK(role IN ('admin','member')),
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS site_users (
	site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	PRIMARY KEY (site_id, user_id)
);
CREATE TABLE IF NOT EXISTS sessions (
	id INTEGER PRIMARY KEY,
	token_hash TEXT NOT NULL UNIQUE,
	site_id INTEGER REFERENCES sites(id) ON DELETE CASCADE,
	user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
	kind TEXT NOT NULL,
	ip TEXT NOT NULL,
	expires_at INTEGER NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_expires ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS attempts (
	site_id INTEGER NOT NULL,
	ip TEXT NOT NULL,
	count INTEGER NOT NULL DEFAULT 0,
	locked_until INTEGER NOT NULL DEFAULT 0,
	updated_at INTEGER NOT NULL,
	PRIMARY KEY (site_id, ip)
);
CREATE TABLE IF NOT EXISTS setup_tokens (
	token_hash TEXT PRIMARY KEY,
	expires_at INTEGER NOT NULL
);
`

func Open(dir string) (*Store, error) {
	dsn := filepath.Join(dir, "vakt.db") + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) DB() *sql.DB  { return s.db }
func (s *Store) Close() error { return s.db.Close() }
