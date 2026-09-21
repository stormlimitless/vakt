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
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Columns added after the first release. SQLite has no ADD COLUMN IF NOT
// EXISTS, so each one is only applied when the table does not already have it.
// Both fresh and existing databases go through here, which keeps the column
// list in one place rather than duplicated in the CREATE TABLE above.
var addedColumns = []struct{ table, column, ddl string }{
	{"sites", "theme", "ALTER TABLE sites ADD COLUMN theme TEXT NOT NULL DEFAULT ''"},
	{"sites", "logo_url", "ALTER TABLE sites ADD COLUMN logo_url TEXT NOT NULL DEFAULT ''"},
	{"sites", "accent", "ALTER TABLE sites ADD COLUMN accent TEXT NOT NULL DEFAULT ''"},
	{"sites", "heading", "ALTER TABLE sites ADD COLUMN heading TEXT NOT NULL DEFAULT ''"},
}

func migrate(db *sql.DB) error {
	for _, c := range addedColumns {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM pragma_table_info(?) WHERE name=?`, c.table, c.column).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		if _, err := db.Exec(c.ddl); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) DB() *sql.DB  { return s.db }
func (s *Store) Close() error { return s.db.Close() }
