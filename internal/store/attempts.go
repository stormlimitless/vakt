package store

import (
	"database/sql"
	"errors"
	"time"
)

type Attempt struct {
	SiteID      int64
	IP          string
	Count       int
	LockedUntil time.Time
}

func (s *Store) GetAttempt(siteID int64, ip string) (*Attempt, error) {
	a := &Attempt{SiteID: siteID, IP: ip}
	var locked int64
	err := s.db.QueryRow(`SELECT count, locked_until FROM attempts WHERE site_id=? AND ip=?`, siteID, ip).Scan(&a.Count, &locked)
	if errors.Is(err, sql.ErrNoRows) {
		return a, nil
	}
	if err != nil {
		return nil, err
	}
	a.LockedUntil = time.Unix(locked, 0)
	return a, nil
}

func (s *Store) PutAttempt(a *Attempt) error {
	_, err := s.db.Exec(`INSERT INTO attempts (site_id, ip, count, locked_until, updated_at) VALUES (?,?,?,?,?)
		ON CONFLICT(site_id, ip) DO UPDATE SET count=excluded.count, locked_until=excluded.locked_until, updated_at=excluded.updated_at`,
		a.SiteID, a.IP, a.Count, a.LockedUntil.Unix(), time.Now().Unix())
	return err
}

func (s *Store) DeleteAttempt(siteID int64, ip string) error {
	_, err := s.db.Exec(`DELETE FROM attempts WHERE site_id=? AND ip=?`, siteID, ip)
	return err
}

func (s *Store) ListLocked() ([]Attempt, error) {
	rows, err := s.db.Query(`SELECT site_id, ip, count, locked_until FROM attempts WHERE locked_until > ? ORDER BY locked_until DESC`, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Attempt
	for rows.Next() {
		var a Attempt
		var locked int64
		if err := rows.Scan(&a.SiteID, &a.IP, &a.Count, &locked); err != nil {
			return nil, err
		}
		a.LockedUntil = time.Unix(locked, 0)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) PutSetupToken(hash string, expires time.Time) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO setup_tokens (token_hash, expires_at) VALUES (?,?)`, hash, expires.Unix())
	return err
}

func (s *Store) ConsumeSetupToken(hash string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM setup_tokens WHERE token_hash=? AND expires_at > ?`, hash, time.Now().Unix())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}
