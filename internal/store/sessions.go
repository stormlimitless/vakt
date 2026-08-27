package store

import (
	"database/sql"
	"time"
)

type Session struct {
	ID        int64
	TokenHash string
	SiteID    int64
	UserID    int64
	Kind      string
	IP        string
	ExpiresAt time.Time
}

func nullID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

func (s *Store) CreateSession(sess *Session) error {
	res, err := s.db.Exec(`INSERT INTO sessions (token_hash, site_id, user_id, kind, ip, expires_at, created_at) VALUES (?,?,?,?,?,?,?)`,
		sess.TokenHash, nullID(sess.SiteID), nullID(sess.UserID), sess.Kind, sess.IP, sess.ExpiresAt.Unix(), time.Now().Unix())
	if err != nil {
		return err
	}
	sess.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) SessionByTokenHash(h string) (*Session, error) {
	var sess Session
	var siteID, userID sql.NullInt64
	var exp int64
	err := s.db.QueryRow(`SELECT id, token_hash, site_id, user_id, kind, ip, expires_at FROM sessions WHERE token_hash=? AND expires_at > ?`, h, time.Now().Unix()).
		Scan(&sess.ID, &sess.TokenHash, &siteID, &userID, &sess.Kind, &sess.IP, &exp)
	if err != nil {
		return nil, err
	}
	sess.SiteID, sess.UserID = siteID.Int64, userID.Int64
	sess.ExpiresAt = time.Unix(exp, 0)
	return &sess, nil
}

func (s *Store) DeleteSession(id int64) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id=?`, id)
	return err
}

func (s *Store) PurgeExpiredSessions() error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at <= ?`, time.Now().Unix())
	return err
}

func (s *Store) CountActiveSessions() (map[int64]int, error) {
	rows, err := s.db.Query(`SELECT coalesce(site_id,0), count(*) FROM sessions WHERE expires_at > ? GROUP BY site_id`, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int{}
	for rows.Next() {
		var id int64
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}
