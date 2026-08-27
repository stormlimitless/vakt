package store

import (
	"encoding/json"
	"strings"
	"time"
)

type Site struct {
	ID           int64
	Host         string
	Upstream     string
	Methods      []string
	PinHash      string
	PasswordHash string
	SessionTTL   time.Duration
	Allowlist    []string
	RequireTOTP  bool
}

func (s *Site) Has(method string) bool {
	for _, m := range s.Methods {
		if m == method {
			return true
		}
	}
	return false
}

const siteCols = `id, host, upstream, methods, coalesce(pin_hash,''), coalesce(password_hash,''), session_ttl_seconds, allowlist, require_totp`

func scanSite(row scanner) (*Site, error) {
	var st Site
	var methods, allow string
	var ttl int64
	if err := row.Scan(&st.ID, &st.Host, &st.Upstream, &methods, &st.PinHash, &st.PasswordHash, &ttl, &allow, &st.RequireTOTP); err != nil {
		return nil, err
	}
	if methods != "" {
		st.Methods = strings.Split(methods, ",")
	}
	st.SessionTTL = time.Duration(ttl) * time.Second
	if err := json.Unmarshal([]byte(allow), &st.Allowlist); err != nil {
		return nil, err
	}
	return &st, nil
}

func nullIfEmpty(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func (s *Store) UpsertSite(site *Site) error {
	allow := []byte("[]")
	if len(site.Allowlist) > 0 {
		allow, _ = json.Marshal(site.Allowlist)
	}
	now := time.Now().Unix()
	_, err := s.db.Exec(`INSERT INTO sites (host, upstream, methods, pin_hash, password_hash, session_ttl_seconds, allowlist, require_totp, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(host) DO UPDATE SET upstream=excluded.upstream, methods=excluded.methods, pin_hash=excluded.pin_hash,
		password_hash=excluded.password_hash, session_ttl_seconds=excluded.session_ttl_seconds, allowlist=excluded.allowlist,
		require_totp=excluded.require_totp, updated_at=excluded.updated_at`,
		site.Host, site.Upstream, strings.Join(site.Methods, ","), nullIfEmpty(site.PinHash), nullIfEmpty(site.PasswordHash),
		int64(site.SessionTTL.Seconds()), string(allow), site.RequireTOTP, now, now)
	if err != nil {
		return err
	}
	return s.db.QueryRow(`SELECT id FROM sites WHERE host=?`, site.Host).Scan(&site.ID)
}

func (s *Store) UpdateSite(site *Site) error {
	allow := []byte("[]")
	if len(site.Allowlist) > 0 {
		allow, _ = json.Marshal(site.Allowlist)
	}
	_, err := s.db.Exec(`UPDATE sites SET host=?, upstream=?, methods=?, pin_hash=?, password_hash=?, session_ttl_seconds=?, allowlist=?, require_totp=?, updated_at=? WHERE id=?`,
		site.Host, site.Upstream, strings.Join(site.Methods, ","), nullIfEmpty(site.PinHash), nullIfEmpty(site.PasswordHash),
		int64(site.SessionTTL.Seconds()), string(allow), site.RequireTOTP, time.Now().Unix(), site.ID)
	return err
}

func (s *Store) SiteByHost(host string) (*Site, error) {
	return scanSite(s.db.QueryRow(`SELECT `+siteCols+` FROM sites WHERE host=?`, host))
}

func (s *Store) SiteByID(id int64) (*Site, error) {
	return scanSite(s.db.QueryRow(`SELECT `+siteCols+` FROM sites WHERE id=?`, id))
}

func (s *Store) ListSites() ([]Site, error) {
	rows, err := s.db.Query(`SELECT ` + siteCols + ` FROM sites ORDER BY host`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Site
	for rows.Next() {
		st, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *st)
	}
	return out, rows.Err()
}

func (s *Store) DeleteSite(id int64) error {
	_, err := s.db.Exec(`DELETE FROM sites WHERE id=?`, id)
	return err
}

func (s *Store) SetSiteUsers(siteID int64, userIDs []int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM site_users WHERE site_id=?`, siteID); err != nil {
		return err
	}
	for _, uid := range userIDs {
		if _, err := tx.Exec(`INSERT INTO site_users (site_id, user_id) VALUES (?,?)`, siteID, uid); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) SiteUserIDs(siteID int64) ([]int64, error) {
	rows, err := s.db.Query(`SELECT user_id FROM site_users WHERE site_id=?`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) UserAllowedOnSite(siteID, userID int64) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM site_users WHERE site_id=? AND user_id=?`, siteID, userID).Scan(&n)
	return n > 0, err
}
