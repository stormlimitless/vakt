package store_test

import (
	"database/sql"
	"testing"
	"time"

	"github.com/stormlimitless/vakt/internal/store"
)

func openTest(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenCreatesTables(t *testing.T) {
	s := openTest(t)
	var n int
	err := s.DB().QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('sites','users','site_users','sessions','attempts','setup_tokens')`).Scan(&n)
	if err != nil || n != 6 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestSiteRoundTrip(t *testing.T) {
	s := openTest(t)
	site := &store.Site{Host: "app.example.com", Upstream: "http://app:3000", Methods: []string{"pin", "users"},
		PinHash: "h", SessionTTL: time.Hour, Allowlist: []string{"10.0.0.0/8"}, RequireTOTP: true}
	if err := s.UpsertSite(site); err != nil || site.ID == 0 {
		t.Fatalf("id=%d err=%v", site.ID, err)
	}
	got, err := s.SiteByHost("app.example.com")
	if err != nil || got.Upstream != "http://app:3000" || len(got.Methods) != 2 || got.PinHash != "h" || got.SessionTTL != time.Hour || got.Allowlist[0] != "10.0.0.0/8" || !got.RequireTOTP || !got.Has("pin") {
		t.Fatalf("mismatch: %+v %v", got, err)
	}
	site.Upstream = "http://app:4000"
	if err := s.UpsertSite(site); err != nil {
		t.Fatal(err)
	}
	list, _ := s.ListSites()
	if len(list) != 1 || list[0].Upstream != "http://app:4000" {
		t.Fatalf("upsert did not update: %+v", list)
	}
	if _, err := s.SiteByHost("nope"); err != sql.ErrNoRows {
		t.Fatalf("want ErrNoRows, got %v", err)
	}
	site.Host = "renamed.example.com"
	if err := s.UpdateSite(site); err != nil {
		t.Fatal(err)
	}
	if got, err := s.SiteByID(site.ID); err != nil || got.Host != "renamed.example.com" {
		t.Fatalf("update by id failed: %+v %v", got, err)
	}
	u := &store.User{Username: "x", PasswordHash: "h", Role: "member"}
	s.CreateUser(u)
	s.SetSiteUsers(site.ID, []int64{u.ID})
	if ok, _ := s.UserAllowedOnSite(site.ID, u.ID); !ok {
		t.Fatal("user not allowed")
	}
	if ids, _ := s.SiteUserIDs(site.ID); len(ids) != 1 || ids[0] != u.ID {
		t.Fatalf("ids=%v", ids)
	}
	if err := s.DeleteSite(site.ID); err != nil {
		t.Fatal(err)
	}
	if list, _ = s.ListSites(); len(list) != 0 {
		t.Fatal("not deleted")
	}
}

func TestUserRoundTrip(t *testing.T) {
	s := openTest(t)
	u := &store.User{Username: "henri", PasswordHash: "h", Role: "admin"}
	if err := s.CreateUser(u); err != nil || u.ID == 0 {
		t.Fatal(err)
	}
	if n, _ := s.CountAdmins(); n != 1 {
		t.Fatalf("admins=%d", n)
	}
	u.TOTPSecretEnc = []byte("enc")
	u.Role = "member"
	if err := s.UpdateUser(u); err != nil {
		t.Fatal(err)
	}
	got, err := s.UserByName("henri")
	if err != nil || string(got.TOTPSecretEnc) != "enc" || got.Role != "member" {
		t.Fatalf("got %+v err %v", got, err)
	}
	if err := s.CreateUser(&store.User{Username: "henri", PasswordHash: "x", Role: "member"}); err == nil {
		t.Fatal("duplicate username allowed")
	}
	if list, _ := s.ListUsers(); len(list) != 1 {
		t.Fatal("list")
	}
	s.DeleteUser(u.ID)
	if _, err := s.UserByID(u.ID); err != sql.ErrNoRows {
		t.Fatal("not deleted")
	}
}

func TestSessionExpiry(t *testing.T) {
	s := openTest(t)
	sess := &store.Session{TokenHash: "t1", Kind: "pin", IP: "1.2.3.4", ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.CreateSession(sess); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionByTokenHash("t1"); err != nil {
		t.Fatal(err)
	}
	s.CreateSession(&store.Session{TokenHash: "t2", Kind: "pin", IP: "1.2.3.4", ExpiresAt: time.Now().Add(-time.Second)})
	if _, err := s.SessionByTokenHash("t2"); err != sql.ErrNoRows {
		t.Fatalf("expired session returned: %v", err)
	}
	if err := s.PurgeExpiredSessions(); err != nil {
		t.Fatal(err)
	}
	if counts, _ := s.CountActiveSessions(); counts[0] != 1 {
		t.Fatalf("counts=%v", counts)
	}
	s.DeleteSession(sess.ID)
	if _, err := s.SessionByTokenHash("t1"); err != sql.ErrNoRows {
		t.Fatal("not deleted")
	}
}

func TestAttempts(t *testing.T) {
	s := openTest(t)
	a, err := s.GetAttempt(1, "1.1.1.1")
	if err != nil || a.Count != 0 {
		t.Fatalf("%+v %v", a, err)
	}
	a.Count = 3
	a.LockedUntil = time.Now().Add(time.Minute)
	if err := s.PutAttempt(a); err != nil {
		t.Fatal(err)
	}
	if locked, _ := s.ListLocked(); len(locked) != 1 || locked[0].Count != 3 {
		t.Fatalf("%+v", locked)
	}
	s.DeleteAttempt(1, "1.1.1.1")
	if a, _ = s.GetAttempt(1, "1.1.1.1"); a.Count != 0 {
		t.Fatal("not deleted")
	}
}

func TestSetupToken(t *testing.T) {
	s := openTest(t)
	s.PutSetupToken("h", time.Now().Add(time.Hour))
	if ok, _ := s.ConsumeSetupToken("h"); !ok {
		t.Fatal("want ok")
	}
	if ok, _ := s.ConsumeSetupToken("h"); ok {
		t.Fatal("token reused")
	}
	s.PutSetupToken("old", time.Now().Add(-time.Hour))
	if ok, _ := s.ConsumeSetupToken("old"); ok {
		t.Fatal("expired token accepted")
	}
}

// Branding columns are added by migrate(), not the CREATE TABLE, so a database
// created by an older build must gain them on open without losing its rows.
func TestMigrateAddsBrandingToExistingDB(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`ALTER TABLE sites DROP COLUMN theme`); err != nil {
		t.Fatal(err)
	}
	site := &store.Site{Host: "old.example.com", Upstream: "http://a", Methods: []string{"pin"}, SessionTTL: time.Hour}
	if _, err := s.DB().Exec(`INSERT INTO sites (host, upstream, methods, session_ttl_seconds, allowlist, require_totp, created_at, updated_at)
		VALUES (?,?,?,?,'[]',0,0,0)`, site.Host, site.Upstream, "pin", 3600); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s2, err := store.Open(dir)
	if err != nil {
		t.Fatalf("reopen after schema drift: %v", err)
	}
	defer s2.Close()
	got, err := s2.SiteByHost("old.example.com")
	if err != nil || got.Theme != "" {
		t.Fatalf("got %+v err %v", got, err)
	}
	got.Theme, got.Accent, got.LogoURL, got.Heading = "dark", "#2563eb", "https://x/logo.svg", "Acme"
	if err := s2.UpdateSite(got); err != nil {
		t.Fatal(err)
	}
	again, _ := s2.SiteByHost("old.example.com")
	if again.Theme != "dark" || again.Accent != "#2563eb" || again.Heading != "Acme" || again.Title() != "Acme" {
		t.Fatalf("branding round trip: %+v", again)
	}
}

func TestSiteTitleFallsBackToHost(t *testing.T) {
	s := &store.Site{Host: "a.example.com"}
	if s.Title() != "a.example.com" {
		t.Fatal("empty heading should fall back to host")
	}
}
