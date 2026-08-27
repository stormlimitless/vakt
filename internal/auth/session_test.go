package auth_test

import (
	"testing"
	"time"

	"github.com/stormlimitless/vakt/internal/auth"
	"github.com/stormlimitless/vakt/internal/store"
)

func TestSessions(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	defer st.Close()
	site := &store.Site{Host: "a.test", Upstream: "http://a"}
	st.UpsertSite(site)
	s := &auth.Sessions{Store: st}
	tok, err := s.Create(site.ID, 0, "pin", "1.2.3.4", time.Hour)
	if err != nil || tok == "" {
		t.Fatal(err)
	}
	sess, ok := s.Lookup(tok)
	if !ok || sess.SiteID != site.ID || sess.Kind != "pin" {
		t.Fatalf("ok=%v sess=%+v", ok, sess)
	}
	if _, ok := s.Lookup("nope"); ok {
		t.Fatal("bogus token accepted")
	}
	s.Delete(tok)
	if _, ok := s.Lookup(tok); ok {
		t.Fatal("deleted session still valid")
	}
}
