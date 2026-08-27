package admin_test

import (
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stormlimitless/vakt/internal/auth"
)

func TestCreateEditDeleteSite(t *testing.T) {
	a, srv, client := loginAdmin(t)
	csrf := csrfFrom(t, get(t, client, srv.URL+"/admin/sites/new"))
	resp := post(t, client, srv.URL+"/admin/sites/new", url.Values{"csrf": {csrf}, "host": {"app.test"}, "upstream": {"http://app:3000"}, "methods": {"pin"}, "pin": {"1234"}, "session_ttl_hours": {"24"}, "allowlist": {"10.0.0.0/8\n"}})
	if resp.StatusCode != 303 {
		t.Fatalf("create: %d", resp.StatusCode)
	}
	site, err := a.Store.SiteByHost("app.test")
	if err != nil || !auth.VerifySecret(site.PinHash, "1234") || site.SessionTTL != 24*time.Hour || site.Allowlist[0] != "10.0.0.0/8" {
		t.Fatalf("%+v %v", site, err)
	}
	id := strconv.FormatInt(site.ID, 10)
	post(t, client, srv.URL+"/admin/sites/"+id, url.Values{"csrf": {csrf}, "host": {"app.test"}, "upstream": {"http://app:4000"}, "methods": {"pin"}, "pin": {""}, "session_ttl_hours": {"24"}})
	site, _ = a.Store.SiteByHost("app.test")
	if site.Upstream != "http://app:4000" || !auth.VerifySecret(site.PinHash, "1234") {
		t.Fatal("edit lost pin or did not update upstream")
	}
	post(t, client, srv.URL+"/admin/sites/"+id, url.Values{"csrf": {csrf}, "host": {"renamed.test"}, "upstream": {"http://app:4000"}, "methods": {"pin"}, "session_ttl_hours": {"24"}})
	if _, err := a.Store.SiteByHost("app.test"); err == nil {
		t.Fatal("rename left old host behind")
	}
	if s, err := a.Store.SiteByHost("renamed.test"); err != nil || !auth.VerifySecret(s.PinHash, "1234") {
		t.Fatal("rename lost site or pin")
	}
	if resp = post(t, client, srv.URL+"/admin/sites/new", url.Values{"csrf": {csrf}, "host": {"bad.test"}, "upstream": {"notaurl"}, "methods": {"pin"}, "pin": {"1234"}}); resp.StatusCode != 400 {
		t.Fatalf("invalid upstream accepted: %d", resp.StatusCode)
	}
	if resp = post(t, client, srv.URL+"/admin/sites/"+id+"/delete", url.Values{"csrf": {csrf}}); resp.StatusCode != 400 {
		t.Fatal("delete without confirm accepted")
	}
	post(t, client, srv.URL+"/admin/sites/"+id+"/delete", url.Values{"csrf": {csrf}, "confirm": {"on"}})
	if _, err := a.Store.SiteByHost("renamed.test"); err == nil {
		t.Fatal("not deleted")
	}
}
