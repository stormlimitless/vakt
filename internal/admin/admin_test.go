package admin_test

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stormlimitless/vakt/internal/admin"
	"github.com/stormlimitless/vakt/internal/auth"
	"github.com/stormlimitless/vakt/internal/store"
)

func get(t *testing.T, c *http.Client, u string) *http.Response {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func post(t *testing.T, c *http.Client, u string, form url.Values) *http.Response {
	t.Helper()
	resp, err := c.PostForm(u, form)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func csrfFrom(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, _ := io.ReadAll(resp.Body)
	const marker = `name="csrf" value="`
	i := strings.Index(string(b), marker)
	if i < 0 {
		t.Fatalf("no csrf in body: %s", b)
	}
	rest := string(b)[i+len(marker):]
	return rest[:strings.Index(rest, `"`)]
}

func newAdmin(t *testing.T) (*admin.Admin, *httptest.Server, *http.Client) {
	t.Helper()
	st, _ := store.Open(t.TempDir())
	c, _ := auth.LoadOrCreateKey(t.TempDir())
	a := &admin.Admin{Store: st, Sessions: &auth.Sessions{Store: st}, Lockout: &auth.Lockout{Store: st, MaxAttempts: 5, Duration: time.Minute}, Cipher: c, Version: "test"}
	srv := httptest.NewServer(a.Handler())
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(func() { srv.Close(); st.Close() })
	return a, srv, client
}

func loginAdmin(t *testing.T) (*admin.Admin, *httptest.Server, *http.Client) {
	t.Helper()
	a, srv, client := newAdmin(t)
	u, _ := a.EnsureSetupToken()
	csrf := csrfFrom(t, get(t, client, srv.URL+u))
	token := strings.TrimPrefix(u, "/admin/setup?token=")
	resp := post(t, client, srv.URL+"/admin/setup", url.Values{"csrf": {csrf}, "token": {token}, "username": {"henri"}, "password": {"correct horse"}})
	if resp.StatusCode != 303 {
		t.Fatalf("setup: %d", resp.StatusCode)
	}
	return a, srv, client
}

func TestSetupCreatesFirstAdmin(t *testing.T) {
	a, srv, client := loginAdmin(t)
	if n, _ := a.Store.CountAdmins(); n != 1 {
		t.Fatal("admin not created")
	}
	if u, _ := a.EnsureSetupToken(); u != "" {
		t.Fatal("setup still offered after admin exists")
	}
	if resp := get(t, client, srv.URL+"/admin/sites"); resp.StatusCode != 200 {
		t.Fatalf("not logged in after setup: %d", resp.StatusCode)
	}
	if resp := get(t, client, srv.URL+"/admin/setup?token=x"); resp.StatusCode != 404 {
		t.Fatal("setup page reachable after admin exists")
	}
}

func TestAdminRequiresLogin(t *testing.T) {
	_, srv, client := newAdmin(t)
	resp := get(t, client, srv.URL+"/admin/sites")
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "/admin/login" {
		t.Fatalf("%d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestAdminLoginAndMemberRejected(t *testing.T) {
	a, srv, client := newAdmin(t)
	h, _ := auth.HashSecret("password1")
	a.Store.CreateUser(&store.User{Username: "m", PasswordHash: h, Role: "member"})
	a.Store.CreateUser(&store.User{Username: "root", PasswordHash: h, Role: "admin"})
	csrf := csrfFrom(t, get(t, client, srv.URL+"/admin/login"))
	if resp := post(t, client, srv.URL+"/admin/login", url.Values{"csrf": {csrf}, "username": {"m"}, "password": {"password1"}}); resp.StatusCode != 401 {
		t.Fatal(resp.StatusCode)
	}
	if resp := post(t, client, srv.URL+"/admin/login", url.Values{"csrf": {csrf}, "username": {"root"}, "password": {"password1"}}); resp.StatusCode != 303 {
		t.Fatal(resp.StatusCode)
	}
	post(t, client, srv.URL+"/admin/logout", url.Values{"csrf": {csrf}})
	if resp := get(t, client, srv.URL+"/admin/sites"); resp.StatusCode != 302 {
		t.Fatal("still logged in after logout")
	}
}
