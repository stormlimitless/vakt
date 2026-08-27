package proxy_test

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/stormlimitless/vakt/internal/auth"
	"github.com/stormlimitless/vakt/internal/proxy"
	"github.com/stormlimitless/vakt/internal/store"
)

type env struct {
	st     *store.Store
	gw     *proxy.Gateway
	srv    *httptest.Server
	client *http.Client
	site   *store.Site
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-User", r.Header.Get("X-Vakt-User"))
		io.WriteString(w, "upstream ok "+r.URL.Path)
	}))
	pinHash, _ := auth.HashSecret("1234")
	site := &store.Site{Host: "app.test", Upstream: up.URL, Methods: []string{"pin"}, PinHash: pinHash, SessionTTL: time.Hour, Allowlist: []string{"192.0.2.0/24"}}
	st.UpsertSite(site)
	cipher, _ := auth.LoadOrCreateKey(t.TempDir())
	gw := &proxy.Gateway{Store: st, Sessions: &auth.Sessions{Store: st}, Lockout: &auth.Lockout{Store: st, MaxAttempts: 3, Duration: time.Minute}, Cipher: cipher, AdminHost: "vakt.test"}
	srv := httptest.NewServer(gw.Handler())
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(func() { srv.Close(); up.Close(); st.Close() })
	return &env{st: st, gw: gw, srv: srv, client: client, site: site}
}

func (e *env) do(t *testing.T, method, host, path string, form url.Values) *http.Response {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, body)
	req.Host = host
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := e.client.Do(req)
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

func TestUnauthenticatedRedirectsToLogin(t *testing.T) {
	e := newEnv(t)
	resp := e.do(t, "GET", "app.test", "/secret?x=1", nil)
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "/vakt/login?next=%2Fsecret%3Fx%3D1" {
		t.Fatalf("%d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestUnknownHost404(t *testing.T) {
	e := newEnv(t)
	if resp := e.do(t, "GET", "nope.test", "/", nil); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
}

func TestStaticServed(t *testing.T) {
	e := newEnv(t)
	if resp := e.do(t, "GET", "nope.test", "/vakt/static/htmx.min.js", nil); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
}

func TestPinLoginFlow(t *testing.T) {
	e := newEnv(t)
	csrf := csrfFrom(t, e.do(t, "GET", "app.test", "/vakt/login?next=/secret", nil))
	if bad := e.do(t, "POST", "app.test", "/vakt/login", url.Values{"csrf": {csrf}, "next": {"/secret"}, "pin": {"9999"}}); bad.StatusCode != 401 {
		t.Fatalf("wrong pin: %d", bad.StatusCode)
	}
	ok := e.do(t, "POST", "app.test", "/vakt/login", url.Values{"csrf": {csrf}, "next": {"/secret"}, "pin": {"1234"}})
	if ok.StatusCode != 303 || ok.Header.Get("Location") != "/secret" {
		t.Fatalf("good pin: %d %s", ok.StatusCode, ok.Header.Get("Location"))
	}
	proxied := e.do(t, "GET", "app.test", "/secret", nil)
	b, _ := io.ReadAll(proxied.Body)
	if proxied.StatusCode != 200 || string(b) != "upstream ok /secret" || proxied.Header.Get("X-Seen-User") != "pin" {
		t.Fatalf("%d %s %s", proxied.StatusCode, b, proxied.Header.Get("X-Seen-User"))
	}
	e.do(t, "POST", "app.test", "/vakt/logout", url.Values{})
	if resp := e.do(t, "GET", "app.test", "/secret", nil); resp.StatusCode != 302 {
		t.Fatal("still logged in after logout")
	}
}

func TestCSRFRequired(t *testing.T) {
	e := newEnv(t)
	if resp := e.do(t, "POST", "app.test", "/vakt/login", url.Values{"pin": {"1234"}}); resp.StatusCode != 400 {
		t.Fatal(resp.StatusCode)
	}
}

func TestLockout(t *testing.T) {
	e := newEnv(t)
	csrf := csrfFrom(t, e.do(t, "GET", "app.test", "/vakt/login", nil))
	for i := 0; i < 3; i++ {
		e.do(t, "POST", "app.test", "/vakt/login", url.Values{"csrf": {csrf}, "pin": {"0000"}})
	}
	if resp := e.do(t, "POST", "app.test", "/vakt/login", url.Values{"csrf": {csrf}, "pin": {"1234"}}); resp.StatusCode != 429 {
		t.Fatalf("expected 429, got %d", resp.StatusCode)
	}
}

func TestOpenRedirectBlocked(t *testing.T) {
	e := newEnv(t)
	csrf := csrfFrom(t, e.do(t, "GET", "app.test", "/vakt/login", nil))
	for _, next := range []string{"https://evil.test/", "//evil.test/", "/\\evil.test"} {
		resp := e.do(t, "POST", "app.test", "/vakt/login", url.Values{"csrf": {csrf}, "next": {next}, "pin": {"1234"}})
		if resp.Header.Get("Location") != "/" {
			t.Fatalf("open redirect via %q: %s", next, resp.Header.Get("Location"))
		}
	}
}

func TestAllowlistBypass(t *testing.T) {
	e := newEnv(t)
	e.gw.Trusted = proxy.ParseCIDRs([]string{"127.0.0.0/8", "::1/128"})
	req, _ := http.NewRequest("GET", e.srv.URL+"/", nil)
	req.Host = "app.test"
	req.Header.Set("X-Forwarded-For", "192.0.2.10")
	resp, _ := e.client.Do(req)
	if resp.StatusCode != 200 || resp.Header.Get("X-Seen-User") != "allowlist" {
		t.Fatalf("allowlisted ip not bypassed: %d", resp.StatusCode)
	}
}

func TestAdminHostRoutesToAdmin(t *testing.T) {
	e := newEnv(t)
	e.gw.Admin = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(418) })
	if resp := e.do(t, "GET", "vakt.test", "/admin", nil); resp.StatusCode != 418 {
		t.Fatal(resp.StatusCode)
	}
}

func TestUsersMethodWithTOTP(t *testing.T) {
	e := newEnv(t)
	pw, _ := auth.HashSecret("hunter22")
	u := &store.User{Username: "henri", PasswordHash: pw, Role: "member"}
	e.st.CreateUser(u)
	other := &store.User{Username: "other", PasswordHash: pw, Role: "member"}
	e.st.CreateUser(other)
	e.site.Methods = []string{"users"}
	e.st.UpsertSite(e.site)
	e.st.SetSiteUsers(e.site.ID, []int64{u.ID})
	csrf := csrfFrom(t, e.do(t, "GET", "app.test", "/vakt/login", nil))
	form := func(name, pw, code string) url.Values {
		return url.Values{"csrf": {csrf}, "username": {name}, "user_password": {pw}, "totp": {code}}
	}
	if r := e.do(t, "POST", "app.test", "/vakt/login", form("henri", "wrong", "")); r.StatusCode != 401 {
		t.Fatalf("wrong pw %d", r.StatusCode)
	}
	if r := e.do(t, "POST", "app.test", "/vakt/login", form("other", "hunter22", "")); r.StatusCode != 401 {
		t.Fatalf("unassigned user %d", r.StatusCode)
	}
	if r := e.do(t, "POST", "app.test", "/vakt/login", form("henri", "hunter22", "")); r.StatusCode != 303 {
		t.Fatalf("good login %d", r.StatusCode)
	}
	if r := e.do(t, "GET", "app.test", "/", nil); r.Header.Get("X-Seen-User") != "henri" {
		t.Fatal("username not forwarded")
	}
	e.do(t, "POST", "app.test", "/vakt/logout", url.Values{})
	secret, _, _ := auth.NewTOTPSecret("Vakt", "henri")
	u.TOTPSecretEnc, _ = e.gw.Cipher.Encrypt([]byte(secret))
	e.st.UpdateUser(u)
	if r := e.do(t, "POST", "app.test", "/vakt/login", form("henri", "hunter22", "")); r.StatusCode != 401 {
		t.Fatalf("missing totp accepted %d", r.StatusCode)
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	if r := e.do(t, "POST", "app.test", "/vakt/login", form("henri", "hunter22", code)); r.StatusCode != 303 {
		t.Fatalf("totp login %d", r.StatusCode)
	}
}
