package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stormlimitless/vakt/internal/auth"
	"github.com/stormlimitless/vakt/internal/config"
	"github.com/stormlimitless/vakt/internal/store"
)

const sample = `
admin_host: vakt.example.com
tls:
  mode: autocert
  email: a@b.c
trusted_proxies: ["10.0.0.0/8"]
lockout:
  max_attempts: 3
  minutes: 5
sites:
  - host: app.example.com
    upstream: http://app:3000
    methods: [pin, users]
    pin: "482913"
    allowlist: ["192.168.1.0/24"]
    session_ttl: 2h
    require_totp: true
`

func TestLoadAndEnv(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vakt.yaml")
	os.WriteFile(p, []byte(sample), 0o600)
	t.Setenv("VAKT_ADMIN_HOST", "override.example.com")
	c, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.AdminHost != "override.example.com" || c.ListenHTTP != ":80" || c.TLS.Mode != "autocert" || c.Lockout.MaxAttempts != 3 || c.Sites[0].SessionTTL != 2*time.Hour {
		t.Fatalf("%+v", c)
	}
	t.Setenv("VAKT_ADMIN_HOST", "")
	if _, err := config.Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("missing file without admin host should fail validation")
	}
}

func TestCookiesSecure(t *testing.T) {
	c := config.Default()
	if c.CookiesSecure() {
		t.Fatal("tls off should default to insecure cookies")
	}
	c.TLS.Mode = "autocert"
	if !c.CookiesSecure() {
		t.Fatal("tls on should default to secure cookies")
	}
	c.TLS.Mode = "off"
	c.ApplyEnv(func(k string) string {
		if k == "VAKT_SECURE_COOKIES" {
			return "true"
		}
		return ""
	})
	if !c.CookiesSecure() {
		t.Fatal("VAKT_SECURE_COOKIES should force secure cookies behind a tls terminator")
	}
}

func TestValidate(t *testing.T) {
	c := config.Default()
	c.AdminHost = "vakt.example.com"
	c.Sites = []config.SiteCfg{{Host: "a.example.com", Upstream: "http://a", Methods: []string{"pin"}}}
	if err := c.Validate(); err == nil {
		t.Fatal("pin method without pin should fail")
	}
	c.Sites[0].Pin = "1234"
	c.Sites[0].Methods = []string{"bogus"}
	if err := c.Validate(); err == nil {
		t.Fatal("unknown method should fail")
	}
	c.Sites[0].Methods = []string{"pin"}
	c.Sites[0].Host = "vakt.example.com"
	if err := c.Validate(); err == nil {
		t.Fatal("site host equal to admin host should fail")
	}
	c.Sites[0].Host = "a.example.com"
	c.TLS.Mode = "autocert"
	if err := c.Validate(); err == nil {
		t.Fatal("autocert without email should fail")
	}
	c.TLS.Email = "x@y.z"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestApplySitesHashesAndKeepsExisting(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	defer st.Close()
	c := config.Default()
	c.AdminHost = "vakt.example.com"
	c.Sites = []config.SiteCfg{{Host: "a.example.com", Upstream: "http://a", Methods: []string{"pin"}, Pin: "1234"}}
	if err := c.ApplySites(st); err != nil {
		t.Fatal(err)
	}
	site, _ := st.SiteByHost("a.example.com")
	if !auth.VerifySecret(site.PinHash, "1234") || site.SessionTTL != 7*24*time.Hour {
		t.Fatalf("%+v", site)
	}
	c.Sites[0].Pin = ""
	c.Sites[0].Upstream = "http://b"
	if err := c.ApplySites(st); err != nil {
		t.Fatal(err)
	}
	site, _ = st.SiteByHost("a.example.com")
	if site.Upstream != "http://b" || !auth.VerifySecret(site.PinHash, "1234") {
		t.Fatal("existing hash not kept or upstream not updated")
	}
}
