package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/stormlimitless/vakt/internal/auth"
	"github.com/stormlimitless/vakt/internal/store"
)

type TLS struct {
	Mode     string `yaml:"mode"`
	Email    string `yaml:"email"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type LockoutCfg struct {
	MaxAttempts int `yaml:"max_attempts"`
	Minutes     int `yaml:"minutes"`
}

type SiteCfg struct {
	Host        string        `yaml:"host"`
	Upstream    string        `yaml:"upstream"`
	Methods     []string      `yaml:"methods"`
	Pin         string        `yaml:"pin"`
	Password    string        `yaml:"password"`
	Allowlist   []string      `yaml:"allowlist"`
	SessionTTL  time.Duration `yaml:"session_ttl"`
	RequireTOTP bool          `yaml:"require_totp"`
}

type Config struct {
	AdminHost      string     `yaml:"admin_host"`
	DataDir        string     `yaml:"data_dir"`
	ListenHTTP     string     `yaml:"listen_http"`
	ListenHTTPS    string     `yaml:"listen_https"`
	TLS            TLS        `yaml:"tls"`
	TrustedProxies []string   `yaml:"trusted_proxies"`
	Lockout        LockoutCfg `yaml:"lockout"`
	Sites          []SiteCfg  `yaml:"sites"`
}

const DefaultSessionTTL = 7 * 24 * time.Hour

var validMethods = map[string]bool{"pin": true, "password": true, "users": true}

func Default() Config {
	dir := "/data"
	if runtime.GOOS == "windows" {
		dir = "./data"
	}
	return Config{DataDir: dir, ListenHTTP: ":80", ListenHTTPS: ":443", TLS: TLS{Mode: "off"}, Lockout: LockoutCfg{MaxAttempts: 5, Minutes: 15}}
}

func Load(path string) (Config, error) {
	c := Default()
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return c, err
	}
	if err == nil {
		if err := yaml.Unmarshal(data, &c); err != nil {
			return c, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	c.ApplyEnv(os.Getenv)
	if c.Lockout.MaxAttempts < 1 {
		c.Lockout.MaxAttempts = 5
	}
	if c.Lockout.Minutes < 1 {
		c.Lockout.Minutes = 15
	}
	return c, c.Validate()
}

func (c *Config) ApplyEnv(getenv func(string) string) {
	set := func(dst *string, key string) {
		if v := getenv(key); v != "" {
			*dst = v
		}
	}
	set(&c.AdminHost, "VAKT_ADMIN_HOST")
	set(&c.DataDir, "VAKT_DATA_DIR")
	set(&c.ListenHTTP, "VAKT_LISTEN_HTTP")
	set(&c.ListenHTTPS, "VAKT_LISTEN_HTTPS")
	set(&c.TLS.Mode, "VAKT_TLS_MODE")
	set(&c.TLS.Email, "VAKT_TLS_EMAIL")
}

func (c Config) Validate() error {
	if c.AdminHost == "" {
		return errors.New("admin_host is required")
	}
	switch c.TLS.Mode {
	case "off":
	case "autocert":
		if c.TLS.Email == "" {
			return errors.New("tls.email is required for autocert")
		}
	case "manual":
		if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
			return errors.New("tls.cert_file and tls.key_file are required for manual tls")
		}
	default:
		return fmt.Errorf("tls.mode %q must be off, autocert or manual", c.TLS.Mode)
	}
	for _, p := range c.TrustedProxies {
		if _, _, err := net.ParseCIDR(p); err != nil {
			return fmt.Errorf("trusted_proxies: %w", err)
		}
	}
	seen := map[string]bool{}
	for _, s := range c.Sites {
		if seen[s.Host] {
			return fmt.Errorf("site host %q duplicated", s.Host)
		}
		seen[s.Host] = true
		if err := ValidateSite(s, c.AdminHost, s.Pin != "", s.Password != ""); err != nil {
			return err
		}
	}
	return nil
}

func ValidateSite(s SiteCfg, adminHost string, hasPin, hasPassword bool) error {
	if s.Host == "" || strings.ContainsAny(s.Host, "/: ") {
		return fmt.Errorf("site host %q is invalid", s.Host)
	}
	if s.Host == adminHost {
		return fmt.Errorf("site %s: host equals admin_host", s.Host)
	}
	u, err := url.Parse(s.Upstream)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("site %s: upstream must be an http(s) URL", s.Host)
	}
	if len(s.Methods) == 0 {
		return fmt.Errorf("site %s: at least one method required", s.Host)
	}
	for _, m := range s.Methods {
		if !validMethods[m] {
			return fmt.Errorf("site %s: unknown method %q", s.Host, m)
		}
	}
	if hasMethod(s.Methods, "pin") && !hasPin {
		return fmt.Errorf("site %s: method pin requires a pin", s.Host)
	}
	if hasMethod(s.Methods, "password") && !hasPassword {
		return fmt.Errorf("site %s: method password requires a password", s.Host)
	}
	if s.Pin != "" && !validPin(s.Pin) {
		return fmt.Errorf("site %s: pin must be 4-12 digits", s.Host)
	}
	for _, a := range s.Allowlist {
		if _, _, err := net.ParseCIDR(a); err != nil {
			return fmt.Errorf("site %s: allowlist: %w", s.Host, err)
		}
	}
	return nil
}

func hasMethod(ms []string, m string) bool {
	for _, x := range ms {
		if x == m {
			return true
		}
	}
	return false
}

func validPin(p string) bool {
	return len(p) >= 4 && len(p) <= 12 && strings.Trim(p, "0123456789") == ""
}

// ApplySites upserts YAML sites into the store. YAML wins for every field it
// sets; an empty pin/password keeps whatever hash the store already has.
func (c Config) ApplySites(st *store.Store) error {
	for _, s := range c.Sites {
		site := &store.Site{Host: s.Host, Upstream: s.Upstream, Methods: s.Methods, Allowlist: s.Allowlist, SessionTTL: s.SessionTTL, RequireTOTP: s.RequireTOTP}
		if site.SessionTTL == 0 {
			site.SessionTTL = DefaultSessionTTL
		}
		if existing, err := st.SiteByHost(s.Host); err == nil {
			site.PinHash, site.PasswordHash = existing.PinHash, existing.PasswordHash
		}
		var err error
		if s.Pin != "" {
			if site.PinHash, err = auth.HashSecret(s.Pin); err != nil {
				return err
			}
		}
		if s.Password != "" {
			if site.PasswordHash, err = auth.HashSecret(s.Password); err != nil {
				return err
			}
		}
		if err := ValidateSite(s, c.AdminHost, site.PinHash != "", site.PasswordHash != ""); err != nil {
			return err
		}
		if err := st.UpsertSite(site); err != nil {
			return err
		}
	}
	return nil
}
