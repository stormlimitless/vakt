package proxy

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/stormlimitless/vakt/internal/auth"
	"github.com/stormlimitless/vakt/internal/store"
	"github.com/stormlimitless/vakt/internal/web"
)

const (
	sessionCookie = "vakt_session"
	csrfCookie    = "vakt_csrf"
)

type Gateway struct {
	Store     *store.Store
	Sessions  *auth.Sessions
	Lockout   *auth.Lockout
	Cipher    *auth.Cipher
	Trusted   []*net.IPNet
	Secure    bool
	Admin     http.Handler
	AdminHost string
}

type siteKey struct{}

func withSite(ctx context.Context, s *store.Site) context.Context {
	return context.WithValue(ctx, siteKey{}, s)
}

func siteFrom(ctx context.Context) *store.Site {
	s, _ := ctx.Value(siteKey{}).(*store.Site)
	return s
}

func (g *Gateway) Handler() http.Handler {
	sub, _ := fs.Sub(web.Static, "static")
	static := http.StripPrefix("/vakt/static/", http.FileServerFS(sub))
	own := web.SecurityHeaders(http.HandlerFunc(g.serveOwn))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/vakt/static/") {
			static.ServeHTTP(w, r)
			return
		}
		host := hostOnly(r.Host)
		if host == g.AdminHost && g.Admin != nil {
			web.SecurityHeaders(g.Admin).ServeHTTP(w, r)
			return
		}
		site, err := g.Store.SiteByHost(host)
		if errors.Is(err, sql.ErrNoRows) {
			web.Render(w, 404, "error", map[string]any{"Title": "Unknown site", "Message": "No site is configured for " + host + "."})
			return
		}
		if err != nil {
			log.Printf("site lookup %s: %v", host, err)
			http.Error(w, "internal error", 500)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/vakt/") {
			own.ServeHTTP(w, r.WithContext(withSite(r.Context(), site)))
			return
		}
		ip := ClientIP(r, g.Trusted)
		if InAllowlist(ip, ParseCIDRs(site.Allowlist)) {
			g.proxy(w, r, site, "allowlist")
			return
		}
		if c, err := r.Cookie(sessionCookie); err == nil {
			if sess, ok := g.Sessions.Lookup(c.Value); ok && sess.SiteID == site.ID {
				g.proxy(w, r, site, g.sessionUser(sess))
				return
			}
		}
		http.Redirect(w, r, "/vakt/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
	})
}

func (g *Gateway) serveOwn(w http.ResponseWriter, r *http.Request) {
	site := siteFrom(r.Context())
	switch r.URL.Path {
	case "/vakt/login":
		g.login(w, r, site)
	case "/vakt/logout":
		g.logout(w, r)
	default:
		http.NotFound(w, r)
	}
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

func (g *Gateway) sessionUser(sess *store.Session) string {
	if sess.UserID == 0 {
		return sess.Kind
	}
	u, err := g.Store.UserByID(sess.UserID)
	if err != nil {
		return "user"
	}
	return u.Username
}

func (g *Gateway) proxy(w http.ResponseWriter, r *http.Request, site *store.Site, user string) {
	target, err := url.Parse(site.Upstream)
	if err != nil {
		http.Error(w, "bad upstream", 502)
		return
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = target.Host
			pr.SetXForwarded()
			pr.Out.Header.Set("X-Forwarded-Host", r.Host)
			pr.Out.Header.Set("X-Vakt-User", user)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("upstream %s: %v", site.Host, err)
			web.Render(w, 502, "error", map[string]any{"Title": "Upstream unavailable", "Message": "Vakt could not reach the site behind this address."})
		},
	}
	rp.ServeHTTP(w, r)
}
