package proxy

import (
	"crypto/subtle"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stormlimitless/vakt/internal/auth"
	"github.com/stormlimitless/vakt/internal/store"
	"github.com/stormlimitless/vakt/internal/web"
)

func (g *Gateway) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: g.Secure, SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
}

func (g *Gateway) csrfToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookie); err == nil && len(c.Value) >= 32 {
		return c.Value
	}
	tok, _ := auth.RandomToken(24)
	g.setCookie(w, csrfCookie, tok, 0)
	return tok
}

func (g *Gateway) csrfValid(r *http.Request) bool {
	c, err := r.Cookie(csrfCookie)
	return err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.PostFormValue("csrf"))) == 1
}

// SafeNext only allows same-origin absolute paths as post-login redirect targets.
func SafeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return "/"
	}
	if u, err := url.Parse(next); err != nil || u.Host != "" || u.Scheme != "" {
		return "/"
	}
	return next
}

func (g *Gateway) renderLogin(w http.ResponseWriter, r *http.Request, site *store.Site, status int, errMsg string) {
	web.Render(w, status, "login", map[string]any{
		"Title": "Sign in", "Host": site.Host, "Methods": site.Methods,
		"CSRF": g.csrfToken(w, r), "Next": SafeNext(r.FormValue("next")), "Error": errMsg,
	})
}

func renderLocked(w http.ResponseWriter, until time.Time) {
	web.Render(w, 429, "locked", map[string]any{"Title": "Locked", "Until": until.UTC().Format(time.RFC1123)})
}

func (g *Gateway) login(w http.ResponseWriter, r *http.Request, site *store.Site) {
	ip := ClientIP(r, g.Trusted)
	if locked, until, _ := g.Lockout.Locked(site.ID, ip); locked {
		renderLocked(w, until)
		return
	}
	switch r.Method {
	case http.MethodGet:
		g.renderLogin(w, r, site, 200, "")
		return
	case http.MethodPost:
	default:
		http.Error(w, "method not allowed", 405)
		return
	}
	if !g.csrfValid(r) {
		http.Error(w, "invalid form token", 400)
		return
	}
	kind, userID, ok := g.verify(r, site)
	if !ok {
		if locked, _ := g.Lockout.Fail(site.ID, ip); locked {
			_, until, _ := g.Lockout.Locked(site.ID, ip)
			renderLocked(w, until)
			return
		}
		g.renderLogin(w, r, site, 401, "That didn't match. Try again.")
		return
	}
	g.Lockout.Reset(site.ID, ip)
	if c, err := r.Cookie(sessionCookie); err == nil {
		g.Sessions.Delete(c.Value)
	}
	tok, err := g.Sessions.Create(site.ID, userID, kind, ip, site.SessionTTL)
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	g.setCookie(w, sessionCookie, tok, int(site.SessionTTL.Seconds()))
	http.Redirect(w, r, SafeNext(r.PostFormValue("next")), http.StatusSeeOther)
}

func (g *Gateway) verify(r *http.Request, site *store.Site) (string, int64, bool) {
	if pin := r.PostFormValue("pin"); pin != "" && site.Has("pin") {
		return "pin", 0, auth.VerifySecret(site.PinHash, pin)
	}
	if pw := r.PostFormValue("password"); pw != "" && site.Has("password") {
		return "password", 0, auth.VerifySecret(site.PasswordHash, pw)
	}
	if name := r.PostFormValue("username"); name != "" && site.Has("users") {
		u, err := g.Store.UserByName(name)
		if err != nil || !auth.VerifySecret(u.PasswordHash, r.PostFormValue("user_password")) {
			return "user", 0, false
		}
		if allowed, _ := g.Store.UserAllowedOnSite(site.ID, u.ID); !allowed {
			return "user", 0, false
		}
		secret, enrolled := auth.TOTPEnrolled(g.Cipher, u.TOTPSecretEnc)
		if enrolled || site.RequireTOTP {
			if !enrolled {
				return "user", 0, false
			}
			ok, counter := auth.VerifyTOTP(secret, r.PostFormValue("totp"), time.Now(), u.TOTPLastUsed)
			if !ok {
				return "user", 0, false
			}
			u.TOTPLastUsed = counter
			g.Store.UpdateUser(u)
		}
		return "user", u.ID, true
	}
	return "", 0, false
}

func (g *Gateway) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		g.Sessions.Delete(c.Value)
	}
	g.setCookie(w, sessionCookie, "", -1)
	http.Redirect(w, r, "/vakt/login", http.StatusSeeOther)
}
