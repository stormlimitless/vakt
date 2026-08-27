package admin

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"time"

	"github.com/stormlimitless/vakt/internal/auth"
	"github.com/stormlimitless/vakt/internal/proxy"
	"github.com/stormlimitless/vakt/internal/store"
	"github.com/stormlimitless/vakt/internal/web"
)

const (
	sessionCookie = "vakt_admin"
	csrfCookie    = "vakt_admin_csrf"
	adminTTL      = 12 * time.Hour
)

type Admin struct {
	Store    *store.Store
	Sessions *auth.Sessions
	Lockout  *auth.Lockout
	Cipher   *auth.Cipher
	Trusted  []*net.IPNet
	Secure   bool
	Version  string
}

type userKey struct{}

func (a *Admin) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/setup", a.setupForm)
	mux.HandleFunc("POST /admin/setup", a.setupSubmit)
	mux.HandleFunc("GET /admin/login", a.loginForm)
	mux.HandleFunc("POST /admin/login", a.loginSubmit)
	a.handle(mux, "POST /admin/logout", a.logout)
	mux.Handle("GET /admin/{$}", http.RedirectHandler("/admin/sites", http.StatusFound))
	mux.Handle("GET /{$}", http.RedirectHandler("/admin/sites", http.StatusFound))
	a.routeSites(mux)
	a.routeUsers(mux)
	a.routeStatus(mux)
	return mux
}

func (a *Admin) handle(mux *http.ServeMux, pattern string, f http.HandlerFunc) {
	mux.Handle(pattern, a.requireAdmin(f))
}

func (a *Admin) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/admin", HttpOnly: true, Secure: a.Secure, SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
}

func (a *Admin) csrfToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookie); err == nil && len(c.Value) >= 32 {
		return c.Value
	}
	tok, _ := auth.RandomToken(24)
	a.setCookie(w, csrfCookie, tok, 0)
	return tok
}

func (a *Admin) csrfValid(r *http.Request) bool {
	c, err := r.Cookie(csrfCookie)
	return err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.PostFormValue("csrf"))) == 1
}

func (a *Admin) currentUser(r *http.Request) *store.User {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	sess, ok := a.Sessions.Lookup(c.Value)
	if !ok || sess.Kind != "admin" {
		return nil
	}
	u, err := a.Store.UserByID(sess.UserID)
	if err != nil || u.Role != "admin" {
		return nil
	}
	return u
}

func (a *Admin) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := a.currentUser(r)
		if u == nil {
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}
		if r.Method == http.MethodPost && !a.csrfValid(r) {
			http.Error(w, "invalid form token", 400)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey{}, u)))
	})
}

func (a *Admin) render(w http.ResponseWriter, r *http.Request, status int, name string, data map[string]any) {
	data["CSRF"] = a.csrfToken(w, r)
	data["Version"] = a.Version
	if u, _ := r.Context().Value(userKey{}).(*store.User); u != nil {
		data["User"] = u.Username
	}
	web.Render(w, status, name, data)
}

func (a *Admin) clientIP(r *http.Request) string { return proxy.ClientIP(r, a.Trusted) }

func (a *Admin) loginForm(w http.ResponseWriter, r *http.Request) {
	a.render(w, r, 200, "admin_login", map[string]any{"Title": "Admin sign in"})
}

func (a *Admin) loginSubmit(w http.ResponseWriter, r *http.Request) {
	ip := a.clientIP(r)
	if locked, until, _ := a.Lockout.Locked(0, ip); locked {
		web.Render(w, 429, "locked", map[string]any{"Title": "Locked", "Until": until.UTC().Format(time.RFC1123)})
		return
	}
	if !a.csrfValid(r) {
		http.Error(w, "invalid form token", 400)
		return
	}
	u, err := a.Store.UserByName(r.PostFormValue("username"))
	ok := err == nil && u.Role == "admin" && auth.VerifySecret(u.PasswordHash, r.PostFormValue("password"))
	if ok {
		if secret, enrolled := auth.TOTPEnrolled(a.Cipher, u.TOTPSecretEnc); enrolled {
			var counter int64
			if ok, counter = auth.VerifyTOTP(secret, r.PostFormValue("totp"), time.Now(), u.TOTPLastUsed); ok {
				u.TOTPLastUsed = counter
				a.Store.UpdateUser(u)
			}
		}
	}
	if !ok {
		a.Lockout.Fail(0, ip)
		a.render(w, r, 401, "admin_login", map[string]any{"Title": "Admin sign in", "Error": "Invalid credentials."})
		return
	}
	a.Lockout.Reset(0, ip)
	a.startSession(w, u, ip)
	http.Redirect(w, r, "/admin/sites", http.StatusSeeOther)
}

func (a *Admin) startSession(w http.ResponseWriter, u *store.User, ip string) {
	tok, err := a.Sessions.Create(0, u.ID, "admin", ip, adminTTL)
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	a.setCookie(w, sessionCookie, tok, int(adminTTL.Seconds()))
}

func (a *Admin) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.Sessions.Delete(c.Value)
	}
	a.setCookie(w, sessionCookie, "", -1)
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}
