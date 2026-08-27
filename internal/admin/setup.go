package admin

import (
	"net/http"
	"time"

	"github.com/stormlimitless/vakt/internal/auth"
	"github.com/stormlimitless/vakt/internal/store"
)

func (a *Admin) EnsureSetupToken() (string, error) {
	n, err := a.Store.CountAdmins()
	if err != nil || n > 0 {
		return "", err
	}
	tok, err := auth.RandomToken(32)
	if err != nil {
		return "", err
	}
	if err := a.Store.PutSetupToken(auth.TokenHash(tok), time.Now().Add(time.Hour)); err != nil {
		return "", err
	}
	return "/admin/setup?token=" + tok, nil
}

func (a *Admin) setupForm(w http.ResponseWriter, r *http.Request) {
	if n, _ := a.Store.CountAdmins(); n > 0 {
		http.NotFound(w, r)
		return
	}
	a.render(w, r, 200, "admin_setup", map[string]any{"Title": "Create admin", "Token": r.URL.Query().Get("token")})
}

func (a *Admin) setupSubmit(w http.ResponseWriter, r *http.Request) {
	if !a.csrfValid(r) {
		http.Error(w, "invalid form token", 400)
		return
	}
	if n, _ := a.Store.CountAdmins(); n > 0 {
		http.NotFound(w, r)
		return
	}
	name, pw := r.PostFormValue("username"), r.PostFormValue("password")
	if name == "" || len(pw) < 8 {
		a.render(w, r, 400, "admin_setup", map[string]any{"Title": "Create admin", "Token": r.PostFormValue("token"), "Error": "Username required and password must be at least 8 characters."})
		return
	}
	if ok, err := a.Store.ConsumeSetupToken(auth.TokenHash(r.PostFormValue("token"))); err != nil || !ok {
		http.Error(w, "invalid or expired setup token", 403)
		return
	}
	hash, err := auth.HashSecret(pw)
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	u := &store.User{Username: name, PasswordHash: hash, Role: "admin"}
	if err := a.Store.CreateUser(u); err != nil {
		http.Error(w, "could not create user", 500)
		return
	}
	a.startSession(w, u, a.clientIP(r))
	http.Redirect(w, r, "/admin/sites", http.StatusSeeOther)
}
