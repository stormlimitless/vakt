package admin

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pquerna/otp"

	"github.com/stormlimitless/vakt/internal/auth"
	"github.com/stormlimitless/vakt/internal/store"
)

func (a *Admin) routeUsers(mux *http.ServeMux) {
	a.handle(mux, "GET /admin/users", a.usersList)
	a.handle(mux, "GET /admin/users/new", a.userForm)
	a.handle(mux, "POST /admin/users/new", a.userSave)
	a.handle(mux, "GET /admin/users/{id}", a.userForm)
	a.handle(mux, "POST /admin/users/{id}", a.userSave)
	a.handle(mux, "POST /admin/users/{id}/delete", a.userDelete)
	a.handle(mux, "POST /admin/users/{id}/totp/start", a.totpStart)
	a.handle(mux, "GET /admin/users/{id}/totp", a.totpShow)
	a.handle(mux, "POST /admin/users/{id}/totp/confirm", a.totpConfirm)
	a.handle(mux, "POST /admin/users/{id}/totp/reset", a.totpReset)
}

type userRow struct {
	store.User
	TOTP bool
}

func (a *Admin) usersList(w http.ResponseWriter, r *http.Request) {
	users, _ := a.Store.ListUsers()
	rows := make([]userRow, 0, len(users))
	for _, u := range users {
		_, ok := auth.TOTPEnrolled(a.Cipher, u.TOTPSecretEnc)
		rows = append(rows, userRow{u, ok})
	}
	a.render(w, r, 200, "admin_users", map[string]any{"Title": "Users", "Nav": "users", "Users": rows})
}

func (a *Admin) loadUser(r *http.Request) (*store.User, error) {
	idStr := r.PathValue("id")
	if idStr == "" {
		return &store.User{Role: "member"}, nil
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return nil, err
	}
	return a.Store.UserByID(id)
}

func (a *Admin) existingUser(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
	u, err := a.loadUser(r)
	if err != nil || u.ID == 0 {
		http.NotFound(w, r)
		return nil, false
	}
	return u, true
}

func userPath(u *store.User, suffix string) string {
	return "/admin/users/" + strconv.FormatInt(u.ID, 10) + suffix
}

func (a *Admin) renderUserForm(w http.ResponseWriter, r *http.Request, u *store.User, status int, errMsg string) {
	sites, _ := a.Store.ListSites()
	assigned := map[int64]bool{}
	for _, s := range sites {
		if ok, _ := a.Store.UserAllowedOnSite(s.ID, u.ID); ok {
			assigned[s.ID] = true
		}
	}
	_, enrolled := auth.TOTPEnrolled(a.Cipher, u.TOTPSecretEnc)
	a.render(w, r, status, "admin_user_form", map[string]any{"Title": "User", "U": u, "Sites": sites, "Assigned": assigned, "Enrolled": enrolled, "Error": errMsg})
}

func (a *Admin) userForm(w http.ResponseWriter, r *http.Request) {
	u, err := a.loadUser(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	a.renderUserForm(w, r, u, 200, "")
}

func (a *Admin) userSave(w http.ResponseWriter, r *http.Request) {
	u, err := a.loadUser(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	u.Username = strings.TrimSpace(r.PostFormValue("username"))
	if role := r.PostFormValue("role"); role == "admin" || role == "member" {
		u.Role = role
	}
	if pw := r.PostFormValue("password"); pw != "" {
		if len(pw) < 8 {
			a.renderUserForm(w, r, u, 400, "Password must be at least 8 characters.")
			return
		}
		if u.PasswordHash, err = auth.HashSecret(pw); err != nil {
			http.Error(w, "internal error", 500)
			return
		}
	}
	if u.Username == "" || u.PasswordHash == "" {
		a.renderUserForm(w, r, u, 400, "Username and password are required.")
		return
	}
	if u.ID == 0 {
		err = a.Store.CreateUser(u)
	} else {
		err = a.Store.UpdateUser(u)
	}
	if err != nil {
		a.renderUserForm(w, r, u, 400, "Could not save: "+err.Error())
		return
	}
	a.saveUserSites(r, u.ID)
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func (a *Admin) saveUserSites(r *http.Request, userID int64) {
	want := map[int64]bool{}
	for _, v := range r.PostForm["sites"] {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil {
			want[id] = true
		}
	}
	sites, _ := a.Store.ListSites()
	for _, s := range sites {
		ids, _ := a.Store.SiteUserIDs(s.ID)
		next := ids[:0]
		for _, id := range ids {
			if id != userID {
				next = append(next, id)
			}
		}
		if want[s.ID] {
			next = append(next, userID)
		}
		a.Store.SetSiteUsers(s.ID, next)
	}
}

func (a *Admin) userDelete(w http.ResponseWriter, r *http.Request) {
	u, ok := a.existingUser(w, r)
	if !ok {
		return
	}
	if r.PostFormValue("confirm") != "on" {
		http.Error(w, "confirmation required", 400)
		return
	}
	if u.Role == "admin" {
		if n, _ := a.Store.CountAdmins(); n <= 1 {
			http.Error(w, "cannot delete the last admin", 400)
			return
		}
	}
	a.Store.DeleteUser(u.ID)
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func (a *Admin) totpStart(w http.ResponseWriter, r *http.Request) {
	u, ok := a.existingUser(w, r)
	if !ok {
		return
	}
	secret, _, err := auth.NewTOTPSecret("Vakt", u.Username)
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	if u.TOTPSecretEnc, err = a.Cipher.Encrypt(auth.PendingSecret(secret)); err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	u.TOTPLastUsed = 0
	a.Store.UpdateUser(u)
	http.Redirect(w, r, userPath(u, "/totp"), http.StatusSeeOther)
}

func (a *Admin) totpShow(w http.ResponseWriter, r *http.Request) {
	u, ok := a.existingUser(w, r)
	if !ok {
		return
	}
	secret, pending := auth.TOTPPending(a.Cipher, u.TOTPSecretEnc)
	if !pending {
		http.Redirect(w, r, userPath(u, ""), http.StatusSeeOther)
		return
	}
	key, err := otp.NewKeyFromURL("otpauth://totp/Vakt:" + u.Username + "?secret=" + secret + "&issuer=Vakt")
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	img, err := key.Image(200, 200)
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	var buf bytes.Buffer
	png.Encode(&buf, img)
	errMsg := ""
	if r.URL.Query().Get("error") != "" {
		errMsg = "That code didn't match. Try again."
	}
	a.render(w, r, 200, "admin_totp", map[string]any{"Title": "Enrol authenticator", "Nav": "users", "U": u, "Secret": secret,
		"QR": "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()), "Error": errMsg})
}

func (a *Admin) totpConfirm(w http.ResponseWriter, r *http.Request) {
	u, ok := a.existingUser(w, r)
	if !ok {
		return
	}
	secret, pending := auth.TOTPPending(a.Cipher, u.TOTPSecretEnc)
	if !pending {
		http.NotFound(w, r)
		return
	}
	valid, counter := auth.VerifyTOTP(secret, r.PostFormValue("code"), time.Now(), 0)
	if !valid {
		http.Redirect(w, r, userPath(u, "/totp?error=1"), http.StatusSeeOther)
		return
	}
	var err error
	if u.TOTPSecretEnc, err = a.Cipher.Encrypt([]byte(secret)); err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	u.TOTPLastUsed = counter
	a.Store.UpdateUser(u)
	http.Redirect(w, r, userPath(u, ""), http.StatusSeeOther)
}

func (a *Admin) totpReset(w http.ResponseWriter, r *http.Request) {
	u, ok := a.existingUser(w, r)
	if !ok {
		return
	}
	u.TOTPSecretEnc, u.TOTPLastUsed = nil, 0
	a.Store.UpdateUser(u)
	http.Redirect(w, r, userPath(u, ""), http.StatusSeeOther)
}
