package admin

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/stormlimitless/vakt/internal/auth"
	"github.com/stormlimitless/vakt/internal/config"
	"github.com/stormlimitless/vakt/internal/store"
)

func (a *Admin) routeSites(mux *http.ServeMux) {
	a.handle(mux, "GET /admin/sites", a.sitesList)
	a.handle(mux, "GET /admin/sites/new", a.siteForm)
	a.handle(mux, "POST /admin/sites/new", a.siteSave)
	a.handle(mux, "GET /admin/sites/{id}", a.siteForm)
	a.handle(mux, "POST /admin/sites/{id}", a.siteSave)
	a.handle(mux, "POST /admin/sites/{id}/delete", a.siteDelete)
}

func (a *Admin) sitesList(w http.ResponseWriter, r *http.Request) {
	sites, err := a.Store.ListSites()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	counts, _ := a.Store.CountActiveSessions()
	a.render(w, r, 200, "admin_sites", map[string]any{"Title": "Sites", "Sites": sites, "Counts": counts})
}

func (a *Admin) loadSite(r *http.Request) (*store.Site, error) {
	idStr := r.PathValue("id")
	if idStr == "" {
		return &store.Site{SessionTTL: config.DefaultSessionTTL}, nil
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return nil, err
	}
	return a.Store.SiteByID(id)
}

func (a *Admin) siteForm(w http.ResponseWriter, r *http.Request) {
	site, err := a.loadSite(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	a.renderSiteForm(w, r, site, 200, "")
}

func (a *Admin) renderSiteForm(w http.ResponseWriter, r *http.Request, site *store.Site, status int, errMsg string) {
	users, _ := a.Store.ListUsers()
	assigned := map[int64]bool{}
	if site.ID != 0 {
		ids, _ := a.Store.SiteUserIDs(site.ID)
		for _, id := range ids {
			assigned[id] = true
		}
	}
	a.render(w, r, status, "admin_site_form", map[string]any{
		"Title": "Site", "Site": site, "Users": users, "Assigned": assigned, "Error": errMsg,
		"TTLHours": int(site.SessionTTL.Hours()), "AllowlistText": strings.Join(site.Allowlist, "\n"),
	})
}

func (a *Admin) siteSave(w http.ResponseWriter, r *http.Request) {
	site, err := a.loadSite(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	hours, _ := strconv.Atoi(r.PostFormValue("session_ttl_hours"))
	if hours < 1 {
		hours = int(config.DefaultSessionTTL.Hours())
	}
	cfg := config.SiteCfg{
		Host: strings.TrimSpace(r.PostFormValue("host")), Upstream: strings.TrimSpace(r.PostFormValue("upstream")),
		Methods: r.PostForm["methods"], Pin: r.PostFormValue("pin"), Password: r.PostFormValue("password"),
		Allowlist: splitLines(r.PostFormValue("allowlist")), SessionTTL: time.Duration(hours) * time.Hour,
		RequireTOTP: r.PostFormValue("require_totp") == "on",
	}
	pinHash, pwHash := site.PinHash, site.PasswordHash
	if r.PostFormValue("clear_pin") == "on" {
		pinHash = ""
	}
	if r.PostFormValue("clear_password") == "on" {
		pwHash = ""
	}
	if cfg.Pin != "" {
		if pinHash, err = auth.HashSecret(cfg.Pin); err != nil {
			http.Error(w, "internal error", 500)
			return
		}
	}
	if cfg.Password != "" {
		if pwHash, err = auth.HashSecret(cfg.Password); err != nil {
			http.Error(w, "internal error", 500)
			return
		}
	}
	if verr := config.ValidateSite(cfg, hostOnly(r.Host), pinHash != "", pwHash != ""); verr != nil {
		a.renderSiteForm(w, r, site, 400, verr.Error())
		return
	}
	site.Host, site.Upstream, site.Methods, site.Allowlist, site.SessionTTL, site.RequireTOTP = cfg.Host, cfg.Upstream, cfg.Methods, cfg.Allowlist, cfg.SessionTTL, cfg.RequireTOTP
	site.PinHash, site.PasswordHash = pinHash, pwHash
	if site.ID == 0 {
		err = a.Store.UpsertSite(site)
	} else {
		err = a.Store.UpdateSite(site)
	}
	if err != nil {
		a.renderSiteForm(w, r, site, 400, "Could not save: "+err.Error())
		return
	}
	var userIDs []int64
	for _, v := range r.PostForm["users"] {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil {
			userIDs = append(userIDs, id)
		}
	}
	a.Store.SetSiteUsers(site.ID, userIDs)
	http.Redirect(w, r, "/admin/sites", http.StatusSeeOther)
}

func (a *Admin) siteDelete(w http.ResponseWriter, r *http.Request) {
	site, err := a.loadSite(r)
	if err != nil || site.ID == 0 {
		http.NotFound(w, r)
		return
	}
	if r.PostFormValue("confirm") != "on" {
		http.Error(w, "confirmation required", 400)
		return
	}
	a.Store.DeleteSite(site.ID)
	http.Redirect(w, r, "/admin/sites", http.StatusSeeOther)
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}
