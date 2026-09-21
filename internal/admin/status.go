package admin

import "net/http"

func (a *Admin) routeStatus(mux *http.ServeMux) {
	a.handle(mux, "GET /admin/status", a.status)
}

func (a *Admin) status(w http.ResponseWriter, r *http.Request) {
	sites, _ := a.Store.ListSites()
	counts, _ := a.Store.CountActiveSessions()
	locked, _ := a.Store.ListLocked()
	hosts := map[int64]string{0: "admin"}
	for _, s := range sites {
		hosts[s.ID] = s.Host
	}
	a.render(w, r, 200, "admin_status", map[string]any{"Title": "Status", "Nav": "status", "Sites": sites, "Counts": counts, "Locked": locked, "Hosts": hosts})
}
