package web

import (
	"embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"regexp"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var Static embed.FS

// str reads an optional string out of the render data. Pages that carry no
// branding simply leave the key out, and a missing map key would otherwise be
// an untyped nil that eq cannot compare against a string.
var funcs = template.FuncMap{
	"str": func(v any) string { s, _ := v.(string); return s },
}

var templates = template.Must(template.New("vakt").Funcs(funcs).ParseFS(templateFS, "templates/*.html"))

func Render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := templates.ExecuteTemplate(w, name+".html", data); err != nil {
		log.Printf("render %s: %v", name, err)
	}
}

// accentRe guards against anything but a plain hex colour reaching the
// stylesheet, so a stored value can never break out into arbitrary CSS.
var accentRe = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// ThemeCSS serves a site's accent colour as a same-origin stylesheet. Doing it
// this way rather than with an inline style attribute keeps style-src 'self'
// intact — no 'unsafe-inline', no per-request nonce plumbing.
func ThemeCSS(w http.ResponseWriter, accent string) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if !accentRe.MatchString(accent) {
		return
	}
	fmt.Fprintf(w, ":root{--accent:%s}", accent)
}

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		// img-src allows https: so a site can point at its own hosted logo.
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data: https:; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
