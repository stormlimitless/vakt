package web

import (
	"embed"
	"html/template"
	"log"
	"net/http"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var Static embed.FS

var templates = template.Must(template.ParseFS(templateFS, "templates/*.html"))

func Render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := templates.ExecuteTemplate(w, name+".html", data); err != nil {
		log.Printf("render %s: %v", name, err)
	}
}

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
