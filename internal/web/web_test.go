package web_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormlimitless/vakt/internal/web"
)

func TestRenderLogin(t *testing.T) {
	rec := httptest.NewRecorder()
	web.Render(rec, 200, "login", map[string]any{"Title": "Sign in", "Host": "app.example.com", "Methods": []string{"pin"}, "CSRF": "x"})
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "app.example.com") || !strings.Contains(body, `name="pin"`) || !strings.Contains(body, `name="csrf" value="x"`) {
		t.Fatalf("code=%d body=%s", rec.Code, body)
	}
}

func TestRenderLoginBranding(t *testing.T) {
	rec := httptest.NewRecorder()
	web.Render(rec, 200, "login", map[string]any{"Title": "Sign in", "Host": "app.example.com", "Methods": []string{"pin"},
		"CSRF": "x", "Heading": "Acme staging", "Theme": "dark", "LogoURL": "https://cdn.example.com/logo.svg"})
	body := rec.Body.String()
	if !strings.Contains(body, "Acme staging") || strings.Contains(body, "app.example.com") {
		t.Fatalf("heading should replace the host: %s", body)
	}
	if !strings.Contains(body, "bg-stone-950") {
		t.Fatal("dark theme not applied")
	}
	if !strings.Contains(body, `src="https://cdn.example.com/logo.svg"`) {
		t.Fatal("logo not rendered")
	}
	if !strings.Contains(body, "github.com/stormlimitless/vakt") {
		t.Fatal("Protected by Vakt should link to the project")
	}
}

// An unknown theme must fall back rather than emit a broken class list.
func TestRenderLoginUnknownTheme(t *testing.T) {
	rec := httptest.NewRecorder()
	web.Render(rec, 200, "login", map[string]any{"Title": "Sign in", "Host": "a.example.com", "Methods": []string{"pin"}, "CSRF": "x", "Theme": "nope"})
	if !strings.Contains(rec.Body.String(), "bg-stone-100") {
		t.Fatalf("expected light fallback: %s", rec.Body.String())
	}
}

func TestThemeCSS(t *testing.T) {
	rec := httptest.NewRecorder()
	web.ThemeCSS(rec, "#2563eb")
	if got := rec.Body.String(); got != ":root{--accent:#2563eb}" {
		t.Fatalf("got %q", got)
	}
	// Anything that is not a plain hex colour must not reach the stylesheet.
	for _, bad := range []string{"", "red", "#fff", "#2563eb;}body{display:none", "url(javascript:alert(1))"} {
		rec := httptest.NewRecorder()
		web.ThemeCSS(rec, bad)
		if rec.Body.Len() != 0 {
			t.Fatalf("accent %q leaked into css: %q", bad, rec.Body.String())
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	web.SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Header().Get("X-Frame-Options") != "DENY" || rec.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("%v", rec.Header())
	}
}
