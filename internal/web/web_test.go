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

func TestSecurityHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	web.SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Header().Get("X-Frame-Options") != "DENY" || rec.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("%v", rec.Header())
	}
}
