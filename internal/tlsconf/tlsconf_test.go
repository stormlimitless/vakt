package tlsconf_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stormlimitless/vakt/internal/config"
	"github.com/stormlimitless/vakt/internal/tlsconf"
)

func TestBuildModes(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	tc, wrapped, err := tlsconf.Build(config.TLS{Mode: "off"}, t.TempDir(), nil, h)
	if err != nil || tc != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 204 {
		t.Fatal("off mode must pass through")
	}
	if _, _, err = tlsconf.Build(config.TLS{Mode: "manual", CertFile: "missing.pem", KeyFile: "missing.key"}, t.TempDir(), nil, h); err == nil {
		t.Fatal("missing cert should error")
	}
	tc, _, err = tlsconf.Build(config.TLS{Mode: "autocert", Email: "a@b.c"}, t.TempDir(), []string{"x.test"}, h)
	if err != nil || tc == nil || tc.GetCertificate == nil {
		t.Fatal("autocert config missing")
	}
}

func TestRedirectToHTTPS(t *testing.T) {
	rec := httptest.NewRecorder()
	tlsconf.RedirectHTTPS().ServeHTTP(rec, httptest.NewRequest("GET", "http://app.test/x?y=1", nil))
	if rec.Code != 308 || rec.Header().Get("Location") != "https://app.test/x?y=1" {
		t.Fatalf("%d %s", rec.Code, rec.Header().Get("Location"))
	}
}
