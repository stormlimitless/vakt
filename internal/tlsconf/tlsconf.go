package tlsconf

import (
	"crypto/tls"
	"net/http"
	"path/filepath"

	"golang.org/x/crypto/acme/autocert"

	"github.com/stormlimitless/vakt/internal/config"
)

func RedirectHTTPS() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := *r.URL
		u.Scheme, u.Host = "https", r.Host
		http.Redirect(w, r, u.String(), http.StatusPermanentRedirect)
	})
}

// Build returns the TLS config for the HTTPS listener (nil when off) and the
// handler the plain HTTP listener should serve: the gateway itself when TLS
// is off, otherwise a redirect (wrapped with the ACME challenge handler for autocert).
func Build(cfg config.TLS, dataDir string, hosts []string, fallback http.Handler) (*tls.Config, http.Handler, error) {
	switch cfg.Mode {
	case "off":
		return nil, fallback, nil
	case "manual":
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, nil, err
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, RedirectHTTPS(), nil
	default:
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Email:      cfg.Email,
			Cache:      autocert.DirCache(filepath.Join(dataDir, "certs")),
			HostPolicy: autocert.HostWhitelist(hosts...),
		}
		tc := m.TLSConfig()
		tc.MinVersion = tls.VersionTLS12
		return tc, m.HTTPHandler(RedirectHTTPS()), nil
	}
}
