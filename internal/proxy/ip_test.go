package proxy_test

import (
	"net/http/httptest"
	"testing"

	"github.com/stormlimitless/vakt/internal/proxy"
)

func TestClientIP(t *testing.T) {
	trusted := proxy.ParseCIDRs([]string{"10.0.0.0/8"})
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.5:1234"
	r.Header.Set("X-Forwarded-For", "198.51.100.9")
	if got := proxy.ClientIP(r, trusted); got != "203.0.113.5" {
		t.Fatalf("untrusted proxy header honoured: %s", got)
	}
	r.RemoteAddr = "10.1.2.3:1234"
	r.Header.Set("X-Forwarded-For", "198.51.100.9, 10.9.9.9")
	if got := proxy.ClientIP(r, trusted); got != "198.51.100.9" {
		t.Fatalf("got %s", got)
	}
	nets := proxy.ParseCIDRs([]string{"192.168.1.0/24", "garbage"})
	if len(nets) != 1 || !proxy.InAllowlist("192.168.1.7", nets) || proxy.InAllowlist("192.168.2.7", nets) {
		t.Fatal("allowlist wrong")
	}
}
