package proxy

import (
	"net"
	"net/http"
	"strings"
)

func ParseCIDRs(list []string) []*net.IPNet {
	var out []*net.IPNet
	for _, s := range list {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(s)); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func InAllowlist(ip string, nets []*net.IPNet) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

// ClientIP honours X-Forwarded-For only when the direct peer is a trusted
// proxy, and walks the chain right-to-left to the first untrusted hop.
func ClientIP(r *http.Request, trusted []*net.IPNet) string {
	remote, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remote = r.RemoteAddr
	}
	if !InAllowlist(remote, trusted) {
		return remote
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(parts[i])
		if ip != "" && !InAllowlist(ip, trusted) {
			return ip
		}
	}
	return remote
}
