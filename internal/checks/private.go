package checks

import (
	"fmt"
	"strings"
)

// IsPrivateTarget sagt, ob ein Ziel im privaten Netz liegt (RFC 1918, ULA, Loopback, Link-Local,
// .local, localhost). Solche Ziele kann ipv64 von aussen nicht pruefen.
func IsPrivateTarget(typ, target string) bool {
	if typ == string(TypeDocker) {
		return true // Container der Node sind von aussen nie erreichbar
	}
	host := strings.ToLower(strings.TrimSpace(target))
	if typ == "dns" {
		host = strings.TrimSuffix(host, ".")
	}
	if typ == "http" || typ == "keyword" || typ == "json" {
		if i := strings.Index(host, "://"); i >= 0 {
			host = host[i+3:]
		}
		if i := strings.IndexAny(host, "/?#"); i >= 0 {
			host = host[:i]
		}
	}
	if i := strings.LastIndex(host, ":"); i >= 0 && !strings.Contains(host, "]") && strings.Count(host, ":") == 1 {
		host = host[:i]
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".localhost") {
		return true
	}
	for _, p := range []string{"10.", "127.", "192.168.", "169.254.", "fc", "fd", "fe80:", "::1"} {
		if strings.HasPrefix(host, p) {
			return true
		}
	}
	if strings.HasPrefix(host, "172.") {
		var a, b int
		if n, _ := fmt.Sscanf(host, "172.%d.%d", &a, &b); n >= 1 && a >= 16 && a <= 31 {
			return true
		}
	}
	return false
}
