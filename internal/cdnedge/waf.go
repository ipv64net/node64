package cdnedge

import (
	"net/http"
	"strings"
)

// Muster-WAF (Abschnitt 3 von docs/PLAN-CDN64-SCHUTZ.md): nur Modus 2 und 3, je Anfrage vor der Weitergabe, einfache
// Textvergleiche ohne regulaere Ausdruecke und ohne Body - Pfade, die Scanner immer suchen, und deren User-Agents.
// Treffer: 403 mit der Fehlerseite. Je Name abschaltbar (edge/config waf = false).

var wafPaths = [...]string{"/.git/", "/.env", "/.svn/", "/.htpasswd", "/wp-config.php", "/.aws/", "/.ssh/", "/phpinfo.php", "/etc/passwd", "../"}

var wafAgents = [...]string{"sqlmap", "nikto", "nuclei", "masscan", "zgrab", "wpscan", "acunetix", "nessus", "dirbuster", "gobuster"}

// wafHit: Pfad (dekodiert, aber nicht bereinigt - "../" bleibt) bzw. User-Agent, kleingeschrieben, enthaelt ein Muster.
func wafHit(r *http.Request) bool {
	p := strings.ToLower(r.URL.Path)
	for _, m := range wafPaths {
		if strings.Contains(p, m) {
			return true
		}
	}
	ua := strings.ToLower(r.UserAgent())
	if ua == "" {
		return false
	}
	for _, m := range wafAgents {
		if strings.Contains(ua, m) {
			return true
		}
	}
	return false
}
