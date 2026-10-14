package dns64

import (
	"net/http"
	"strings"

	"github.com/ipv64net/node64/internal/store"
)

// audit schreibt eine Aenderung ins Audit-Log des Kerns (g.Audit: Akteur aus Sitzung oder API-Key, IP wie im Kern,
// auch hinter einem Proxy). target ist das "was" (Name, Kennung, URL), details ein Zusatz ohne Geheimnisse.
// Ohne Guard (Tests) direkt in die Datenbank.
func (m *Module) audit(r *http.Request, action, target, details string) {
	if m.g.Audit != nil {
		m.g.Audit(r, action, target, details)
		return
	}
	ip := r.RemoteAddr
	if i := strings.LastIndex(ip, ":"); i > 0 {
		ip = strings.Trim(ip[:i], "[]")
	}
	if err := m.core.Audit(r.Context(), store.AuditEntry{Action: action, Target: target, Details: details, IP: ip, Origin: "local"}); err != nil {
		m.log.Error("audit", "err", err)
	}
}
