package dns64

import (
	"net/http"
	"strings"

	"github.com/ipv64net/node64/internal/store"
)

// audit schreibt eine Aenderung ins Audit-Log des Kerns (Akteur aus Sitzung oder API-Key). target ist das "was"
// (Name, Kennung, URL), details ein Zusatz ohne Geheimnisse.
func (m *Module) audit(r *http.Request, action, target, details string) {
	ip := r.RemoteAddr
	if i := strings.LastIndex(ip, ":"); i > 0 {
		ip = strings.Trim(ip[:i], "[]")
	}
	actor := ""
	if m.g.Actor != nil {
		actor = m.g.Actor(r)
	}
	if err := m.core.Audit(r.Context(), store.AuditEntry{Actor: actor, Action: action, Target: target, Details: details, IP: ip, Origin: "local"}); err != nil {
		m.log.Error("audit", "err", err)
	}
}
