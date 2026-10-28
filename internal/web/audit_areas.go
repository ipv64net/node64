package web

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/store"
)

// Aufbewahrung des Audit-Logs (Datenhaltung): Auswahl wie bei den Healthchecks, der erste Wert ist der Standard,
// 0 = unbegrenzt. Geloescht wird in housekeeping (server.go).
const SettingAuditDays = "audit.keep_days"

var AuditDayOptions = []int{365, 90, 180, 730, 0}

// AuditDays liefert die gueltige Einstellung (sonst den Standard).
func AuditDays(st *store.Store) int {
	if n, err := strconv.Atoi(st.SettingOr(context.Background(), SettingAuditDays, "")); err == nil {
		for _, o := range AuditDayOptions {
			if o == n {
				return n
			}
		}
	}
	return AuditDayOptions[0]
}

// auditKeep: Aufbewahrung als Dauer (0 = unbegrenzt).
func auditKeep(st *store.Store) time.Duration { return time.Duration(AuditDays(st)) * 24 * time.Hour }

// Bereiche fuer den Filter im Audit-Log (Praefixe der Aktionsnamen) und in GET /api/audit?area=.
var auditAreaOrder = []string{"login", "settings", "healthchecks", "dyndns", "cdn64", "dns64", "certs", "sync", "honeypot", "mcp"}

var auditAreas = map[string][]string{
	"login":        {"setup", "login", "logout", "twofa.", "passkey.", "sso.", "apikey.", "user."},
	"settings":     {"settings.", "logging.", "notify.", "channel.", "module.", "edge.settings", "edge.ui", "web.tls_cert", "backup.", "config.", "node."},
	"healthchecks": {"check.", "proxmox."},
	"dyndns":       {"dyndns."},
	"cdn64":        {"cdn64.", "edge.default", "certs.dns."},
	"dns64":        {"dns64."},
	"certs":        {"cert."},
	"sync":         {"sync.", "peer."},
	"honeypot":     {"honeypot."},
	"mcp":          {"mcp."},
}

// AuditAction: Aktionsname des Audit-Logs in der Sprache des Benutzers (unbekannte bleiben, wie sie sind).
func (v *View) AuditAction(action string) string {
	key := "audit.actions." + strings.ReplaceAll(action, ".", "_")
	if t := v.T(key); t != key {
		return t
	}
	return action
}
