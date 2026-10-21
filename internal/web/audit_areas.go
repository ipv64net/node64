package web

import "strings"

// Bereiche fuer den Filter im Audit-Log (Praefixe der Aktionsnamen) und in GET /api/audit?area=.
var auditAreaOrder = []string{"login", "settings", "healthchecks", "dyndns", "cdn64", "dns64", "certs", "sync", "honeypot"}

var auditAreas = map[string][]string{
	"login":        {"setup", "login", "logout", "twofa.", "passkey.", "sso.", "apikey."},
	"settings":     {"settings.", "logging.", "notify.", "channel.", "module.", "edge.settings", "edge.ui", "web.tls_cert", "backup.", "config.", "node."},
	"healthchecks": {"check.", "proxmox."},
	"dyndns":       {"dyndns."},
	"cdn64":        {"cdn64.", "edge.default", "certs.dns."},
	"dns64":        {"dns64."},
	"certs":        {"cert."},
	"sync":         {"sync.", "peer."},
	"honeypot":     {"honeypot."},
}

// AuditAction: Aktionsname des Audit-Logs in der Sprache des Benutzers (unbekannte bleiben, wie sie sind).
func (v *View) AuditAction(action string) string {
	key := "audit.actions." + strings.ReplaceAll(action, ".", "_")
	if t := v.T(key); t != key {
		return t
	}
	return action
}
