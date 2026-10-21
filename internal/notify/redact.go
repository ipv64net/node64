package notify

import (
	"regexp"
	"strings"
)

// Schwaerzen von Geheimnissen in Fehlertexten (z. B. DNS-Provider bei Zertifikaten, die Zugangsdaten in URLs oder
// Fehlermeldungen zurueckgeben): URLs nur mit Schema und Host (RedactURLs), dazu Schluessel=Wert-Paare (auch mit
// Vor-/Nachsilbe wie client_secret, auth_token, secret_key, und als JSON-Paar) und Authorization-Werte. Fuer Texte,
// die gespeichert, ueber die API ausgegeben oder geloggt werden. Die MCP-Schnittstelle nutzt das mit (internal/mcp).

// redactName: Schluesselname mit Geheimnis, optional mit Vor- und Nachsilben (client_secret, api-token, secret_key).
const redactName = `(?:[a-z0-9]+[_-])*(?:token|secret|password|passwd|pwd|api[_-]?key|apikey|auth|signature)(?:[_-][a-z0-9]+)*`

var (
	redactJSONRe = regexp.MustCompile(`(?i)"(` + redactName + `)"(\s*:\s*)"(?:[^"\\]|\\.)*"`)
	redactKVRe   = regexp.MustCompile(`(?i)\b(` + redactName + `)(\s*[=:]\s*"?)([^&\s"';,]+)`)
	// Authorization-Kopf mit beliebigem Schema (Bearer, Token, Bot, ...) bzw. ohne Schema
	redactHeaderRe = regexp.MustCompile(`(?i)\b((?:proxy-)?authorization\s*:\s*)(?:([a-z][a-z0-9._-]*)\s+)?([^\s,;"']+)`)
	redactAuthRe   = regexp.MustCompile(`(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}`)
	redactBasicRe  = regexp.MustCompile(`(?i)\b(basic)\s+([A-Za-z0-9+/]{8,}={0,2})`)
)

// base64ish: sieht nach Base64 aus (Ziffer, +/=, oder Grossbuchstabe nach dem ersten Zeichen) – "basic constraints"
// oder "Basic Authentication" bleiben stehen.
func base64ish(s string) bool {
	if strings.ContainsAny(s, "0123456789+/=") {
		return true
	}
	for _, r := range s[1:] {
		if r >= 'A' && r <= 'Z' {
			return true
		}
	}
	return false
}

// RedactSecrets entfernt typische Geheimnisse aus einem Text.
func RedactSecrets(s string) string {
	if s == "" {
		return s
	}
	s = RedactURLs(s)
	s = redactJSONRe.ReplaceAllString(s, `"$1"$2"***"`)
	s = redactHeaderRe.ReplaceAllStringFunc(s, func(m string) string {
		g := redactHeaderRe.FindStringSubmatch(m)
		if g[3] == "***" {
			return m
		}
		if g[2] != "" {
			return g[1] + g[2] + " ***"
		}
		return g[1] + "***"
	})
	s = redactKVRe.ReplaceAllString(s, "$1$2***")
	s = redactAuthRe.ReplaceAllString(s, "$1 ***")
	return redactBasicRe.ReplaceAllStringFunc(s, func(m string) string {
		g := redactBasicRe.FindStringSubmatch(m)
		if !base64ish(g[2]) {
			return m
		}
		return g[1] + " ***"
	})
}
