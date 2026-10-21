package notify

import "regexp"

// Schwaerzen von Geheimnissen in Fehlertexten (z. B. DNS-Provider bei Zertifikaten, die Zugangsdaten in URLs oder
// Fehlermeldungen zurueckgeben): URLs nur mit Schema und Host (RedactURLs), dazu Schluessel=Wert-Paare und
// Authorization-Werte. Fuer Texte, die gespeichert, ueber die API ausgegeben oder geloggt werden.
var (
	redactKVRe   = regexp.MustCompile(`(?i)\b(token|access_token|secret|password|passwd|pwd|api[_-]?key|apikey|auth|signature)=([^&\s"';,]+)`)
	redactAuthRe = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`)
)

// RedactSecrets entfernt typische Geheimnisse aus einem Text.
func RedactSecrets(s string) string {
	if s == "" {
		return s
	}
	s = RedactURLs(s)
	s = redactKVRe.ReplaceAllString(s, "$1=***")
	return redactAuthRe.ReplaceAllString(s, "$1 ***")
}
