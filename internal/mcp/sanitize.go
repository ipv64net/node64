package mcp

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ipv64net/node64/internal/logging"
	"github.com/ipv64net/node64/internal/notify"
)

// Zentraler Filter fuer alle Antworten der Werkzeuge: Geheimnisse entfernen, fremde Texte saeubern und kuerzen,
// Zeiten einheitlich (RFC 3339, UTC). Die Werkzeuge waehlen ihre Felder ausdruecklich aus (Positivliste); der
// Filter hier ist die zweite Sicherung fuer alles, was trotzdem durchrutscht (z. B. Fehlertexte mit URLs).

// secretKey: Feldnamen, die nie ausgegeben werden (ausser unter "untrusted", dort stehen z. B. die Passwoerter, die
// Angreifer am Honeypot probiert haben – das sind Daten der Angreifer, keine Geheimnisse der Node). Gemeinsame Liste
// mit dem Log (logging.IsSecretKey), dazu Felder, die bei MCP nie gebraucht werden (Push-Adresse, PEM, Koepfe).
var mcpSecretKeyRe = regexp.MustCompile(`(?i)(push_url|_pem$|^headers$|^params$|request_headers|response_headers)`)

func secretKey(k string) bool { return logging.IsSecretKey(k) || mcpSecretKeyRe.MatchString(k) }

var (
	pemRe = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`)
	// zusaetzlich zu notify.RedactSecrets: kurze bzw. allgemeine Namen, die in Fehlertexten zu oft vorkommen,
	// fuer die KI aber trotzdem nicht gebraucht werden
	kvRe      = regexp.MustCompile(`(?i)\b(pass|key|sig|session|sid|code)=([^&\s"';,]+)`)
	tokSchRe  = regexp.MustCompile(`(?i)\b(token)\s+[A-Za-z0-9._~+/=-]{8,}`)
	prefixRe  = regexp.MustCompile(`\b(node64|mcp64)_[A-Za-z0-9_-]{16,}`)
	longTokRe = regexp.MustCompile(`[A-Za-z0-9_-]{24,}`)
	// Steuerzeichen und unsichtbare Richtungs-/Breitenzeichen (Unicode-Tricks in fremden Texten)
	invisible = map[rune]bool{0x200B: true, 0x200C: true, 0x200D: true, 0x200E: true, 0x200F: true, 0x2028: true, 0x2029: true,
		0x202A: true, 0x202B: true, 0x202C: true, 0x202D: true, 0x202E: true, 0x2060: true, 0x2066: true, 0x2067: true,
		0x2068: true, 0x2069: true, 0xFEFF: true}
)

// looksLikeToken: lange Zeichenfolge aus Gross-, Kleinbuchstaben und Ziffern (Zufallstoken). Hex-Werte
// (Fingerabdruecke, Hashes) bestehen nur aus Kleinbuchstaben und Ziffern und bleiben stehen.
func looksLikeToken(s string) bool {
	var up, low, dig bool
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			up = true
		case r >= 'a' && r <= 'z':
			low = true
		case r >= '0' && r <= '9':
			dig = true
		}
	}
	return up && low && dig
}

// scrubSecrets entfernt typische Geheimnis-Muster aus einem Text: notify.RedactSecrets (URLs nur mit Schema und
// Host – in Pfad, Query und Zugangsdaten stehen oft Tokens –, Schluessel=Wert, JSON-Paare, Authorization), dazu
// private Schluessel (PEM), Schluessel der Node (node64_/mcp64_) und lange Zufallstokens.
func scrubSecrets(s string) string {
	if s == "" {
		return s
	}
	s = pemRe.ReplaceAllString(s, "[private key removed]")
	s = notify.RedactSecrets(s)
	s = kvRe.ReplaceAllString(s, "$1=***")
	s = tokSchRe.ReplaceAllString(s, "$1 ***")
	s = prefixRe.ReplaceAllString(s, "${1}_***")
	s = longTokRe.ReplaceAllStringFunc(s, func(t string) string {
		if looksLikeToken(t) {
			return t[:4] + "…"
		}
		return t
	})
	return s
}

// clean: fremder Text ohne Steuerzeichen und ohne Geheimnisse, gekuerzt auf max Zeichen (Runen). Geschwaerzt wird
// vor dem Kuerzen: ein an der Grenze abgeschnittenes Token waere sonst zu kurz fuer die Erkennung.
func clean(s string, max int) string {
	if s == "" {
		return ""
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\t' || r == '\r' {
			r = ' '
		}
		if unicode.IsControl(r) || invisible[r] {
			continue
		}
		b.WriteRune(r)
	}
	s = scrubSecrets(b.String())
	if utf8.RuneCountInString(s) > max {
		n := 0
		for i := range s {
			if n == max {
				s = s[:i] + "…"
				break
			}
			n++
		}
	}
	return strings.TrimSpace(s)
}

// sanitize geht rekursiv durch die Ausgabe: Geheimnis-Felder weg, alle Texte gefiltert.
func sanitize(v any, inUntrusted bool) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if !inUntrusted && secretKey(k) {
				continue
			}
			sv := sanitize(val, inUntrusted || k == "untrusted")
			if sv == nil {
				continue
			}
			if m, ok := sv.(map[string]any); ok && len(m) == 0 {
				continue
			}
			if str, ok := sv.(string); ok && str == "" {
				continue
			}
			out[k] = sv
		}
		return out
	case []any:
		out := make([]any, 0, len(x))
		for _, e := range x {
			if sv := sanitize(e, inUntrusted); sv != nil {
				out = append(out, sv)
			}
		}
		return out
	case []map[string]any:
		out := make([]any, 0, len(x))
		for _, e := range x {
			out = append(out, sanitize(e, inUntrusted))
		}
		return out
	case []string:
		out := make([]any, 0, len(x))
		for _, e := range x {
			out = append(out, sanitize(e, inUntrusted))
		}
		return out
	case string:
		return clean(x, 2000)
	default:
		return v
	}
}

// ---------------------------------------------------------------- Zugriff auf dekodiertes JSON

type obj = map[string]any

func asObj(v any) obj {
	m, _ := v.(map[string]any)
	return m
}

func asArr(v any) []any {
	a, _ := v.([]any)
	return a
}

func str(m obj, k string) string {
	switch x := m[k].(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case bool:
		return strconv.FormatBool(x)
	}
	return ""
}

func num(m obj, k string) float64 {
	switch x := m[k].(type) {
	case json.Number:
		f, _ := x.Float64()
		return f
	case float64:
		return x
	case int:
		return float64(x)
	case int64:
		return float64(x)
	}
	return 0
}

func i64(m obj, k string) int64 {
	if n, ok := m[k].(json.Number); ok {
		if i, err := n.Int64(); err == nil {
			return i
		}
	}
	return int64(num(m, k))
}

func boolean(m obj, k string) bool {
	b, _ := m[k].(bool)
	return b
}

func strs(m obj, k string) []string {
	var out []string
	for _, e := range asArr(m[k]) {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// ts: Zeit als RFC 3339 in UTC; Nullzeit bzw. leer = "" (faellt aus der Ausgabe).
func ts(v any) string {
	switch x := v.(type) {
	case string:
		if x == "" {
			return ""
		}
		t, err := time.Parse(time.RFC3339Nano, x)
		if err != nil {
			return ""
		}
		if t.Year() <= 1 {
			return ""
		}
		return t.UTC().Format(time.RFC3339)
	case time.Time:
		if x.IsZero() {
			return ""
		}
		return x.UTC().Format(time.RFC3339)
	}
	return ""
}

func parseTS(v any) time.Time {
	s, _ := v.(string)
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

// round auf n Nachkommastellen (kompakte Ausgabe).
func round(f float64, n int) float64 {
	p := 1.0
	for range n {
		p *= 10
	}
	if f < 0 {
		return -float64(int64(-f*p+0.5)) / p
	}
	return float64(int64(f*p+0.5)) / p
}

// shortID: Kennung eines Checks fuer die KI (Anfang des Tokens). Das ganze Token ist bei Push-Checks die
// Berechtigung fuer die Push-Adresse und wird nie ausgegeben.
func shortID(token string) string {
	if len(token) > 8 {
		return token[:8]
	}
	return token
}
