package model

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Uebersetzbare Texte. Sammler kennen die Sprache des Betrachters nicht: Dienstnamen, Zustandstexte, Fact-Texte und
// eigene Fehlertexte bestehen deshalb aus Token "i18n:<schluessel>?k=v&..." (T) und festen Teilen; uebersetzt wird
// erst bei der Ausgabe (Translate in Go fuer Meldungen und CSV, tx in monitor64.js fuer die Oberflaeche). Die Texte
// stehen in internal/i18n/locales unter monitor64.svc.* (Dienstnamen), monitor64.txt.* (Zustaende, Hinweise,
// Fehler) und monitor64.note.* (Hinweise der Agents); TestTextKeys haelt Quellen, Liste und Sprachdateien zusammen.
//
// Regeln:
//   - Ein Text darf mehrere Token und feste Teile enthalten ("ONLINE · i18n:monitor64.txt.free?v=3+GB"). Nach einem
//     Token steht das Textende, ein Leerzeichen oder ein Satzzeichen ausser . - _ ~ (die gehoeren zum Token).
//   - Sprachneutrales bleibt fester Teil: Zahlen mit Einheit ("3 GB", "45 °C"), Zustaende des Geraets ("ONLINE"),
//     Fehlermeldungen von Programmen.
//   - Eigennamen vom Geraet (Pool, Schnittstelle, VM, Sensor) sind entweder Parameter eines Tokens (T entschaerft
//     und kodiert sie, sie werden nie uebersetzt) oder laufen als fester Teil durch Raw – ein Geraet darf kein
//     eigenes Token einschleusen.
//   - Soll ein Parameter selbst uebersetzt werden (Bezeichnung in einem Satz), steht er ausdruecklich als Sub im
//     Aufruf. Ausgegeben wird immer escaped.

const tokenPrefix = "i18n:"

// Schluessel aus Kleinbuchstaben, Ziffern und _ mit Punkten dazwischen; die Parameter sind genau das, was
// url.Values.Encode liefert (alles andere ist kodiert).
var reToken = regexp.MustCompile(`i18n:([a-z0-9_]+(?:\.[a-z0-9_]+)*)(?:\?([A-Za-z0-9%+=&_.~-]*))?`)

// Sub ist ein Parameter, der selbst uebersetzbarer Text ist (Token und feste Teile); nur fuer eigene Texte, nie
// fuer Text vom Geraet.
type Sub string

// T baut ein Token fuer den Schluessel key (voll, "monitor64.txt.free"); kv sind Paare Name, Wert. Werte sind
// fertige Texte (Zahl, Eigenname vom Geraet) und werden entschaerft; nur ein Sub wird bei der Ausgabe uebersetzt.
func T(key string, kv ...any) string {
	if len(kv) < 2 {
		return tokenPrefix + key
	}
	q := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v, sub := kv[i+1].(Sub)
		if !sub {
			v = Sub(Raw(fmt.Sprint(kv[i+1])))
		}
		q.Set(fmt.Sprint(kv[i]), string(v))
	}
	return tokenPrefix + key + "?" + q.Encode()
}

// Raw entschaerft Text vom Geraet, der als fester Teil neben Token steht: aus "i18n:x" wird "i18n: x", damit kein
// fremdes Token entsteht. Andere Texte bleiben unveraendert.
func Raw(s string) string {
	if !strings.Contains(s, tokenPrefix) {
		return s
	}
	var b strings.Builder
	for {
		i := strings.Index(s, tokenPrefix)
		if i < 0 {
			break
		}
		i += len(tokenPrefix)
		b.WriteString(s[:i])
		s = s[i:]
		if s != "" && (s[0] == '_' || s[0] >= 'a' && s[0] <= 'z' || s[0] >= '0' && s[0] <= '9') {
			b.WriteByte(' ')
		}
	}
	b.WriteString(s)
	return b.String()
}

// RawErr entschaerft den Text eines Fehlers vom Geraet (siehe Raw); nil ergibt "".
func RawErr(err error) string {
	if err == nil {
		return ""
	}
	return Raw(err.Error())
}

// Join verbindet die nicht leeren Teile eines Zustandstexts mit " · ".
func Join(parts ...string) string {
	out := parts[:0:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, " · ")
}

// Translate ersetzt alle Token in s durch ihren Text. tr uebersetzt einen Schluessel mit Parametern (Paare Name,
// Wert, nach Namen sortiert) und gibt bei unbekanntem Schluessel den Schluessel zurueck (wie i18n.Bundle.T). Nur
// Schluessel unter "monitor64." werden uebersetzt; feste Teile, alte Texte ohne Token und unlesbare Token bleiben,
// wie sie sind; Parameter mit Token (Sub) werden mit uebersetzt. Das Ergebnis enthaelt keine Token mehr, ein
// zweiter Aufruf aendert also nichts.
func Translate(s string, tr func(key string, args ...any) string) string {
	if tr == nil {
		return s
	}
	return translate(s, tr, 0)
}

const maxDepth = 4 // Token in Parametern: so tief wird uebersetzt, darunter nur noch entschaerft

func translate(s string, tr func(key string, args ...any) string, depth int) string {
	if !strings.Contains(s, tokenPrefix) {
		return s
	}
	if depth > maxDepth {
		return Raw(s)
	}
	return reToken.ReplaceAllStringFunc(s, func(tok string) string {
		key, args, ok := parseToken(tok)
		if !ok {
			return Raw(tok)
		}
		for i := 1; i < len(args); i += 2 {
			args[i] = translate(args[i].(string), tr, depth+1)
		}
		out := tr(key, args...)
		if out != key {
			return out
		}
		// unbekannter Schluessel (z. B. Text einer neueren Version): Schluessel und Werte zeigen
		out = strings.TrimPrefix(key, "monitor64.")
		var vals []string
		for i := 1; i < len(args); i += 2 {
			vals = append(vals, fmt.Sprint(args[i]))
		}
		if len(vals) > 0 {
			out += " (" + strings.Join(vals, ", ") + ")"
		}
		return out
	})
}

// parseToken zerlegt ein Token in Schluessel und Parameter (Paare Name, Wert).
func parseToken(tok string) (key string, args []any, ok bool) {
	m := reToken.FindStringSubmatch(tok)
	if m == nil || m[0] != tok || !strings.HasPrefix(m[1], "monitor64.") {
		return "", nil, false
	}
	vals, err := url.ParseQuery(m[2])
	if err != nil {
		return "", nil, false
	}
	names := make([]string, 0, len(vals))
	for k := range vals {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		args = append(args, k, vals.Get(k))
	}
	return m[1], args, true
}

// Key liefert den Schluessel, wenn s genau ein Token ist (Texte in SNMP-Profilen).
func Key(s string) (string, bool) {
	key, _, ok := parseToken(s)
	return key, ok
}

// Keys nennt die Schluessel aller Token in s (fuer Tests).
func Keys(s string) []string {
	var out []string
	for _, m := range reToken.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}
