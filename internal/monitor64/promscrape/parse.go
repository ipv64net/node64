package promscrape

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Parser fuer das Prometheus-Textformat 0.0.4 (und OpenMetrics-Text, soweit kompatibel). Bewusst klein und ohne
// Bibliothek: HELP wird ignoriert, TYPE nur gemerkt (Histogramm-Buckets und Summary-Quantile werden verworfen, _sum
// und _count bleiben), Zeitstempel und Exemplare werden gelesen bzw. uebersprungen. Ungueltige oder zu lange Zeilen
// zaehlen als Skipped und brechen nicht ab; zu grosse Antworten bzw. zu viele Serien sind ein Fehler (lieber keine
// Daten als halbe, sonst gaelten Dienste als verschwunden).

// Limits sind die harten Grenzen des Parsers.
type Limits struct {
	MaxBytes     int // ganze Antwort (nach gzip)
	MaxLineBytes int // eine Zeile (laengere werden uebersprungen)
	MaxSeries    int // Serien insgesamt (mehr = Fehler)
	MaxLabels    int // Labels je Serie (mehr = Zeile uebersprungen)
}

// DefaultLimits gelten, wenn nichts anderes eingestellt ist.
var DefaultLimits = Limits{MaxBytes: 8 << 20, MaxLineBytes: 64 << 10, MaxSeries: 200000, MaxLabels: 64}

// Fehler des Parsers.
var (
	ErrTooLarge      = errors.New("Antwort zu groß")
	ErrTooManySeries = errors.New("zu viele Serien")
)

// Label ist ein Label einer Serie.
type Label struct {
	Name, Value string
}

// Sample ist ein Messwert (eine Zeile ohne Kommentar). Value kann NaN oder ±Inf sein (Auswertung prueft finite).
type Sample struct {
	Name   string
	Labels []Label
	Value  float64
}

// Label liefert den Wert eines Labels ("" = fehlt).
func (s *Sample) Label(name string) string {
	for _, l := range s.Labels {
		if l.Name == name {
			return l.Value
		}
	}
	return ""
}

// Metrics ist das Ergebnis des Parsers.
type Metrics struct {
	byName  map[string][]Sample
	types   map[string]string
	Series  int // gelesene Serien
	Skipped int // uebersprungene Zeilen (ungueltig, zu lang, Buckets/Quantile)
}

// Get liefert alle Serien eines Namens (in der Reihenfolge der Antwort).
func (m *Metrics) Get(name string) []Sample { return m.byName[name] }

// Has sagt, ob es Serien mit diesem Namen gibt.
func (m *Metrics) Has(name string) bool { return len(m.byName[name]) > 0 }

// Value liefert den ersten endlichen Wert eines Namens.
func (m *Metrics) Value(name string) (float64, bool) {
	for _, s := range m.byName[name] {
		if finite(s.Value) {
			return s.Value, true
		}
	}
	return 0, false
}

// Type liefert den TYPE einer Familie ("" = unbekannt).
func (m *Metrics) Type(name string) string { return m.types[name] }

// hasPrefix sagt, ob es irgendeine Serie mit diesem Namensanfang gibt.
func (m *Metrics) hasPrefix(p string) bool {
	for n := range m.byName {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// Parse liest eine Antwort im Textformat.
func Parse(b []byte, lim Limits) (*Metrics, error) {
	lim = lim.withDefaults()
	if len(b) > lim.MaxBytes {
		return nil, ErrTooLarge
	}
	text := string(b) // eine Kopie; Namen und Werte teilen sich diesen Speicher
	m := &Metrics{byName: map[string][]Sample{}, types: map[string]string{}}
	for len(text) > 0 {
		var ln string
		if i := strings.IndexByte(text, '\n'); i >= 0 {
			ln, text = text[:i], text[i+1:]
		} else {
			ln, text = text, ""
		}
		if len(ln) > lim.MaxLineBytes {
			m.Skipped++
			continue
		}
		ln = strings.TrimRight(ln, "\r")
		ln = strings.TrimLeft(ln, " \t")
		if ln == "" {
			continue
		}
		if ln[0] == '#' {
			m.comment(ln, lim)
			continue
		}
		s, ok := parseSample(ln, lim)
		if !ok {
			m.Skipped++
			continue
		}
		if m.skipSeries(&s) {
			m.Skipped++
			continue
		}
		if m.Series >= lim.MaxSeries {
			return nil, fmt.Errorf("%w (mehr als %d)", ErrTooManySeries, lim.MaxSeries)
		}
		m.Series++
		m.byName[s.Name] = append(m.byName[s.Name], s)
	}
	return m, nil
}

func (l Limits) withDefaults() Limits {
	if l.MaxBytes <= 0 {
		l.MaxBytes = DefaultLimits.MaxBytes
	}
	if l.MaxLineBytes <= 0 {
		l.MaxLineBytes = DefaultLimits.MaxLineBytes
	}
	if l.MaxSeries <= 0 {
		l.MaxSeries = DefaultLimits.MaxSeries
	}
	if l.MaxLabels <= 0 {
		l.MaxLabels = DefaultLimits.MaxLabels
	}
	return l
}

// comment liest "# TYPE name typ" (HELP, UNIT, EOF und freie Kommentare werden ignoriert).
func (m *Metrics) comment(ln string, lim Limits) {
	rest, ok := strings.CutPrefix(ln[1:], " TYPE ")
	if !ok {
		return
	}
	rest = strings.TrimLeft(rest, " \t")
	var name string
	if strings.HasPrefix(rest, `"`) { // OpenMetrics/UTF-8: Name in Anfuehrungszeichen
		n, r, ok := parseQuoted(rest)
		if !ok {
			return
		}
		name, rest = n, r
	} else {
		i := 0
		for i < len(rest) && rest[i] != ' ' && rest[i] != '\t' {
			i++
		}
		name, rest = rest[:i], rest[i:]
	}
	typ := strings.ToLower(strings.TrimSpace(rest))
	if name == "" || typ == "" || len(m.types) >= lim.MaxSeries {
		return
	}
	m.types[name] = typ
}

// skipSeries: Histogramm-Buckets und Summary-Quantile (sowie OpenMetrics _created) braucht Monitor64 nicht.
func (m *Metrics) skipSeries(s *Sample) bool {
	if base, ok := strings.CutSuffix(s.Name, "_bucket"); ok {
		for _, l := range s.Labels {
			if l.Name == "le" {
				return true
			}
		}
		if t := m.types[base]; t == "histogram" || t == "gaugehistogram" {
			return true
		}
	}
	if m.types[s.Name] == "summary" {
		for _, l := range s.Labels {
			if l.Name == "quantile" {
				return true
			}
		}
	}
	if base, ok := strings.CutSuffix(s.Name, "_created"); ok {
		switch m.types[base] {
		case "counter", "histogram", "summary", "gaugehistogram":
			return true
		}
	}
	return false
}

// parseSample liest eine Zeile "name{l="v",...} wert [zeitstempel] [# exemplar]".
func parseSample(ln string, lim Limits) (Sample, bool) {
	var s Sample
	rest := ln
	if rest[0] != '{' {
		i := 0
		for i < len(rest) && isNameChar(rest[i], i == 0) {
			i++
		}
		if i == 0 {
			return s, false
		}
		s.Name, rest = rest[:i], rest[i:]
	}
	if strings.HasPrefix(rest, "{") {
		var ok bool
		rest, ok = s.parseLabels(rest[1:], lim)
		if !ok {
			return s, false
		}
	}
	if s.Name == "" {
		return s, false
	}
	// mindestens ein Leerzeichen vor dem Wert
	if rest == "" || (rest[0] != ' ' && rest[0] != '\t') {
		return s, false
	}
	rest = strings.TrimLeft(rest, " \t")
	tok, rest := nextToken(rest)
	v, ok := parseValue(tok)
	if !ok {
		return s, false
	}
	s.Value = v
	rest = strings.TrimLeft(rest, " \t")
	if rest != "" && rest[0] != '#' { // Zeitstempel (0.0.4: ms als Ganzzahl, OpenMetrics: Sekunden mit Komma)
		var ts string
		ts, rest = nextToken(rest)
		if t, err := strconv.ParseFloat(ts, 64); err != nil || !finite(t) {
			return s, false
		}
		rest = strings.TrimLeft(rest, " \t")
	}
	if rest != "" && rest[0] != '#' { // nur noch ein Exemplar ("# {...} wert") ist erlaubt
		return s, false
	}
	return s, true
}

// parseLabels liest die Labels bis "}" (rest beginnt hinter "{"). Ein Name in Anfuehrungszeichen ohne "=" ist der
// Metrik-Name (UTF-8-Schreibweise {"mein.name", l="v"}).
func (s *Sample) parseLabels(rest string, lim Limits) (string, bool) {
	for {
		rest = strings.TrimLeft(rest, " \t")
		if rest == "" {
			return "", false
		}
		if rest[0] == '}' {
			return rest[1:], true
		}
		var name string
		if rest[0] == '"' {
			n, r, ok := parseQuoted(rest)
			if !ok {
				return "", false
			}
			name, rest = n, strings.TrimLeft(r, " \t")
			if rest != "" && (rest[0] == ',' || rest[0] == '}') { // Metrik-Name
				if s.Name != "" || name == "" {
					return "", false
				}
				s.Name = name
				if rest[0] == ',' {
					rest = rest[1:]
				}
				continue
			}
		} else {
			i := 0
			for i < len(rest) && isLabelChar(rest[i], i == 0) {
				i++
			}
			if i == 0 {
				return "", false
			}
			name, rest = rest[:i], strings.TrimLeft(rest[i:], " \t")
		}
		if rest == "" || rest[0] != '=' {
			return "", false
		}
		rest = strings.TrimLeft(rest[1:], " \t")
		val, r, ok := parseQuoted(rest)
		if !ok {
			return "", false
		}
		if len(s.Labels) >= lim.MaxLabels {
			return "", false
		}
		s.Labels = append(s.Labels, Label{Name: name, Value: val})
		rest = strings.TrimLeft(r, " \t")
		if rest == "" {
			return "", false
		}
		switch rest[0] {
		case ',':
			rest = rest[1:]
		case '}':
		default:
			return "", false
		}
	}
}

// parseQuoted liest einen Text in Anfuehrungszeichen mit den Escapes \\, \" und \n (s beginnt mit ").
func parseQuoted(s string) (val, rest string, ok bool) {
	if s == "" || s[0] != '"' {
		return "", "", false
	}
	// schneller Weg ohne Escapes
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '"':
			return s[1:i], s[i+1:], true
		case '\\':
			return parseQuotedSlow(s)
		}
	}
	return "", "", false
}

func parseQuotedSlow(s string) (string, string, bool) {
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			return b.String(), s[i+1:], true
		case '\\':
			if i+1 >= len(s) {
				return "", "", false
			}
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case '\\', '"':
				b.WriteByte(s[i])
			default: // unbekanntes Escape: wie geschrieben behalten
				b.WriteByte('\\')
				b.WriteByte(s[i])
			}
		default:
			b.WriteByte(c)
		}
	}
	return "", "", false
}

func nextToken(s string) (tok, rest string) {
	i := 0
	for i < len(s) && s[i] != ' ' && s[i] != '\t' {
		i++
	}
	return s[:i], s[i:]
}

// parseValue liest einen Wert (auch NaN, +Inf, -Inf).
func parseValue(tok string) (float64, bool) {
	if tok == "" || len(tok) > 64 {
		return 0, false
	}
	switch tok {
	case "NaN":
		return math.NaN(), true
	case "+Inf", "Inf":
		return math.Inf(1), true
	case "-Inf":
		return math.Inf(-1), true
	}
	v, err := strconv.ParseFloat(tok, 64)
	if err != nil {
		var ne *strconv.NumError
		if errors.As(err, &ne) && errors.Is(ne.Err, strconv.ErrRange) {
			return v, true // ±Inf bzw. 0 bei Ueberlauf; finite() verwirft Unendlich spaeter
		}
		return 0, false
	}
	return v, true
}

func isNameChar(c byte, first bool) bool {
	return c == '_' || c == ':' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (!first && c >= '0' && c <= '9')
}

func isLabelChar(c byte, first bool) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (!first && c >= '0' && c <= '9')
}

func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }
