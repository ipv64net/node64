package snmp

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"
)

// Grenzen gegen feindliche bzw. kaputte Agenten (endlose Tabellen, nicht steigende OIDs).
const (
	maxTableRows   = 5000 // Zeilen je Spalte
	maxWalkReqs    = 1000 // Anfragen je Tabellen-Abfrage
	maxGetOIDs     = 20   // OIDs je GET
	varbindBudget  = 60   // Varbinds je GETBULK-Antwort (Zeilen = Budget / Spalten)
	maxTextLen     = 256  // Texte vom Geraet (Namen, Beschreibungen)
	maxKeyPartLen  = 120  // Teil eines Dienst-Schluessels aus Geraete-Texten
	maxOIDParts    = 128  // Bestandteile einer OID
	maxOIDTextSize = 512
	maxValueBytes  = 1024    // ein Wert (OCTET STRING) wird darueber gekuerzt
	maxWalkBytes   = 8 << 20 // Werte einer Tabellen-Abfrage zusammen
)

// clip kuerzt lange Texte (feindliche Agenten koennen je Wert fast 64 KB schicken) und liefert die Groesse.
func clip(p pdu) (pdu, int) {
	if b, ok := p.Value.([]byte); ok {
		if len(b) > maxValueBytes {
			p.Value = append([]byte(nil), b[:maxValueBytes]...)
			return p, maxValueBytes
		}
		return p, len(b)
	}
	if s, ok := p.Value.(string); ok && len(s) > maxValueBytes {
		p.Value = s[:maxValueBytes]
	}
	return p, 16
}

// pdu ist ein Wert aus einer Antwort (gekapselt, damit Tests ohne gosnmp-Typen auskommen).
type pdu = gosnmp.SnmpPDU

// conn ist die Verbindung zu einem Agenten (gosnmp oder ein Fake in Tests). Nicht gleichzeitig benutzen.
type conn interface {
	get(ctx context.Context, oids []string) ([]pdu, error)
	getNext(ctx context.Context, oids []string) ([]pdu, error)
	getBulk(ctx context.Context, oids []string, maxRep uint32) ([]pdu, error)
	v1() bool
	close()
}

// snmpError ist ein Fehlerstatus in der Antwort (noSuchName, tooBig ...).
type snmpError struct {
	status gosnmp.SNMPError
	index  int // 1-basiert (0 = ohne Index)
}

func (e *snmpError) Error() string {
	return fmt.Sprintf("SNMP-Fehler %s (Index %d)", e.status, e.index)
}

func statusOf(err error) gosnmp.SNMPError {
	var se *snmpError
	if errors.As(err, &se) {
		return se.status
	}
	return gosnmp.NoError
}

// gsConn ist die echte Verbindung ueber gosnmp.
type gsConn struct {
	g *gosnmp.GoSNMP
}

func (c *gsConn) v1() bool { return c.g.Version == gosnmp.Version1 }

func (c *gsConn) close() {
	if c.g != nil && c.g.Conn != nil {
		_ = c.g.Conn.Close()
	}
}

func (c *gsConn) check(p *gosnmp.SnmpPacket, err error) ([]pdu, error) {
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, errors.New("leere Antwort")
	}
	if p.Error != gosnmp.NoError {
		return nil, &snmpError{status: p.Error, index: int(p.ErrorIndex)}
	}
	return p.Variables, nil
}

func (c *gsConn) get(ctx context.Context, oids []string) ([]pdu, error) {
	c.g.Context = ctx
	return c.check(c.g.Get(oids))
}

func (c *gsConn) getNext(ctx context.Context, oids []string) ([]pdu, error) {
	c.g.Context = ctx
	return c.check(c.g.GetNext(oids))
}

func (c *gsConn) getBulk(ctx context.Context, oids []string, maxRep uint32) ([]pdu, error) {
	c.g.Context = ctx
	return c.check(c.g.GetBulk(oids, 0, maxRep))
}

// ---- OIDs ----

// oid ist eine numerische OID.
type oid []uint32

// parseOID liest ".1.3.6.1..." bzw. "1.3.6.1...".
func parseOID(s string) (oid, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), ".")
	if s == "" || len(s) > maxOIDTextSize {
		return nil, false
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > maxOIDParts {
		return nil, false
	}
	out := make(oid, len(parts))
	for i, p := range parts {
		if p == "" || len(p) > 10 {
			return nil, false
		}
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, false
		}
		out[i] = uint32(v)
	}
	return out, true
}

func (o oid) String() string {
	var b strings.Builder
	for _, v := range o {
		b.WriteByte('.')
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	}
	return b.String()
}

// cmpOID vergleicht lexikografisch (wie SNMP).
func cmpOID(a, b oid) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

// hasPrefix: o liegt unterhalb von p (echt laenger).
func (o oid) hasPrefix(p oid) bool {
	if len(o) <= len(p) {
		return false
	}
	for i := range p {
		if o[i] != p[i] {
			return false
		}
	}
	return true
}

// normOID bringt eine OID in die Form ".1.3.6..." ("" bei ungueltiger OID).
func normOID(s string) string {
	o, ok := parseOID(s)
	if !ok {
		return ""
	}
	return o.String()
}

// ---- Werte ----

// missing: Wert fehlt (noSuchObject, noSuchInstance, endOfMibView, Null).
func missing(p pdu) bool {
	switch p.Type {
	case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView, gosnmp.Null:
		return true
	}
	return p.Value == nil
}

// num liefert den Zahlenwert (auch Zahlen in Texten wie "42" oder "37 C/98 F" mit leading).
func num(p pdu) (float64, bool) {
	if missing(p) {
		return 0, false
	}
	var f float64
	switch v := p.Value.(type) {
	case int:
		f = float64(v)
	case int64:
		f = float64(v)
	case uint:
		f = float64(v)
	case uint32:
		f = float64(v)
	case uint64:
		f = float64(v)
	case float32:
		f = float64(v)
	case float64:
		f = v
	case []byte:
		return parseNumText(string(v), false)
	case string:
		return parseNumText(v, false)
	default:
		return 0, false
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

// u64 liefert einen Zaehlerstand (nur ganze, nicht negative Zahlen).
func u64(p pdu) (uint64, bool) {
	if missing(p) {
		return 0, false
	}
	switch v := p.Value.(type) {
	case uint:
		return uint64(v), true
	case uint32:
		return uint64(v), true
	case uint64:
		return v, true
	case int:
		if v >= 0 {
			return uint64(v), true
		}
	case int64:
		if v >= 0 {
			return uint64(v), true
		}
	}
	return 0, false
}

// is64 sagt, ob der Wert ein 64-Bit-Zaehler ist.
func is64(p pdu) bool { return p.Type == gosnmp.Counter64 }

// parseNumText liest eine Zahl aus einem Text; leading=true erlaubt Text nach der Zahl ("37 C/98 F", "5 %").
func parseNumText(s string, leading bool) (float64, bool) {
	s = strings.TrimSpace(s)
	if len(s) > 64 {
		s = s[:64]
	}
	if !leading {
		f, err := strconv.ParseFloat(s, 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, false
		}
		return f, true
	}
	i := 0
	if i < len(s) && (s[i] == '-' || s[i] == '+') {
		i++
	}
	dot := false
	start := i
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || (s[i] == '.' || s[i] == ',') && !dot) {
		if s[i] == '.' || s[i] == ',' {
			dot = true
		}
		i++
	}
	if i == start {
		return 0, false
	}
	f, err := strconv.ParseFloat(strings.Replace(strings.TrimRight(s[:i], ".,"), ",", ".", 1), 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

// text liefert einen Wert als bereinigten Text (gueltiges UTF-8, ohne Steuerzeichen, gekuerzt).
func text(p pdu) string {
	if missing(p) {
		return ""
	}
	switch v := p.Value.(type) {
	case []byte:
		return cleanText(string(v))
	case string:
		return cleanText(v)
	case net.IP:
		return v.String()
	default:
		if f, ok := num(p); ok {
			return strconv.FormatFloat(f, 'f', -1, 64)
		}
	}
	return ""
}

// rawBytes liefert die Bytes eines OCTET STRING (z. B. BITS, MAC).
func rawBytes(p pdu) []byte {
	if b, ok := p.Value.([]byte); ok {
		return b
	}
	if s, ok := p.Value.(string); ok {
		return []byte(s)
	}
	return nil
}

// cleanText: gueltiges UTF-8, Steuerzeichen raus, Leerraum zusammengefasst, hoechstens maxTextLen Zeichen.
func cleanText(s string) string {
	if len(s) > 4*maxTextLen {
		s = s[:4*maxTextLen]
	}
	s = strings.ToValidUTF8(s, "")
	var b strings.Builder
	space := false
	n := 0
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == utf8.RuneError {
			r = ' '
		}
		if r == ' ' {
			if space || b.Len() == 0 {
				continue
			}
			space = true
		} else {
			space = false
		}
		b.WriteRune(r)
		n++
		if n >= maxTextLen {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// keyPart: Teil eines Dienst-Schluessels aus einem Geraete-Text (ohne Leerraum am Rand, gekuerzt).
func keyPart(s string) string {
	s = cleanText(s)
	if len(s) > maxKeyPartLen {
		s = s[:maxKeyPartLen]
		s = strings.ToValidUTF8(s, "")
	}
	return s
}

// ---- Abfragen ----

// getScalars fragt OIDs ab (in Paketen); fehlende Werte fehlen im Ergebnis. v1: ein fehlender Wert (noSuchName)
// laesst die ganze Anfrage scheitern – dann ohne diesen Wert erneut.
func getScalars(ctx context.Context, c conn, oids []string) (map[string]pdu, error) {
	out := map[string]pdu{}
	for start := 0; start < len(oids); start += maxGetOIDs {
		chunk := append([]string(nil), oids[start:min(start+maxGetOIDs, len(oids))]...)
		for tries := 0; len(chunk) > 0 && tries <= maxGetOIDs; tries++ {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			res, err := c.get(ctx, chunk)
			if err != nil {
				var se *snmpError
				if errors.As(err, &se) && se.status == gosnmp.NoSuchName && se.index >= 1 && se.index <= len(chunk) {
					chunk = append(chunk[:se.index-1], chunk[se.index:]...)
					continue
				}
				return out, err
			}
			for _, p := range res {
				if missing(p) {
					continue
				}
				if n := normOID(p.Name); n != "" {
					out[n], _ = clip(p)
				}
			}
			break
		}
	}
	return out, nil
}

// table ist das Ergebnis einer Tabellen-Abfrage: Spalte -> Index (Rest-OID ohne Punkt vorn) -> Wert.
type table map[string]map[string]pdu

// col liefert eine Spalte (nie nil).
func (t table) col(c string) map[string]pdu {
	if m := t[c]; m != nil {
		return m
	}
	return map[string]pdu{}
}

// rows: alle Indizes, die in mindestens einer Spalte vorkommen (sortiert nach OID).
func (t table) rows() []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range t {
		for idx := range m {
			if !seen[idx] {
				seen[idx] = true
				out = append(out, idx)
			}
		}
	}
	sortIdx(out)
	return out
}

func sortIdx(l []string) {
	parsed := make(map[string]oid, len(l))
	for _, s := range l {
		o, _ := parseOID("0." + s)
		parsed[s] = o
	}
	for i := 1; i < len(l); i++ { // Einfuegesortierung genuegt (Tabellen sind meist schon sortiert)
		for j := i; j > 0 && cmpOID(parsed[l[j]], parsed[l[j-1]]) < 0; j-- {
			l[j], l[j-1] = l[j-1], l[j]
		}
	}
}

// walkColumns fragt mehrere Spalten gleichzeitig ab (GETBULK mit mehreren OIDs, v1 GETNEXT). Jede Spalte endet,
// sobald eine Antwort ausserhalb ihres Praefixes liegt, nicht steigt oder endOfMibView meldet.
func walkColumns(ctx context.Context, c conn, cols []string, maxRep int) (table, error) {
	type colState struct {
		name   string
		prefix oid
		last   oid
		done   bool
		rows   int
	}
	out := table{}
	states := make([]*colState, 0, len(cols))
	for _, s := range cols {
		o, ok := parseOID(s)
		if !ok {
			return out, fmt.Errorf("ungueltige OID %q", s)
		}
		n := o.String()
		out[n] = map[string]pdu{}
		states = append(states, &colState{name: n, prefix: o, last: o})
	}
	if maxRep <= 0 {
		maxRep = 20
	}
	total := 0
	for req := 0; req < maxWalkReqs; req++ {
		var active []*colState
		for _, st := range states {
			if !st.done {
				active = append(active, st)
			}
		}
		if len(active) == 0 {
			return out, nil
		}
		if err := ctx.Err(); err != nil {
			return out, err
		}
		oids := make([]string, len(active))
		for i, st := range active {
			oids[i] = st.last.String()
		}
		var res []pdu
		var err error
		if c.v1() {
			res, err = c.getNext(ctx, oids)
			if statusOf(err) == gosnmp.NoSuchName { // v1: Ende der MIB fuer eine Spalte
				var se *snmpError
				errors.As(err, &se)
				if se.index >= 1 && se.index <= len(active) {
					active[se.index-1].done = true
					continue
				}
				for _, st := range active {
					st.done = true
				}
				continue
			}
		} else {
			rep := max(1, min(maxRep, varbindBudget/len(active)))
			res, err = c.getBulk(ctx, oids, uint32(rep))
			if statusOf(err) == gosnmp.TooBig && maxRep > 1 {
				maxRep = max(1, rep/2)
				continue
			}
		}
		if err != nil {
			return out, err
		}
		if len(res) == 0 {
			return out, errors.New("leere Antwort")
		}
		changed := false
		for i, p := range res {
			st := active[i%len(active)]
			if st.done {
				continue
			}
			changed = true
			o, ok := parseOID(p.Name)
			if !ok || p.Type == gosnmp.EndOfMibView || !o.hasPrefix(st.prefix) || cmpOID(o, st.last) <= 0 {
				st.done = true
				continue
			}
			st.last = o
			if st.rows >= maxTableRows {
				st.done = true
				continue
			}
			if missing(p) {
				continue
			}
			st.rows++
			cp, size := clip(p)
			if total += size; total > maxWalkBytes {
				return out, errors.New("Antwort zu gross")
			}
			out[st.name][o[len(st.prefix):].String()[1:]] = cp
		}
		if !changed { // Antwort ohne verwertbare Werte: nicht endlos weiterfragen
			for _, st := range active {
				st.done = true
			}
		}
	}
	return out, errors.New("zu viele Anfragen fuer eine Tabelle")
}
