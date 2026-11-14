package filter

import (
	"errors"
	"math/bits"
	"strings"
)

// Eigene Filterregeln im AdGuard/Adblock-Stil (Forum 5162, #70): Sperren und Freigaben in einem Textfeld, gespeichert
// in den beiden eigenen Listen (Sperrliste denylist.txt, Freigaben allowlist.txt; je Eintrag Domain samt Subdomains).
// Verstanden werden die DNS-tauglichen Formen, die Nutzer aus AdGuard Home und Pi-hole mitbringen:
//
//	||example.com^            sperren samt Subdomains ("$important" erlaubt)
//	@@||example.com^          freigeben samt Subdomains
//	example.com, *.example.com, example.com^   sperren samt Subdomains
//	0.0.0.0 example.com       hosts-Zeile: sperren
//	# bzw. ! am Zeilenanfang  Kommentar
//
// Nicht moeglich: Regeln nur fuer genau einen Namen ("|example.com^"; die eigenen Listen gelten immer samt
// Subdomains), Pfade und Browser-Regeln sowie "$client=..." - Regeln je Geraet gibt es ueber Geraetegruppen (eigene
// Sperren und Freigaben je Gruppe; eine Gruppe darf ein einzelnes Geraet enthalten).

// Rule ist eine eigene Filterregel: Domain samt Subdomains sperren bzw. (Allow) freigeben.
type Rule struct {
	Domain string `json:"domain"`
	Allow  bool   `json:"allow"`
}

// Fehler einer Regel (zusaetzlich ErrInvalidDomain).
var (
	ErrRuleClient = errors.New("$client: Regeln je Geraet ueber Geraetegruppen")
	ErrRuleExact  = errors.New("|domain^: eigene Regeln gelten immer samt Subdomains")
	ErrRuleAllow  = errors.New("@@: Freigabe gehoert zu den Freigaben")
)

// ParseRule liest eine Zeile. tok ist die gepruefte Zeile ohne Kommentar (fuer Meldungen); tok == "" heisst nichts zu
// tun (leer, Kommentar, Standardnamen einer hosts-Datei). Ein Zeitstempel nach Tab (Format der Listen-Dateien) und
// ein Kommentar nach Leerzeichen und "#" werden ignoriert.
func ParseRule(line string) (r Rule, tok string, err error) {
	s := strings.TrimSpace(line)
	if s == "" || s[0] == '#' || s[0] == '!' || s[0] == '[' {
		return Rule{}, "", nil
	}
	if i := strings.IndexByte(s, '#'); i > 0 && (s[i-1] == ' ' || s[i-1] == '\t') {
		s = strings.TrimSpace(s[:i])
	}
	tok = s
	if rest, ok := strings.CutPrefix(s, "@@"); ok {
		r.Allow, s = true, rest
	}
	if i := strings.IndexByte(s, '$'); i >= 0 { // Modifikatoren: nur $important (aendert bei DNS nichts)
		for _, mod := range strings.Split(s[i+1:], ",") {
			switch mod = strings.TrimSpace(mod); {
			case mod == "important":
			case strings.HasPrefix(mod, "client="), strings.HasPrefix(mod, "ctag="):
				return Rule{}, tok, ErrRuleClient
			default:
				return Rule{}, tok, ErrInvalidDomain
			}
		}
		s = s[:i]
	}
	adblock := false
	switch {
	case strings.HasPrefix(s, "||"):
		s, adblock = s[2:], true
	case strings.HasPrefix(s, "|*."):
		s, adblock = s[1:], true
	case strings.HasPrefix(s, "|"):
		return Rule{}, tok, ErrRuleExact
	}
	if t := strings.TrimSuffix(s, "|"); strings.HasSuffix(t, "^") {
		s, adblock = strings.TrimSuffix(t, "^"), true
	}
	if !adblock {
		f := strings.Fields(s)
		if len(f) == 0 {
			return Rule{}, tok, ErrInvalidDomain
		}
		s = f[0]
		if isIP(f[0]) && len(f) > 1 { // hosts-Format
			if hostsIgnore[strings.ToLower(f[1])] {
				return Rule{}, "", nil
			}
			if r.Allow {
				return Rule{}, tok, ErrInvalidDomain
			}
			s = f[1]
		}
	}
	d, ok := normalizeEntry(strings.TrimPrefix(s, "*."))
	if !ok {
		return Rule{}, tok, ErrInvalidDomain
	}
	r.Domain = d
	return r, tok, nil
}

// Text ist die Regel im Adblock-Stil (||example.com^ bzw. @@||example.com^).
func (r Rule) Text() string {
	if r.Allow {
		return "@@||" + r.Domain + "^"
	}
	return "||" + r.Domain + "^"
}

// RulesText liefert die eigenen Listen als Regeln fuer das Textfeld: erst Sperren, dann Freigaben, je alphabetisch.
func RulesText(allow, deny *Allowlist) string {
	var out []string
	for _, l := range []struct {
		list  *Allowlist
		allow bool
	}{{deny, false}, {allow, true}} {
		for _, d := range l.list.domains() {
			out = append(out, Rule{Domain: d, Allow: l.allow}.Text())
		}
	}
	return strings.Join(out, "\n")
}

// RulesResult beschreibt das Ersetzen der eigenen Listen aus dem Textfeld.
type RulesResult struct {
	Deny       int      `json:"deny"`       // Sperren danach
	Allow      int      `json:"allow"`      // Freigaben danach
	Added      int      `json:"added"`      // neue Regeln
	Removed    int      `json:"removed"`    // weggefallene Regeln
	Duplicates int      `json:"duplicates"` // doppelte Zeilen (zusammengefasst)
	Invalid    []string `json:"invalid"`    // ungueltige Zeilen (hoechstens 20)
	Client     int      `json:"client"`     // davon mit $client (Hinweis auf Geraetegruppen)
	Exact      int      `json:"exact"`      // davon nur fuer genau einen Namen (|domain^)
}

// ReplaceRules setzt Sperrliste und Freigaben auf die Regeln aus lines. Ungueltige Zeilen werden gemeldet und nicht
// uebernommen; sind alle Zeilen ungueltig, bleiben beide Listen unveraendert (ErrInvalidDomain).
func ReplaceRules(allow, deny *Allowlist, lines []string) (RulesResult, error) {
	res := RulesResult{Invalid: []string{}}
	want := map[bool][]string{}
	seen := map[Rule]bool{}
	bad := 0
	for _, line := range lines {
		r, tok, err := ParseRule(line)
		if tok == "" {
			continue
		}
		if err != nil {
			bad++
			switch {
			case errors.Is(err, ErrRuleClient):
				res.Client++
			case errors.Is(err, ErrRuleExact):
				res.Exact++
			}
			if len(res.Invalid) < 20 {
				res.Invalid = append(res.Invalid, tok)
			}
			continue
		}
		if seen[r] {
			res.Duplicates++
			continue
		}
		seen[r] = true
		want[r.Allow] = append(want[r.Allow], r.Domain)
	}
	if len(seen) == 0 && bad > 0 {
		res.Deny, res.Allow = deny.Len(), allow.Len()
		return res, ErrInvalidDomain
	}
	da, dr, err := deny.setDomains(want[false])
	if err != nil {
		return res, err
	}
	aa, ar, err := allow.setDomains(want[true])
	if err != nil {
		return res, err
	}
	res.Added, res.Removed = len(da)+len(aa), dr+ar
	res.Deny, res.Allow = deny.Len(), allow.Len()
	return res, nil
}

// Lists liefert alle Listen mit einer Regel fuer name (genau dieser Name oder samt Subdomains) als Bitmaske und ob
// eine Ausnahme (@@) einer Liste den Namen freigibt - fuer die Suche "In welcher Liste steht diese Domain?".
func (m *Matcher) Lists(name string) (mask uint64, excepted bool) {
	if m == nil || name == "" {
		return 0, false
	}
	h := m.hash(name)
	_, excepted = m.allowExact[h]
	mask = m.exact[h]
	for s := name; ; {
		h = m.hash(s)
		mask |= m.wild[h]
		if _, ok := m.allow[h]; ok {
			excepted = true
		}
		i := strings.IndexByte(s, '.')
		if i < 0 {
			break
		}
		s = s[i+1:]
	}
	return mask, excepted
}

// ListNames: Namen der Listen einer Bitmaske (Reihenfolge wie geladen).
func (m *Matcher) ListNames(mask uint64) []string {
	var out []string
	for mask != 0 && m != nil {
		i := bits.TrailingZeros64(mask)
		if i < len(m.names) {
			out = append(out, m.names[i])
		}
		mask &^= 1 << uint(i)
	}
	return out
}

// Lookup ist das Ergebnis der Suche nach einer Domain in allen Listen und Regeln (ohne Geraetegruppen).
type Lookup struct {
	Domain   string        `json:"domain"`
	Blocked  bool          `json:"blocked"` // Geraete ohne Gruppe: gesperrt
	Reason   string        `json:"reason"`  // Grund wie im Abfrage-Log (Liste, "own:", "released:")
	Lists    []LookupList  `json:"lists"`   // Blocklisten mit einer Regel fuer die Domain
	Excepted bool          `json:"excepted"`
	Own      string        `json:"own,omitempty"`     // Eintrag der eigenen Sperrliste
	Allowed  string        `json:"allowed,omitempty"` // eigene Freigabe
	Released []string      `json:"released"`          // Freigabe-Listen
	Services []string      `json:"services"`          // Dienste (Gruppen: per Klick sperren)
	Cats     []string      `json:"categories"`        // eingebaute Kategorien
	Groups   []LookupGroup `json:"groups"`            // eigene Sperren/Freigaben der Geraetegruppen
}

// LookupList ist eine Blockliste mit Treffer; Global = gilt fuer Geraete ohne Gruppe.
type LookupList struct {
	Name   string `json:"name"`
	Global bool   `json:"global"`
}

// LookupGroup ist eine Regel einer Geraetegruppe ("block" bzw. "allow") mit dem Eintrag.
type LookupGroup struct {
	Group string `json:"group"`
	Kind  string `json:"kind"`
	Entry string `json:"entry"`
}

// Lookup sucht name in den Blocklisten, den eigenen Listen, den Freigabe-Listen und den eingebauten Kategorien und
// Diensten - dieselben Regeln wie beim Beantworten (Check).
func (m *Manager) Lookup(name string) Lookup {
	out := Lookup{Domain: name, Lists: []LookupList{}, Released: []string{}, Services: []string{}, Cats: []string{}, Groups: []LookupGroup{}}
	out.Blocked, out.Reason = m.Check(name)
	mt := m.cur.Load()
	mask, exc := mt.Lists(name)
	global := m.Global()
	for i := 0; mask != 0; i++ {
		if mask&1 != 0 && mt != nil && i < len(mt.names) {
			out.Lists = append(out.Lists, LookupList{Name: mt.names[i], Global: global&(1<<uint(i)) != 0})
		}
		mask >>= 1
	}
	out.Excepted = exc
	out.Own, _ = m.Deny.Match(name)
	out.Allowed, _ = m.Allow.Match(name)
	if m.Release != nil && len(m.Release.lists) > 0 {
		rm, _ := m.Release.cur.Load().Lists(name)
		out.Released = append(out.Released, m.Release.cur.Load().ListNames(rm)...)
	}
	for _, s := range Services {
		if _, ok := serviceSets[ServicePrefix+s.ID].Match(name); ok {
			out.Services = append(out.Services, s.Name)
		}
	}
	for _, k := range GroupCategories { // Kategorien ueber eine Blockliste (z. B. Gluecksspiel) haben keine Menge
		if _, ok := categorySets[k].Match(name); ok {
			out.Cats = append(out.Cats, k)
		}
	}
	return out
}
