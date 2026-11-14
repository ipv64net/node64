package filter

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Allowlist holds domains the user released from blocking. An entry covers
// the domain and all of its subdomains. It is stored as a plain text file
// ("domain<TAB>RFC3339 time" per line) so it survives image updates.
type Allowlist struct {
	path   string
	header string // erste Zeile der Datei
	allow  bool   // Freigaben (sonst eigene Sperrliste): nimmt auch Regeln mit "@@" an
	mu     sync.RWMutex
	set    map[string]time.Time
}

type AllowEntry struct {
	Domain  string    `json:"domain"`
	AddedAt time.Time `json:"addedAt"`
}

var ErrInvalidDomain = errors.New("ungültiger Domainname")

func LoadAllowlist(path string) (*Allowlist, error) {
	return loadDomainList(path, "# Freigegebene Domains (inkl. Subdomains)", true)
}

// LoadDenylist laedt die eigene Sperrliste (gleiches Format wie die Freigaben; Eintrag = Domain samt Subdomains).
func LoadDenylist(path string) (*Allowlist, error) {
	return loadDomainList(path, "# Eigene Sperrliste (inkl. Subdomains)", false)
}

// loadDomainList liest eine Liste ("domain<TAB>Zeit" je Zeile). Von Hand eingetragene Zeilen im Adblock-Stil
// (||example.com^, in den Freigaben auch @@||example.com^) und hosts-Zeilen zaehlen mit (ParseRule).
func loadDomainList(path, header string, allow bool) (*Allowlist, error) {
	a := &Allowlist{path: path, header: header, allow: allow, set: map[string]time.Time{}}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return a, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		name, ts, _ := strings.Cut(line, "\t")
		r, tok, err := ParseRule(name)
		if tok == "" || err != nil || r.Allow && !allow {
			continue
		}
		added, _ := time.Parse(time.RFC3339, ts)
		a.set[r.Domain] = added
	}
	return a, sc.Err()
}

// Contains reports whether name or one of its parent domains is allowed.
func (a *Allowlist) Contains(name string) bool {
	_, ok := a.Match(name)
	return ok
}

// Match liefert den genauesten Eintrag, der name abdeckt (name selbst oder eine Elterndomain).
func (a *Allowlist) Match(name string) (string, bool) {
	if a == nil {
		return "", false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if len(a.set) == 0 {
		return "", false
	}
	for s := name; ; {
		if _, ok := a.set[s]; ok {
			return s, true
		}
		i := strings.IndexByte(s, '.')
		if i < 0 {
			return "", false
		}
		s = s[i+1:]
	}
}

// Add nimmt eine Domain auf (samt Subdomains); auch im Adblock-Stil (||example.com^, bei Freigaben @@||example.com^)
// oder als hosts-Zeile. Fehler: ErrInvalidDomain, ErrRuleClient, ErrRuleExact, ErrRuleAllow (@@ in der Sperrliste).
func (a *Allowlist) Add(domain string) (string, error) {
	r, tok, err := ParseRule(domain)
	if tok == "" && err == nil {
		err = ErrInvalidDomain
	}
	if err == nil && r.Allow && !a.allow {
		err = ErrRuleAllow
	}
	if err != nil {
		return "", err
	}
	d := r.Domain
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.set[d]; exists {
		return d, nil
	}
	a.set[d] = time.Now().UTC()
	return d, a.saveLocked()
}

func (a *Allowlist) Remove(domain string) error {
	d, ok := normalizeDomain(strings.TrimSpace(domain))
	if !ok {
		return ErrInvalidDomain
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.set, d)
	return a.saveLocked()
}

// ReplaceResult beschreibt das Ersetzen einer Liste aus einem Textfeld.
type ReplaceResult struct {
	Total      int      `json:"total"`      // Eintraege danach
	Added      int      `json:"added"`      // neu
	Removed    int      `json:"removed"`    // nicht mehr enthalten
	Duplicates int      `json:"duplicates"` // doppelte Zeilen (zusammengefasst)
	Invalid    []string `json:"invalid"`    // ungueltige Zeilen (hoechstens 20)
	New        []string `json:"-"`          // neu aufgenommene Domains
}

// LineDomain liefert die Domain einer Zeile aus einem Textfeld (Format wie ParseRule: Domain, *.Domain,
// ||Domain^, hosts-Zeile; Kommentare und ein Zeitstempel nach Tab werden ignoriert). tok ist die gepruefte Zeile
// (fuer die Meldung ungueltiger Zeilen); tok == "" heisst nichts zu tun (leere Zeile, Kommentar, Standardnamen einer
// hosts-Datei wie localhost). Eine IP-Adresse ist nie eine Domain; Freigaben (@@) gelten hier als ungueltig.
func LineDomain(line string) (d, tok string, ok bool) {
	r, tok, err := ParseRule(line)
	if tok == "" || err != nil || r.Allow {
		return "", tok, false
	}
	return r.Domain, tok, true
}

// normalizeEntry wie normalizeDomain, lehnt aber IP-Adressen ab ("0.0.0.0" saehe sonst wie ein Name aus).
func normalizeEntry(s string) (string, bool) {
	d, ok := normalizeDomain(s)
	if !ok || isIP(d) {
		return "", false
	}
	return d, true
}

func isIP(s string) bool {
	_, err := netip.ParseAddr(strings.Trim(s, "[]"))
	return err == nil
}

// Replace setzt die Liste auf die Domains aus lines (eine je Zeile, Format wie LineDomain). Vorhandene Eintraege
// behalten ihr Datum. Ungueltige Zeilen werden gemeldet und nicht uebernommen; sind alle Zeilen ungueltig, bleibt
// die Liste unveraendert.
func (a *Allowlist) Replace(lines []string) (ReplaceResult, error) {
	var res ReplaceResult
	res.Invalid = []string{}
	next := map[string]bool{}
	bad := 0
	for _, line := range lines {
		r, tok, err := ParseRule(line)
		if tok == "" {
			continue
		}
		d, ok := r.Domain, err == nil && (a.allow || !r.Allow)
		if !ok {
			bad++
			if len(res.Invalid) < 20 {
				res.Invalid = append(res.Invalid, tok)
			}
			continue
		}
		if next[d] {
			res.Duplicates++
			continue
		}
		next[d] = true
	}
	if len(next) == 0 && bad > 0 {
		res.Total = a.Len()
		return res, ErrInvalidDomain
	}
	list := make([]string, 0, len(next))
	for d := range next {
		list = append(list, d)
	}
	var err error
	res.New, res.Removed, err = a.setDomains(list)
	res.Added, res.Total = len(res.New), a.Len()
	return res, err
}

// setDomains setzt die Liste auf domains (geprueft); vorhandene Eintraege behalten ihr Datum.
func (a *Allowlist) setDomains(domains []string) (added []string, removed int, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now().UTC()
	set := make(map[string]time.Time, len(domains))
	for _, d := range domains {
		if t, ok := a.set[d]; ok {
			set[d] = t
		} else if _, dup := set[d]; !dup {
			set[d] = now
			added = append(added, d)
		}
	}
	for d := range a.set {
		if _, ok := set[d]; !ok {
			removed++
		}
	}
	a.set = set
	return added, removed, a.saveLocked()
}

// Len ist die Zahl der Eintraege.
func (a *Allowlist) Len() int {
	if a == nil {
		return 0
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.set)
}

// domains: alle Eintraege alphabetisch.
func (a *Allowlist) domains() []string {
	if a == nil {
		return nil
	}
	a.mu.RLock()
	out := make([]string, 0, len(a.set))
	for d := range a.set {
		out = append(out, d)
	}
	a.mu.RUnlock()
	sort.Strings(out)
	return out
}

// Text liefert die Eintraege fuer ein Textfeld (eine Domain je Zeile, alphabetisch).
func (a *Allowlist) Text() string {
	return strings.Join(a.domains(), "\n")
}

func (a *Allowlist) List() []AllowEntry {
	a.mu.RLock()
	out := make([]AllowEntry, 0, len(a.set))
	for d, t := range a.set {
		out = append(out, AllowEntry{d, t})
	}
	a.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].AddedAt.After(out[j].AddedAt) })
	return out
}

func (a *Allowlist) saveLocked() error {
	var sb strings.Builder
	sb.WriteString(a.header + "\n")
	for d, t := range a.set {
		fmt.Fprintf(&sb, "%s\t%s\n", d, t.Format(time.RFC3339))
	}
	tmp := a.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, a.path)
}
