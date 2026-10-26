package filter

import (
	"bufio"
	"errors"
	"fmt"
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
	mu     sync.RWMutex
	set    map[string]time.Time
}

type AllowEntry struct {
	Domain  string    `json:"domain"`
	AddedAt time.Time `json:"addedAt"`
}

var ErrInvalidDomain = errors.New("ungültiger Domainname")

func LoadAllowlist(path string) (*Allowlist, error) {
	return loadDomainList(path, "# Freigegebene Domains (inkl. Subdomains)")
}

// LoadDenylist laedt die eigene Sperrliste (gleiches Format wie die Freigaben; Eintrag = Domain samt Subdomains).
func LoadDenylist(path string) (*Allowlist, error) {
	return loadDomainList(path, "# Eigene Sperrliste (inkl. Subdomains)")
}

func loadDomainList(path, header string) (*Allowlist, error) {
	a := &Allowlist{path: path, header: header, set: map[string]time.Time{}}
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
		d, ok := normalizeDomain(name)
		if !ok {
			continue
		}
		added, _ := time.Parse(time.RFC3339, ts)
		a.set[d] = added
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

func (a *Allowlist) Add(domain string) (string, error) {
	d, ok := normalizeDomain(strings.TrimSpace(domain))
	if !ok {
		return "", ErrInvalidDomain
	}
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
