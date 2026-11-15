package filter

import (
	"bufio"
	"hash/maphash"
	"io"
	"math/bits"
	"strings"
)

// Matcher is an immutable snapshot of all blocklists. Domains are stored as
// 64-bit hashes instead of strings, which keeps ~1M rules at a few dozen MB.
// The value is a bit mask of the lists that contain the rule (bit i = list i,
// at most MaxLists), so device groups can use their own selection of lists and
// the UI can show which list blocked a query.
type Matcher struct {
	seed  maphash.Seed
	exact map[uint64]uint64
	wild  map[uint64]uint64
	allow map[uint64]struct{}
	// allowExact: Ausnahmen nur fuer genau diesen Namen (@@|example.com^)
	allowExact map[uint64]struct{}
	names      []string
	skipped    []int // je Liste: Zeilen mit Inhalt ohne DNS-Regel (nicht erkannt)
	limited    []int // je Liste: Regeln, die wegen maxRules nicht mehr geladen wurden
}

// maxRules: so viele Regeln (alle Listen zusammen, mit Ausnahmen) haelt ein Matcher hoechstens - sonst reichten
// 64 Listen zu je 64 MB fuer einen Speicherueberlauf auf kleinen Geraeten (Variable fuer Tests).
var maxRules = 4_000_000

// MaxLists is the number of lists one matcher can tell apart (bits of the mask).
const MaxLists = 64

// AllLists is the mask with every list.
const AllLists = ^uint64(0)

func newMatcher(names []string) *Matcher { return newMatcherSize(names, 1<<18) }

// newMatcherSize wie newMatcher; hint = erwartete Regeln je Map (Platz vorab).
func newMatcherSize(names []string, hint int) *Matcher {
	return &Matcher{
		seed:       maphash.MakeSeed(),
		exact:      make(map[uint64]uint64, hint),
		wild:       make(map[uint64]uint64, hint),
		allow:      make(map[uint64]struct{}),
		allowExact: make(map[uint64]struct{}),
		names:      names,
	}
}

func (m *Matcher) hash(s string) uint64 { return maphash.String(m.seed, s) }

func (m *Matcher) skip(idx int) {
	if len(m.skipped) <= idx {
		m.skipped = append(m.skipped, make([]int, idx+1-len(m.skipped))...)
	}
	m.skipped[idx]++
}

func (m *Matcher) limit(idx int) {
	if len(m.limited) <= idx {
		m.limited = append(m.limited, make([]int, idx+1-len(m.limited))...)
	}
	m.limited[idx]++
}

// Limited: Regeln der Liste idx, die wegen der Gesamtgrenze (maxRules) fehlen.
func (m *Matcher) Limited(idx int) int {
	if m == nil || idx >= len(m.limited) {
		return 0
	}
	return m.limited[idx]
}

// Skipped: Zeilen der Liste idx, die keine DNS-Regel ergaben (ohne Kommentare und Leerzeilen).
func (m *Matcher) Skipped(idx int) int {
	if m == nil || idx >= len(m.skipped) {
		return 0
	}
	return m.skipped[idx]
}

// load reads one list (index idx < MaxLists) into the matcher and returns the number of rules no list
// before it had.
func (m *Matcher) load(idx int, r io.Reader) (int, error) { return m.loadAs(idx, r, false) }

// loadAs wie load; release = Freigabe-Liste: auch Ausnahmen zaehlen als Eintrag der Liste (@@||example.com^ samt
// Subdomains, @@|example.com^ genau dieser Name).
func (m *Matcher) loadAs(idx int, r io.Reader, release bool) (int, error) {
	bit := uint64(1) << uint(idx)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	added := 0
	for sc.Scan() {
		domain, kind := parseLine(sc.Text())
		if kind == ruleNone {
			if t := strings.TrimSpace(sc.Text()); t != "" && t[0] != '#' && t[0] != '!' && t[0] != '[' {
				m.skip(idx)
			}
			continue
		}
		if release {
			switch kind {
			case ruleAllow:
				kind = ruleWildcard
			case ruleAllowExact:
				kind = ruleExact
			}
		}
		h := m.hash(domain)
		if m.full() && !m.has(kind, h) {
			m.limit(idx)
			continue
		}
		switch kind {
		case ruleExact:
			if m.exact[h] == 0 {
				added++
			}
			m.exact[h] |= bit
		case ruleWildcard:
			if m.wild[h] == 0 {
				added++
			}
			m.wild[h] |= bit
		case ruleAllow:
			m.allow[h] = struct{}{}
		case ruleAllowExact:
			m.allowExact[h] = struct{}{}
		}
	}
	return added, sc.Err()
}

// full: Gesamtgrenze erreicht (neue Regeln werden nicht mehr geladen, vorhandene bekommen weiter ihr Listen-Bit).
func (m *Matcher) full() bool {
	return len(m.exact)+len(m.wild)+len(m.allow)+len(m.allowExact) >= maxRules
}

// has: die Regel steht schon im Matcher (kostet keinen weiteren Platz).
func (m *Matcher) has(kind ruleKind, h uint64) bool {
	var ok bool
	switch kind {
	case ruleExact:
		_, ok = m.exact[h]
	case ruleWildcard:
		_, ok = m.wild[h]
	case ruleAllow:
		_, ok = m.allow[h]
	case ruleAllowExact:
		_, ok = m.allowExact[h]
	}
	return ok
}

// Size returns the number of blocking rules.
func (m *Matcher) Size() int { return len(m.exact) + len(m.wild) }

// Match reports whether any list blocks name and which one. name must be
// lowercase without trailing dot. Exceptions always win over blocks.
func (m *Matcher) Match(name string) (bool, string) { return m.MatchMask(name, AllLists) }

// MatchMask is Match restricted to the lists in mask; the reason is the first of them that blocks.
func (m *Matcher) MatchMask(name string, mask uint64) (bool, string) {
	if m == nil || name == "" || mask == 0 {
		return false, ""
	}
	exactHash := m.hash(name)
	if len(m.allowExact) > 0 {
		if _, ok := m.allowExact[exactHash]; ok {
			return false, ""
		}
	}
	hit := m.exact[exactHash] & mask
	for s := name; ; {
		h := exactHash
		if s != name {
			h = m.hash(s)
		}
		if _, ok := m.allow[h]; ok {
			return false, ""
		}
		if hit == 0 {
			hit = m.wild[h] & mask
		}
		i := strings.IndexByte(s, '.')
		if i < 0 {
			break
		}
		s = s[i+1:]
	}
	if hit == 0 {
		return false, ""
	}
	return true, m.names[bits.TrailingZeros64(hit)]
}
