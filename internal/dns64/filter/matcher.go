package filter

import (
	"bufio"
	"hash/maphash"
	"io"
	"strings"
)

// Matcher is an immutable snapshot of all blocklists. Domains are stored as
// 64-bit hashes instead of strings, which keeps ~1M rules at a few dozen MB.
// The value is the index of the first list that contained the rule, so the UI
// can show which list blocked a query.
type Matcher struct {
	seed  maphash.Seed
	exact map[uint64]uint8
	wild  map[uint64]uint8
	allow map[uint64]struct{}
	names []string
}

func newMatcher(names []string) *Matcher {
	return &Matcher{
		seed:  maphash.MakeSeed(),
		exact: make(map[uint64]uint8, 1<<18),
		wild:  make(map[uint64]uint8, 1<<18),
		allow: make(map[uint64]struct{}),
		names: names,
	}
}

func (m *Matcher) hash(s string) uint64 { return maphash.String(m.seed, s) }

// load reads one list into the matcher and returns the number of new rules.
func (m *Matcher) load(idx uint8, r io.Reader) (int, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	added := 0
	for sc.Scan() {
		domain, kind := parseLine(sc.Text())
		if kind == ruleNone {
			continue
		}
		h := m.hash(domain)
		switch kind {
		case ruleExact:
			if _, ok := m.exact[h]; !ok {
				m.exact[h] = idx
				added++
			}
		case ruleWildcard:
			if _, ok := m.wild[h]; !ok {
				m.wild[h] = idx
				added++
			}
		case ruleAllow:
			m.allow[h] = struct{}{}
		}
	}
	return added, sc.Err()
}

// Size returns the number of blocking rules.
func (m *Matcher) Size() int { return len(m.exact) + len(m.wild) }

// Match reports whether name is blocked and by which list. name must be
// lowercase without trailing dot. Exceptions always win over blocks.
func (m *Matcher) Match(name string) (bool, string) {
	if m == nil || name == "" {
		return false, ""
	}
	exactHash := m.hash(name)
	var (
		found bool
		list  uint8
	)
	if idx, ok := m.exact[exactHash]; ok {
		found, list = true, idx
	}
	for s := name; ; {
		h := exactHash
		if s != name {
			h = m.hash(s)
		}
		if _, ok := m.allow[h]; ok {
			return false, ""
		}
		if !found {
			if idx, ok := m.wild[h]; ok {
				found, list = true, idx
			}
		}
		i := strings.IndexByte(s, '.')
		if i < 0 {
			break
		}
		s = s[i+1:]
	}
	if !found {
		return false, ""
	}
	return true, m.names[list]
}
