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
	names []string
}

// MaxLists is the number of lists one matcher can tell apart (bits of the mask).
const MaxLists = 64

// AllLists is the mask with every list.
const AllLists = ^uint64(0)

func newMatcher(names []string) *Matcher {
	return &Matcher{
		seed:  maphash.MakeSeed(),
		exact: make(map[uint64]uint64, 1<<18),
		wild:  make(map[uint64]uint64, 1<<18),
		allow: make(map[uint64]struct{}),
		names: names,
	}
}

func (m *Matcher) hash(s string) uint64 { return maphash.String(m.seed, s) }

// load reads one list (index idx < MaxLists) into the matcher and returns the number of rules no list
// before it had.
func (m *Matcher) load(idx int, r io.Reader) (int, error) {
	bit := uint64(1) << uint(idx)
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
		}
	}
	return added, sc.Err()
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
