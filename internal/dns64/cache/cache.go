// Package cache is a TTL-respecting DNS response cache with optimistic
// caching: popular entries are refreshed shortly before they expire, and
// expired entries are still served (with a short TTL) while a fresh copy is
// fetched in the background (RFC 8767 "serve stale").
package cache

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	maxTTL      = 24 * time.Hour
	maxNegative = 5 * time.Minute

	staleWindow  = time.Hour        // how long past expiry an entry may still be served
	staleTTL     = 30               // TTL in seconds handed out with stale answers (RFC 8767)
	prefetchHits = 2                // hits before an entry is kept warm ahead of expiry
	refreshRetry = 10 * time.Second // back-off before retrying a failed background refresh

	bytesPerEntry = 1024     // Speicher-Budget je Platz (ungefaehre Groesse der Antworten), Antworten sind meist kleiner
	maxEntryBytes = 16 << 10 // groessere Antworten werden nicht zwischengespeichert
)

// State says how an answer came out of the cache.
type State int

const (
	Miss  State = iota
	Fresh       // within TTL
	Stale       // expired, served while a refresh runs
)

type entry struct {
	msg       *dns.Msg
	stored    time.Time
	expires   time.Time
	ttl       time.Duration
	size      int // ungefaehre Groesse der Antwort in Byte
	hits      uint32
	refreshAt time.Time // start of the last background refresh; zero = none
}

type Cache struct {
	mu       sync.Mutex
	m        map[string]*entry
	max      int
	bytes    int // Summe der Groessen aller Eintraege
	maxBytes int

	hits, misses, stale        uint64
	refreshed, refreshFailures uint64
}

func New(max int) *Cache {
	return &Cache{m: make(map[string]*entry, max), max: max, maxBytes: max * bytesPerEntry}
}

func key(r *dns.Msg) string {
	q := r.Question[0]
	do := "0"
	if opt := r.IsEdns0(); opt != nil && opt.Do() {
		do = "1"
	}
	cd := "0" // CD=1: ungepruefte Antwort, nie an Clients mit CD=0
	if r.CheckingDisabled {
		cd = "1"
	}
	return strings.ToLower(q.Name) + "|" + strconv.Itoa(int(q.Qtype)) + "|" + strconv.Itoa(int(q.Qclass)) + "|" + do + cd
}

// Get returns a copy of the cached answer, or nil on a miss. refresh is true
// when the caller should fetch a new copy in the background: the entry is
// stale, or it is popular and in the last 10% of its TTL. Only one caller
// per entry gets refresh=true at a time.
func (c *Cache) Get(req *dns.Msg) (resp *dns.Msg, state State, refresh bool) {
	k := key(req)
	now := time.Now()

	c.mu.Lock()
	e, ok := c.m[k]
	if ok && now.After(e.expires.Add(staleWindow)) {
		c.drop(k, e)
		ok = false
	}
	if !ok {
		c.misses++
		c.mu.Unlock()
		return nil, Miss, false
	}
	c.hits++
	e.hits++
	state = Fresh
	if !now.Before(e.expires) {
		state = Stale
		c.stale++
		refresh = claim(e, now)
	} else if e.hits >= prefetchHits && e.expires.Sub(now) <= e.ttl/10 {
		refresh = claim(e, now)
	}
	msg, stored := e.msg, e.stored
	c.mu.Unlock()

	resp = msg.Copy()
	age := uint32(now.Sub(stored) / time.Second)
	for _, sec := range [][]dns.RR{resp.Answer, resp.Ns, resp.Extra} {
		for _, rr := range sec {
			h := rr.Header()
			switch {
			case h.Rrtype == dns.TypeOPT:
			case state == Stale:
				h.Ttl = staleTTL
			case h.Ttl > age:
				h.Ttl -= age
			default:
				h.Ttl = 0
			}
		}
	}
	resp.Id = req.Id
	return resp, state, refresh
}

func claim(e *entry, now time.Time) bool {
	if !e.refreshAt.IsZero() && now.Sub(e.refreshAt) < refreshRetry {
		return false
	}
	e.refreshAt = now
	return true
}

func (c *Cache) Set(req, resp *dns.Msg) {
	if resp.Truncated || (resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError) {
		return
	}
	ttl := ttlOf(resp)
	if ttl <= 0 {
		return
	}
	size := resp.Len()
	if size > maxEntryBytes {
		return
	}
	now := time.Now()
	e := &entry{msg: resp.Copy(), stored: now, expires: now.Add(ttl), ttl: ttl, size: size}
	k := key(req)

	c.mu.Lock()
	defer c.mu.Unlock()
	if old, ok := c.m[k]; ok {
		e.hits = old.hits // keep popularity across refreshes
		c.drop(k, old)
	}
	for len(c.m) > 0 && (len(c.m) >= c.max || c.bytes+size > c.maxBytes) {
		c.evict(now)
	}
	c.m[k] = e
	c.bytes += size
}

// drop entfernt einen Eintrag und zieht seine Groesse ab (c.mu gehalten).
func (c *Cache) drop(k string, e *entry) {
	delete(c.m, k)
	c.bytes -= e.size
}

// Delete drops an entry, e.g. when a refresh revealed a blocked CNAME.
func (c *Cache) Delete(req *dns.Msg) {
	c.mu.Lock()
	k := key(req)
	if e, ok := c.m[k]; ok {
		c.drop(k, e)
	}
	c.mu.Unlock()
}

// RefreshDone records the outcome of a background refresh for the stats.
func (c *Cache) RefreshDone(ok bool) {
	c.mu.Lock()
	if ok {
		c.refreshed++
	} else {
		c.refreshFailures++
	}
	c.mu.Unlock()
}

// Flush removes all entries and returns how many there were.
func (c *Cache) Flush() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.m)
	clear(c.m)
	c.bytes = 0
	return n
}

// evict makes room: first entries beyond the stale window, then stale ones,
// then arbitrary ones (map iteration order is random).
func (c *Cache) evict(now time.Time) {
	removed := 0
	for k, e := range c.m {
		if now.After(e.expires.Add(staleWindow)) {
			c.drop(k, e)
			removed++
		}
		if removed >= 64 {
			return
		}
	}
	for k, e := range c.m {
		if removed >= 16 {
			return
		}
		if !now.Before(e.expires) {
			c.drop(k, e)
			removed++
		}
	}
	for k, e := range c.m {
		if removed >= 16 {
			return
		}
		c.drop(k, e)
		removed++
	}
}

func ttlOf(m *dns.Msg) time.Duration {
	var lowest uint32
	found := false
	take := func(t uint32) {
		if !found || t < lowest {
			lowest, found = t, true
		}
	}
	for _, rr := range m.Answer {
		take(rr.Header().Ttl)
	}
	if len(m.Answer) > 0 && m.Rcode == dns.RcodeSuccess && hasAnswerFor(m) {
		return min(time.Duration(lowest)*time.Second, maxTTL)
	}
	// Negative answer (auch NXDOMAIN/NODATA hinter einem CNAME): RFC 2308 - the minimum of SOA TTL and SOA MINIMUM.
	soa := false
	for _, rr := range m.Ns {
		if s, ok := rr.(*dns.SOA); ok {
			take(s.Hdr.Ttl)
			take(s.Minttl)
			soa = true
		}
	}
	if !soa {
		return 0 // ohne SOA nicht negativ zwischenspeichern (RFC 2308 5)
	}
	return min(time.Duration(lowest)*time.Second, maxNegative)
}

// hasAnswerFor: die Antwort enthaelt Daten des gefragten Typs (sonst NODATA, z. B. nur die CNAME-Kette).
func hasAnswerFor(m *dns.Msg) bool {
	if len(m.Question) == 0 {
		return true
	}
	qt := m.Question[0].Qtype
	if qt == dns.TypeANY {
		return true
	}
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == qt {
			return true
		}
	}
	return false
}

type Stats struct {
	Entries         int    `json:"entries"`
	Max             int    `json:"max"`
	StaleEntries    int    `json:"staleEntries"`
	Hits            uint64 `json:"hits"`
	Misses          uint64 `json:"misses"`
	StaleServed     uint64 `json:"staleServed"`
	Refreshed       uint64 `json:"refreshed"`
	RefreshFailures uint64 `json:"refreshFailures"`
}

func (c *Cache) Stats() Stats {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	stale := 0
	for _, e := range c.m {
		if !now.Before(e.expires) {
			stale++
		}
	}
	return Stats{
		Entries: len(c.m), Max: c.max, StaleEntries: stale,
		Hits: c.hits, Misses: c.misses, StaleServed: c.stale,
		Refreshed: c.refreshed, RefreshFailures: c.refreshFailures,
	}
}
