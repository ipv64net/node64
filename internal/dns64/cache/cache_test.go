package cache

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func answer(name string, ttl uint32) (*dns.Msg, *dns.Msg) {
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.IPv4(192, 0, 2, 1),
	}}
	return req, resp
}

// age moves an entry's clock back so tests need not sleep.
func age(c *Cache, req *dns.Msg, d time.Duration) {
	e := c.m[key(req)]
	e.stored = e.stored.Add(-d)
	e.expires = e.expires.Add(-d)
}

func TestFreshHitCountsDownTTL(t *testing.T) {
	c := New(10)
	req, resp := answer("example.com.", 300)
	c.Set(req, resp)
	age(c, req, 100*time.Second)

	got, state, refresh := c.Get(req)
	if state != Fresh || refresh {
		t.Fatalf("state=%v refresh=%v, want Fresh without refresh", state, refresh)
	}
	if ttl := got.Answer[0].Header().Ttl; ttl != 200 {
		t.Errorf("TTL = %d, want 200", ttl)
	}
}

func TestPrefetchPopularEntryNearExpiry(t *testing.T) {
	c := New(10)
	req, resp := answer("popular.example.", 100)
	c.Set(req, resp)
	c.Get(req) // first hit: not popular yet
	age(c, req, 95*time.Second)

	if _, state, refresh := c.Get(req); state != Fresh || !refresh {
		t.Fatalf("state=%v refresh=%v, want Fresh with refresh", state, refresh)
	}
	if _, _, refresh := c.Get(req); refresh {
		t.Error("second caller must not start another refresh")
	}
}

func TestNoPrefetchForOneOffEntry(t *testing.T) {
	c := New(10)
	req, resp := answer("rare.example.", 100)
	c.Set(req, resp)
	age(c, req, 95*time.Second)
	if _, _, refresh := c.Get(req); refresh {
		t.Error("an entry hit only once should not be prefetched")
	}
}

func TestServeStale(t *testing.T) {
	c := New(10)
	req, resp := answer("stale.example.", 60)
	c.Set(req, resp)
	age(c, req, 10*time.Minute)

	got, state, refresh := c.Get(req)
	if got == nil || state != Stale || !refresh {
		t.Fatalf("got=%v state=%v refresh=%v, want stale answer with refresh", got != nil, state, refresh)
	}
	if ttl := got.Answer[0].Header().Ttl; ttl != staleTTL {
		t.Errorf("stale TTL = %d, want %d", ttl, staleTTL)
	}

	// a refresh replaces the entry and keeps its popularity
	_, fresh := answer("stale.example.", 60)
	c.Set(req, fresh)
	if _, state, _ := c.Get(req); state != Fresh {
		t.Errorf("after refresh state=%v, want Fresh", state)
	}
	if hits := c.m[key(req)].hits; hits < 2 {
		t.Errorf("hits = %d, popularity lost on refresh", hits)
	}
}

func TestBeyondStaleWindowIsMiss(t *testing.T) {
	c := New(10)
	req, resp := answer("old.example.", 60)
	c.Set(req, resp)
	age(c, req, staleWindow+2*time.Minute)
	if got, state, _ := c.Get(req); got != nil || state != Miss {
		t.Fatalf("want miss after stale window, got state=%v", state)
	}
}

func TestFlushAndStats(t *testing.T) {
	c := New(10)
	req, resp := answer("a.example.", 60)
	c.Set(req, resp)
	c.Get(req)
	if n := c.Flush(); n != 1 {
		t.Errorf("Flush() = %d, want 1", n)
	}
	st := c.Stats()
	if st.Entries != 0 || st.Hits != 1 {
		t.Errorf("stats = %+v", st)
	}
}

// CD=1 (Pruefung aus) und CD=0 teilen sich keinen Eintrag: ungepruefte Antworten nie an validierende Clients.
func TestCheckingDisabledSeparateKey(t *testing.T) {
	c := New(10)
	req, resp := answer("cd.example.", 300)
	req.CheckingDisabled = true
	c.Set(req, resp)
	plain := new(dns.Msg)
	plain.SetQuestion("cd.example.", dns.TypeA)
	if got, _, _ := c.Get(plain); got != nil {
		t.Fatal("CD=1 answer served to a CD=0 query")
	}
	if got, _, _ := c.Get(req); got == nil {
		t.Fatal("CD=1 answer not cached for CD=1")
	}
}

// NXDOMAIN bzw. NODATA hinter einem CNAME: negative TTL aus dem SOA, nicht die (lange) TTL des CNAME.
func TestNegativeBehindCNAME(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("alias.example.", dns.TypeAAAA)
	for _, rcode := range []int{dns.RcodeSuccess, dns.RcodeNameError} {
		resp := new(dns.Msg)
		resp.SetRcode(req, rcode)
		resp.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: "alias.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 86400}, Target: "target.example."}}
		resp.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600}, Ns: "ns.example.", Mbox: "h.example.", Minttl: 60}}
		if ttl := ttlOf(resp); ttl != 60*time.Second {
			t.Errorf("rcode %s: ttl = %s, want 1m0s", dns.RcodeToString[rcode], ttl)
		}
		resp.Ns = nil
		if ttl := ttlOf(resp); ttl != 0 {
			t.Errorf("rcode %s without SOA: ttl = %s, want 0 (not cached)", dns.RcodeToString[rcode], ttl)
		}
	}
	_, pos := answer("example.com.", 300)
	if ttl := ttlOf(pos); ttl != 300*time.Second {
		t.Errorf("positive ttl = %s", ttl)
	}
}

// Speicher-Budget: grosse Antworten bleiben draussen, die Summe der Groessen bleibt unter dem Budget.
func TestByteBudget(t *testing.T) {
	c := New(1000)
	big := func(name string, n int) (*dns.Msg, *dns.Msg) {
		req, resp := answer(name, 300)
		for i := 0; i < n; i++ {
			resp.Answer = append(resp.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{strings.Repeat("x", 250)}})
		}
		return req, resp
	}
	req, resp := big("huge.example.", 80) // ca. 20 KB
	c.Set(req, resp)
	if got, _, _ := c.Get(req); got != nil {
		t.Fatal("response above maxEntryBytes was cached")
	}
	for i := 0; i < 300; i++ { // je ca. 8 KB, zusammen mehr als 1000 * 1 KB
		req, resp := big(strconv.Itoa(i)+".example.", 30)
		c.Set(req, resp)
	}
	if c.bytes > c.maxBytes {
		t.Fatalf("bytes = %d above budget %d", c.bytes, c.maxBytes)
	}
	sum := 0
	for _, e := range c.m {
		sum += e.size
	}
	if sum != c.bytes {
		t.Fatalf("bytes = %d, sum of entries = %d", c.bytes, sum)
	}
	c.Flush()
	if c.bytes != 0 {
		t.Fatalf("bytes after flush = %d", c.bytes)
	}
}
