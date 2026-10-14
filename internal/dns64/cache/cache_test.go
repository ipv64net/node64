package cache

import (
	"net"
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
