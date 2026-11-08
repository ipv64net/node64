package upstream

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeDNS: klassischer DNS-Server auf UDP; rcode 0 = A-Antwort 192.0.2.<n>, sonst nur der Rcode. down = keine Antwort.
type fakeDNS struct {
	n     byte
	rcode atomic.Int32
	down  atomic.Bool
	hits  atomic.Int32
	url   string
}

func startFake(t *testing.T, n byte) *fakeDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeDNS{n: n, url: "dns://" + pc.LocalAddr().String()}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		f.hits.Add(1)
		if f.down.Load() {
			return
		}
		if rc := int(f.rcode.Load()); rc != 0 {
			m := new(dns.Msg)
			m.SetRcode(r, rc)
			_ = w.WriteMsg(m)
			return
		}
		_ = w.WriteMsg(answer(r, f.n))
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return f
}

// #37: Der erste Upstream faellt aus - nach drei Fehlern wird er uebersprungen (keine Wartezeit mehr), nach der Pause
// prueft ihn eine Anfrage im Hintergrund, und wenn er wieder antwortet, ist er wieder vorne.
func TestOrderedBreaker(t *testing.T) {
	a, b := startFake(t, 1), startFake(t, 2)
	r := New([]Server{{Name: "A", URL: a.url}, {Name: "B", URL: b.url}}, ModeOrdered)
	defer r.Close()
	if ip, up := ask(t, r); ip != "192.0.2.1" || up != "A" {
		t.Fatalf("got %s from %s", ip, up)
	}
	a.down.Store(true)
	for i := 0; i < breakAfter; i++ { // drei langsame Anfragen (A antwortet nicht)
		if _, up := ask(t, r); up != "B" {
			t.Fatalf("fallback: %s", up)
		}
	}
	st := r.Stats()
	if st[0].PausedUntil == nil || time.Until(*st[0].PausedUntil) < 20*time.Second {
		t.Fatalf("A not paused: %+v", st[0])
	}
	hits := a.hits.Load()
	start := time.Now()
	if _, up := ask(t, r); up != "B" || time.Since(start) > time.Second || a.hits.Load() != hits {
		t.Fatalf("paused upstream asked first: %s after %v", up, time.Since(start))
	}
	// Pause vorbei, A noch weg: die Pruefung im Hintergrund verlaengert die Pause (doppelt so lange)
	setPause(r.ups[0], time.Now().Add(-time.Millisecond))
	start = time.Now()
	if _, up := ask(t, r); up != "B" || time.Since(start) > time.Second {
		t.Fatalf("probe blocked the query: %s after %v", up, time.Since(start))
	}
	waitFor(t, func() bool {
		r.ups[0].mu.Lock()
		defer r.ups[0].mu.Unlock()
		return !r.ups[0].probing && r.ups[0].backoff == 2*breakMin
	})
	// A wieder da: nach der naechsten Pruefung wieder vorne
	a.down.Store(false)
	setPause(r.ups[0], time.Now().Add(-time.Millisecond))
	_, _ = ask(t, r)
	waitFor(t, func() bool { return r.Stats()[0].PausedUntil == nil })
	if ip, up := ask(t, r); ip != "192.0.2.1" || up != "A" {
		t.Fatalf("after recovery: %s from %s", ip, up)
	}
}

// #37: REFUSED (falsche access-control beim eigenen Resolver) fuehrt zum naechsten Upstream und zaehlt als Fehler.
func TestOrderedRefused(t *testing.T) {
	a, b := startFake(t, 1), startFake(t, 2)
	a.rcode.Store(dns.RcodeRefused)
	r := New([]Server{{Name: "A", URL: a.url}, {Name: "B", URL: b.url}}, ModeOrdered)
	defer r.Close()
	if ip, up := ask(t, r); ip != "192.0.2.2" || up != "B" {
		t.Fatalf("got %s from %s", ip, up)
	}
	if st := r.Stats()[0]; st.Errors != 1 || st.LastError != "refused" || st.Healthy {
		t.Fatalf("stats A: %+v", st)
	}
	// alle REFUSED: die Antwort REFUSED geht an den Client (kein Fehler)
	b.rcode.Store(dns.RcodeRefused)
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	resp, _, err := r.Exchange(context.Background(), q)
	if err != nil || resp.Rcode != dns.RcodeRefused {
		t.Fatalf("all refused: %v %v", resp, err)
	}
	// parallel: REFUSED verliert gegen eine gute Antwort
	b.rcode.Store(0)
	p := New([]Server{{Name: "A", URL: a.url}, {Name: "B", URL: b.url}}, ModeParallel)
	defer p.Close()
	for i := 0; i < 5; i++ {
		if ip, up := ask(t, p); ip != "192.0.2.2" || up != "B" {
			t.Fatalf("parallel: %s from %s", ip, up)
		}
	}
}

func setPause(u *doh, until time.Time) {
	u.mu.Lock()
	u.skipUntil = until
	u.mu.Unlock()
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}
