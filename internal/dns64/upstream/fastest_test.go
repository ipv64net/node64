package upstream

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeDoH antwortet nach delay mit 192.0.2.<n>; zaehlt echte Anfragen (A), nicht die Messungen (". NS").
type fakeDoH struct {
	n     byte
	delay time.Duration
	fail  atomic.Bool
	hits  atomic.Int64
}

func (f *fakeDoH) start(t *testing.T, cert tls.Certificate) Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if q.Unpack(body) != nil {
			http.Error(w, "bad", 400)
			return
		}
		if q.Question[0].Qtype == dns.TypeA {
			f.hits.Add(1)
		}
		time.Sleep(f.delay)
		if f.fail.Load() {
			http.Error(w, "down", 500)
			return
		}
		m := answer(q, f.n)
		if q.Question[0].Qtype != dns.TypeA {
			m = new(dns.Msg)
			m.SetReply(q)
		}
		out, _ := m.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	port := strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port)
	return Server{Name: "s" + strconv.Itoa(int(f.n)), URL: "https://doh.test:" + port + "/dns-query", IPs: []string{"127.0.0.1"}}
}

// "fastest" fragt nur die schnellsten zwei; die anderen werden gemessen, bekommen aber keine Anfragen. Faellt
// der schnellste aus, uebernimmt der naechste ohne Fehler fuer den Client.
func TestFastestMode(t *testing.T) {
	cert := testCert(t, "doh.test")
	fakes := []*fakeDoH{{n: 1, delay: 150 * time.Millisecond}, {n: 2, delay: 5 * time.Millisecond}, {n: 3, delay: 40 * time.Millisecond}, {n: 4, delay: 250 * time.Millisecond}}
	var servers []Server
	for _, f := range fakes {
		servers = append(servers, f.start(t, cert))
	}
	r := New(servers, ModeFastest)
	defer r.Close()
	if r.Mode() != ModeFastest || r.Top() != DefaultTop {
		t.Fatalf("mode %s top %d", r.Mode(), r.Top())
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.RunProbes(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	// erste Messrunde abwarten
	for i := 0; i < 200; i++ {
		ok := true
		for _, s := range r.Stats() {
			ok = ok && s.AvgMs > 0
		}
		if ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	for i := 0; i < 10; i++ {
		if ip, up := ask(t, r); ip != "192.0.2.2" || up != "s2" {
			t.Fatalf("query %d: %s from %s, want the fastest (s2)", i, ip, up)
		}
	}
	time.Sleep(100 * time.Millisecond) // Verlierer (s3) laufen zu Ende
	if fakes[0].hits.Load() != 0 || fakes[3].hits.Load() != 0 || fakes[1].hits.Load() != 10 || fakes[2].hits.Load() != 10 {
		t.Fatalf("hits = %d %d %d %d, want 0 10 10 0", fakes[0].hits.Load(), fakes[1].hits.Load(), fakes[2].hits.Load(), fakes[3].hits.Load())
	}
	st := r.Stats()
	if !st[1].Active || !st[2].Active || st[0].Active || st[3].Active || st[0].Requests != 0 {
		t.Fatalf("stats = %+v", st)
	}
	// s2 faellt aus: Antwort kommt von s3, danach rueckt s1 nach
	fakes[1].fail.Store(true)
	if ip, _ := ask(t, r); ip != "192.0.2.3" {
		t.Fatalf("failover answer %s", ip)
	}
	time.Sleep(50 * time.Millisecond)
	if ip, _ := ask(t, r); ip != "192.0.2.3" || fakes[0].hits.Load() != 1 {
		t.Fatalf("after failure: %s, s1 hits %d", ip, fakes[0].hits.Load())
	}
}

// Antworten die ersten nicht rechtzeitig, kommt der naechste dazu.
func TestFastestHedge(t *testing.T) {
	cert := testCert(t, "doh.test")
	slow, fast := &fakeDoH{n: 1, delay: 5 * time.Millisecond}, &fakeDoH{n: 2, delay: 20 * time.Millisecond}
	r := New([]Server{slow.start(t, cert), fast.start(t, cert)}, ModeFastest)
	defer r.Close()
	r.SetTop(1)
	r.probe(context.Background(), time.Time{}, true)
	slow.delay = 800 * time.Millisecond // der bisher schnellste haengt jetzt
	start := time.Now()
	if ip, up := ask(t, r); ip != "192.0.2.2" || up != "s2" {
		t.Fatalf("%s from %s", ip, up)
	}
	if d := time.Since(start); d > 700*time.Millisecond {
		t.Fatalf("hedge took %v", d)
	}
}
