package cdnedge

import (
	"context"
	"testing"
	"time"
)

// Namen, die bei ipv64 verschwinden (z. B. verwaiste Tunnel aufgeraeumt): Zaehler und Zertifikats-Plan werden
// vergessen, die Zaehler der uebrigen Namen bleiben.
func TestForgetGoneNames(t *testing.T) {
	cf, kf, pool, _ := testCA(t, "edge.test")
	s := startEdge(t, &Config{Name: "A", ListenHTTP: freeAddr(t), TLSCert: cf, TLSKey: kf, DataDir: t.TempDir()}, pool)
	host := func(id int, name string, wild bool) apiHost {
		return apiHost{ID: id, Name: name, Wildcard: wild, Mode: 1, Tunnels: []string{"t1"}}
	}
	s.applyConfig(&apiConfig{Tunnels: []apiTunnel{{ID: "t1"}}, Hosts: []apiHost{host(1, "keep.test", false), host(2, "wild.test", true), host(3, "gone.test", false)}})
	for _, n := range []string{"keep.test", "wild.test", "gone.test"} {
		s.stats.of(n).BytesIn.Add(10)
		s.apist.mu.Lock()
		s.apist.sent[n] = [repN]int64{5}
		s.apist.mu.Unlock()
	}
	p := newCertPlan()
	old := time.Now().Add(-time.Hour)
	p.nextTry["gone.test"], p.missingSince["gone.test"], p.backoff["gone.test"] = old, old, time.Hour

	s.applyConfig(&apiConfig{Tunnels: []apiTunnel{{ID: "t1"}}, Hosts: []apiHost{host(1, "keep.test", false), host(2, "wild.test", true)}})
	s.stats.mu.Lock()
	_, gone := s.stats.m["gone.test"]
	_, keep := s.stats.m["keep.test"]
	_, wild := s.stats.m["wild.test"]
	s.stats.mu.Unlock()
	s.apist.mu.Lock()
	_, sent := s.apist.sent["gone.test"]
	s.apist.mu.Unlock()
	if gone || sent || !keep || !wild {
		t.Fatalf("stats after removal: gone %v sent %v keep %v wild %v", gone, sent, keep, wild)
	}
	s.certRound(context.Background(), p)
	if len(p.nextTry)+len(p.missingSince)+len(p.backoff) != 0 {
		t.Fatalf("cert plan keeps removed name: %+v", p)
	}
}
