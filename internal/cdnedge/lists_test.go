package cdnedge

import (
	"net/netip"
	"testing"
)

// Sperrliste der Node je Tunnel: gilt fuer alle Namen des Tunnels (auch neben einer Liste des Namens), die
// Freigabeliste geht vor; Namen anderer Tunnel bleiben frei; abgewiesen und gezaehlt wird als Zugriffsliste.
func TestTunnelLists(t *testing.T) {
	cfg := &apiConfig{
		Tunnels: []apiTunnel{{ID: "t1", Deny: []string{"203.0.113.0/24", "2001:db8::1", "kein-netz"}, Allow: []string{"203.0.113.7"}}, {ID: "t2"}},
		Hosts: []apiHost{{ID: 1, Name: "a.test", Mode: 1, Tunnels: []string{"t1"}}, {ID: 2, Name: "b.test", Mode: 1, Tunnels: []string{"t2"}},
			{ID: 3, Name: "c.test", Mode: 2, Tunnels: []string{"t2", "t1"}, ACL: &apiACL{Default: "deny", List: []string{"198.51.100.0/24"}}}},
	}
	rs := newRoutes(nil, cfg)
	ip := netip.MustParseAddr
	a, b, c := rs.lookup("a.test"), rs.lookup("b.test"), rs.lookup("c.test")
	for _, x := range []struct {
		re   *route
		ip   string
		want bool
	}{
		{a, "203.0.113.9", false}, {a, "203.0.113.7", true}, {a, "2001:db8::1", false}, {a, "::ffff:203.0.113.9", false}, {a, "198.51.100.1", true},
		{b, "203.0.113.9", true},
		{c, "203.0.113.9", false}, {c, "198.51.100.1", true}, {c, "192.0.2.1", false},
	} {
		if got := x.re.allows(ip(x.ip)); got != x.want {
			t.Errorf("%s %s: %v", x.re.Name, x.ip, got)
		}
	}

	cf, kf, pool, _ := testCA(t, "edge.test")
	ec := &Config{Name: "A", ListenHTTP: freeAddr(t), ListenHTTPS: freeAddr(t), TLSCert: cf, TLSKey: kf, DataDir: t.TempDir(), Shield: ShieldConfig{ConnRate: -1, ReqRate: -1}}
	s := startEdge(t, ec, pool)
	s.applyConfig(&apiConfig{Tunnels: []apiTunnel{{ID: "t1", Deny: []string{"127.0.0.1"}}}, Hosts: []apiHost{{ID: 1, Name: "m1.test", Mode: 1, Tunnels: []string{"t1"}}}})
	if code := rawHTTP(t, ec.ListenHTTP, "m1.test", "/", "x"); code != 503 {
		t.Fatalf("denied: %d", code)
	}
	waitFor(t, "counted as access list", func() bool { return s.stats.of("m1.test").BlockedACL.Load() == 1 })
	s.applyConfig(&apiConfig{Tunnels: []apiTunnel{{ID: "t1", Deny: []string{"127.0.0.1"}, Allow: []string{"127.0.0.0/8"}}},
		Hosts: []apiHost{{ID: 1, Name: "m1.test", Mode: 1, Tunnels: []string{"t1"}}}})
	_ = rawHTTP(t, ec.ListenHTTP, "m1.test", "/", "x") // Tunnel nicht verbunden: nicht erreichbar, aber nicht als Liste
	if n := s.stats.of("m1.test").BlockedACL.Load(); n != 1 {
		t.Fatalf("allow list must win: %d", n)
	}
}
