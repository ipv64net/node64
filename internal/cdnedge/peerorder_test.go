package cdnedge

import (
	"strings"
	"testing"
)

// Server je Account: ein Server ohne den Tunnel reicht zuerst an die Nachbarn weiter, die der Account nutzt (Name oder
// Adresse wie in edge/config), dann an die uebrigen; ohne Angabe bleibt die Reihenfolge der Konfiguration.
func TestPeerOrder(t *testing.T) {
	s := &Server{cfg: &Config{Peers: []PeerEntry{{Name: "srv08", Addr: "2.28.6.30:7845"}, {Name: "x", Addr: "[2a01:4f8:1c19:6003::1]:7845"}, {Name: "srv09", Addr: "srv09.cdn64.de:7845"}}}}
	cfg := &apiConfig{
		Edges:   []apiEdge{{Name: "srv10", Host: "srv10.cdn64.de", IPs: []string{"2a01:4f8:1c19:6003::1", "116.203.146.186"}}},
		Tunnels: []apiTunnel{{ID: "t1", Edges: []string{"srv10"}}, {ID: "t2", Edges: []string{"srv09", "srv07"}}, {ID: "t3"}},
		Hosts: []apiHost{{ID: 1, Name: "a.test", Mode: 1, Tunnels: []string{"t1"}}, {ID: 2, Name: "b.test", Mode: 2, Tunnels: []string{"t2"}, Wildcard: true},
			{ID: 3, Name: "c.test", Mode: 1, Tunnels: []string{"t3"}}},
	}
	s.routes.Store(newRoutes(nil, cfg))
	names := func(host string) (out []string) {
		for _, p := range s.peerOrder(host) {
			out = append(out, p.Name)
		}
		return out
	}
	for host, want := range map[string]string{
		"a.test":   "x srv08 srv09", // srv10 ueber seine Adresse
		"x.b.test": "srv09 srv08 x", // Wildcard, srv09 ueber den Namen
		"c.test":   "srv08 x srv09", // Tunnel ohne Angabe: wie konfiguriert
		"acme-tok": "srv08 x srv09", // unbekannter Name
	} {
		if got := strings.Join(names(host), " "); got != want {
			t.Errorf("%s: %q, want %q", host, got, want)
		}
	}
}
