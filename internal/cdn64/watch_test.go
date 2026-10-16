package cdn64

import (
	"context"
	"encoding/json"
	"testing"
)

func TestWatchIndex(t *testing.T) {
	m := &Module{}
	m.SetCheckFinder(func(context.Context) []CheckRef {
		return []CheckRef{
			{Token: "a", Type: "http", Target: "http://192.168.10.20:9443/", State: "up", Local: true},            // von "Healthcheck fuer dieses Ziel"
			{Token: "b", Type: "tcp", Target: "NAS.lan", Params: json.RawMessage(`{"port":5000}`), State: "down"}, // von Hand, andere Schreibweise
			{Token: "c", Type: "tcp", Target: "[fd00::5]:8080"},
			{Token: "d", Type: "icmp", Target: "nas.lan", Paused: true},
			{Token: "e", Type: "https", Target: "x"}, // unbekannter Typ
			{Token: "f", Type: "http", Target: "https://other.example/"},
		}
	})
	idx := m.watchIndex(context.Background())
	cases := []struct {
		host string
		port int
		want []string
	}{
		{"192.168.10.20", 9443, []string{"a"}},
		{"nas.lan", 5000, []string{"b", "d"}}, // genau + Ping auf den Host
		{"fd00::5", 8080, []string{"c"}},
		{"[FD00::5]", 8080, []string{"c"}},
		{"192.168.10.20", 80, nil},
		{"other.example", 443, []string{"f"}},
	}
	for _, c := range cases {
		got := idx.of(c.host, c.port)
		var toks []string
		for _, w := range got {
			toks = append(toks, w.Token)
		}
		if len(toks) != len(c.want) {
			t.Fatalf("%s:%d: %v, want %v", c.host, c.port, toks, c.want)
		}
		for i := range toks {
			if toks[i] != c.want[i] {
				t.Fatalf("%s:%d: %v, want %v", c.host, c.port, toks, c.want)
			}
		}
	}
	if w := idx.of("nas.lan", 5000); !w[1].HostOnly || !w[1].Paused {
		t.Fatalf("ping entry: %+v", w[1])
	}
	m.SetCheckFinder(nil)
	if m.watchIndex(context.Background()).of("nas.lan", 5000) != nil {
		t.Fatal("without healthchecks nothing")
	}
}
