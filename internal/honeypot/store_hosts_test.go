package honeypot

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// #113: Rangliste der angefragten Domains (Host-Kopfzeile bzw. SNI), ohne Port, IP-Adressen zaehlen nicht.
func TestStoreTopHosts(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sink := s.Sink()
	ev := func(host string, n int) {
		for i := 0; i < n; i++ {
			sink(Event{Service: SvcHTTPS, Port: 443, Kind: KindHTTPScan, Src: ip("192.0.2.7"), Method: "GET", Path: "/", Host: host})
		}
	}
	ev("nas.example.de", 3)
	ev("NAS.example.de:8443", 2) // gleicher Name: Port und Gross-/Kleinschreibung zaehlen nicht
	ev("nas.example.de.", 1)
	ev("cloud.example.de", 4)
	ev("192.0.2.10:443", 9) // Aufruf ueber die IP
	ev("[2001:db8::1]:443", 9)
	ev("", 5)
	for i := 0; i < 25; i++ {
		ev(fmt.Sprintf("h%02d.example.org", i), 1)
	}
	sink(Event{Time: time.Now().Add(-48 * time.Hour), Service: SvcHTTP, Port: 80, Kind: KindHTTPScan, Src: ip("192.0.2.8"), Host: "alt.example.de"})
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	st, err := s.Stats(ctx, time.Now().Add(-24*time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	h := st.TopHosts
	if len(h) != topHostsMin || h[0].Key != "nas.example.de" || h[0].Count != 6 || h[1].Key != "cloud.example.de" || h[1].Count != 4 || h[0].Last.IsZero() {
		t.Fatalf("top hosts (%d): %+v", len(h), h)
	}
	if h[2].Key != "h00.example.org" {
		t.Fatalf("Gleichstand nach Name: %+v", h[2])
	}
	for _, c := range h {
		if c.Key == "192.0.2.10" || c.Key == "2001:db8::1" || c.Key == "" || c.Key == "alt.example.de" {
			t.Fatalf("unerwartet: %+v", c)
		}
	}
	// groesseres top gilt auch hier
	if st, _ = s.Stats(ctx, time.Now().Add(-24*time.Hour), 50); len(st.TopHosts) != 27 {
		t.Fatalf("top 50: %d", len(st.TopHosts))
	}
	for in, want := range map[string]string{"Example.COM": "example.com", "example.com:80": "example.com", "[::1]": "", "10.0.0.1": "", "a b": "", "x.de.": "x.de"} {
		if got := hostName(in); got != want {
			t.Errorf("hostName(%q) = %q, want %q", in, got, want)
		}
	}
}
