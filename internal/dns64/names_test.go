package dns64

import (
	"context"
	"testing"

	"github.com/ipv64net/node64/internal/dns64/groups"
)

// Client-Namen (#49): Name aus der Gruppe vor eigenem PTR-Eintrag (auch aus A-Eintraegen), ohne beides kein Name
// (dann fragt clientNames den Router; ohne engine hier nicht).
func TestClientNamesOrder(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	for _, r := range []Record{
		{Name: "20.84.10.10.in-addr.arpa", Type: "PTR", Value: "home-assistant-ar"},
		{Name: "68.78.10.10.in-addr.arpa", Type: "PTR", Value: "ls-nest-audio-ez"},
		{Name: "nas.home.lan", Type: "A", Value: "10.10.84.30"}, // Rueckwaertssuche aus dem A-Eintrag
	} {
		r.Enabled = true
		if _, err := m.AddRecord(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	m.buildDeviceNames([]groups.Group{{Members: []groups.Member{
		{Kind: groups.KindIP, Value: "10.10.78.68", Label: "Nest Wohnzimmer"}, // Gruppe schlaegt PTR
		{Kind: groups.KindIP, Value: "10.10.84.40"},                           // ohne Namen: zaehlt nicht
	}}})
	got := m.clientNames(ctx, nil, []string{"10.10.84.20", "10.10.78.68", "10.10.84.30", "10.10.84.40", "10.10.84.x"})
	want := map[string]string{"10.10.84.20": "home-assistant-ar", "10.10.78.68": "Nest Wohnzimmer", "10.10.84.30": "nas.home.lan"}
	if len(got) != len(want) {
		t.Fatalf("names: %v", got)
	}
	for ip, n := range want {
		if got[ip] != n {
			t.Fatalf("%s: %q, want %q (all %v)", ip, got[ip], n, got)
		}
	}
}

// Issue #119: die Bezeichnung (Kommentar) eines eigenen PTR- bzw. A-Eintrags ist der Client-Name im Abfrage-Log und
// bei den Top-Clients - nach der Gruppe, vor dem technischen PTR-Namen; ohne Bezeichnung bleibt der PTR-Name.
func TestClientNamesRecordLabel(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	for _, r := range []Record{
		{Name: "10.10.10.10.in-addr.arpa", Type: "PTR", Value: "pm-nb-bunkerweb-lxc", Comment: "BunkerWeb LXC"},
		{Name: "alexa-kueche.home.lan", Type: "A", Value: "10.10.10.11", Comment: "Alexa Küche"}, // PTR aus dem A-Eintrag
		{Name: "12.10.10.10.in-addr.arpa", Type: "PTR", Value: "drucker"},                        // ohne Bezeichnung
		{Name: "13.10.10.10.in-addr.arpa", Type: "PTR", Value: "tv", Comment: "Fernseher"},
		{Name: "tv-a.home.lan", Type: "A", Value: "10.10.10.13", Comment: "anderer Name"}, // eigener PTR geht vor
	} {
		if _, err := m.AddRecord(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	m.buildDeviceNames([]groups.Group{{Members: []groups.Member{{Kind: groups.KindIP, Value: "10.10.10.13", Label: "TV Wohnzimmer"}}}})
	got := m.clientNames(ctx, nil, []string{"10.10.10.10", "10.10.10.11", "10.10.10.12", "10.10.10.13"})
	want := map[string]string{"10.10.10.10": "BunkerWeb LXC", "10.10.10.11": "Alexa Küche", "10.10.10.12": "drucker", "10.10.10.13": "TV Wohnzimmer"}
	for ip, n := range want {
		if got[ip] != n {
			t.Fatalf("%s: %q, want %q (all %v)", ip, got[ip], n, got)
		}
	}
	m.buildDeviceNames(nil) // ohne Gruppe: Bezeichnung des eigenen PTR vor der des A-Eintrags
	if n := m.clientNames(ctx, nil, []string{"10.10.10.13"})["10.10.10.13"]; n != "Fernseher" {
		t.Fatalf("10.10.10.13 ohne Gruppe: %q", n)
	}
}
