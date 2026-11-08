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
