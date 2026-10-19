package dns64

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"

	"github.com/ipv64net/node64/internal/dns64/groups"
	"github.com/ipv64net/node64/internal/dns64/upstream"
)

// G2: eine Gruppe hat eigene Blocklisten, Kategorien, Freigaben und Sperren; Geraete ohne Gruppe bleiben bei der
// globalen Auswahl.
func TestGroupRules(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	const listA, listB = "https://lists.test/a.txt", "https://lists.test/kids.txt"
	dir := filepath.Join(m.dir(), "lists")
	_ = os.MkdirAll(dir, 0o755)
	for u, body := range map[string]string{listA: "0.0.0.0 ads.example\n", listB: "||game.example^\n"} {
		h := sha256.Sum256([]byte(u))
		if err := os.WriteFile(filepath.Join(dir, "list-"+hex.EncodeToString(h[:6])+".txt"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c := m.loadConfig(ctx)
	for i := range c.Lists {
		c.Lists[i].Enabled = false
	}
	for i := range c.Upstreams {
		c.Upstreams[i].Enabled = false
	}
	if err := c.addList("A", listA); err != nil {
		t.Fatal(err)
	}
	if err := c.addList("Kids", listB); err != nil {
		t.Fatal(err)
	}
	c.Lists[len(c.Lists)-1].Enabled = false // Kids nur fuer die Gruppe
	c.Upstreams = append(c.Upstreams, upstreamSetting{Server: upstream.Server{Name: "Nirgends", URL: "https://127.0.0.1:1/dns-query"}, Enabled: true, Custom: true})
	if err := m.saveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil || m.running() == nil {
		t.Fatalf("start: %v %s", err, m.startError())
	}
	g, _ := m.AddGroup(ctx, "Kinder")
	if _, err := m.AddMember(ctx, groups.Member{GroupID: g.ID, Kind: groups.KindIP, Value: "192.168.1.50"}); err != nil {
		t.Fatal(err)
	}
	if err := m.SetGroupRules(ctx, g.ID, groups.ListsCustom, []string{listB, "https://unbekannt.test/x"}, []string{"social", "kaputt"}); err != nil {
		t.Fatal(err)
	}
	for _, d := range []groups.Domain{{GroupID: g.ID, Domain: "evil.example", Action: groups.ActionBlock}, {GroupID: g.ID, Domain: "ok.game.example", Action: groups.ActionAllow}} {
		if _, err := m.AddGroupDomain(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	list, _ := m.Groups(ctx)
	if len(list[0].Lists) != 1 || len(list[0].Cats) != 1 || len(list[0].Domains) != 2 {
		t.Fatalf("rules stored: %+v", list[0])
	}
	blocked := func(client, name string) bool {
		t.Helper()
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(name), dns.TypeA)
		r := m.running().srv.Answer(q, netip.MustParseAddr(client), "udp")
		return len(r.Answer) == 1 && r.Answer[0].(*dns.A).A.Equal(net.IPv4zero)
	}
	kid, other := "192.168.1.50", "192.168.1.60"
	for _, tt := range []struct {
		client, name string
		want         bool
	}{
		{kid, "x.game.example", true}, {kid, "ads.example", false}, {kid, "www.tiktok.com", true}, {kid, "evil.example", true},
		{kid, "ok.game.example", false}, {other, "ads.example", true}, {other, "x.game.example", false}, {other, "www.tiktok.com", false},
	} {
		if got := blocked(tt.client, tt.name); got != tt.want {
			t.Errorf("%s %s: blocked=%v, want %v", tt.client, tt.name, got, tt.want)
		}
	}
	// zurueck auf die globale Auswahl: Kinderliste aus, ads.example wieder gesperrt
	if err := m.SetGroupRules(ctx, g.ID, groups.ListsGlobal, nil, nil); err != nil {
		t.Fatal(err)
	}
	if !blocked(kid, "ads.example") || blocked(kid, "x.game.example") || blocked(kid, "www.tiktok.com") {
		t.Fatal("global selection not applied")
	}
	// eine Kategorie mit Blockliste, die noch nicht geladen ist: Neustart laedt sie
	old := m.running()
	if err := m.SetGroupRules(ctx, g.ID, groups.ListsGlobal, nil, []string{"gambling"}); err != nil {
		t.Fatal(err)
	}
	if m.running() == old || m.running().lists.Mask([]string{"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/gambling.txt"}) == 0 {
		t.Fatal("gambling list not loaded")
	}
}
