package dns64

import (
	"context"
	"net/netip"
	"testing"

	"github.com/miekg/dns"

	"github.com/ipv64net/node64/internal/dns64/filter"
	"github.com/ipv64net/node64/internal/dns64/groups"
	"github.com/ipv64net/node64/internal/dns64/upstream"
)

// G3: SafeSearch per CNAME je Gruppe, Firefox-DoH global aus (abschaltbar), Umgehungsschutz je Gruppe
// (iCloud Private Relay aus, Bypass-Liste geladen).
func TestGroupSafeSearch(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	c := m.loadConfig(ctx)
	for i := range c.Upstreams {
		c.Upstreams[i].Enabled = false
	}
	for i := range c.Lists {
		c.Lists[i].Enabled = false
	}
	c.Upstreams = append(c.Upstreams, upstreamSetting{Server: upstream.Server{Name: "Nirgends", URL: "https://127.0.0.1:1/dns-query"}, Enabled: true, Custom: true})
	if err := m.saveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	if !m.loadConfig(ctx).Canary {
		t.Fatal("firefox canary must be on by default")
	}
	if err := m.Start(ctx); err != nil || m.running() == nil {
		t.Fatalf("start: %v %s", err, m.startError())
	}
	g, _ := m.AddGroup(ctx, "Kinder")
	if _, err := m.AddMember(ctx, groups.Member{GroupID: g.ID, Kind: groups.KindIP, Value: "192.168.1.50"}); err != nil {
		t.Fatal(err)
	}
	if err := m.SetGroupRules(ctx, g.ID, groups.Rules{SafeSearch: true, YouTube: "kaputt", Bypass: true}); err != nil {
		t.Fatal(err)
	}
	if list, _ := m.Groups(ctx); !list[0].SafeSearch || list[0].YouTube != "strict" || !list[0].Bypass {
		t.Fatalf("rules: %+v", list[0])
	}
	if m.running().lists.Mask([]string{filter.BypassList}) == 0 {
		t.Fatal("bypass list not loaded")
	}
	ask := func(client, name string) *dns.Msg {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(name), dns.TypeA)
		return m.running().srv.Answer(q, netip.MustParseAddr(client), "udp")
	}
	kid, other := "192.168.1.50", "192.168.1.60"
	r := ask(kid, "www.google.de")
	if len(r.Answer) == 0 || r.Answer[0].(*dns.CNAME).Target != "forcesafesearch.google.com." {
		t.Fatalf("safesearch: %v", r)
	}
	if r := ask(kid, "www.youtube.com"); len(r.Answer) == 0 || r.Answer[0].(*dns.CNAME).Target != "restrict.youtube.com." {
		t.Fatalf("youtube: %v", r)
	}
	if r := ask(other, "www.google.de"); len(r.Answer) > 0 {
		if _, isCNAME := r.Answer[0].(*dns.CNAME); isCNAME {
			t.Fatal("safesearch for a device without group")
		}
	}
	if ask(other, "use-application-dns.net").Rcode != dns.RcodeNameError || ask(kid, "mask.icloud.com").Rcode != dns.RcodeNameError {
		t.Fatal("canary / relay not answered with NXDOMAIN")
	}
	if ask(other, "mask.icloud.com").Rcode == dns.RcodeNameError {
		t.Fatal("relay off for a device without group")
	}
	// Firefox-Schalter global aus: nur die Gruppe mit Umgehungsschutz behaelt ihn
	c = m.loadConfig(ctx)
	c.Canary = false
	if err := m.saveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := m.restart(ctx); err != nil {
		t.Fatal(err)
	}
	if ask(other, "use-application-dns.net").Rcode == dns.RcodeNameError || ask(kid, "use-application-dns.net").Rcode != dns.RcodeNameError {
		t.Fatal("canary switch")
	}
}
