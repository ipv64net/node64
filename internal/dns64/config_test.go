package dns64

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"

	"github.com/miekg/dns"

	"github.com/ipv64net/node64/internal/dns64/filter"
	"github.com/ipv64net/node64/internal/dns64/upstream"
)

func TestConfigDefaultsAndSave(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	c := m.loadConfig(ctx)
	if len(c.activeUpstreams()) != 2 || c.activeUpstreams()[0].Name != "Cloudflare" || len(c.Upstreams) != len(upstream.Presets) {
		t.Fatalf("upstreams = %+v", c.Upstreams)
	}
	if len(c.activeLists()) != len(filter.DefaultLists) || len(c.Lists) != len(filter.DefaultLists)+len(filter.MoreLists) {
		t.Fatalf("lists = %d active of %d", len(c.activeLists()), len(c.Lists))
	}
	// eigener Upstream ohne Bootstrap-IPs wird abgelehnt, mit IPs angenommen
	c.Upstreams = append(c.Upstreams, upstreamSetting{Server: upstream.Server{URL: "https://dns.example/dns-query"}, Enabled: true, Custom: true})
	if err := m.saveConfig(ctx, c); err == nil {
		t.Fatal("custom upstream without bootstrap IPs accepted")
	}
	c.Upstreams[len(c.Upstreams)-1].IPs = []string{"192.0.2.1"}
	c.AllowNets = []string{"2001:db8:1::5/48", "10.9.0.1"}
	c.BlockMode, c.Anonymize = blockNX, anonMask
	if err := m.saveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	c2 := m.loadConfig(ctx)
	if c2.Upstreams[len(c2.Upstreams)-1].Name != "dns.example" || c2.BlockMode != blockNX || c2.AllowNets[0] != "2001:db8:1::/48" || c2.AllowNets[1] != "10.9.0.1/32" {
		t.Fatalf("saved config = %+v", c2)
	}
	// alle Upstreams aus: abgelehnt
	for i := range c2.Upstreams {
		c2.Upstreams[i].Enabled = false
	}
	if err := m.saveConfig(ctx, c2); err == nil {
		t.Fatal("config without upstream accepted")
	}
	if a := (config{Anonymize: anonMask}).anonymizer(); a(netip.MustParseAddr("192.168.70.142")) != "192.168.70.0" || a(netip.MustParseAddr("2001:db8:1:2::5")) != "2001:db8:1::" {
		t.Fatal("mask anonymizer")
	}
}

func TestRecords(t *testing.T) {
	m, port := testModule(t)
	ctx := context.Background()
	for _, r := range []Record{
		{Name: "NAS.home.lan.", Type: "A", Value: "192.168.1.10"},
		{Name: "nas.home.lan", Type: "AAAA", Value: "fd00::10"},
		{Name: "*.dev.lan", Type: "A", Value: "192.168.1.20"},
		{Name: "files.home.lan", Type: "CNAME", Value: "nas.home.lan"},
	} {
		if _, err := m.AddRecord(ctx, r); err != nil {
			t.Fatalf("%+v: %v", r, err)
		}
	}
	for _, bad := range []Record{
		{Name: "nas.home.lan", Type: "A", Value: "192.168.1.10"}, // doppelt
		{Name: "nas.home.lan", Type: "CNAME", Value: "x.lan"},    // CNAME neben A
		{Name: "x.lan", Type: "A", Value: "fd00::1"},             // falsche Familie
		{Name: "bad name.lan", Type: "A", Value: "1.2.3.4"},      // Name
		{Name: "loop.lan", Type: "CNAME", Value: "loop.lan"},     // auf sich selbst
		{Name: "x.lan", Type: "MX", Value: "mail.lan"},           // Typ
	} {
		if _, err := m.AddRecord(ctx, bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if err := m.Start(ctx); err != nil || m.running() == nil {
		t.Fatalf("start: %v %s", err, m.startError())
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ask := func(name string, qt uint16) *dns.Msg {
		c := &dns.Client{}
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(name), qt)
		r, _, err := c.Exchange(q, addr)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return r
	}
	if r := ask("nas.home.lan", dns.TypeA); len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "192.168.1.10" {
		t.Fatalf("A: %v", r)
	}
	if r := ask("app.dev.lan", dns.TypeA); len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "192.168.1.20" {
		t.Fatalf("wildcard: %v", r)
	}
	if r := ask("files.home.lan", dns.TypeAAAA); len(r.Answer) != 2 || r.Answer[1].(*dns.AAAA).AAAA.String() != "fd00::10" {
		t.Fatalf("cname follow: %v", r)
	}
	if r := ask("10.1.168.192.in-addr.arpa", dns.TypePTR); len(r.Answer) != 1 || r.Answer[0].(*dns.PTR).Ptr != "nas.home.lan." {
		t.Fatalf("ptr: %v", r)
	}
	if r := ask("nas.home.lan", dns.TypeTXT); r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
		t.Fatalf("nodata: %v", r)
	}
	// ausschalten wirkt sofort: der Name geht dann an den (Test-)Router, der NXDOMAIN liefert
	list, _ := m.Records(ctx)
	for _, r := range list {
		if r.Name == "*.dev.lan" {
			if err := m.SetRecordEnabled(ctx, r.ID, false); err != nil {
				t.Fatal(err)
			}
		}
	}
	if r := ask("app.dev.lan", dns.TypeA); r.Rcode != dns.RcodeNameError {
		t.Fatalf("disabled wildcard still answers: %v", r)
	}
}

func TestAllowNetsHardening(t *testing.T) {
	m, _ := testModule(t)
	for _, n := range []string{"0.0.0.0/0", "::/0"} {
		c := m.loadConfig(context.Background())
		c.AllowNets = []string{n}
		var ce *cfgError
		if err := c.validate(); !errors.As(err, &ce) || ce.Key != "err_net_any" {
			t.Fatalf("%s: err = %v", n, err)
		}
	}
	c := config{AllowNets: []string{"10.8.0.0/24", "2001:db8:7::/48", "fd00::/8", "0.0.0.0/0"}}
	if got := c.PublicNets(); len(got) != 1 || got[0] != "2001:db8:7::/48" {
		t.Fatalf("public = %v", got)
	}
}
