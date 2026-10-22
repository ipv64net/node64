package dns64

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ipv64net/node64/internal/dns64/groups"
)

func TestDeviceSlugAndArpa(t *testing.T) {
	for in, want := range map[string]string{"Tablet Lea": "tablet-lea", " Jörgs  Handy! ": "joergs-handy", "ß-Box": "ss-box", "---": "", "PC_2": "pc-2"} {
		if got := deviceSlug(in); got != want {
			t.Errorf("deviceSlug(%q) = %q, want %q", in, got, want)
		}
	}
	if a, ok := arpaAddr("50.1.168.192.in-addr.arpa"); !ok || a.String() != "192.168.1.50" {
		t.Errorf("arpa v4 = %v %v", a, ok)
	}
	arpa, _ := dns.ReverseAddr("fd00::1:2")
	if a, ok := arpaAddr(arpa[:len(arpa)-1]); !ok || a.String() != "fd00::1:2" {
		t.Errorf("arpa v6 = %v %v", a, ok)
	}
}

func ask(t *testing.T, addr, name string, qtype uint16) *dns.Msg {
	t.Helper()
	c := &dns.Client{Timeout: 2 * time.Second}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	r, _, err := c.Exchange(q, addr)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return r
}

// Zustaendige Zone mit Geraetenamen: A, NODATA mit SOA, NXDOMAIN mit SOA, SOA der Zone, Rueckwaertssuche;
// eigene Eintraege gehen vor; eine nicht zustaendige Zone laesst Unbekanntes an den Router.
func TestLocalZones(t *testing.T) {
	m, port := testModule(t)
	ctx := context.Background()
	if _, err := m.AddZone(ctx, Zone{Name: "Home.LAN.", Authoritative: true, Devices: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddZone(ctx, Zone{Name: "home.lan"}); err == nil {
		t.Fatal("duplicate zone accepted")
	}
	if _, err := m.AddZone(ctx, Zone{Name: "10.in-addr.arpa"}); err == nil {
		t.Fatal("arpa zone accepted")
	}
	if _, err := m.AddZone(ctx, Zone{Name: "lab.lan"}); err != nil {
		t.Fatal(err)
	}
	g, err := m.AddGroup(ctx, "Kinder")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddMember(ctx, groups.Member{GroupID: g.ID, Kind: groups.KindIP, Value: "192.168.1.50", Label: "Tablet Lea"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddRecord(ctx, Record{Name: "nas.home.lan", Type: "A", Value: "192.168.1.10"}); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	r := ask(t, addr, "tablet-lea.home.lan", dns.TypeA)
	if a, ok := firstA(r); !ok || a != "192.168.1.50" {
		t.Fatalf("device A = %v", r)
	}
	if r := ask(t, addr, "tablet-lea.home.lan", dns.TypeAAAA); r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 || len(r.Ns) != 1 {
		t.Fatalf("device AAAA = %v", r)
	}
	if r := ask(t, addr, "gibtsnicht.home.lan", dns.TypeA); r.Rcode != dns.RcodeNameError || len(r.Ns) != 1 {
		t.Fatalf("unknown in zone = %v", r)
	}
	if r := ask(t, addr, "home.lan", dns.TypeSOA); len(r.Answer) != 1 || r.Answer[0].Header().Rrtype != dns.TypeSOA {
		t.Fatalf("SOA = %v", r)
	}
	if a, ok := firstA(ask(t, addr, "nas.home.lan", dns.TypeA)); !ok || a != "192.168.1.10" {
		t.Fatal("record in zone lost")
	}
	r = ask(t, addr, "50.1.168.192.in-addr.arpa", dns.TypePTR)
	if len(r.Answer) != 1 || r.Answer[0].(*dns.PTR).Ptr != "tablet-lea.home.lan." {
		t.Fatalf("device PTR = %v", r)
	}
	// nicht zustaendig: Unbekanntes geht an den (Test-)Router, dessen NXDOMAIN hat keine SOA der Zone
	if r := ask(t, addr, "x.lab.lan", dns.TypeA); r.Rcode != dns.RcodeNameError || len(r.Ns) != 0 {
		t.Fatalf("non-authoritative zone = %v", r)
	}
	names := m.DeviceNames()
	if len(names) != 1 || names[0].Name != "tablet-lea.home.lan" || len(names[0].IPs) != 1 {
		t.Fatalf("device names = %+v", names)
	}
}
