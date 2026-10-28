package dns64

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestQualify(t *testing.T) {
	for _, c := range [][3]string{{"nas", "home.lan", "nas.home.lan"}, {"@", "home.lan", "home.lan"}, {"", "home.lan", "home.lan"},
		{"nas.home.lan", "home.lan", "nas.home.lan"}, {"other.lan.", "home.lan", "other.lan."}, {"nas", "", "nas"}} {
		if got := qualify(c[0], c[1]); got != c[2] {
			t.Errorf("qualify(%q, %q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
}

// Zonendatei: Export mit $ORIGIN/SOA und relativen Namen, Import auf einer anderen Node ergibt dieselben Eintraege.
func TestZoneFileRoundTrip(t *testing.T) {
	a, _ := testModule(t)
	ctx := context.Background()
	z, err := a.AddZone(ctx, Zone{Name: "home.lan", Authoritative: true, TTL: 600, Refresh: 7200, Hostmaster: "admin@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []Record{{Name: "nas.home.lan", Type: "A", Value: "192.168.1.10", Comment: "NAS"}, {Name: "home.lan", Type: "MX", Value: "10 mail.home.lan"},
		{Name: "_sip._tcp.home.lan", Type: "SRV", Value: "0 5 5060 sip.home.lan"}, {Name: "www.home.lan", Type: "CNAME", Value: "nas.home.lan"},
		{Name: "home.lan", Type: "TXT", Value: "v=spf1 -all"}, {Name: "other.lan", Type: "A", Value: "10.0.0.1"}} {
		if _, err := a.AddRecord(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	body, err := a.zoneFile(ctx, z)
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	for _, want := range []string{"$ORIGIN home.lan.", "$TTL 600", "admin.example.org.", "7200", "nas\t300\tIN\tA\t192.168.1.10 ; NAS", "www\t300\tIN\tCNAME\tnas.home.lan."} {
		if !strings.Contains(s, want) {
			t.Fatalf("zone file misses %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "other.lan") {
		t.Fatalf("record of another zone exported:\n%s", s)
	}

	b, _ := testModule(t)
	if _, err := b.AddZone(ctx, Zone{Name: "home.lan"}); err != nil {
		t.Fatal(err)
	}
	res, err := b.importText(ctx, s, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 5 || res.Invalid != 0 || res.Skipped != 1 { // NS der Zone uebersprungen
		t.Fatalf("import = %+v", res)
	}
	zl, _ := b.Zones(ctx)
	if zl[0].Refresh != 7200 {
		t.Fatalf("SOA not taken over: %+v", zl[0])
	}
	// relative Namen ohne $ORIGIN: Zone aus der Seite
	res, _ = b.importText(ctx, "drucker  300 IN A 192.168.1.20\n", "home.lan")
	if res.Added != 1 {
		t.Fatalf("relative import = %+v", res)
	}
	if rrs, ok := b.Lookup("drucker.home.lan", dns.TypeA); !ok || len(rrs) != 1 {
		t.Fatal("relative record missing")
	}
}

// RFC 2136: Update mit TSIG ueber den DNS-Port (hinzufuegen mit Vorbedingung, ersetzen, loeschen); ohne bzw. mit
// falschem Schluessel abgelehnt; Zone ohne dynamische Updates lehnt ab.
func TestDynamicUpdate(t *testing.T) {
	m, port := testModule(t)
	ctx := context.Background()
	z, err := m.AddZone(ctx, Zone{Name: "home.lan", Authoritative: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	send := func(key, secret string, build func(*dns.Msg)) int {
		t.Helper()
		u := new(dns.Msg)
		u.SetUpdate("home.lan.")
		build(u)
		c := &dns.Client{Net: "tcp", Timeout: 3 * time.Second}
		if key != "" {
			u.SetTsig(key+".", dns.HmacSHA256, 300, time.Now().Unix())
			c.TsigSecret = map[string]string{key + ".": secret}
		}
		r, _, err := c.Exchange(u, addr)
		if err != nil {
			t.Fatalf("update: %v", err)
		}
		return r.Rcode
	}
	rr := func(s string) dns.RR {
		x, err := dns.NewRR(s)
		if err != nil {
			t.Fatal(err)
		}
		return x
	}

	if rc := send("", "", func(u *dns.Msg) { u.Insert([]dns.RR{rr("pc1.home.lan. 300 IN A 192.168.1.50")}) }); rc != dns.RcodeRefused {
		t.Fatalf("without tsig: %s", dns.RcodeToString[rc])
	}
	if err := m.SetZoneDynamic(ctx, z.ID, true, false); err != nil {
		t.Fatal(err)
	}
	zl, _ := m.Zones(ctx)
	key, secret := zl[0].TSIGName, zl[0].TSIGSecret
	if key != "node64-home.lan" || len(secret) < 40 {
		t.Fatalf("key = %q", key)
	}
	if rc := send(key, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", func(u *dns.Msg) { u.Insert([]dns.RR{rr("pc1.home.lan. 300 IN A 192.168.1.50")}) }); rc != dns.RcodeNotAuth {
		t.Fatalf("wrong secret: %s", dns.RcodeToString[rc])
	}
	// wie ISC/Kea: Name darf noch nicht existieren, dann A + DHCID
	if rc := send(key, secret, func(u *dns.Msg) {
		u.NameNotUsed([]dns.RR{rr("pc1.home.lan. 0 IN A 0.0.0.0")})
		u.Insert([]dns.RR{rr("pc1.home.lan. 300 IN A 192.168.1.50"), rr("pc1.home.lan. 300 IN DHCID AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=")})
	}); rc != dns.RcodeSuccess {
		t.Fatalf("add: %s", dns.RcodeToString[rc])
	}
	if a, ok := firstA(ask(t, addr, "pc1.home.lan", dns.TypeA)); !ok || a != "192.168.1.50" {
		t.Fatal("added A not answered")
	}
	// zweites Mal: Vorbedingung schlaegt fehl (Name vorhanden)
	if rc := send(key, secret, func(u *dns.Msg) {
		u.NameNotUsed([]dns.RR{rr("pc1.home.lan. 0 IN A 0.0.0.0")})
		u.Insert([]dns.RR{rr("pc1.home.lan. 300 IN A 192.168.1.51")})
	}); rc != dns.RcodeYXDomain {
		t.Fatalf("prereq: %s", dns.RcodeToString[rc])
	}
	// neue IP: RRset ersetzen
	if rc := send(key, secret, func(u *dns.Msg) {
		u.RemoveRRset([]dns.RR{rr("pc1.home.lan. 0 IN A 0.0.0.0")})
		u.Insert([]dns.RR{rr("pc1.home.lan. 300 IN A 192.168.1.51")})
	}); rc != dns.RcodeSuccess {
		t.Fatalf("replace: %s", dns.RcodeToString[rc])
	}
	recs, _ := m.Records(ctx)
	var a []string
	for _, r := range recs {
		if r.Name == "pc1.home.lan" && r.Type == "A" {
			a = append(a, r.Value)
			if !r.Dynamic {
				t.Fatal("record not marked dynamic")
			}
		}
	}
	if len(a) != 1 || a[0] != "192.168.1.51" {
		t.Fatalf("A after replace = %v", a)
	}
	// ungueltiger Eintrag hinter einem gueltigen: FORMERR und nichts angewendet (alles oder nichts)
	if rc := send(key, secret, func(u *dns.Msg) {
		u.Insert([]dns.RR{rr("pc3.home.lan. 300 IN A 192.168.1.53")})
		u.Ns = append(u.Ns, &dns.A{Hdr: dns.RR_Header{Name: "pc4.home.lan.", Rrtype: dns.TypeA, Class: dns.ClassCHAOS, Ttl: 300}, A: net.ParseIP("192.168.1.54")})
	}); rc != dns.RcodeFormatError {
		t.Fatalf("invalid class: %s", dns.RcodeToString[rc])
	}
	recs, _ = m.Records(ctx)
	for _, r := range recs {
		if r.Name == "pc3.home.lan" {
			t.Fatal("update partly applied before FORMERR")
		}
	}
	// ausserhalb der Zone, SOA-Aenderung
	if rc := send(key, secret, func(u *dns.Msg) { u.Insert([]dns.RR{rr("x.other.lan. 300 IN A 10.0.0.1")}) }); rc != dns.RcodeNotZone {
		t.Fatalf("not zone: %s", dns.RcodeToString[rc])
	}
	if rc := send(key, secret, func(u *dns.Msg) { u.Insert([]dns.RR{rr("home.lan. 300 IN NS ns.example.org.")}) }); rc != dns.RcodeRefused {
		t.Fatalf("NS update: %s", dns.RcodeToString[rc])
	}
	// Name loeschen
	if rc := send(key, secret, func(u *dns.Msg) { u.RemoveName([]dns.RR{rr("pc1.home.lan. 0 IN A 0.0.0.0")}) }); rc != dns.RcodeSuccess {
		t.Fatalf("remove name: %s", dns.RcodeToString[rc])
	}
	if r := ask(t, addr, "pc1.home.lan", dns.TypeA); r.Rcode != dns.RcodeNameError {
		t.Fatalf("after remove: %v", r)
	}
	// ausgeschaltet: abgelehnt
	if err := m.SetZoneDynamic(ctx, z.ID, false, false); err != nil {
		t.Fatal(err)
	}
	if rc := send(key, secret, func(u *dns.Msg) { u.Insert([]dns.RR{rr("pc2.home.lan. 300 IN A 192.168.1.52")}) }); rc == dns.RcodeSuccess {
		t.Fatal("update accepted after switching off")
	}
}
