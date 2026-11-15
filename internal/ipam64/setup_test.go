package ipam64

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
)

// Assistent: Vorschlaege aus DHCP-Netzen, Schnittstellen und Hand-Eintraegen in DNS64; Uebernahme mit Schaltern.
func TestSetup(t *testing.T) {
	m, fn, _ := modTest(t)
	ctx := context.Background()
	f := newFake()
	h := f.hooks()
	done := false // nach der Uebernahme sind die Eintraege in DNS64 gekennzeichnet (nicht mehr "von Hand")
	h.Unowned = func(context.Context) (Owned, error) {
		if done {
			return Owned{}, nil
		}
		return Owned{
			Reservations: []OwnedRes{{MAC: "02:00:00:00:00:14", IP: "192.168.1.20", Name: "Drucker"}, {MAC: "02:00:00:00:00:99", IP: "10.9.9.9"}},
			Records: []OwnedRec{
				{Name: "nas.home.lan", Type: "A", Value: "192.168.1.10"},
				{Name: "nas2.home.lan", Type: "A", Value: "192.168.1.10"},
				{Name: "pi.other.lan", Type: "A", Value: "192.168.1.30", NoPTR: true},
				{Name: "bad_name.home.lan", Type: "A", Value: "192.168.1.40"},
				{Name: "nas.home.lan", Type: "AAAA", Value: "fd00:10::10"},
			},
		}, nil
	}
	m.SetDNS64(h)
	m.SetNetworks(func(context.Context) []NetHint {
		return []NetHint{{Name: "LAN", Subnet: netip.MustParsePrefix("192.168.1.0/24"), Start: ip("192.168.1.100"), End: ip("192.168.1.199"), Domain: "home.lan"}}
	})
	fn.locals = append(fn.locals, netip.MustParsePrefix("2001:db8:1:10::2/64"))
	plan, err := m.SetupPlan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, p := range plan.Prefixes {
		keys = append(keys, p.Key)
	}
	slices.Sort(keys)
	if len(keys) != 3 || keys[0] != "p:192.168.1.0/24" || keys[1] != "p:2001:db8:1:10::/64" || keys[2] != "p:fd00:10::/64" {
		t.Fatalf("prefixes: %v", keys)
	}
	for _, p := range plan.Prefixes {
		if (p.Prefix.Prefix == "2001:db8:1:10::/64") != (p.Prefix.DynSource == DynAuto) {
			t.Fatalf("dynamic: %+v", p)
		}
	}
	if len(plan.Addresses) != 4 || len(plan.Skipped) != 3 {
		t.Fatalf("plan: %+v / %+v", plan.Addresses, plan.Skipped)
	}
	byIP := map[string]SetupAddress{}
	for _, a := range plan.Addresses {
		byIP[a.Address.Address] = a
	}
	if a := byIP["192.168.1.20"].Address; !a.DHCP || a.Name != "drucker" || a.MAC != "02:00:00:00:00:14" || a.DNS {
		t.Fatalf("drucker: %+v", a)
	}
	if a := byIP["192.168.1.30"].Address; !a.DNS || a.DNSZone != "other.lan" || a.PTR {
		t.Fatalf("pi: %+v", a)
	}
	if a := byIP["192.168.1.10"].Address; !a.DNS || a.DNSZone != "" || a.Name != "nas" {
		t.Fatalf("nas: %+v", a)
	}
	// alles ausser dem dynamischen Praefix uebernehmen
	take := []string{"p:192.168.1.0/24", "p:fd00:10::/64", "a:192.168.1.10", "a:192.168.1.20", "a:192.168.1.30", "a:fd00:10::10"}
	res, err := m.ApplySetup(ctx, take, "t", func(e error) string { return e.Error() })
	if err != nil || res.Prefixes != 2 || res.Addresses != 4 || len(res.Failed) != 0 {
		t.Fatalf("apply: %+v %v", res, err)
	}
	nas, _ := m.AddressByIP(ctx, "192.168.1.10")
	v6, _ := m.AddressByIP(ctx, "fd00:10::10")
	if nas == nil || !nas.DNS || len(f.recs[nas.UID]) != 1 || v6 == nil || f.recs[v6.UID][0].Name != "nas.home.lan" {
		t.Fatalf("applied: %+v %+v %+v", nas, v6, f.recs)
	}
	if p, _ := m.Prefixes(ctx); len(p) != 2 {
		t.Fatalf("prefixes stored: %+v", p)
	}
	// zweiter Lauf: nur noch das dynamische Praefix
	done = true
	plan, _ = m.SetupPlan(ctx)
	if len(plan.Prefixes) != 1 || len(plan.Addresses) != 0 {
		t.Fatalf("second plan: %+v %+v", plan.Prefixes, plan.Addresses)
	}
}

// Dynamisches IPv6-Praefix: Praefix-ID, Erkennung ueber die Adressen der Node, Umnummerierung samt AAAA.
func TestDynamicPrefix(t *testing.T) {
	m, fn, _ := modTest(t)
	ctx := context.Background()
	f := newFake()
	m.SetDNS64(f.hooks())
	src := []Sighting{{Addr: "https://[2001:db8:4f2a:e710::10]:8443", Note: "nas.beispiel.ipv64.net"}}
	m.SetSource(SrcProxy, func(context.Context) []Sighting { return src })
	if _, err := m.SavePrefix(ctx, Prefix{Prefix: "192.168.0.0/16", DynSource: DynAuto}, "t"); !errors.Is(err, ErrDyn) {
		t.Fatalf("dyn v4: %v", err)
	}
	if _, err := m.SavePrefix(ctx, Prefix{Prefix: "fd00::/48", DynSource: DynAuto}, "t"); !errors.Is(err, ErrDyn) {
		t.Fatalf("dyn ula: %v", err)
	}
	root := mustPrefix(t, m, Prefix{Prefix: "2001:db8:4f2a:e700::/56", Status: StatusContainer, DynSource: DynAuto})
	lan := mustPrefix(t, m, Prefix{Prefix: "2001:db8:4f2a:e710::/64", Name: "LAN", DNSZone: "home.lan"})
	if lan.DynParent != root.UID || lan.DynIndex != "10" {
		t.Fatalf("index: %+v", lan)
	}
	a, err := m.ApplyAddress(ctx, Address{Address: "2001:db8:4f2a:e710::10", Name: "nas", DNS: true, PTR: true}, "t")
	if err != nil || f.recs[a.UID][0].Value != "2001:db8:4f2a:e710::10" {
		t.Fatalf("address: %+v %v", f.recs, err)
	}
	fn.locals = []netip.Prefix{netip.MustParsePrefix("2001:db8:4f2a:e710::2/64")}
	if ch, err := m.CheckDynamic(ctx); err != nil || len(ch) != 0 {
		t.Fatalf("no change: %+v %v", ch, err)
	}
	// zwei moegliche neue Praefixe: nichts tun
	fn.locals = []netip.Prefix{netip.MustParsePrefix("2001:db8:aaaa:c110::2/64"), netip.MustParsePrefix("2001:db8:bbbb:d110::2/64")}
	if ch, _ := m.CheckDynamic(ctx); len(ch) != 0 {
		t.Fatalf("ambiguous: %+v", ch)
	}
	// Node liegt nicht in einem bekannten Kind (Praefix-ID 20 statt 10): nichts tun
	fn.locals = []netip.Prefix{netip.MustParsePrefix("2001:db8:4f2a:c120::2/64")}
	if ch, _ := m.CheckDynamic(ctx); len(ch) != 0 {
		t.Fatalf("wrong child: %+v", ch)
	}
	// Wechsel
	fn.locals = []netip.Prefix{netip.MustParsePrefix("2001:db8:4f2a:c110::2/64")}
	ch, err := m.CheckDynamic(ctx)
	if err != nil || len(ch) != 1 || ch[0].From != "2001:db8:4f2a:e700::/56" || ch[0].To != "2001:db8:4f2a:c100::/56" || ch[0].Prefixes != 2 || ch[0].Addresses != 1 {
		t.Fatalf("change: %+v %v", ch, err)
	}
	moved, _ := m.AddressByIP(ctx, "2001:db8:4f2a:c110::10")
	if moved == nil || moved.UID != a.UID || f.recs[a.UID][0].Value != "2001:db8:4f2a:c110::10" {
		t.Fatalf("moved: %+v %+v", moved, f.recs)
	}
	if p, _ := m.prefixByUID(ctx, lan.UID); p.Prefix != "2001:db8:4f2a:c110::/64" || p.DNSZone != "home.lan" {
		t.Fatalf("child: %+v", p)
	}
	if last := m.LastDynChange(ctx); last == nil || last.To != "2001:db8:4f2a:c100::/56" {
		t.Fatalf("last: %+v", last)
	}
	if st := m.StaleTargets(ctx, "2001:db8:4f2a:e700::/56"); len(st) != 1 {
		t.Fatalf("stale: %v", st)
	}
	// zweite Node im Cluster: lag zuletzt im alten Wert, bekommt den Wechsel ueber den Cluster und hat noch eine
	// Adresse im alten Praefix - sie nummeriert nicht zurueck (Anker)
	if err := m.core.SetSetting(ctx, setDynAnchor, `{"`+root.UID+`":"2001:db8:4f2a:e700::/56"}`); err != nil {
		t.Fatal(err)
	}
	fn.locals = []netip.Prefix{netip.MustParsePrefix("2001:db8:4f2a:e710::3/64")}
	if ch, err := m.CheckDynamic(ctx); err != nil || len(ch) != 0 {
		t.Fatalf("ping-pong: %+v %v", ch, err)
	}
	// ohne Anker (Node lag nie in der Wurzel) ebenso nicht
	if err := m.core.SetSetting(ctx, setDynAnchor, "{}"); err != nil {
		t.Fatal(err)
	}
	if ch, _ := m.CheckDynamic(ctx); len(ch) != 0 {
		t.Fatalf("no anchor: %+v", ch)
	}
	// liegt die Node wieder im aktuellen Wert, setzt sie den Anker; ein echter Wechsel nummeriert dann um
	fn.locals = []netip.Prefix{netip.MustParsePrefix("2001:db8:4f2a:c110::2/64")}
	if ch, _ := m.CheckDynamic(ctx); len(ch) != 0 {
		t.Fatalf("anchor set: %+v", ch)
	}
	fn.locals = []netip.Prefix{netip.MustParsePrefix("2001:db8:4f2a:e710::2/64")}
	if ch, _ := m.CheckDynamic(ctx); len(ch) != 1 || ch[0].To != "2001:db8:4f2a:e700::/56" {
		t.Fatalf("change back: %+v", ch)
	}
	if got := replaceTop(netip.MustParseAddr("2001:db8:4f2a:e7ff::1"), netip.MustParsePrefix("2001:db8:1:200::/55")).String(); got != "2001:db8:1:3ff::1" {
		t.Fatalf("replaceTop: %s", got)
	}
}
