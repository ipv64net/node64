package ipam64

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Nachstellungen der Befunde aus dem Code-Review (v1.5.0..d2ee60bb), je Befund ein Test; Nummern wie im Auftrag.

// lanHint: DHCP-Netz 192.168.1.0/24 mit Pool .100-.199 und Zone home.lan.
func lanHint(context.Context) []NetHint {
	return []NetHint{{Name: "LAN", Subnet: netip.MustParsePrefix("192.168.1.0/24"), Start: ip("192.168.1.100"), End: ip("192.168.1.199"), Domain: "home.lan"}}
}

// 1) Kind-Praefix im DHCP-Netz: Ausnahme fuer Adressen im Pool, keine Pool-Adresse als "naechste freie", reservierte
// Bereiche der Eltern gelten auch im Kind.
func TestReviewPoolInChild(t *testing.T) {
	m, _, _ := modTest(t)
	ctx := context.Background()
	f := newFake()
	m.SetDNS64(f.hooks())
	m.SetNetworks(lanHint)
	mustPrefix(t, m, Prefix{Prefix: "192.168.1.128/26", Name: "Kameras"})
	cam, err := m.ApplyAddress(ctx, Address{Address: "192.168.1.150", Name: "kamera"}, "t")
	if err != nil {
		t.Fatal(err)
	}
	if f.excl[cam.UID].IP != "192.168.1.150" {
		t.Fatalf("no exclude for pool address in child prefix: %+v", f.excl)
	}
	if free, err := m.Available(ctx, "192.168.1.128/26", "", 5); err != nil || len(free) != 0 {
		t.Fatalf("pool addresses offered as free: %v %v", free, err)
	}
	// Zone des DHCP-Netzes gilt auch im Kind
	nvr, err := m.ApplyAddress(ctx, Address{Address: "192.168.1.140", Name: "nvr", DNS: true, PTR: true}, "t")
	if err != nil || len(f.recs[nvr.UID]) != 1 || f.recs[nvr.UID][0].Name != "nvr.home.lan" {
		t.Fatalf("zone of dhcp net in child: %+v %v", f.recs, err)
	}
	// reservierter Bereich im Eltern-Praefix, der in das Kind hineinreicht
	mustPrefix(t, m, Prefix{Prefix: "192.168.2.0/24"})
	mustPrefix(t, m, Prefix{Prefix: "192.168.2.32/28"})
	if _, err := m.SaveRange(ctx, Range{Start: "192.168.2.20", End: "192.168.2.40", Kind: RangeReserved}, "t"); err != nil {
		t.Fatal(err)
	}
	if free, _ := m.Available(ctx, "192.168.2.32/28", "", 1); len(free) != 1 || free[0].String() != "192.168.2.41" {
		t.Fatalf("reserved range of parent ignored: %v", free)
	}
}

// 9) Adressbereich im Kind: das Eltern-Praefix findet trotzdem seine freien Adressen.
func TestReviewRangesOfChild(t *testing.T) {
	m, _, _ := modTest(t)
	ctx := context.Background()
	mustPrefix(t, m, Prefix{Prefix: "10.1.0.0/24"})
	mustPrefix(t, m, Prefix{Prefix: "10.1.0.0/25"})
	if _, err := m.SaveRange(ctx, Range{Start: "10.1.0.10", End: "10.1.0.20", Kind: RangeFixed}, "t"); err != nil {
		t.Fatal(err)
	}
	if free, err := m.Available(ctx, "10.1.0.0/24", "", 1); err != nil || len(free) != 1 || free[0].String() != "10.1.0.128" {
		t.Fatalf("parent: %v %v", free, err)
	}
	if free, _ := m.Available(ctx, "10.1.0.0/25", "", 1); len(free) != 1 || free[0].String() != "10.1.0.10" {
		t.Fatalf("child: %v", free)
	}
}

// 2) Scheitert DNS64, gibt die Rueckabwicklung uebernommene Eintraege von Hand frei, statt sie zu loeschen - mit
// Vorpruefung (DNS64 lehnt ab, bevor etwas geschrieben ist) und ohne (Rueckabwicklung nach dem Schreiben).
func TestReviewRollbackKeepsHandEntries(t *testing.T) {
	for _, noCheck := range []bool{false, true} {
		m, _, _ := modTest(t)
		ctx := context.Background()
		f := newFake()
		f.noCheck = noCheck
		m.SetDNS64(f.hooks())
		m.SetNetworks(lanHint)
		f.handRecs["drucker.home.lan|192.168.1.20"] = true
		f.res["other"] = OwnedRes{Ref: "other", MAC: "02:00:00:00:00:14", IP: "192.168.1.21"} // MAC schon vergeben
		if _, err := m.ApplyAddress(ctx, Address{Address: "192.168.1.20", Name: "drucker", MAC: "02:00:00:00:00:14", DNS: true, PTR: true, DHCP: true}, "t"); err == nil {
			t.Fatal("dup mac accepted")
		}
		if !f.handRecs["drucker.home.lan|192.168.1.20"] {
			t.Fatalf("noCheck=%v: hand record lost on rollback: %+v %+v", noCheck, f.handRecs, f.recs)
		}
		// geaenderte Adresse: neuer Name trifft einen Eintrag von Hand, Reservierung scheitert -> alter Stand, Hand-Eintrag
		// bleibt
		a, err := m.ApplyAddress(ctx, Address{Address: "192.168.1.30", Name: "pi", MAC: "02:00:00:00:00:1e", DNS: true, PTR: true, DHCP: true}, "t")
		if err != nil {
			t.Fatal(err)
		}
		f.handRecs["scanner.home.lan|192.168.1.30"] = true
		a.Name, a.MAC = "scanner", "02:00:00:00:00:14"
		if _, err := m.ApplyAddress(ctx, a, "t"); err == nil {
			t.Fatal("dup mac accepted on change")
		}
		if !f.handRecs["scanner.home.lan|192.168.1.30"] || len(f.recs[a.UID]) != 1 || f.recs[a.UID][0].Name != "pi.home.lan" || f.res[a.UID].MAC != "02:00:00:00:00:1e" {
			t.Fatalf("noCheck=%v: change rollback: hand %+v recs %+v res %+v", noCheck, f.handRecs, f.recs[a.UID], f.res[a.UID])
		}
	}
}

// 3) Uebergabe an DNS64 im Cluster: die andere Node gibt ihre Eintraege ebenfalls frei (statt sie zu loeschen), und
// freigegebene Ausnahmen werden nicht wieder gekennzeichnet.
func TestReviewHandoverInCluster(t *testing.T) {
	m, _, _ := modTest(t)
	ctx := context.Background()
	f := newFake()
	m.SetDNS64(f.hooks())
	m.SetNetworks(lanHint)
	nas, err := m.ApplyAddress(ctx, Address{Address: "192.168.1.10", Name: "nas", DNS: true, PTR: true}, "t")
	if err != nil {
		t.Fatal(err)
	}
	cam, err := m.ApplyAddress(ctx, Address{Address: "192.168.1.150", Name: "kamera"}, "t")
	if err != nil {
		t.Fatal(err)
	}
	// Node A hat uebergeben: beide Adressen kommen ueber den Cluster mit "uebergeben"
	for _, a := range []Address{nas, cam} {
		a.DNS, a.DHCP, a.Released = false, false, true
		a.Updated = time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
		b, _ := json.Marshal(a)
		if err := m.ClusterApply(ctx, ClusterItemAddresses, a.UID, b, false); err != nil {
			t.Fatal(err)
		}
	}
	m.now = func() time.Time { return time.Now().Add(settleFor + time.Minute) }
	if _, err := m.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.recs[nas.UID]) != 0 || !f.handRecs["nas.home.lan|192.168.1.10"] {
		t.Fatalf("record deleted instead of released: recs %+v hand %+v", f.recs, f.handRecs)
	}
	if _, ok := f.excl[cam.UID]; ok || !f.handExcl["192.168.1.150"] {
		t.Fatalf("exclude: %+v hand %+v", f.excl, f.handExcl)
	}
	if n, _ := m.reconcile(ctx); n != 0 || len(f.excl) != 0 {
		t.Fatalf("released exclude tagged again: %d %+v", n, f.excl)
	}
	// Schaltet jemand DNS wieder ein, verwaltet IPAM64 die Adresse wieder
	cur, _ := m.AddressByIP(ctx, "192.168.1.10")
	cur.DNS = true
	saved, err := m.ApplyAddress(ctx, *cur, "t")
	if err != nil || saved.Released || len(f.recs[nas.UID]) != 1 {
		t.Fatalf("dns on again: %+v %v %+v", saved, err, f.recs)
	}
	// Uebergabe auf dieser Node: auch Adressen ohne DNS/DHCP (Ausnahme im Pool) gelten als uebergeben
	if _, err := m.ApplyAddress(ctx, Address{Address: "192.168.1.160", Name: "tv"}, "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Handover(ctx, "t"); err != nil {
		t.Fatal(err)
	}
	if tv, _ := m.AddressByIP(ctx, "192.168.1.160"); tv == nil || !tv.Released {
		t.Fatalf("handover: %+v", tv)
	}
	if n, _ := m.reconcile(ctx); n != 0 || len(f.excl) != 0 || len(f.recs) != 0 {
		t.Fatalf("after handover: %d %+v %+v", n, f.excl, f.recs)
	}
}

// 4) DNS64-Bereich im Cluster an, IPAM-Adressen aus: gekennzeichnete Eintraege anderer Nodes sind keine Waisen.
func TestReviewForeignTagged(t *testing.T) {
	m, _, _ := modTest(t)
	ctx := context.Background()
	f := newFake()
	m.SetDNS64(f.hooks())
	foreign := true
	m.SetCluster(ClusterHooks{ForeignDNS64: func(context.Context) bool { return foreign }})
	f.recs["other-node"] = []OwnedRec{{Ref: "other-node", Name: "x.home.lan", Type: "A", Value: "192.168.1.77"}}
	m.now = func() time.Time { return time.Now().Add(settleFor + time.Minute) }
	for range 3 {
		if _, err := m.reconcile(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.recs["other-node"]) != 1 {
		t.Fatal("foreign tagged entry deleted")
	}
	foreign = false // ohne fremde Nodes: Waise, im zweiten Lauf geloescht
	_, _ = m.reconcile(ctx)
	_, _ = m.reconcile(ctx)
	if len(f.recs["other-node"]) != 0 {
		t.Fatal("orphan kept")
	}
}

// 5) Gleiche Adresse auf zwei Nodes (clusterDouble): der Abgleich ersetzt die Eintraege der verdraengten uid im selben
// Lauf (erst Waisen, dann schreiben) - ohne err_dup und ohne Luecke.
func TestReviewDoubleReconcile(t *testing.T) {
	m, _, _ := modTest(t)
	ctx := context.Background()
	f := newFake()
	m.SetDNS64(f.hooks())
	m.SetNetworks(lanHint)
	mine, err := m.ApplyAddress(ctx, Address{Address: "192.168.1.10", Name: "nas", MAC: "02:00:00:00:00:0a", DNS: true, PTR: true, DHCP: true}, "t")
	if err != nil {
		t.Fatal(err)
	}
	other := mine
	other.UID = "00000000000000000000000000000001" // kleiner: gewinnt
	other.Updated = time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	b, _ := json.Marshal(other)
	if err := m.ClusterApply(ctx, ClusterItemAddresses, other.UID, b, false); err != nil {
		t.Fatal(err)
	}
	m.now = func() time.Time { return time.Now().Add(settleFor + time.Minute) }
	if _, err := m.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.recs[other.UID]) != 1 || f.res[other.UID].IP != "192.168.1.10" || len(f.recs[mine.UID]) != 0 {
		t.Fatalf("after one run: recs %+v res %+v", f.recs, f.res)
	}
}

// 6) Vergabe im Cluster: verdraengt eine andere Node eine eigene Adresse, gibt es einen Fund (und eine Meldung).
func TestReviewDoubleFinding(t *testing.T) {
	m, _, _ := modTest(t)
	ctx := context.Background()
	mustPrefix(t, m, Prefix{Prefix: "192.168.1.0/24"})
	mine, err := m.SaveAddress(ctx, Address{Address: "192.168.1.10", Name: "nas"}, "t")
	if err != nil {
		t.Fatal(err)
	}
	other := mine
	other.UID, other.Name = "00000000000000000000000000000001", "drucker"
	b, _ := json.Marshal(other)
	if err := m.ClusterApply(ctx, ClusterItemAddresses, other.UID, b, false); err != nil {
		t.Fatal(err)
	}
	found, err := m.Findings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ok := false
	for _, x := range found {
		ok = ok || (x.Kind == "double" && x.IP == "192.168.1.10" && x.Name == "nas")
	}
	if !ok {
		t.Fatalf("no finding for cluster double: %+v", found)
	}
}

// 7) Dynamische Wurzel ohne Kinder: nur Adressen der Schnittstelle zaehlen, auf der die Node in der Wurzel lag
// (WireGuard/Docker mit eigener globaler Adresse fuehren weder zu "mehrdeutig" noch zu falschem Umnummerieren).
func TestReviewDynIface(t *testing.T) {
	m, fn, _ := modTest(t)
	ctx := context.Background()
	m.SetDNS64(newFake().hooks())
	mustPrefix(t, m, Prefix{Prefix: "2001:db8:4f2a:e700::/56", DynSource: DynAuto})
	fn.ifs = map[string]string{"2001:db8:4f2a:e700::2/64": "eth0", "2001:db8:9999:1::2/64": "wg0", "2001:db8:4f2a:c100::2/64": "eth0"}
	fn.locals = []netip.Prefix{netip.MustParsePrefix("2001:db8:4f2a:e700::2/64"), netip.MustParsePrefix("2001:db8:9999:1::2/64")}
	if ch, err := m.CheckDynamic(ctx); err != nil || len(ch) != 0 {
		t.Fatalf("no change: %+v %v", ch, err)
	}
	// Provider wechselt: neue Adresse auf eth0, wg0 bleibt
	fn.locals = []netip.Prefix{netip.MustParsePrefix("2001:db8:4f2a:c100::2/64"), netip.MustParsePrefix("2001:db8:9999:1::2/64")}
	ch, err := m.CheckDynamic(ctx)
	if err != nil || len(ch) != 1 || ch[0].To != "2001:db8:4f2a:c100::/56" {
		t.Fatalf("change: %+v %v", ch, err)
	}
	// nur noch wg0 (eth0 ohne globale Adresse): nicht nach wg0 umnummerieren
	fn.locals = []netip.Prefix{netip.MustParsePrefix("2001:db8:9999:1::2/64")}
	if ch, _ := m.CheckDynamic(ctx); len(ch) != 0 {
		t.Fatalf("renumbered to foreign interface: %+v", ch)
	}
}

// 8) Umnummerieren am Stueck: scheitert es mittendrin, bleibt der alte Stand (kein halber Wechsel).
func TestReviewRenumberAtomic(t *testing.T) {
	m, fn, _ := modTest(t)
	ctx := context.Background()
	m.SetDNS64(newFake().hooks())
	root := mustPrefix(t, m, Prefix{Prefix: "2001:db8:4f2a:e700::/56", Status: StatusContainer, DynSource: DynAuto})
	mustPrefix(t, m, Prefix{Prefix: "2001:db8:4f2a:e710::/64"})
	if _, err := m.SaveAddress(ctx, Address{Address: "2001:db8:4f2a:e710::10"}, "t"); err != nil {
		t.Fatal(err)
	}
	tmp := mustPrefix(t, m, Prefix{Prefix: "2001:db8:4f2a:c110::/64"}) // Adresse, mit der das Umnummerieren kollidiert
	if _, err := m.SaveAddress(ctx, Address{Address: "2001:db8:4f2a:c110::10"}, "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.DeletePrefix(ctx, tmp.UID); err != nil {
		t.Fatal(err)
	}
	fn.locals = []netip.Prefix{netip.MustParsePrefix("2001:db8:4f2a:e710::2/64")}
	if _, err := m.CheckDynamic(ctx); err != nil {
		t.Fatal(err)
	}
	fn.locals = []netip.Prefix{netip.MustParsePrefix("2001:db8:4f2a:c110::2/64")}
	if _, err := m.CheckDynamic(ctx); err == nil {
		t.Fatal("collision not reported")
	}
	if p, _ := m.prefixByUID(ctx, root.UID); p.Prefix != "2001:db8:4f2a:e700::/56" {
		t.Fatalf("half renumbered: root now %s", p.Prefix)
	}
	// abgebrochene Anfrage: Umnummerieren laeuft trotzdem ganz durch (eigener Kontext)
	if _, err := m.RemoveAddress(ctx, mustAddr(t, m, "2001:db8:4f2a:c110::10").UID); err != nil {
		t.Fatal(err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := m.renumber(cctx, netip.MustParsePrefix("2001:db8:4f2a:e700::/56"), netip.MustParsePrefix("2001:db8:4f2a:c100::/56")); err != nil {
		t.Fatalf("renumber with canceled request: %v", err)
	}
	if a, _ := m.AddressByIP(ctx, "2001:db8:4f2a:c110::10"); a == nil {
		t.Fatal("address not moved")
	}
}

func mustAddr(t *testing.T, m *Module, s string) *Address {
	t.Helper()
	a, err := m.AddressByIP(context.Background(), s)
	if err != nil || a == nil {
		t.Fatalf("address %s: %v", s, err)
	}
	return a
}

// 10) Geraetetausch ist kein Konflikt "dup": Beruehrung bzw. zurueckdatierte erste Sichtung zaehlt nicht als
// Ueberschneidung, echtes Abwechseln schon.
func TestReviewDupTolerance(t *testing.T) {
	t0 := time.Now().Add(-time.Hour)
	swap := acc{recent: []seenRow{
		{MAC: "02:00:00:00:00:01", First: t0, Last: t0.Add(20 * time.Minute)},
		{MAC: "02:00:00:00:00:02", First: t0.Add(19 * time.Minute), Last: t0.Add(40 * time.Minute)}, // zurueckdatiert
	}}
	if c := swap.conflict(); c == "dup" {
		t.Fatal("device swap reported as dup")
	}
	touch := acc{recent: []seenRow{
		{MAC: "02:00:00:00:00:01", First: t0, Last: t0.Add(20 * time.Minute)},
		{MAC: "02:00:00:00:00:02", First: t0.Add(20 * time.Minute), Last: t0.Add(40 * time.Minute)},
	}}
	if c := touch.conflict(); c == "dup" {
		t.Fatal("touching sightings reported as dup")
	}
	dup := acc{recent: []seenRow{
		{MAC: "02:00:00:00:00:01", First: t0, Last: t0.Add(40 * time.Minute)},
		{MAC: "02:00:00:00:00:02", First: t0.Add(5 * time.Minute), Last: t0.Add(35 * time.Minute)},
	}}
	if c := dup.conflict(); c != "dup" {
		t.Fatalf("alternating devices: %q", c)
	}
}

// 11) Kaputte CSV-Zeile: Fehler fuer diese Zeile, der Rest wird weiter gelesen.
func TestReviewImportBadLine(t *testing.T) {
	m, _, _ := modTest(t)
	ctx := context.Background()
	mustPrefix(t, m, Prefix{Prefix: "192.168.1.0/24"})
	rows, err := m.ParseImport(ctx, []byte("ip,name\n192.168.1.10,nas\n192.168.1.11,dru\"cker\n192.168.1.12,pi\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[1].Err == nil || rows[1].Line != 3 || rows[2].Key != "192.168.1.12" || rows[2].Err != nil {
		t.Fatalf("rows: %+v", rows)
	}
	if errKey(rows[1].Err) == "" {
		t.Fatalf("csv error without text: %v", rows[1].Err)
	}
}

// 12) Ziel mit Namen haengt immer an derselben Adresse (IPv4 vor IPv6), nicht zufaellig.
func TestReviewNameDeterministic(t *testing.T) {
	m, _, _ := modTest(t)
	ctx := context.Background()
	mustPrefix(t, m, Prefix{Prefix: "192.168.1.0/24"})
	mustPrefix(t, m, Prefix{Prefix: "fd00:10::/64"})
	for _, a := range []string{"fd00:10::10", "192.168.1.10"} {
		if _, err := m.SaveAddress(ctx, Address{Address: a, Name: "nas"}, "t"); err != nil {
			t.Fatal(err)
		}
	}
	m.SetSource(SrcHealthchecks, func(context.Context) []Sighting { return []Sighting{{Addr: "https://nas:5001/"}} })
	for i := range 30 {
		m.invalidate()
		s, err := m.Snapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		v4, v6 := s.Entry(ip("192.168.1.10")), s.Entry(ip("fd00:10::10"))
		if !strings.Contains(strings.Join(v4.Sources, " "), SrcHealthchecks) || strings.Contains(strings.Join(v6.Sources, " "), SrcHealthchecks) {
			t.Fatalf("run %d: v4 %v v6 %v", i, v4.Sources, v6.Sources)
		}
	}
}

// 13) Keine Inline-Ereignisse in den Vorlagen (CSP script-src 'self' blockiert sie).
func TestReviewNoInlineHandlers(t *testing.T) {
	files, _ := filepath.Glob("templates/pages/*.html")
	re := regexp.MustCompile(`\son[a-z]+="`)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if re.Match(b) {
			t.Fatalf("%s: inline event handler", f)
		}
	}
}

// 14) Dashboard-Karte: Belegung nur aus IPv4-Praefixen mit Groesse (IPv6 und Container zaehlen nicht mit).
func TestReviewCardPct(t *testing.T) {
	m, _, _ := modTest(t)
	ctx := context.Background()
	mustPrefix(t, m, Prefix{Prefix: "192.168.0.0/16", Status: StatusContainer})
	mustPrefix(t, m, Prefix{Prefix: "192.168.5.0/30"})
	mustPrefix(t, m, Prefix{Prefix: "fd00:10::/64"})
	for _, a := range []string{"192.168.5.1", "fd00:10::1", "fd00:10::2", "fd00:10::3"} {
		if _, err := m.SaveAddress(ctx, Address{Address: a}, "t"); err != nil {
			t.Fatal(err)
		}
	}
	c, err := m.Card(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if c.Stats[1].Pct != 50 {
		t.Fatalf("pct: %v", c.Stats[1].Pct)
	}
}

// 15) Automatischer Scan zeigt kein "invalid Prefix".
func TestReviewAutoScanPrefix(t *testing.T) {
	m, _, _ := modTest(t)
	m.scanAll(context.Background())
	if p := m.Scanning().Prefix; p != "" {
		t.Fatalf("prefix: %q", p)
	}
}
