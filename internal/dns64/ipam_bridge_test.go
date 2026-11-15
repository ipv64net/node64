package dns64

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// IPAM64 (Stufe I2): gekennzeichnete Reservierungen, Ausnahmen und Eintraege; Sperre, Uebergabe, Cluster.
func TestIPAMBridgeDHCP(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	s, err := m.AddDHCPScope(ctx, DHCPScope{Iface: "eth9", Subnet: "192.168.50.0/24", Start: "192.168.50.100", End: "192.168.50.150", Domain: "home.lan"})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.PutIPAMReservation(ctx, "u1", "02:00:00:00:00:01", "10.9.9.9", "nas"); err == nil {
		t.Fatal("reservation outside any network accepted")
	}
	if err := m.PutIPAMReservation(ctx, "u1", "02:00:00:00:00:01", "192.168.50.20", "nas"); err != nil {
		t.Fatal(err)
	}
	// neue MAC fuer dieselbe Adresse: ersetzt, nicht doppelt
	if err := m.PutIPAMReservation(ctx, "u1", "02-00-00-00-00-02", "192.168.50.20", "nas"); err != nil {
		t.Fatal(err)
	}
	res, _ := m.DHCPReservations(ctx)
	if len(res) != 1 || res[0].MAC != "02:00:00:00:00:02" || res[0].Origin != OriginIPAM || res[0].Ref != "u1" {
		t.Fatalf("reservations: %+v", res)
	}
	// gleiche von Hand: wird gekennzeichnet; andere von Hand auf derselben IP: Fehler
	if _, err := m.AddDHCPReservation(ctx, DHCPReservation{ScopeID: s.ID, MAC: "02:00:00:00:00:03", IP: "192.168.50.30", Name: "drucker"}); err != nil {
		t.Fatal(err)
	}
	if err := m.PutIPAMReservation(ctx, "u2", "02:00:00:00:00:03", "192.168.50.30", "drucker"); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if err := m.PutIPAMReservation(ctx, "u3", "02:00:00:00:00:04", "192.168.50.30", "x"); err == nil {
		t.Fatal("dup accepted")
	}
	// Ausnahme statt Reservierung (gleiche Adresse aus IPAM64): Reservierung faellt weg
	if err := m.PutIPAMExclude(ctx, "u2", "192.168.50.30", "fest eingestellt"); err != nil {
		t.Fatal(err)
	}
	if err := m.PutIPAMExclude(ctx, "u4", "192.168.50.20", ""); err == nil {
		t.Fatal("exclude over other reservation accepted")
	}
	if err := m.PutIPAMExclude(ctx, "u5", "192.168.50.120", "im Pool"); err != nil {
		t.Fatal(err)
	}
	cfg, err := m.dhcpConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Reservations) != 1 || len(cfg.Excludes) != 2 {
		t.Fatalf("config: %+v / %+v", cfg.Reservations, cfg.Excludes)
	}
	st, err := m.IPAMEntries(ctx)
	if err != nil || len(st.Reservations) != 1 || len(st.Excludes) != 2 {
		t.Fatalf("entries: %+v %v", st, err)
	}
	// Sperre nur, solange IPAM64 laeuft
	id := st.Reservations[0].ID
	on := true
	m.SetIPAM(func() bool { return on })
	var ce *cfgError
	if err := m.DeleteDHCPReservation(ctx, id); !errors.As(err, &ce) || ce.Key != "err_ipam_managed" {
		t.Fatalf("locked delete: %v", err)
	}
	if _, err := m.UpdateDHCPReservation(ctx, id, DHCPReservation{ScopeID: s.ID, MAC: "02:00:00:00:00:09", IP: "192.168.50.21"}); !errors.As(err, &ce) {
		t.Fatalf("locked update: %v", err)
	}
	// Uebergabe: Kennzeichen weg, danach normal bearbeitbar
	n, err := m.ReleaseIPAM(ctx, "u1")
	if err != nil || n != 1 {
		t.Fatalf("release: %d %v", n, err)
	}
	if err := m.DeleteDHCPReservation(ctx, id); err != nil {
		t.Fatalf("delete after release: %v", err)
	}
	on = false
	if err := m.DeleteIPAMExclude(ctx, "u5"); err != nil {
		t.Fatal(err)
	}
	if x, _ := m.DHCPExcludes(ctx); len(x) != 1 || x[0].Ref != "u2" {
		t.Fatalf("excludes: %+v", x)
	}
}

func TestIPAMBridgeRecords(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	v4, v6 := netip.MustParseAddr("192.168.50.20"), netip.MustParseAddr("fd00:10::20")
	if err := m.PutIPAMRecords(ctx, "u1", "NAS.home.lan.", []netip.Addr{v4, v6}, true); err != nil {
		t.Fatal(err)
	}
	if rrs, ok := m.Lookup("nas.home.lan", dns.TypeAAAA); !ok || len(rrs) != 1 {
		t.Fatalf("aaaa: %v", rrs)
	}
	arpa, _ := dns.ReverseAddr(v4.String())
	if rrs, ok := m.Lookup(strings.TrimSuffix(arpa, "."), dns.TypePTR); !ok || len(rrs) != 1 {
		t.Fatalf("ptr: %v %v", rrs, ok)
	}
	// nur noch IPv4, ohne PTR: AAAA faellt weg
	if err := m.PutIPAMRecords(ctx, "u1", "nas.home.lan", []netip.Addr{v4}, false); err != nil {
		t.Fatal(err)
	}
	if rrs, _ := m.Lookup("nas.home.lan", dns.TypeAAAA); len(rrs) != 0 {
		t.Fatalf("aaaa left: %v", rrs)
	}
	if _, ok := m.Lookup(strings.TrimSuffix(arpa, "."), dns.TypePTR); ok {
		t.Fatal("ptr despite no_ptr")
	}
	// gleicher Eintrag von Hand: wird gekennzeichnet; CNAME auf dem Namen: Fehler; fremder IPAM-Eintrag: Fehler
	if _, err := m.AddRecord(ctx, Record{Name: "pi.home.lan", Type: "A", Value: "192.168.50.3"}); err != nil {
		t.Fatal(err)
	}
	if err := m.PutIPAMRecords(ctx, "u2", "pi.home.lan", []netip.Addr{netip.MustParseAddr("192.168.50.3")}, true); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if _, err := m.AddRecord(ctx, Record{Name: "web.home.lan", Type: "CNAME", Value: "nas.home.lan"}); err != nil {
		t.Fatal(err)
	}
	if err := m.PutIPAMRecords(ctx, "u3", "web.home.lan", []netip.Addr{v4}, true); err == nil {
		t.Fatal("cname accepted")
	}
	if err := m.PutIPAMRecords(ctx, "u3", "nas.home.lan", []netip.Addr{v4}, true); err == nil {
		t.Fatal("other ipam record accepted")
	}
	recs, _ := m.Records(ctx)
	owned := 0
	var pi Record
	for _, r := range recs {
		if r.Origin == OriginIPAM {
			owned++
		}
		if r.Name == "pi.home.lan" {
			pi = r
		}
	}
	if owned != 2 || pi.Ref != "u2" {
		t.Fatalf("records: %+v", recs)
	}
	// Sperre und Uebergabe
	m.SetIPAM(func() bool { return true })
	var ce *cfgError
	for _, f := range []func() error{
		func() error { return m.DeleteRecord(ctx, pi.ID) },
		func() error { return m.SetRecordEnabled(ctx, pi.ID, false) },
		func() error {
			_, err := m.UpdateRecord(ctx, pi.ID, Record{Name: "pi.home.lan", Type: "A", Value: "192.168.50.4"})
			return err
		},
	} {
		if err := f(); !errors.As(err, &ce) || ce.Key != "err_ipam_managed" {
			t.Fatalf("locked: %v", err)
		}
	}
	if err := m.DeleteIPAMRecords(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Lookup("nas.home.lan", dns.TypeA); ok {
		t.Fatal("deleted record still answered")
	}
	if n, err := m.ReleaseIPAM(ctx, ""); err != nil || n != 1 {
		t.Fatalf("release all: %d %v", n, err)
	}
	if err := m.DeleteRecord(ctx, pi.ID); err != nil {
		t.Fatalf("delete after release: %v", err)
	}
	// Stapel: Eintraege stehen sofort in der Tabelle, der DNS antwortet erst nach dem Stapel (ein Neuaufbau)
	err := m.IPAMBatch(ctx, func(ctx context.Context) error {
		for i := 1; i <= 50; i++ {
			ip := netip.AddrFrom4([4]byte{192, 168, 60, byte(i)})
			if err := m.PutIPAMRecords(ctx, "b"+ip.String(), "h"+strconv.Itoa(i)+".home.lan", []netip.Addr{ip}, true); err != nil {
				return err
			}
		}
		if _, ok := m.Lookup("h1.home.lan", dns.TypeA); ok {
			t.Error("answered inside batch")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if rrs, ok := m.Lookup("h50.home.lan", dns.TypeA); !ok || len(rrs) != 1 {
		t.Fatalf("after batch: %v", rrs)
	}
}

// Kennzeichen und Ausnahmen gehen ueber den Cluster.
func TestIPAMBridgeCluster(t *testing.T) {
	a, _ := testModule(t)
	b, _ := testModule(t)
	ctx := context.Background()
	for _, m := range []*Module{a, b} {
		if _, err := m.AddDHCPScope(ctx, DHCPScope{Iface: "eth9", Subnet: "192.168.50.0/24", Start: "192.168.50.100", End: "192.168.50.150"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.PutIPAMReservation(ctx, "u1", "02:00:00:00:00:01", "192.168.50.20", "nas"); err != nil {
		t.Fatal(err)
	}
	if err := a.PutIPAMExclude(ctx, "u2", "192.168.50.110", "fest"); err != nil {
		t.Fatal(err)
	}
	if err := a.PutIPAMRecords(ctx, "u1", "nas.home.lan", []netip.Addr{netip.MustParseAddr("192.168.50.20")}, true); err != nil {
		t.Fatal(err)
	}
	for _, item := range []string{ItemDHCPRes, ItemRecords} {
		cur, err := a.clCurrent(ctx, item)
		if err != nil {
			t.Fatal(err)
		}
		for id, v := range cur {
			if err := b.ClusterApply(ctx, item, id, json.RawMessage(v), false); err != nil {
				t.Fatalf("%s %s: %v", item, id, err)
			}
		}
	}
	st, err := b.IPAMEntries(ctx)
	if err != nil || len(st.Reservations) != 1 || st.Reservations[0].Ref != "u1" || len(st.Excludes) != 1 || st.Excludes[0].Comment != "fest" ||
		len(st.Records) != 1 || st.Records[0].Ref != "u1" {
		t.Fatalf("b: %+v %v", st, err)
	}
	if err := b.ClusterApply(ctx, ItemDHCPRes, "x:192.168.50.0/24|192.168.50.110", nil, true); err != nil {
		t.Fatal(err)
	}
	if x, _ := b.DHCPExcludes(ctx); len(x) != 0 {
		t.Fatalf("exclude left: %+v", x)
	}
	if err := b.ClusterApply(ctx, ItemDHCPRes, "x:192.168.50.0/24|192.168.60.1", json.RawMessage(`{"subnet":"192.168.50.0/24","ip":"192.168.60.1"}`), false); err == nil {
		t.Fatal("exclude outside network accepted")
	}
}

// Seiten: Kennzeichen IPAM64, bei laufendem IPAM64 statt Bearbeiten/Loeschen ein Link dorthin.
func TestIPAMBridgePages(t *testing.T) {
	tpl, err := template.New("p").Funcs(template.FuncMap{"join": strings.Join}).ParseFS(templateFS, "templates/pages/dhcp.html")
	if err != nil {
		t.Fatal(err)
	}
	sc := DHCPScope{ID: 1, Name: "LAN", Iface: "eth0", Subnet: "192.168.1.0/24", Start: "192.168.1.100", End: "192.168.1.199", Enabled: true}
	page := func(ipam bool) string {
		v := tview{CSRF: "c", Data: pageData{DHCP: dhcpPage{Mode: dhcpOn, ResScope: map[int64]string{1: "LAN"}, Scopes: []dhcpScopeView{{DHCPScope: sc}}, IPAM: ipam,
			Res:      []dhcpResView{{DHCPReservation{ID: 7, ScopeID: 1, MAC: "02:00:00:00:00:0b", IP: "192.168.1.20", Name: "nas", Origin: OriginIPAM, Ref: "u1"}, ""}},
			Excludes: []DHCPExclude{{ID: 1, ScopeID: 1, IP: "192.168.1.150", Origin: OriginIPAM, Ref: "u2"}}}}}
		var b bytes.Buffer
		if err := tpl.ExecuteTemplate(&b, "content", v); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	on := page(true)
	if !strings.Contains(on, `href="/ipam64/address?ip=192.168.1.20"`) || strings.Contains(on, "/dns64/dhcp/reservations/7/delete") || !strings.Contains(on, `id="dhcp-excludes"`) {
		t.Fatalf("ipam on:\n%s", on)
	}
	if off := page(false); !strings.Contains(off, "/dns64/dhcp/reservations/7/delete") || !strings.Contains(off, "IPAM64") {
		t.Fatalf("ipam off:\n%s", off)
	}
}
