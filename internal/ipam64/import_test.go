package ipam64

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/metrics"
)

// CSV-Import: Praefixe und Adressen, Semikolon und BOM, Ergaenzen vorhandener Eintraege, Fehler je Zeile.
func TestImport(t *testing.T) {
	m, _, _ := modTest(t)
	ctx := context.Background()
	f := newFake()
	m.SetDNS64(f.hooks())
	if _, err := m.ParseImport(ctx, []byte("foo,bar\n1,2\n")); !errors.Is(err, ErrImport) {
		t.Fatalf("no columns: %v", err)
	}
	rows, err := m.ParseImport(ctx, []byte("\xef\xbb\xbfPrefix;Name;VLAN;dns_zone;dynamic\n192.168.1.0/24;LAN;10;home.lan;\n2001:db8:1::/48;Provider;;;1\n10.0.0.0/7;zu gross;;;\n"))
	if err != nil || len(rows) != 3 || rows[0].Err != nil || rows[1].Prefix.DynSource != DynAuto || !errors.Is(rows[2].Err, ErrSize) {
		t.Fatalf("prefix rows: %+v %v", rows, err)
	}
	if n, failed := m.ApplyImport(ctx, rows, "t", func(e error) string { return e.Error() }); n != 2 || len(failed) != 0 {
		t.Fatalf("apply prefixes: %d %+v", n, failed)
	}
	if _, err := m.SaveAddress(ctx, Address{Address: "192.168.1.10", Name: "nas", Description: "bleibt"}, "t"); err != nil {
		t.Fatal(err)
	}
	csv := "ip,name,mac,dns,dhcp,tags,kind\n" +
		"192.168.1.10,,00:11:32:aa:10:10,1,1,backup,fixed\n" + // ergaenzt
		"192.168.1.20,drucker.home.lan,30:05:5c:20:20:20,1,,,\n" + // Zone der Praefix, nur Label
		"192.168.1.30,pi.other.lan,,1,,,\n" + // andere Zone
		"10.9.9.9,fremd,,,,,\n" + // kein Praefix
		"192.168.1.40,Bad_Name,,,,,\n"
	rows, err = m.ParseImport(ctx, []byte(csv))
	if err != nil || len(rows) != 5 {
		t.Fatalf("address rows: %+v %v", rows, err)
	}
	if r := rows[0]; r.Err != nil || !r.Exists || r.Address.Description != "bleibt" || !r.Address.DHCP || r.Address.Name != "nas" {
		t.Fatalf("existing: %+v", r)
	}
	if r := rows[1]; r.Err != nil || r.Address.Name != "drucker" || r.Address.DNSZone != "" {
		t.Fatalf("zone of prefix: %+v", r)
	}
	if r := rows[2]; r.Address.DNSZone != "other.lan" {
		t.Fatalf("other zone: %+v", r)
	}
	if !errors.Is(rows[3].Err, ErrNoNet) || !errors.Is(rows[4].Err, ErrHost) {
		t.Fatalf("errors: %v / %v", rows[3].Err, rows[4].Err)
	}
	n, failed := m.ApplyImport(ctx, rows, "t", func(e error) string { return e.Error() })
	if n != 3 || len(failed) != 0 {
		t.Fatalf("apply addresses: %d %+v", n, failed)
	}
	nas, _ := m.AddressByIP(ctx, "192.168.1.10")
	if nas == nil || f.res[nas.UID].MAC != "00:11:32:aa:10:10" || f.recs[nas.UID][0].Name != "nas.home.lan" {
		t.Fatalf("dns64: %+v %+v", f.res, f.recs)
	}
	// eigener Export laesst sich wieder einlesen (gleiche Spalten, Name aus Quellen)
	exp := "prefix,ip,name,note,mac,kind,status,role,tags,sources,last_seen,state\n192.168.1.0/24,192.168.1.10,nas,,00:11:32:aa:10:10,fixed,active,,backup,ipam,,unknown\n"
	if rows, err = m.ParseImport(ctx, []byte(exp)); err != nil || len(rows) != 1 || rows[0].Err != nil || !rows[0].Exists {
		t.Fatalf("export roundtrip: %+v %v", rows, err)
	}
}

func TestMetrics(t *testing.T) {
	m, _, _ := modTest(t)
	ctx := context.Background()
	mustPrefix(t, m, Prefix{Prefix: "192.168.1.0/24", Name: "LAN"})
	if _, err := m.SaveAddress(ctx, Address{Address: "192.168.1.10"}, "t"); err != nil {
		t.Fatal(err)
	}
	w := metrics.New()
	m.Metrics(ctx, w)
	var b bytes.Buffer
	if _, err := w.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"node64_ipam64_prefixes 1", `node64_ipam64_prefix_used{prefix="192.168.1.0/24",name="LAN"} 2`, "node64_ipam64_conflicts 0", "node64_ipam64_unknown_devices"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in\n%s", want, out)
		}
	}
}
