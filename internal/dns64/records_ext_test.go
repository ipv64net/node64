package dns64

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Weitere Typen werden geprueft, vereinheitlicht und richtig beantwortet.
func TestRecordTypes(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	add := func(r Record) Record {
		t.Helper()
		out, err := m.AddRecord(ctx, r)
		if err != nil {
			t.Fatalf("%+v: %v", r, err)
		}
		return out
	}
	if r := add(Record{Name: "home.lan", Type: "mx", Value: "mail.Home.lan."}); r.Value != "10 mail.home.lan" {
		t.Fatalf("mx = %q", r.Value)
	}
	if r := add(Record{Name: "_sip._tcp.home.lan", Type: "SRV", Value: "0 05 5060 sip.home.lan"}); r.Value != "0 5 5060 sip.home.lan" {
		t.Fatalf("srv = %q", r.Value)
	}
	if r := add(Record{Name: "home.lan", Type: "CAA", Value: `0 ISSUE "letsencrypt.org"`}); r.Value != "0 issue letsencrypt.org" {
		t.Fatalf("caa = %q", r.Value)
	}
	if r := add(Record{Name: "192.168.1.77", Type: "PTR", Value: "drucker.home.lan"}); r.Name != "77.1.168.192.in-addr.arpa" {
		t.Fatalf("ptr name = %q", r.Name)
	}
	long := strings.Repeat("x", 300)
	add(Record{Name: "home.lan", Type: "TXT", Value: long})

	for _, bad := range []Record{{Name: "home.lan", Type: "MX", Value: "x mail.home.lan"}, {Name: "a.lan", Type: "SRV", Value: "1 2 sip.lan"},
		{Name: "a.lan", Type: "CAA", Value: "0 foo bar"}, {Name: "a.lan", Type: "TXT", Value: "a\nb"}, {Name: "a.lan", Type: "A", Value: "1.2.3.4", Comment: strings.Repeat("c", 201)}} {
		if _, err := m.AddRecord(ctx, bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}

	rrs, ok := m.Lookup("home.lan", dns.TypeMX)
	if mx, _ := rrs[0].(*dns.MX); !ok || len(rrs) != 1 || mx.Preference != 10 || mx.Mx != "mail.home.lan." {
		t.Fatalf("mx answer = %v", rrs)
	}
	rrs, _ = m.Lookup("_sip._tcp.home.lan", dns.TypeSRV)
	if srv, _ := rrs[0].(*dns.SRV); len(rrs) != 1 || srv.Port != 5060 || srv.Weight != 5 {
		t.Fatalf("srv answer = %v", rrs)
	}
	rrs, _ = m.Lookup("home.lan", dns.TypeTXT)
	if txt, _ := rrs[0].(*dns.TXT); len(rrs) != 1 || len(txt.Txt) != 2 || len(txt.Txt[0]) != 255 {
		t.Fatalf("txt answer = %v", rrs)
	}
	rrs, _ = m.Lookup("home.lan", dns.TypeCAA)
	if caa, _ := rrs[0].(*dns.CAA); len(rrs) != 1 || caa.Tag != "issue" || caa.Value != "letsencrypt.org" {
		t.Fatalf("caa answer = %v", rrs)
	}
	rrs, _ = m.Lookup("77.1.168.192.in-addr.arpa", dns.TypePTR)
	if ptr, _ := rrs[0].(*dns.PTR); len(rrs) != 1 || ptr.Ptr != "drucker.home.lan." {
		t.Fatalf("ptr answer = %v", rrs)
	}
	if rrs, ok := m.Lookup("home.lan", dns.TypeA); !ok || len(rrs) != 0 {
		t.Fatalf("A for home.lan = %v %v, want NODATA", rrs, ok)
	}
}

// Bearbeiten aendert den Eintrag; ohne PTR entfaellt die Rueckwaertssuche.
func TestRecordUpdateNoPTR(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	a, err := m.AddRecord(ctx, Record{Name: "nas.home.lan", Type: "A", Value: "192.168.1.10"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.AddRecord(ctx, Record{Name: "alias.home.lan", Type: "A", Value: "192.168.1.11"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Lookup("10.1.168.192.in-addr.arpa", dns.TypePTR); !ok {
		t.Fatal("no ptr")
	}
	if _, err := m.UpdateRecord(ctx, a.ID, Record{Name: "nas.home.lan", Type: "A", Value: "192.168.1.10", NoPTR: true, Comment: " Keller "}); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Lookup("10.1.168.192.in-addr.arpa", dns.TypePTR); ok {
		t.Fatal("ptr despite no_ptr")
	}
	if _, err := m.UpdateRecord(ctx, b.ID, Record{Name: "nas.home.lan", Type: "A", Value: "192.168.1.10"}); err == nil {
		t.Fatal("duplicate accepted on update")
	}
	if _, err := m.UpdateRecord(ctx, 999, Record{Name: "x.lan", Type: "A", Value: "1.2.3.4"}); err != errNotFound {
		t.Fatalf("missing id: %v", err)
	}
	list, _ := m.Records(ctx)
	for _, r := range list {
		if r.ID == a.ID && (r.Comment != "Keller" || !r.NoPTR) {
			t.Fatalf("stored = %+v", r)
		}
	}
}

// Import erkennt Hosts-Datei, CSV und JSON; Export als Hosts-Datei fasst Namen je IP zusammen.
func TestRecordImportExport(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	res, err := m.ImportRecords(ctx, "\ufeff127.0.0.1 localhost\n::1 ip6-localhost\n0.0.0.0 werbung.example\n192.168.1.10\tnas nas.home.lan # NAS\nfd00::10 nas.home.lan\nkaputt\n")
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 3 || res.Invalid != 1 || res.Skipped != 3 {
		t.Fatalf("hosts import = %+v", res)
	}
	res, _ = m.ImportRecords(ctx, "name;type;value;ttl;comment\nmail.home.lan;A;192.168.1.20;600;Mail\nhome.lan;MX;10 mail.home.lan;;\nnas;A;192.168.1.10;;\nx.lan;A;nope;;\n")
	if res.Added != 2 || res.Skipped != 1 || res.Invalid != 1 {
		t.Fatalf("csv import = %+v", res)
	}
	res, _ = m.ImportRecords(ctx, `[{"name":"txt.home.lan","type":"TXT","value":"hallo","ttl":60}]`)
	if res.Added != 1 {
		t.Fatalf("json import = %+v", res)
	}
	list, _ := m.Records(ctx)
	body, _, ext := exportRecords(list, "hosts")
	if ext != "hosts" || !strings.Contains(string(body), "192.168.1.10\tnas nas.home.lan\n") || strings.Contains(string(body), "MX") {
		t.Fatalf("hosts export:\n%s", body)
	}
	csvBody, _, _ := exportRecords(list, "csv")
	again, _, bad := parseRecords(string(csvBody))
	if bad != 0 || len(again) != len(list) {
		t.Fatalf("csv round trip: %d of %d, bad %d", len(again), len(list), bad)
	}
}

// Grosser Import: in einer Transaktion (frueher je Eintrag neu geladen, bei tausenden quadratisch langsam).
func TestRecordImportLarge(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	var b strings.Builder
	for k := 0; k < 5000; k++ {
		fmt.Fprintf(&b, "10.100.%d.%d host%d.bulk.lan\n", k/250, k%250+1, k)
	}
	start := time.Now()
	res, err := m.ImportRecords(ctx, b.String()+"10.100.0.1 host0.bulk.lan\n")
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 5000 || res.Skipped != 1 {
		t.Fatalf("import = %+v", res)
	}
	if d := time.Since(start); d > 15*time.Second {
		t.Fatalf("import of 5000 took %s", d)
	}
	if rrs, ok := m.Lookup("host4999.bulk.lan", dns.TypeA); !ok || len(rrs) != 1 {
		t.Fatal("imported record not answered")
	}
}
