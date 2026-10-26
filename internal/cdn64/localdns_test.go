package cdn64

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeLocal struct {
	recs  []LocalRecord
	added []string
}

func (f *fakeLocal) Records(context.Context) ([]LocalRecord, error) { return f.recs, nil }

func (f *fakeLocal) Add(_ context.Context, r LocalRecord, comment string) error {
	if comment != "PROXY64" {
		return errors.New("comment")
	}
	f.recs = append(f.recs, r)
	f.added = append(f.added, r.Name+" "+r.Type+" "+r.Value)
	return nil
}

func TestAddLocal(t *testing.T) {
	m := &Module{}
	h := &Host{Names: []string{"cloud.example.de", "Alt.example.de", "*.wild.example.de", "example.de", "nas.example.de", "box.lan"}}
	ctx := context.Background()
	if _, _, _, err := m.addLocal(ctx, h, "192.168.1.5", ""); err == nil {
		t.Fatal("DNS64 aus: Fehler erwartet")
	}
	f := &fakeLocal{recs: []LocalRecord{{Name: "alt.example.de", Type: "CNAME", Value: "x.example.de", Enabled: true}, {Name: "cloud.example.de", Type: "AAAA", Value: "fd00::1", Enabled: true},
		{Name: "nas.example.de", Type: "A", Value: "10.0.0.9"}, {Name: "nas.example.de", Type: "AAAA", Value: "fd00::5"}}} // nas: ausgeschaltet
	m.SetLocalDNS(func() LocalDNS { return f })
	var fe *FieldError
	for _, bad := range [][2]string{{"", " "}, {"fe80::1%eth0", ""}, {"", "192.168.1.6"}, {"fd00::5", ""}, {"", "fe80::1"}, {"127.0.0.1", ""}, {"0.0.0.0", ""}, {"", "::ffff:192.168.1.5"}} {
		if _, _, _, err := m.addLocal(ctx, h, bad[0], bad[1]); !errors.As(err, &fe) {
			t.Fatalf("%v: %v", bad, err)
		}
	}
	added, skipped, excluded, err := m.addLocal(ctx, h, "192.168.1.5", "[fd00::5]")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"cloud.example.de A 192.168.1.5", "nas.example.de A 192.168.1.5", "box.lan A 192.168.1.5", "box.lan AAAA fd00::5"}
	if added != 4 || strings.Join(f.added, "|") != strings.Join(want, "|") {
		t.Fatalf("angelegt %d %v", added, f.added)
	}
	if len(skipped) != 4 { // cloud AAAA vorhanden, alt CNAME (A und AAAA), nas AAAA genau so schon da (aus)
		t.Fatalf("uebersprungen %v", skipped)
	}
	if strings.Join(excluded, ",") != "*.wild.example.de,example.de" {
		t.Fatalf("ausgelassen %v", excluded)
	}
	if n := localCount(m.localIndex(ctx), h.Names); n != 2 { // ausgeschaltete zaehlen nicht (die neuen sind im Fake aus)
		t.Fatalf("localCount aus %d", n)
	}
	for i := range f.recs[4:] {
		f.recs[4+i].Enabled = true
	}
	if n := localCount(m.localIndex(ctx), h.Names); n != 4 { // cloud, alt, nas, box.lan
		t.Fatalf("localCount %d", n)
	}
	// zweiter Klick: nichts Neues
	if added, _, _, _ := m.addLocal(ctx, h, "192.168.1.5", ""); added != 0 {
		t.Fatalf("doppelt angelegt: %d", added)
	}
}

func TestLocalDNSRender(t *testing.T) {
	row := hostRow{Host: &Host{ID: 7, Kind: KindProxy, Names: []string{"a.example.de", "b.example.de"}, Enabled: true}, LocalN: 2}
	body := renderHosts(t, listData{Kind: KindProxy, Rows: []hostRow{row}, OnlineOn: true, LocalOn: true, LocalV4: "192.168.1.5"})
	for _, want := range []string{`id="cdn64-localdns"`, `data-ldns-id="7"`, `data-ldns-names="a.example.de, b.example.de"`, `bi-house-check-fill`,
		`value="192.168.1.5"`, `data-online-pick="1"`, `data-online-pick="2"`, `cdn64.online.ex3_art`, `https://ipv64.net/cdn64`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
	row.LocalN = 0
	body = renderHosts(t, listData{Kind: KindProxy, Rows: []hostRow{row}})
	if strings.Contains(body, "cdn64-localdns") || strings.Contains(body, "data-ldns-id") {
		t.Error("DNS64 aus: kein Knopf und kein Fenster")
	}
}
