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
	h := &Host{Names: []string{"cloud.example.de", "Alt.example.de", "*.wild.example.de"}}
	if _, _, err := m.addLocal(context.Background(), h, "192.168.1.5", ""); err == nil {
		t.Fatal("DNS64 aus: Fehler erwartet")
	}
	f := &fakeLocal{recs: []LocalRecord{{Name: "alt.example.de", Type: "CNAME", Value: "x.example.de"}, {Name: "cloud.example.de", Type: "AAAA", Value: "fd00::1"}}}
	m.SetLocalDNS(func() LocalDNS { return f })
	var fe *FieldError
	if _, _, err := m.addLocal(context.Background(), h, "", " "); !errors.As(err, &fe) {
		t.Fatalf("ohne Adresse: %v", err)
	}
	if _, _, err := m.addLocal(context.Background(), h, "fe80::1%eth0", ""); !errors.As(err, &fe) {
		t.Fatalf("Zone: %v", err)
	}
	added, skipped, err := m.addLocal(context.Background(), h, "192.168.1.5", "[fd00::5]")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"cloud.example.de A 192.168.1.5", "*.wild.example.de A 192.168.1.5", "*.wild.example.de AAAA fd00::5"}
	if added != 3 || len(f.added) != 3 || f.added[0] != want[0] || f.added[1] != want[1] || f.added[2] != want[2] {
		t.Fatalf("angelegt %d %v", added, f.added)
	}
	if len(skipped) != 3 { // cloud AAAA vorhanden, alt CNAME (A und AAAA)
		t.Fatalf("uebersprungen %v", skipped)
	}
	if n := localCount(m.localIndex(context.Background()), h.Names); n != 3 {
		t.Fatalf("localCount %d", n)
	}
	// zweiter Klick: nichts Neues
	if added, _, _ := m.addLocal(context.Background(), h, "192.168.1.5", ""); added != 0 {
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
