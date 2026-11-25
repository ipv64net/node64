package monitor64

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/model"
)

// Issue #283: "In Ordnung, bis sich der Zustand aendert" am Dienst systemd merkt sich die fehlgeschlagenen Units.
// Faellt eine weitere aus, endet die Ausnahme und es wird gemeldet; faellt eine weg, gilt sie fuer die uebrigen
// (eine spaeter wieder fehlschlagende meldet); ohne fehlgeschlagene Unit endet sie wie bisher.
func TestAcceptSystemdItems283(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	sysd := func(units ...string) model.Service {
		s := model.Service{Key: "systemd", Name: "systemd", Kind: "systemd", Default: true,
			Metrics: []model.Metric{{Name: "failed", Value: float64(len(units))}}}
		if len(units) > 0 {
			s.Facts = []model.Fact{{Code: "systemd_failed", Text: strings.Join(units, ", "), Items: units}}
		}
		return s
	}
	fake := &fakeCol{svcs: []model.Service{sysd("smbftpd.service", "foo.service")}}
	rt := hostWithFake(t, e.m, fake)
	uid := rt.host.UID
	hostRule := func() string {
		return e.col(`SELECT host_rule FROM m64_services WHERE host_uid = ? AND key = 'systemd'`, uid)
	}
	view := func() SvcView {
		t.Helper()
		for _, s := range e.m.viewOf(uid).Services {
			if s.Key == "systemd" {
				return s
			}
		}
		t.Fatal("Dienst systemd fehlt")
		return SvcView{}
	}
	firing := func() bool { return slices.Contains(view().Firing, eval.KindSystemdFailed) }
	accepted := func() bool { return slices.Contains(view().Accepted, eval.KindSystemdFailed) }

	e.m.poll(ctx, rt)
	adoptAll(t, e.m, uid)
	e.m.poll(ctx, rt)
	if !firing() {
		t.Fatalf("meldet nicht: %+v", view())
	}
	if c := e.do("PUT", "/api/monitor64/hosts/"+uid+"/service", map[string]any{"key": "systemd", "accept": map[string]any{"kind": eval.KindSystemdFailed, "mode": "change"}}).Code; c != 200 {
		t.Fatalf("accept: %d", c)
	}
	if hr := hostRule(); !strings.Contains(hr, `"accepted_items":["foo.service","smbftpd.service"]`) {
		t.Fatalf("Menge nicht gespeichert: %q", hr)
	}
	e.m.poll(ctx, rt)
	if firing() || !accepted() {
		t.Fatalf("bestaetigt, meldet aber: %+v", view())
	}
	// eine Unit faellt weg: Ausnahme bleibt fuer die uebrige
	fake.set([]model.Service{sysd("smbftpd.service")}, nil)
	e.m.poll(ctx, rt)
	if firing() || !accepted() || !strings.Contains(hostRule(), `"accepted_items":["smbftpd.service"]`) {
		t.Fatalf("weggefallene Unit: %+v, %q", view(), hostRule())
	}
	// die weggefallene schlaegt wieder fehl: nicht mehr in der Menge, meldet
	fake.set([]model.Service{sysd("smbftpd.service", "foo.service")}, nil)
	e.m.poll(ctx, rt)
	if !firing() || accepted() || strings.Contains(hostRule(), "accepted") {
		t.Fatalf("neue Unit meldet nicht: %+v, %q", view(), hostRule())
	}

	// erneut bestaetigen, dann alle wieder in Ordnung: Ausnahme endet wie bisher
	if c := e.do("PUT", "/api/monitor64/hosts/"+uid+"/service", map[string]any{"key": "systemd", "accept": map[string]any{"kind": eval.KindSystemdFailed, "mode": "change"}}).Code; c != 200 {
		t.Fatalf("accept: %d", c)
	}
	e.m.poll(ctx, rt)
	if firing() || !accepted() {
		t.Fatalf("bestaetigt, meldet aber: %+v", view())
	}
	fake.set([]model.Service{sysd()}, nil)
	e.m.poll(ctx, rt)
	if strings.Contains(hostRule(), "accepted") {
		t.Fatalf("Bedingung entfallen, Bestaetigung bleibt: %q", hostRule())
	}
}

// Bestehende Bestaetigung ohne gespeicherte Menge (vor #283): verhaelt sich wie bisher - eine weitere fehlgeschlagene
// Unit beendet sie nicht.
func TestAcceptSystemdWithoutItemsUnchanged283(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	sysd := func(units ...string) model.Service {
		return model.Service{Key: "systemd", Name: "systemd", Kind: "systemd", Default: true,
			Facts: []model.Fact{{Code: "systemd_failed", Text: strings.Join(units, ", "), Items: units}}}
	}
	fake := &fakeCol{svcs: []model.Service{sysd("smbftpd.service")}}
	rt := hostWithFake(t, e.m, fake)
	uid := rt.host.UID
	e.m.poll(ctx, rt)
	adoptAll(t, e.m, uid)
	if _, err := e.m.st.Writer().Exec(`UPDATE m64_services SET host_rule = ? WHERE host_uid = ? AND key = 'systemd'`,
		`{"`+eval.KindSystemdFailed+`":{"accepted":true}}`, uid); err != nil {
		t.Fatal(err)
	}
	fake.set([]model.Service{sysd("smbftpd.service", "foo.service")}, nil)
	e.m.poll(ctx, rt)
	for _, s := range e.m.viewOf(uid).Services {
		if s.Key == "systemd" && (slices.Contains(s.Firing, eval.KindSystemdFailed) || !slices.Contains(s.Accepted, eval.KindSystemdFailed)) {
			t.Fatalf("alte Bestaetigung geaendert: %+v", s)
		}
	}
	if hr := e.col(`SELECT host_rule FROM m64_services WHERE host_uid = ? AND key = 'systemd'`, uid); !strings.Contains(hr, "accepted") {
		t.Fatalf("Bestaetigung entfernt: %q", hr)
	}
}

func TestAcceptedItemsLeft(t *testing.T) {
	acc := []string{"a.service", "b.service"}
	for _, c := range []struct {
		acc  *[]string
		cur  []string
		rest []string
		more bool
	}{
		{&acc, []string{"b.service", "a.service"}, nil, false},
		{&acc, []string{"a.service"}, []string{"a.service"}, false},
		{&acc, []string{"a.service", "c.service"}, nil, true},
		{&acc, nil, nil, false}, // ohne Elemente (Sammler liefert keine): wie bisher
		{nil, []string{"c.service"}, nil, false},
	} {
		rest, more := acceptedItemsLeft(c.acc, c.cur)
		if more != c.more || !slices.Equal(rest, c.rest) {
			t.Errorf("%v %v: %v %v", c.acc, c.cur, rest, more)
		}
	}
}

// Mapper: die Facts tragen die vollstaendige Liste (Text nur die ersten 5).
func TestFactItemsFullList283(t *testing.T) {
	var units []string
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		units = append(units, n+".service")
	}
	for _, s := range MapReport(nil, &m64proto.Report{Systemd: &m64proto.Systemd{Failed: units}}) {
		if s.Key == "systemd" {
			if len(s.Facts) != 1 || !slices.Equal(s.Facts[0].Items, units) {
				t.Fatalf("Facts %+v", s.Facts)
			}
			return
		}
	}
	t.Fatal("Dienst systemd fehlt")
}
