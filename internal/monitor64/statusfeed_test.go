package monitor64

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/monitor64/eval"
)

func TestStatusSourceParse(t *testing.T) {
	for _, c := range []struct {
		in, host, key string
		ok            bool
	}{
		{"m64:host:abc_-1", "abc_-1", "", true},
		{"m64:svc:abc/fs:/var/lib", "abc", "fs:/var/lib", true},
		{"m64:svc:abc/", "", "", false},
		{"m64:svc:abc", "", "", false},
		{"m64:host:", "", "", false},
		{"m64:host:a/b", "", "", false},
		{"m64:host:" + strings.Repeat("a", 65), "", "", false},
		{"m64:svc:abc/" + strings.Repeat("k", 201), "", "", false},
		{"tok_123", "", "", false},
	} {
		h, k, ok := parseStatusSource(c.in)
		if ok != c.ok || (ok && (h != c.host || k != c.key)) {
			t.Errorf("%q: %q %q %v", c.in, h, k, ok)
		}
	}
	if StatusSourceHost("H") != "m64:host:H" || StatusSourceService("H", "fs:/") != "m64:svc:H/fs:/" {
		t.Fatal("source")
	}
}

func TestStatusSpans(t *testing.T) {
	t0 := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	h := func(n int) time.Time { return t0.Add(time.Duration(n) * time.Hour) }
	u := spanUnion([]tspan{{h(5), h(7)}, {h(1), h(3)}, {h(2), h(4)}, {h(7), h(8)}, {h(9), h(9)}})
	if len(u) != 2 || !u[0].from.Equal(h(1)) || !u[0].to.Equal(h(4)) || !u[1].from.Equal(h(5)) || !u[1].to.Equal(h(8)) {
		t.Fatalf("union: %+v", u)
	}
	s := spanSubtract(u, []tspan{{h(0), h(2)}, {h(3), h(6)}, {h(7), h(10)}})
	if len(s) != 2 || !s[0].from.Equal(h(2)) || !s[0].to.Equal(h(3)) || !s[1].from.Equal(h(6)) || !s[1].to.Equal(h(7)) {
		t.Fatalf("subtract: %+v", s)
	}
	if d := spanOverlap(u, h(2), h(6)); d != 3*time.Hour {
		t.Fatalf("overlap: %v", d)
	}
}

func TestStatusWindowSpans(t *testing.T) {
	loc, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skip("no tzdata")
	}
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, loc) // Montag
	// jeden Tag 22:00-02:00 (ueber Mitternacht), ab gestern
	w := eval.Window{ID: "w", Reason: "Nacht", Start: now.Add(-30 * time.Hour), Recurring: &eval.Recurrence{From: eval.At(22, 0), To: eval.At(2, 0)}}
	spans := statusWindowSpans(w, now.Add(-48*time.Hour), now, loc)
	// erster Termin am 7.11. 22:00 liegt vor dem Beginn des Fensters (8.11. 06:00): nur der vom 8.11.
	if len(spans) != 1 || !spans[0].from.Equal(time.Date(2026, 11, 8, 22, 0, 0, 0, loc)) || !spans[0].to.Equal(time.Date(2026, 11, 9, 2, 0, 0, 0, loc)) {
		t.Fatalf("spans: %+v", spans)
	}
	sm, ok := statusMaintNext(w, now, now.Add(7*24*time.Hour), loc)
	if !ok || sm.Active || !sm.Start.Equal(time.Date(2026, 11, 9, 22, 0, 0, 0, loc)) || !sm.End.Equal(time.Date(2026, 11, 10, 2, 0, 0, 0, loc)) || sm.Title != "Nacht" || sm.ID != "w" {
		t.Fatalf("next: %+v %v", sm, ok)
	}
	// nur sonntags, ganzer Tag (gleiche Uhrzeit), wie eval.Window.Active
	sun := eval.Window{Recurring: &eval.Recurrence{Days: []time.Weekday{time.Sunday}, From: eval.At(0, 0), To: eval.At(0, 0)}, Hosts: []string{"h"}}
	spans = statusWindowSpans(sun, now.Add(-72*time.Hour), now, loc)
	if len(spans) != 1 || spans[0].to.Sub(spans[0].from) != 24*time.Hour || spans[0].from.Weekday() != time.Sunday {
		t.Fatalf("sunday: %+v", spans)
	}
	for at := now.Add(-72 * time.Hour); at.Before(now); at = at.Add(17 * time.Minute) {
		in := spanOverlap(spans, at, at.Add(time.Second)) > 0
		if in != sun.Active(at, eval.HostRef{ID: "h"}, loc) {
			t.Fatalf("mismatch with Active at %v", at)
		}
	}
	// jetzt laufend ohne Ende; vorbei; zu weit weg
	if sm, ok := statusMaintNext(eval.Window{Start: now.Add(-time.Hour)}, now, now.Add(time.Hour), loc); !ok || !sm.Active || !sm.End.IsZero() {
		t.Fatalf("open: %+v %v", sm, ok)
	}
	if _, ok := statusMaintNext(eval.Window{Start: now.Add(-2 * time.Hour), End: now.Add(-time.Hour)}, now, now.Add(time.Hour), loc); ok {
		t.Fatal("past window listed")
	}
	if _, ok := statusMaintNext(eval.Window{Start: now.Add(8 * 24 * time.Hour)}, now, now.Add(7*24*time.Hour), loc); ok {
		t.Fatal("far window listed")
	}
}

// statusTestHost legt einen Host an (angelegt um created).
func statusTestHost(t *testing.T, m *Module, name, group string, paused bool, created time.Time) *Host {
	t.Helper()
	ctx := context.Background()
	h := &Host{Name: name, Address: "10.9.8.7", Kind: "linux", Group: group, IntervalSec: 60, Paused: paused}
	if err := m.store.SaveHost(ctx, h, SystemActor); err != nil {
		t.Fatal(err)
	}
	if _, err := m.st.Writer().Exec(`UPDATE m64_hosts SET created_at = ? WHERE uid = ?`, ts(created), h.UID); err != nil {
		t.Fatal(err)
	}
	h, err := m.store.Host(ctx, h.UID)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

type statusTestEv struct {
	at    time.Time
	state string
}

// statusTestProblem legt ein Problem mit seinem Ablauf an (closed leer = offen).
func statusTestProblem(t *testing.T, m *Module, host, key string, closed time.Time, deleted bool, evs ...statusTestEv) {
	t.Helper()
	uid := newUID()
	state, worst := evs[len(evs)-1].state, "warn"
	for _, e := range evs {
		if stateRank[e.state] > stateRank[worst] {
			worst = e.state
		}
	}
	cl := ""
	if !closed.IsZero() {
		state, cl = "ok", ts(closed)
	}
	del := 0
	if deleted {
		del = 1
	}
	if _, err := m.st.Writer().Exec(`INSERT INTO m64_problems (uid, host_uid, service_key, state, worst, opened_at, closed_at, updated_at, deleted) VALUES (?,?,?,?,?,?,?,?,?)`,
		uid, host, key, state, worst, ts(evs[0].at), cl, tsNow(), del); err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		m.event(context.Background(), uid, host, key, e.state, "Wert 97 (Schwelle 90) 10.9.8.7", SystemActor, e.at)
	}
	if !closed.IsZero() {
		m.event(context.Background(), uid, host, key, "ok", "", SystemActor, closed)
	}
}

func TestStatusFeed(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newTestModule(t)
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	hr := func(n int) time.Time { return now.Add(time.Duration(n) * time.Hour) }
	h := statusTestHost(t, m, "nas01", "Keller", false, hr(-60))
	paused := statusTestHost(t, m, "alt", "", true, hr(-60))
	fresh := statusTestHost(t, m, "neu", "", false, hr(-1))
	other := statusTestHost(t, m, "fremd", "", false, hr(-60))
	if _, err := m.store.UpsertDiscovered(ctx, h.UID, []Service{{Key: "disk:sda", Name: "sda", Kind: "disk"}, {Key: "fs:/", Name: "/", Kind: "fs"},
		{Key: "ctr:web", Name: "web", Kind: "ctr"}, {Key: "access:x", Name: "Zugang", Kind: "access"}, {Key: "ign", Name: "Ignoriert", Kind: "x"}},
		map[string]bool{"disk:sda": true, "fs:/": true, "ctr:web": true, "access:x": true, "ign": true}, SystemActor); err != nil {
		t.Fatal(err)
	}
	if _, err := m.store.UpsertDiscovered(ctx, h.UID, []Service{{Key: "new:svc", Name: "Neu", Kind: "x"}}, nil, SystemActor); err != nil {
		t.Fatal(err)
	}
	if err := m.store.SetAdopted(ctx, h.UID, "ign", -1, SystemActor); err != nil {
		t.Fatal(err)
	}

	// Auswahl: Host, dann seine uebernommenen Dienste (ohne Zugaenge, neue und ignorierte), nach Name
	targets, err := m.StatusTargets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var mine []string
	for _, x := range targets {
		if x.Host == "nas01" {
			mine = append(mine, x.Source+"="+x.Name)
		}
	}
	if strings.Join(mine, ",") != "m64:host:"+h.UID+"=,m64:svc:"+h.UID+"/fs:/=/,m64:svc:"+h.UID+"/disk:sda=sda,m64:svc:"+h.UID+"/ctr:web=web" || len(targets) != 7 {
		t.Fatalf("targets: %v (%d)", mine, len(targets))
	}

	// Probleme: nicht erreichbar 50-49 h, sda kritisch 26-25 h, fs:/ offen seit 2 h (Warnung, seit 1 h kritisch);
	// geloeschte und fremde zaehlen nicht
	statusTestProblem(t, m, h.UID, "", hr(-49), false, statusTestEv{hr(-50), "unreachable"})
	statusTestProblem(t, m, h.UID, "disk:sda", hr(-25), false, statusTestEv{hr(-26), "crit"})
	statusTestProblem(t, m, h.UID, "fs:/", time.Time{}, false, statusTestEv{hr(-2), "warn"}, statusTestEv{hr(-1), "crit"})
	statusTestProblem(t, m, h.UID, "ctr:web", hr(-9), true, statusTestEv{hr(-10), "crit"})
	statusTestProblem(t, m, other.UID, "", hr(-29), false, statusTestEv{hr(-30), "unreachable"})

	// aktueller Stand: fs:/ kritisch, ein Dienst "nur anzeigen" mit Warnung zaehlt beim Host nicht
	m.rtMu.Lock()
	m.rts = map[string]*hostRT{}
	for _, x := range []*Host{h, paused, other} {
		rt := &hostRT{host: x}
		rt.setView(&HostView{Host: x, View: eval.ViewCrit, State: eval.Crit, Services: []SvcView{{Key: "fs:/", State: eval.Crit}, {Key: "disk:sda", State: eval.OK},
			{Key: "ctr:web", State: eval.Warn, ShowOnly: true}}})
		m.rts[x.UID] = rt
	}
	m.rtMu.Unlock()

	host, sda, fs, web := StatusSourceHost(h.UID), StatusSourceService(h.UID, "disk:sda"), StatusSourceService(h.UID, "fs:/"), StatusSourceService(h.UID, "ctr:web")
	q := module.StatusQuery{Sources: []string{host, sda, fs, web, host, StatusSourceHost(paused.UID), StatusSourceHost(fresh.UID), "m64:host:NOPE",
		StatusSourceService(h.UID, "new:svc"), StatusSourceService(h.UID, "ign"), StatusSourceService(h.UID, "access:x"), "tok_123"},
		Bounds: []time.Time{hr(-72), hr(-48), hr(-24), now}, History: hr(-72), Ahead: 7 * 24 * time.Hour, Now: now}
	res, err := m.StatusSources(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 6 || res[host] == nil || res[StatusSourceHost(fresh.UID)] == nil {
		t.Fatalf("sources: %d %v", len(res), res)
	}
	for src, want := range map[string]string{host: "crit", sda: "ok", fs: "crit", web: "warn", StatusSourceHost(paused.UID): "paused", StatusSourceHost(fresh.UID): "unknown"} {
		if res[src].State != want {
			t.Errorf("%s: state %s, want %s", src, res[src].State, want)
		}
	}
	if res[host].Name != "nas01" || res[host].Group != "Keller" || res[fs].Name != "nas01 – /" || !res[host].Since.Equal(hr(-2)) || !res[sda].Since.Equal(hr(-25)) {
		t.Fatalf("names/since: %+v %+v %+v", res[host], res[fs], res[sda])
	}
	bar := func(src string, i int) module.StatusBar { return res[src].Bars[i] }
	hb := time.Hour
	type exp struct{ obs, down, warn, maint time.Duration }
	check := func(src string, want []exp) {
		t.Helper()
		if len(res[src].Bars) != len(want) {
			t.Fatalf("%s: %d bars", src, len(res[src].Bars))
		}
		for i, w := range want {
			b := bar(src, i)
			if b.Observed != w.obs || b.Down != w.down || b.Warn != w.warn || b.Maint != w.maint {
				t.Errorf("%s bar %d: %+v, want %+v", src, i, b, w)
			}
		}
	}
	check(host, []exp{{12 * hb, hb, 0, 0}, {24 * hb, hb, 0, 0}, {24 * hb, hb, hb, 0}})
	check(sda, []exp{{12 * hb, hb, 0, 0}, {24 * hb, hb, 0, 0}, {24 * hb, 0, 0, 0}})
	check(fs, []exp{{12 * hb, hb, 0, 0}, {24 * hb, 0, 0, 0}, {24 * hb, hb, hb, 0}})
	check(StatusSourceHost(fresh.UID), []exp{{0, 0, 0, 0}, {0, 0, 0, 0}, {hb, 0, 0, 0}})
	inc := res[host].Incidents
	if len(inc) != 3 || !inc[0].End.IsZero() || !inc[0].Start.Equal(hr(-1)) || inc[0].Reason != "crit" || !inc[1].End.Equal(hr(-25)) ||
		inc[2].Reason != "unreachable" || !inc[2].Start.Equal(hr(-50)) {
		t.Fatalf("incidents: %+v", inc)
	}
	// oeffentlich nur Name, Zustand und Zeiten: keine Adresse, kein Text der Probleme
	b, _ := json.Marshal(res)
	for _, s := range []string{"10.9.8.7", "Schwelle", "Wert 97"} {
		if strings.Contains(string(b), s) {
			t.Fatalf("leaks %q: %s", s, b)
		}
	}

	// Wartung 26-24 h: die Stoerung von sda liegt darin und zaehlt nicht; laufende Wartung (seit 30 min, ohne Ende)
	// macht den Zustand "maintenance" und steht in der Liste
	targetsJSON := `{"hosts":["` + h.UID + `"]}`
	for _, w := range []struct {
		uid, title    string
		start, end    time.Time
		ended, recurs string
	}{
		{"mw1", "Umbau", hr(-26), hr(-24), "", ""},
		{"mw2", "Jetzt", now.Add(-30 * time.Minute), time.Time{}, "", ""},
		{"mw3", "Vorbei", hr(-5), hr(5), ts(hr(-4)), ""}, // vorzeitig beendet
	} {
		end := ""
		if !w.end.IsZero() {
			end = ts(w.end)
		}
		if _, err := m.st.Writer().Exec(`INSERT INTO m64_maint (uid, title, targets, start_at, end_at, recur, ended_at, updated_at) VALUES (?,?,?,?,?,?,?,?)`,
			w.uid, w.title, targetsJSON, ts(w.start), end, w.recurs, w.ended, tsNow()); err != nil {
			t.Fatal(err)
		}
	}
	m.reloadConfig(ctx)
	q.Sources = []string{host, sda}
	res, err = m.StatusSources(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if res[host].State != "maintenance" || len(res[host].Maintenance) != 1 || res[host].Maintenance[0].Title != "Jetzt" || !res[host].Maintenance[0].Active ||
		!res[host].Maintenance[0].End.IsZero() {
		t.Fatalf("maintenance: %s %+v", res[host].State, res[host].Maintenance)
	}
	// Balken 1: 2 h Wartung (26-24 h); Balken 2: 1 h (5-4 h) + 30 min, die Stoerung von fs:/ ab 1 h zaehlt nur bis zur Wartung
	check(sda, []exp{{12 * hb, hb, 0, 0}, {22 * hb, 0, 0, 2 * hb}, {24*hb - 90*time.Minute, 0, 0, 90 * time.Minute}})
	check(host, []exp{{12 * hb, hb, 0, 0}, {22 * hb, 0, 0, 2 * hb}, {24*hb - 90*time.Minute, 30 * time.Minute, hb, 90 * time.Minute}})
	if inc := res[host].Incidents; len(inc) != 2 || inc[0].End.IsZero() || !inc[0].End.Equal(now.Add(-30*time.Minute)) {
		t.Fatalf("incidents with maintenance: %+v", inc)
	}

	// ohne Balken und Historie: nur Zustand und Wartungen (keine Abfrage der Probleme noetig)
	res, err = m.StatusSources(ctx, module.StatusQuery{Sources: []string{host}, Now: now})
	if err != nil || len(res[host].Bars) != 0 || len(res[host].Incidents) != 0 || res[host].State != "maintenance" {
		t.Fatalf("plain: %v %+v", err, res[host])
	}
	// leere Anfrage
	if res, err := m.StatusSources(ctx, module.StatusQuery{}); err != nil || len(res) != 0 {
		t.Fatalf("empty: %v %v", err, res)
	}
}

// Tage mit Zeitumstellung: die Zeitraeume muessen genau dann gelten, wenn eval.Window.Active gilt (Wanduhr der Runden)
func TestStatusWindowSpansDST(t *testing.T) {
	loc, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skip("no tzdata")
	}
	rec := func(from, to eval.Clock, days ...time.Weekday) eval.Window {
		return eval.Window{Hosts: []string{"h"}, Recurring: &eval.Recurrence{Days: days, From: from, To: to}}
	}
	windows := []eval.Window{
		rec(eval.At(1, 0), eval.At(2, 30)),               // endet in der fehlenden Stunde (Maerz)
		rec(eval.At(2, 0), eval.At(3, 0)),                // die fehlende bzw. doppelte Stunde
		rec(eval.At(2, 30), eval.At(2, 45)),              // ganz in der Luecke
		rec(eval.At(22, 0), eval.At(2, 30)),              // ueber Mitternacht in die Umstellung
		rec(eval.At(0, 0), eval.At(0, 0), time.Sunday),   // ganzer Sonntag (23 bzw. 25 Stunden)
		rec(eval.At(1, 30), eval.At(1, 15), time.Sunday), // fast 24 Stunden ab Sonntag
	}
	for _, r := range [][2]time.Time{
		{time.Date(2026, 3, 27, 0, 0, 0, 0, loc), time.Date(2026, 4, 1, 0, 0, 0, 0, loc)},
		{time.Date(2026, 10, 23, 0, 0, 0, 0, loc), time.Date(2026, 10, 28, 0, 0, 0, 0, loc)},
	} {
		for wi, w := range windows {
			spans := statusWindowSpans(w, r[0], r[1], loc)
			for i := 1; i < len(spans); i++ {
				if spans[i].from.Before(spans[i-1].to) {
					t.Fatalf("window %d: overlapping/unsorted %+v", wi, spans)
				}
			}
			for at := r[0]; at.Before(r[1]); at = at.Add(time.Minute) {
				in := spanOverlap(spans, at, at.Add(time.Second)) > 0
				if in != w.Active(at, eval.HostRef{ID: "h"}, loc) {
					t.Fatalf("window %d: mismatch with Active at %v (in=%v)", wi, at, in)
				}
			}
		}
	}
	// Termin ueber die Tagesgrenze bleibt ein Stueck (naechster Termin in der Liste)
	w := windows[3]
	now := time.Date(2026, 3, 28, 12, 0, 0, 0, loc)
	sm, ok := statusMaintNext(w, now, now.Add(48*time.Hour), loc)
	if !ok || !sm.Start.Equal(time.Date(2026, 3, 28, 22, 0, 0, 0, loc)) || !sm.End.Equal(time.Date(2026, 3, 29, 1, 0, 0, 0, time.UTC)) {
		t.Fatalf("next over DST: %+v %v", sm, ok)
	}
}

// Zustand im Cluster: ohne Stand der zustaendigen Node ist der Eintrag unbekannt, auch wenn die Ansicht noch alte
// Dienste enthaelt; eine eigene Ansicht "unbekannt" zaehlt nach den Diensten ohne "nur anzeigen".
func TestStatusStateCluster(t *testing.T) {
	h := &Host{UID: "h1"}
	svcs := []SvcView{{Key: "fs:/", State: eval.OK}, {Key: "disk:sda", State: eval.OK}}
	for _, c := range []struct {
		name string
		v    *HostView
		key  string
		want string
	}{
		{"owner unreachable", &HostView{View: eval.ViewUnknown, State: eval.Unknown, Services: svcs, Cluster: &ClusterRef{Node: "n2", Note: noteOwnerUnreachable}}, "", module.StatusUnknown},
		{"owner unreachable svc", &HostView{View: eval.ViewUnknown, State: eval.Unknown, Services: svcs, Cluster: &ClusterRef{Node: "n2", Note: noteOwnerUnreachable}}, "fs:/", module.StatusUnknown},
		{"no data", &HostView{View: eval.ViewUnknown, State: eval.Unknown, Services: []SvcView{}, Cluster: &ClusterRef{Node: "n2", Note: noteNoData}}, "", module.StatusUnknown},
		{"empty unknown", &HostView{View: eval.ViewUnknown, State: eval.Unknown}, "", module.StatusUnknown},
		{"remote ok", &HostView{View: eval.ViewOK, State: eval.OK, Services: svcs, Cluster: &ClusterRef{Node: "n2", Reachable: true, Reporting: true}}, "", module.StatusOK},
		{"measure only", &HostView{View: eval.ViewWarn, State: eval.Warn, Services: []SvcView{{Key: "fs:/", State: eval.Warn}}, Cluster: &ClusterRef{Node: "n1", Here: true, Note: noteMeasureOnly}}, "", module.StatusWarn},
		{"show-only unknown", &HostView{View: eval.ViewUnknown, State: eval.Unknown, Services: append([]SvcView{{Key: "x", State: eval.Unknown, ShowOnly: true}}, svcs...)}, "", module.StatusOK},
	} {
		if got := statusStateOf(h, c.v, c.key, false); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}

	// ueber StatusSources: fremd ueberwachter Host, zustaendige Node nicht erreichbar (idleView)
	ctx := context.Background()
	m, _, _ := newTestModule(t)
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	x := statusTestHost(t, m, "fremd", "", false, now.Add(-48*time.Hour))
	if _, err := m.store.UpsertDiscovered(ctx, x.UID, []Service{{Key: "fs:/", Name: "/", Kind: "fs"}}, map[string]bool{"fs:/": true}, SystemActor); err != nil {
		t.Fatal(err)
	}
	statusTestProblem(t, m, x.UID, "fs:/", time.Time{}, false, statusTestEv{now.Add(-3 * time.Hour), "warn"})
	rt := &hostRT{host: x}
	rt.setView(&HostView{Host: x, View: eval.ViewUnknown, State: eval.Unknown, Services: []SvcView{{Key: "fs:/", State: eval.OK}},
		Cluster: &ClusterRef{Node: "n2", Note: noteOwnerUnreachable}})
	m.rtMu.Lock()
	m.rts = map[string]*hostRT{x.UID: rt}
	m.rtMu.Unlock()
	res, err := m.StatusSources(ctx, module.StatusQuery{Sources: []string{StatusSourceHost(x.UID), StatusSourceService(x.UID, "fs:/")},
		Bounds: []time.Time{now.Add(-24 * time.Hour), now}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	for src, s := range res {
		if s.State != module.StatusUnknown || !s.Since.IsZero() {
			t.Errorf("%s: %s since %v", src, s.State, s.Since)
		}
	}
	if len(res) != 2 {
		t.Fatalf("sources: %v", res)
	}
}

// Pausierte Zeit zaehlt weder als Stoerung noch als beobachtet (aktuelle Pause seit der letzten Aenderung bzw. dem
// Ereignis, fruehere aus den Ereignissen "pause"/"resume").
func TestStatusFeedPause(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newTestModule(t)
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	hr := func(n int) time.Time { return now.Add(time.Duration(n) * time.Hour) }
	p := statusTestHost(t, m, "pausiert", "", true, hr(-60))
	if _, err := m.st.Writer().Exec(`UPDATE m64_hosts SET updated_at = ? WHERE uid = ?`, ts(hr(-10)), p.UID); err != nil {
		t.Fatal(err)
	}
	statusTestProblem(t, m, p.UID, "", time.Time{}, false, statusTestEv{hr(-20), "crit"}) // offen, laeuft in die Pause
	e := statusTestHost(t, m, "frueher", "", false, hr(-60))
	statusTestProblem(t, m, e.UID, "", hr(-27), false, statusTestEv{hr(-31), "crit"})
	m.event(ctx, "", e.UID, "", "pause", "", SystemActor, hr(-30))
	m.event(ctx, "", e.UID, "", "resume", "", SystemActor, hr(-28))
	// aktuelle Pause mit Ereignis: gilt ab dem Ereignis (nicht ab der spaeteren Aenderung)
	ev := statusTestHost(t, m, "ereignis", "", true, hr(-60))
	if _, err := m.st.Writer().Exec(`UPDATE m64_hosts SET updated_at = ? WHERE uid = ?`, ts(hr(-2)), ev.UID); err != nil {
		t.Fatal(err)
	}
	statusTestProblem(t, m, ev.UID, "", time.Time{}, false, statusTestEv{hr(-8), "crit"})
	m.event(ctx, "", ev.UID, "", "pause", "", SystemActor, hr(-6))

	hp, he, hev := StatusSourceHost(p.UID), StatusSourceHost(e.UID), StatusSourceHost(ev.UID)
	res, err := m.StatusSources(ctx, module.StatusQuery{Sources: []string{hp, he, hev}, Bounds: []time.Time{hr(-48), hr(-24), now}, History: hr(-48), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	h := time.Hour
	type exp struct{ obs, down time.Duration }
	for src, want := range map[string][]exp{
		hp:  {{24 * h, 0}, {14 * h, 10 * h}},
		he:  {{22 * h, 2 * h}, {24 * h, 0}},
		hev: {{24 * h, 0}, {18 * h, 2 * h}},
	} {
		for i, w := range want {
			if b := res[src].Bars[i]; b.Observed != w.obs || b.Down != w.down || b.Maint != 0 {
				t.Errorf("%s bar %d: %+v, want %+v", src, i, b, w)
			}
		}
	}
	if inc := res[hp].Incidents; len(inc) != 1 || inc[0].End.IsZero() || !inc[0].End.Equal(hr(-10)) || res[hp].State != module.StatusPaused {
		t.Fatalf("paused incidents: %s %+v", res[hp].State, inc)
	}
	if inc := res[he].Incidents; len(inc) != 2 || !inc[0].Start.Equal(hr(-28)) || !inc[1].End.Equal(hr(-30)) {
		t.Fatalf("earlier pause incidents: %+v", inc)
	}
}

// Wiederkehrende Wartung ohne Beginn wirkt erst ab ihrer letzten Aenderung (nicht rueckwirkend).
func TestStatusFeedRecurringMaint(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newTestModule(t)
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	hr := func(n int) time.Time { return now.Add(time.Duration(n) * time.Hour) }
	x := statusTestHost(t, m, "nas", "", false, hr(-100))
	statusTestProblem(t, m, x.UID, "", hr(-49), false, statusTestEv{hr(-50), "crit"})
	rc, _ := json.Marshal(eval.Recurrence{From: eval.At(0, 0), To: eval.At(0, 0)}) // jeden Tag ganztags
	if _, err := m.st.Writer().Exec(`INSERT INTO m64_maint (uid, title, targets, start_at, end_at, recur, ended_at, updated_at) VALUES (?,?,?,?,?,?,?,?)`,
		"rw1", "Taeglich", `{"hosts":["`+x.UID+`"]}`, "", "", string(rc), "", ts(hr(-30))); err != nil {
		t.Fatal(err)
	}
	m.reloadConfig(ctx)
	src := StatusSourceHost(x.UID)
	res, err := m.StatusSources(ctx, module.StatusQuery{Sources: []string{src}, Bounds: []time.Time{hr(-72), hr(-48), hr(-24), now}, History: hr(-72), Ahead: time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	s := res[src]
	if b := s.Bars[0]; b.Down != time.Hour || b.Maint != 0 || b.Observed != 24*time.Hour {
		t.Fatalf("old outage hidden by recurring window: %+v", b)
	}
	if b := s.Bars[1]; b.Maint != 6*time.Hour || b.Observed != 18*time.Hour {
		t.Fatalf("bar 1: %+v", b)
	}
	if b := s.Bars[2]; b.Maint != 24*time.Hour || b.Observed != 0 {
		t.Fatalf("bar 2: %+v", b)
	}
	if len(s.Incidents) != 1 || s.State != module.StatusMaintenance || len(s.Maintenance) != 1 || !s.Maintenance[0].Active {
		t.Fatalf("incidents/maintenance: %s %+v %+v", s.State, s.Incidents, s.Maintenance)
	}
}

// Viele Probleme: die neuesten bleiben, die Grenze gilt je Host.
func TestStatusFeedProblemLimit(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newTestModule(t)
	oldTotal, oldHost := statusMaxProblems, statusMaxProblemsHost
	statusMaxProblems, statusMaxProblemsHost = 4, 2
	t.Cleanup(func() { statusMaxProblems, statusMaxProblemsHost = oldTotal, oldHost })
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	hr := func(n int) time.Time { return now.Add(time.Duration(n) * time.Hour) }
	a := statusTestHost(t, m, "a", "", false, hr(-100))
	b := statusTestHost(t, m, "b", "", false, hr(-100))
	for _, n := range []int{-40, -30, -20, -10} {
		statusTestProblem(t, m, a.UID, "", hr(n+1), false, statusTestEv{hr(n), "crit"})
	}
	for _, n := range []int{-45, -35} {
		statusTestProblem(t, m, b.UID, "", hr(n+1), false, statusTestEv{hr(n), "crit"})
	}
	sa, sb := StatusSourceHost(a.UID), StatusSourceHost(b.UID)
	res, err := m.StatusSources(ctx, module.StatusQuery{Sources: []string{sa, sb}, History: hr(-48), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if inc := res[sa].Incidents; len(inc) != 2 || !inc[0].Start.Equal(hr(-10)) || !inc[1].Start.Equal(hr(-20)) {
		t.Fatalf("a: newest problems missing: %+v", inc)
	}
	if inc := res[sb].Incidents; len(inc) != 2 {
		t.Fatalf("b: limit not per host: %+v", inc)
	}
}

// Nur die gefragten Hosts und Dienste werden geladen; Dienste, deren Schluessel die Statusseite nicht annimmt, werden
// nicht angeboten.
func TestStatusFeedLoadAndKeys(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newTestModule(t)
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	x := statusTestHost(t, m, "x", "", false, now.Add(-time.Hour))
	y := statusTestHost(t, m, "y", "", false, now.Add(-time.Hour))
	long := "fs:/" + strings.Repeat("ä", 99) // 202 Bytes, aber nur 103 Zeichen
	ctl := "fs:/a\x01b"
	keys := map[string]bool{"fs:/": true, "disk:sda": true, long: true, ctl: true}
	var list []Service
	for k := range keys {
		list = append(list, Service{Key: k, Name: k, Kind: "fs"})
	}
	for _, h := range []*Host{x, y} {
		if _, err := m.store.UpsertDiscovered(ctx, h.UID, list, keys, SystemActor); err != nil {
			t.Fatal(err)
		}
	}
	targets, err := m.StatusTargets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, tg := range targets {
		if _, _, ok := parseStatusSource(tg.Source); !ok || strings.Contains(tg.Source, "\x01") || strings.Contains(tg.Source, "ä") {
			t.Errorf("invalid target offered: %q", tg.Source)
		}
	}
	if len(targets) != 6 {
		t.Fatalf("targets: %d", len(targets))
	}
	if _, _, ok := parseStatusSource(StatusSourceService(x.UID, long)); ok {
		t.Fatal("long key accepted")
	}
	hosts, svcs, err := m.statusLoad(ctx, []string{x.UID, "NOPE"}, [][2]string{{x.UID, "fs:/"}, {x.UID, "none"}, {y.UID, "disk:sda"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[x.UID] == nil || hosts[x.UID].Name != "x" || len(svcs) != 2 || svcs[x.UID+"|fs:/"] == nil || svcs[y.UID+"|disk:sda"] == nil {
		t.Fatalf("load: %v %v", hosts, svcs)
	}
}
