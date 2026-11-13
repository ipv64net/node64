package healthchecks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/scheduler"
)

// fakeM64 bildet Monitor64 nach (module.StatusFeed): je Quelle ein fester Stand, die Balken passend zur Anfrage
// (voll beobachtet, im letzten Balken lastDown gestoert bzw. lastWarn eingeschraenkt).
type fakeM64 struct {
	mu      sync.Mutex
	targets []module.StatusTarget
	srcs    map[string]fakeM64Src
	queries []module.StatusQuery
	err     error
}

type fakeM64Src struct {
	module.StatusSource
	lastDown, lastWarn time.Duration
}

func (f *fakeM64) StatusTargets(context.Context) ([]module.StatusTarget, error) {
	return f.targets, nil
}

func (f *fakeM64) StatusSources(_ context.Context, q module.StatusQuery) (map[string]*module.StatusSource, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, q)
	if f.err != nil {
		return nil, f.err
	}
	out := map[string]*module.StatusSource{}
	for _, s := range q.Sources {
		src, ok := f.srcs[s]
		if !ok {
			continue
		}
		c := src.StatusSource
		c.Bars = nil
		for i := 0; i+1 < len(q.Bounds); i++ {
			b := module.StatusBar{Observed: q.Bounds[i+1].Sub(q.Bounds[i])}
			if i+2 == len(q.Bounds) {
				b.Down, b.Warn = src.lastDown, src.lastWarn
			}
			c.Bars = append(c.Bars, b)
		}
		out[s] = &c
	}
	return out, nil
}

func (f *fakeM64) lastQuery() module.StatusQuery {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.queries) == 0 {
		return module.StatusQuery{}
	}
	return f.queries[len(f.queries)-1]
}

// m64Fake: Monitor64 mit Hosts in allen Zustaenden; die Quellen enthalten Kennungen und Dienstnamen, die nie
// oeffentlich werden duerfen (ausser als Bezeichnung).
func m64Fake(now time.Time) *fakeM64 {
	src := func(name, group, state string) module.StatusSource {
		return module.StatusSource{Name: name, Group: group, State: state, Incidents: []module.StatusIncident{}, Maintenance: []module.StatusMaint{}}
	}
	w1 := module.StatusMaint{ID: "w1", Title: "Umbau", Start: now.Add(-time.Hour), Active: true} // bis beendet
	nas := src("nas01", "GruppeKeller", module.StatusOK)
	nas.Maintenance = []module.StatusMaint{{ID: "w2", Title: "Update", Start: now.Add(24 * time.Hour), End: now.Add(26 * time.Hour)}}
	router := src("router", "GruppeNetz", module.StatusUnreachable)
	router.Incidents = []module.StatusIncident{{Start: now.Add(-20 * time.Minute), Reason: "unreachable"},
		{Start: now.Add(-50 * time.Hour), End: now.Add(-49 * time.Hour), Reason: "crit"}}
	svc := src("nas01 – postgres-geheim", "GruppeKeller", module.StatusWarn)
	maint := src("lager", "GruppeKeller", module.StatusMaintenance)
	maint.Maintenance = []module.StatusMaint{w1}
	nas.Maintenance = append(nas.Maintenance, w1)
	return &fakeM64{
		targets: []module.StatusTarget{{Source: "m64:host:HOSTUID1", Host: "nas01", Group: "GruppeKeller", Tags: []string{"m64tag", "storage"}},
			{Source: "m64:svc:HOSTUID1/postgres-geheim", Host: "nas01", Name: "postgres-geheim", Group: "GruppeKeller", Tags: []string{"m64tag", "storage"}},
			{Source: "m64:host:HOSTUID2", Host: "router", Group: "GruppeNetz"}},
		srcs: map[string]fakeM64Src{
			"m64:host:HOSTUID1":                {StatusSource: nas},
			"m64:host:HOSTUID2":                {StatusSource: router, lastDown: 20 * time.Minute},
			"m64:svc:HOSTUID1/postgres-geheim": {StatusSource: svc, lastWarn: 30 * time.Minute},
			"m64:host:HOSTUID3":                {StatusSource: maint},
			"m64:host:HOSTUID4":                {StatusSource: src("pausiert", "", module.StatusPaused)},
			"m64:host:HOSTUID5":                {StatusSource: src("neu", "", module.StatusUnknown)},
			"m64:host:HOSTUID6":                {StatusSource: src("kritisch", "", module.StatusCrit)},
		},
	}
}

func TestStatusM64Source(t *testing.T) {
	for tok, ok := range map[string]bool{
		"m64:host:Ab_-09":                     true,
		"m64:svc:Ab09/fs:/var/lib":            true,
		"m64:svc:Ab09/disk:sda":               true,
		"m64:host:":                           false,
		"m64:host:a/b":                        false,
		"m64:svc:Ab09":                        false,
		"m64:svc:Ab09/":                       false,
		"m64:svc:/fs":                         false,
		"m64:foo:x":                           false,
		"m64:svc:Ab09/a\nb":                   false,
		"m64:host:" + strings.Repeat("a", 65): false,
		// Laenge des Schluessels in Bytes (wie Monitor64), nicht in Zeichen
		"m64:svc:Ab09/" + strings.Repeat("k", 200): true,
		"m64:svc:Ab09/" + strings.Repeat("k", 201): false,
		"m64:svc:Ab09/" + strings.Repeat("ä", 100): true,
		"m64:svc:Ab09/" + strings.Repeat("ä", 101): false,
		"m64:svc:Ab09/a\x7fb":                      false,
	} {
		if validM64Source(tok) != ok {
			t.Errorf("%q: want %v", tok, ok)
		}
		p := &StatusPage{Slug: "s1", Title: "T", Groups: []StatusGroup{{Items: []StatusItem{{Token: tok}}}}}
		if err := p.normalize(); (err == nil) != ok {
			t.Errorf("normalize %q: %v", tok, err)
		}
	}
	if statusM64HostUID("m64:svc:H1/fs:/x") != "H1" || statusM64HostUID("m64:host:H2") != "H2" {
		t.Fatal("host uid")
	}
	for in, want := range map[string]string{"ok": "up", "warn": "degraded", "crit": "down", "unreachable": "down", "unknown": "unknown",
		"maintenance": "maintenance", "paused": "paused", "": "unknown", "boom": "unknown"} {
		if got := statusM64State(in); got != want {
			t.Errorf("state %q: %q, want %q", in, got, want)
		}
	}
	// Balken: Wartung ab der Haelfte, eingeschraenkt macht gelb, 15 min gestoert rot, nichts beobachtet grau
	h := time.Hour
	for _, c := range []struct {
		b    module.StatusBar
		want string
	}{
		{module.StatusBar{Observed: h}, "up"},
		{module.StatusBar{Observed: h, Warn: time.Minute}, "partial"},
		{module.StatusBar{Observed: h, Down: 2 * time.Minute}, "partial"},
		{module.StatusBar{Observed: h, Down: 5 * time.Minute}, "down"}, // unter 95 %
		{module.StatusBar{Observed: h, Down: 15 * time.Minute}, "down"},
		{module.StatusBar{Observed: h / 2, Maint: h / 2}, "maintenance"},
		{module.StatusBar{Maint: h}, "maintenance"},
		{module.StatusBar{}, "none"},
	} {
		if got := statusM64Bar("x", c.b, h); got.State != c.want {
			t.Errorf("bar %+v: %s, want %s", c.b, got.State, c.want)
		}
	}
	if a := statusM64Agg(module.StatusBar{Observed: time.Minute, Down: time.Hour}); a.count != 60 || a.up != 0 {
		t.Fatalf("agg: %+v", a)
	}
}

func TestStatusM64View(t *testing.T) {
	m, _ := newStatusModule(t)
	now := statusFixNow(t, m)
	up := statusAddCheck(t, m, "Webseite", scheduler.Runtime{State: scheduler.StateUp, Since: now.Add(-time.Hour), LastCheck: now.Add(-30 * time.Second)})
	p := &StatusPage{Slug: "mix", Title: "Mix", Days: 7, ShowUptime: true, ShowHistory: true, HCGroups: true, Groups: []StatusGroup{{Items: []StatusItem{
		{Token: up.Token}, {Token: "m64:host:HOSTUID1"}, {Token: "m64:svc:HOSTUID1/postgres-geheim", Label: "Datenbank"}, {Token: "m64:host:HOSTUID2"},
		{Token: "m64:host:HOSTUID3", Label: "Lager"}, {Token: "m64:host:HOSTUID4"}, {Token: "m64:host:HOSTUID5"}, {Token: "m64:host:HOSTUID6"},
		{Token: "m64:host:GONE"},
	}}}}
	p = statusSavePage(t, m, p, "")

	// ohne Monitor64 (nicht registriert bzw. aus): Eintraege fallen weg, die Seite laeuft
	for _, fn := range []func() module.StatusFeed{nil, func() module.StatusFeed { return nil }} {
		if fn != nil {
			m.SetMonitor64Status(fn)
		}
		v, err := m.buildStatusView(context.Background(), p, "de")
		if err != nil || len(v.Groups) != 1 || len(v.Groups[0].Items) != 1 || v.Groups[0].Items[0].Label != "Webseite" || v.Overall != "up" {
			t.Fatalf("without monitor64: %v %+v", err, v)
		}
	}
	// Fehler in Monitor64: ebenso
	f := m64Fake(now)
	f.err = errors.New("db locked")
	m.SetMonitor64Status(func() module.StatusFeed { return f })
	if v, err := m.buildStatusView(context.Background(), p, "de"); err != nil || len(v.Groups) != 1 {
		t.Fatalf("monitor64 error: %v %+v", err, v)
	}
	f.err = nil

	v, err := m.buildStatusView(context.Background(), p, "de")
	if err != nil {
		t.Fatal(err)
	}
	q := f.lastQuery()
	if len(q.Sources) != 8 || len(q.Bounds) != 8 || !q.Bounds[7].Equal(now) || q.History.IsZero() || q.Ahead != statusMaintAhead {
		t.Fatalf("query: %+v", q)
	}
	got := map[string]StatusViewItem{}
	groupOf := map[string]string{}
	for _, g := range v.Groups {
		for _, it := range g.Items {
			got[it.Label] = it
			groupOf[it.Label] = g.Name
		}
	}
	for label, state := range map[string]string{"Webseite": "up", "nas01": "up", "Datenbank": "degraded", "router": "down", "Lager": "maintenance",
		"pausiert": "paused", "neu": "unknown", "kritisch": "down"} {
		if got[label].State != state {
			t.Errorf("%s: state %q, want %q", label, got[label].State, state)
		}
	}
	if len(got) != 8 || v.Overall != "down" {
		t.Fatalf("items: %d overall %s", len(got), v.Overall)
	}
	if groupOf["nas01"] != "GruppeKeller" || groupOf["Datenbank"] != "GruppeKeller" || groupOf["router"] != "GruppeNetz" || groupOf["Webseite"] != "" {
		t.Fatalf("groups: %+v", groupOf)
	}
	// eigener Abschnitt: erst die Healthchecks, dann die Monitor64-Systeme (mit ihren Gruppen)
	if v.Groups[0].Section != "" || v.Groups[0].Items[0].Label != "Webseite" {
		t.Fatalf("healthchecks first: %+v", v.Groups[0])
	}
	for _, g := range v.Groups[1:] {
		if g.Section != "systems" {
			t.Fatalf("monitor64 section: %+v", g)
		}
	}
	sp := stBuildPage(v, statusRenderOpts{T: func(k string, _ ...any) string { return k }})
	if sp.Groups[0].Section != "hc.status.pub.section_checks" || sp.Groups[1].Section != "hc.status.pub.section_systems" || sp.Groups[2].Section != "" {
		t.Fatalf("section titles: %q %q %q", sp.Groups[0].Section, sp.Groups[1].Section, sp.Groups[2].Section)
	}
	// Balken: 7 Tage, heute beim Router rot (20 min), beim Dienst gelb, sonst gruen; Verfuegbarkeit aus den Zeiten
	r, db, nas := got["router"], got["Datenbank"], got["nas01"]
	if len(r.Bars) != 7 || r.Bars[6].State != "down" || r.Bars[6].DownMins != 20 || r.Bars[5].State != "up" || db.Bars[6].State != "partial" ||
		nas.Uptime != 100 || r.Uptime >= 100 || r.Uptime < 99 || r.Bars[6].Day != "2026-10-20" {
		t.Fatalf("bars: router %+v db %+v nas %v", r.Bars, db.Bars[6], nas.Uptime)
	}
	// Wartungen: Fenster w1 einmal mit beiden Eintraegen, ohne Ende; w2 geplant
	var w1, w2 *StatusViewMaint
	for i := range v.Maintenance {
		switch v.Maintenance[i].Title {
		case "Umbau":
			w1 = &v.Maintenance[i]
		case "Update":
			w2 = &v.Maintenance[i]
		}
	}
	if w1 == nil || !w1.Active || !w1.End.IsZero() || strings.Join(w1.Items, ",") != "nas01,Lager" || w2 == nil || w2.Active || w2.End.IsZero() || len(v.Maintenance) != 2 {
		t.Fatalf("maintenance: %+v", v.Maintenance)
	}
	// Stoerungen mit Anzeigename, laufende ohne Ende; aelter als 30 Tage faellt weg (hier keine)
	var rInc []StatusViewIncid
	for _, i := range v.Incidents {
		if i.Item == "router" {
			rInc = append(rInc, i)
		}
	}
	if len(rInc) != 2 || !rInc[0].End.IsZero() || rInc[1].End.IsZero() || rInc[0].Reason == "" {
		t.Fatalf("incidents: %+v", v.Incidents)
	}
	// ohne Verfuegbarkeit und Verlauf: keine Prozente, keine Stoerungen, Abfrage ohne Historie
	p.ShowUptime, p.ShowHistory = false, false
	v, _ = m.buildStatusView(context.Background(), p, "de")
	if q := f.lastQuery(); !q.History.IsZero() || len(v.Incidents) != 0 || v.Groups[0].Items[0].Uptime != -1 {
		t.Fatalf("no history: %+v %+v", q, v.Incidents)
	}
	for _, g := range v.Groups {
		for _, it := range g.Items {
			for _, b := range it.Bars {
				if b.Uptime != -1 {
					t.Fatalf("uptime shown: %+v", it)
				}
			}
		}
	}
	// 24 Stunden: Stundenbalken
	p.Days = 1
	v, _ = m.buildStatusView(context.Background(), p, "de")
	if q := f.lastQuery(); len(q.Bounds) != 25 || v.BarUnit != "hour" || len(v.Groups[0].Items[0].Bars) != 24 {
		t.Fatalf("hourly: %d %s", len(q.Bounds), v.BarUnit)
	}
}

// Oeffentliche Ausgabe (HTML, status.json, Feed, Details, Badges): nur Bezeichnung und Zustand, nie Quelle, Kennung
// oder Dienstname.
func TestStatusM64Public(t *testing.T) {
	m, srv := newStatusModule(t)
	now := time.Now()
	f := m64Fake(now)
	m.SetMonitor64Status(func() module.StatusFeed { return f })
	statusSavePage(t, m, &StatusPage{Slug: "m64", Title: "Status", Enabled: true, PublishNode: true, ShowUptime: true, ShowHistory: true, Days: 30,
		Groups: []StatusGroup{{Items: []StatusItem{{Token: "m64:host:HOSTUID1", Label: "Speicher"}, {Token: "m64:svc:HOSTUID1/postgres-geheim", Label: "Datenbank"},
			{Token: "m64:host:HOSTUID2", Label: "Internet"}}}}}, "")
	base := srv.URL + "/status/m64"
	hidden := []string{"m64:", "HOSTUID", "postgres-geheim", "nas01", "router", "GruppeKeller", "GruppeNetz"}
	code, _, body := statusGet(t, base+"/status.json")
	if code != 200 {
		t.Fatalf("status.json: %d %s", code, body)
	}
	var v StatusView
	if err := json.Unmarshal([]byte(body), &v); err != nil || len(v.Groups) != 1 || len(v.Groups[0].Items) != 3 || v.Overall != "down" {
		t.Fatalf("view: %v %s", err, body)
	}
	var svcID int64
	for _, it := range v.Groups[0].Items {
		if it.Label == "Datenbank" {
			svcID = it.ID
		}
	}
	pages := map[string]string{"status.json": body}
	for _, u := range []string{"", "/feed.atom", "/badge.svg", "/badge/" + strconv.FormatInt(svcID, 10) + "?type=uptime", "/item/" + strconv.FormatInt(svcID, 10)} {
		code, _, b := statusGet(t, base+u)
		if code != 200 {
			t.Fatalf("%s: %d %s", u, code, b)
		}
		pages[u] = b
	}
	for u, b := range pages {
		for _, s := range hidden {
			if strings.Contains(b, s) {
				t.Errorf("%q leaks %q", u, s)
			}
		}
	}
	// laufende Wartung ohne Ende: kein "bis"
	if html := pages[""]; !strings.Contains(html, "hc.status.pub.maint.active") || strings.Contains(html, "hc.status.pub.maint.until") {
		t.Fatalf("maintenance html: %s", html)
	}
	if strings.Count(pages["/feed.atom"], "<entry") != 2 { // Stoerungen des Routers (Text ohne Uebersetzer nur Schluessel)
		t.Fatalf("feed without incident: %s", pages["/feed.atom"])
	}
	var d StatusItemDetail
	if err := json.Unmarshal([]byte(pages["/item/"+strconv.FormatInt(svcID, 10)]), &d); err != nil || d.State != "degraded" || len(d.Hours) != 24 ||
		d.Latency != -1 || d.Uptime30d != 100 || d.Hours[23].State != "partial" || d.Label != "Datenbank" {
		t.Fatalf("detail: %v %+v", err, d)
	}
	// Details fragen 30 Tage, 7 Tage, 24 Stunden und die Stundenbalken in einem Rutsch ab
	if q := f.lastQuery(); len(q.Bounds) != 28 || len(q.Sources) != 1 || q.History.IsZero() {
		t.Fatalf("detail query: %d %v", len(q.Bounds), q.Sources)
	}
	// Monitor64 aus: Details des Eintrags 404, Seite ohne die Eintraege
	m.SetMonitor64Status(func() module.StatusFeed { return nil })
	m.statusFlush()
	if code, _, _ := statusGet(t, base+"/item/"+strconv.FormatInt(svcID, 10)); code != 404 {
		t.Fatalf("detail without monitor64: %d", code)
	}
	if code, _, b := statusGet(t, base+"/status.json"); code != 200 || !strings.Contains(b, `"groups":[]`) {
		t.Fatalf("page without monitor64: %d %s", code, b)
	}
}

func TestStatusM64Editor(t *testing.T) {
	e := newSPEnv(t)
	ctx := t.Context()
	f := m64Fake(time.Now())
	feedOn := true
	var mu sync.Mutex
	e.m.SetMonitor64Status(func() module.StatusFeed {
		mu.Lock()
		defer mu.Unlock()
		if !feedOn {
			return nil
		}
		return f
	})
	chk := e.check("Alpha", "Web")
	if w := e.do("GET", "/healthchecks/status-pages/new", nil, ""); w.Code != 200 {
		t.Fatalf("new: %d", w.Code)
	}
	d := e.formData()
	var m64 []statusCheckOpt
	for _, c := range d.Checks {
		if c.M64 {
			m64 = append(m64, c)
		}
	}
	if !d.M64On || d.M64Off || len(m64) != 3 || m64[0].Value != "m64:host:HOSTUID1" || m64[1].Name != "postgres-geheim" || m64[1].Sub != "nas01" ||
		m64[0].Group != statusM64Group || !containsStr(d.HCGroups, statusM64Group) || d.Checks[0].Token != chk {
		t.Fatalf("form: %+v", d)
	}
	// Tags der Monitor64-Hosts stehen im Filter und am Eintrag (#102)
	if !containsStr(d.Tags, "m64tag") || !containsStr(d.Tags, "storage") || m64[0].Tags != "m64tag,storage" || m64[2].Tags != "" {
		t.Fatalf("tags: %v %+v", d.Tags, m64)
	}
	// hinzufuegen: bekannte Eintraege, unbekannte fallen weg, nichts doppelt
	v := baseForm(&StatusPage{Title: "Mit Monitor64"})
	v.Set("op", "add")
	v["add_m64"] = []string{"m64:svc:HOSTUID1/postgres-geheim", "m64:host:UNBEKANNT", "m64:host:HOSTUID2"}
	v["add_tok"] = []string{chk}
	e.form("/healthchecks/status-pages/new", v)
	d = e.formData()
	if len(d.PageList) != 3 || d.PageList[0].Token != chk || d.PageList[1].Token != "m64:svc:HOSTUID1/postgres-geheim" || !d.PageList[1].M64 ||
		d.PageList[1].Name != "nas01 – postgres-geheim" || d.PageList[1].Group != "GruppeKeller" || d.PageList[1].Link != "/monitor64/host/HOSTUID1" || d.PageList[2].Name != "router" {
		t.Fatalf("add: %+v", d.PageList)
	}
	v = baseForm(d.Page)
	v.Set("op", "add")
	v["add_m64"] = []string{"m64:host:HOSTUID2"}
	e.form("/healthchecks/status-pages/new", v)
	if d = e.formData(); len(d.PageList) != 3 {
		t.Fatalf("add twice: %+v", d.PageList)
	}
	// speichern: Quellen stehen am Eintrag
	v = baseForm(d.Page)
	if w := e.form("/healthchecks/status-pages/new", v); w.Code != 303 {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	list, _ := e.m.st.StatusPages(ctx)
	p, _ := e.m.st.StatusPage(ctx, list[0].ID)
	if len(p.Groups[0].Items) != 3 || p.Groups[0].Items[2].Token != "m64:host:HOSTUID2" {
		t.Fatalf("saved: %+v", p.Groups)
	}
	edit := "/healthchecks/status-pages/" + strconv.FormatInt(p.ID, 10) + "/edit"
	// API: Monitor64-Eintraege anhaengen; unbekannt bzw. Monitor64 aus = 422
	id := strconv.FormatInt(p.ID, 10)
	if code, body := e.api("POST", "/api/status-pages/"+id+"/items", map[string]any{"tokens": []string{"m64:host:HOSTUID1"}}); code != 200 ||
		!strings.Contains(string(body), `"token":"m64:host:HOSTUID1"`) {
		t.Fatalf("api add: %d %s", code, body)
	}
	if code, body := e.api("POST", "/api/status-pages/"+id+"/items", map[string]any{"tokens": []string{"m64:host:NOPE"}}); code != 422 {
		t.Fatalf("api unknown: %d %s", code, body)
	}

	// Monitor64 aus: Hinweis, Eintraege bleiben beim Speichern erhalten
	mu.Lock()
	feedOn = false
	mu.Unlock()
	if code, _ := e.api("POST", "/api/status-pages/"+id+"/items", map[string]any{"tokens": []string{"m64:host:HOSTUID1"}}); code != 422 {
		t.Fatalf("api off: %d", code)
	}
	e.do("GET", edit, nil, "")
	d = e.formData()
	if d.M64On || !d.M64Off || len(d.PageList) != 4 || d.PageList[1].Name != "" || !d.PageList[1].M64 {
		t.Fatalf("off: %+v", d)
	}
	for _, c := range d.Checks {
		if c.M64 {
			t.Fatalf("monitor64 offered while off: %+v", c)
		}
	}
	p, _ = e.m.st.StatusPage(ctx, p.ID)
	if w := e.form(edit, baseForm(p)); w.Code != 303 {
		t.Fatalf("save off: %d", w.Code)
	}
	if p2, _ := e.m.st.StatusPage(ctx, p.ID); len(p2.Groups[0].Items) != 4 {
		t.Fatalf("items lost while off: %+v", p2.Groups)
	}
	// API: ungueltige Quelle 422
	if code, body := e.api("PUT", "/api/status-pages/"+id, map[string]any{"groups": []map[string]any{{"items": []map[string]any{{"token": "m64:svc:x"}}}}}); code != 422 {
		t.Fatalf("api bad source: %d %s", code, body)
	}
}

// Formular mit Monitor64-Eintraegen (an und aus) laesst sich ausfuehren.
func TestStatusM64FormTemplate(t *testing.T) {
	funcs := template.FuncMap{"add": func(a, b int) int { return a + b }, "split": strings.Fields}
	p := &StatusPage{ID: 3, Slug: "s", Title: "T", Layout: "list", Theme: "auto", Days: 90, RefreshSec: 60,
		Groups: []StatusGroup{{Items: []StatusItem{{Token: "m64:host:H1"}, {Token: "m64:host:H9"}}}}}
	for _, on := range []bool{true, false} {
		d := statusFormData{Page: p, Edit: true, M64On: on, M64Off: !on, Items: 2, Layouts: []string{"list"}, Themes: []string{"auto"}, DaysOpts: []int{90},
			PageList: []statusPageItem{{Token: "m64:host:H1", M64: true, Link: "/monitor64/host/H1"}, {Token: "m64:host:H9", M64: true, Link: "/monitor64/host/H9"}}}
		if on {
			d.PageList[0].Name = "nas01"
			d.Checks = []statusCheckOpt{{M64: true, Value: "m64:host:H1", Name: "nas01", Group: statusM64Group, Type: "hc.status.m64_host", OnPage: true},
				{M64: true, Value: "m64:svc:H1/fs:/", Name: "fs:/", Sub: "nas01", Group: statusM64Group, Type: "hc.status.m64_service"}}
		}
		tpl := template.Must(template.New("root").Funcs(funcs).Parse(`{{template "content" .}}`))
		template.Must(tpl.ParseFS(templateFS, "templates/pages/status_page_form.html"))
		var buf bytes.Buffer
		if err := tpl.Execute(&buf, fakeView{Data: d, CSRF: "c"}); err != nil {
			t.Fatal(err)
		}
		out := buf.String()
		if on && (!strings.Contains(out, `name="add_m64" value="m64:svc:H1/fs:/"`) || !strings.Contains(out, `href="/monitor64/host/H1"`) ||
			!strings.Contains(out, "hc.status.m64_gone") || !strings.Contains(out, "hc.status.m64_hint") || strings.Contains(out, "hc.status.m64_off") ||
			!strings.Contains(out, "Monitor64 · nas01")) {
			t.Fatalf("on: %s", out)
		}
		if !on && (!strings.Contains(out, "hc.status.m64_off") || !strings.Contains(out, "hc.status.m64_hidden") || strings.Contains(out, "add_m64") ||
			!strings.Contains(out, `name="it_tok" value="m64:host:H9"`)) {
			t.Fatalf("off: %s", out)
		}
	}
}

// Cluster: Monitor64-Eintraege gehen mit der Seite mit; eine Node ohne Monitor64 (bzw. ohne den Host) zeigt sie nicht,
// behaelt sie aber, sodass sie bei einer Aenderung dort nicht verloren gehen.
func TestStatusM64Cluster(t *testing.T) {
	ctx := context.Background()
	a, _ := newTestModule(t)
	b, _ := newTestModule(t)
	var la, lb hcLog
	a.SetCluster(ClusterHooks{Change: la.hook})
	b.SetCluster(ClusterHooks{Change: lb.hook})
	f := m64Fake(time.Now())
	a.SetMonitor64Status(func() module.StatusFeed { return f })
	var fbMu sync.Mutex
	var fb module.StatusFeed = &fakeM64{} // Monitor64 laeuft, kennt den Host aber nicht (kein Bereich Monitor64)
	b.SetMonitor64Status(func() module.StatusFeed { fbMu.Lock(); defer fbMu.Unlock(); return fb })

	p := &StatusPage{Slug: "c1", Title: "Cluster", Enabled: true, Groups: []StatusGroup{{Items: []StatusItem{{Token: "m64:host:HOSTUID1", Label: "NAS"}}}}}
	if err := a.st.SaveStatusPage(ctx, p, ""); err != nil {
		t.Fatal(err)
	}
	hcTransfer(t, a, b, la.take())
	pb, err := b.st.StatusPageBySlug(ctx, "c1")
	if err != nil || len(pb.Groups) != 1 || len(pb.Groups[0].Items) != 1 || pb.Groups[0].Items[0].Token != "m64:host:HOSTUID1" {
		t.Fatalf("on B: %+v %v", pb, err)
	}
	if v, err := b.buildStatusView(ctx, pb, "de"); err != nil || len(v.Groups) != 0 || v.Overall != "unknown" {
		t.Fatalf("view on B: %v %+v", err, v)
	}
	if v, err := a.buildStatusView(ctx, p, "de"); err != nil || len(v.Groups) != 1 || v.Groups[0].Items[0].Label != "NAS" {
		t.Fatalf("view on A: %v %+v", err, v)
	}
	// Phase 4: Monitor64 gleicht die Hosts ab, B kennt den Host auch. Ueberwacht ihn A und ist A fuer B nicht
	// erreichbar, liefert Monitor64 auf B "unbekannt" (nicht den letzten Stand) - die Seite zeigt den Eintrag so an.
	fbMu.Lock()
	fb = &fakeM64{srcs: map[string]fakeM64Src{"m64:host:HOSTUID1": {StatusSource: module.StatusSource{Name: "nas01", State: module.StatusUnknown,
		Incidents: []module.StatusIncident{}, Maintenance: []module.StatusMaint{}}}}}
	fbMu.Unlock()
	if v, err := b.buildStatusView(ctx, pb, "de"); err != nil || len(v.Groups) != 1 || len(v.Groups[0].Items) != 1 || v.Groups[0].Items[0].Label != "NAS" ||
		v.Groups[0].Items[0].State != "unknown" || v.Overall != "unknown" {
		t.Fatalf("view on B (cluster, owner unreachable): %v %+v", err, v)
	}
	// Aenderung auf B kommt mit dem Eintrag zurueck
	pb.Title = "Neu"
	if err := b.st.SaveStatusPage(ctx, pb, ""); err != nil {
		t.Fatal(err)
	}
	hcTransfer(t, b, a, lb.take())
	if pa, _ := a.st.StatusPage(ctx, p.ID); pa.Title != "Neu" || len(pa.Groups[0].Items) != 1 || pa.Groups[0].Items[0].Token != "m64:host:HOSTUID1" {
		t.Fatalf("back on A: %+v", pa)
	}
}
