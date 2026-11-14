package healthchecks

import (
	"bytes"
	"context"
	"encoding/json"
	"html/template"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/scheduler"
)

// #131: Eintraege frei sortieren, Ueberschriften und Trenner als eigene Eintraege.

func statusViewSummary(v *StatusView) string {
	var got []string
	for _, g := range v.Groups {
		var names []string
		for _, it := range g.Items {
			names = append(names, it.Label)
		}
		s := g.Name + ":" + strings.Join(names, ",")
		if g.Divider {
			s = "--" + s
		}
		if g.Section != "" {
			s = g.Section + "/" + s
		}
		got = append(got, s)
	}
	return strings.Join(got, " | ")
}

func TestStatusOrderedView(t *testing.T) {
	m, _ := newStatusModule(t)
	ctx := context.Background()
	now := time.Now()
	f := m64Fake(now)
	m.SetMonitor64Status(func() module.StatusFeed { return f })
	up := scheduler.Runtime{State: scheduler.StateUp, LastCheck: now}
	down := up
	down.State = scheduler.StateDown
	a := statusAddCheck(t, m, "alpha", up)
	b := statusAddCheck(t, m, "beta", down)
	c := statusAddCheck(t, m, "gamma", up)

	// ohne Gliederung wie bisher: Abschnitte (Dienste vor Systemen), Reihenfolge der Seite je Abschnitt
	p := statusSavePage(t, m, &StatusPage{Slug: "ordnung", Title: "O", Enabled: true, Groups: []StatusGroup{{Items: []StatusItem{
		{Token: "m64:host:HOSTUID2"}, {Token: c.Token}, {Token: a.Token}, {Token: "m64:host:HOSTUID1"}}}}}, "")
	v, err := m.statusView(ctx, p, "de")
	if err != nil {
		t.Fatal(err)
	}
	if got := statusViewSummary(v); v.Ordered || got != ":gamma,alpha | systems/:router,nas01" {
		t.Fatalf("auto: %s", got)
	}

	// mit Gliederung: genau die Reihenfolge der Seite, Ueberschriften als Gruppen, Trenner als Linie; ein Trenner vor
	// einer leeren Gruppe gilt fuer die naechste, eine Ueberschrift ohne (vorhandene) Eintraege faellt weg
	p.Groups = []StatusGroup{{Items: []StatusItem{
		{Token: "m64:host:HOSTUID2"}, {Token: c.Token},
		{Kind: "heading", Label: "  Host  "}, {Token: "m64:host:HOSTUID1"}, {Token: b.Token, Label: "Beta"},
		{Kind: "divider", Label: "weg"}, {Token: statusHeadingTok, Label: "Leer"}, {Token: "nicht-da"},
		{Token: statusDividerTok}, {Token: a.Token}, {Token: "@spaeter"}}}}
	p = statusSavePage(t, m, p, "")
	if it := p.Groups[0].Items[2]; it.Token != statusHeadingTok || it.Kind != "heading" || it.Label != "Host" {
		t.Fatalf("heading saved: %+v", it)
	}
	if it := p.Groups[0].Items[5]; it.Token != statusDividerTok || it.Kind != "divider" || it.Label != "" {
		t.Fatalf("divider saved: %+v", it)
	}
	m.statusFlush()
	v, err = m.statusView(ctx, p, "de")
	if err != nil {
		t.Fatal(err)
	}
	if got := statusViewSummary(v); !v.Ordered || got != ":router,gamma | Host:nas01,Beta | --:alpha" {
		t.Fatalf("ordered: %s", got)
	}
	// Ueberschriften haben keine Details
	if _, err := m.statusItemDetail(ctx, p, p.Groups[0].Items[2].ID, "de"); err == nil {
		t.Fatal("detail of a heading")
	}
	// Ueberschrift ohne Text: Fehler
	p.Groups[0].Items = append(p.Groups[0].Items, StatusItem{Kind: "heading"})
	if err := m.st.SaveStatusPage(ctx, p, ""); err == nil || !strings.Contains(err.Error(), "hc.status.err.heading") {
		t.Fatalf("empty heading: %v", err)
	}
	p.Groups[0].Items[len(p.Groups[0].Items)-1] = StatusItem{Kind: "bogus", Token: a.Token}
	if err := m.st.SaveStatusPage(ctx, p, ""); err == nil {
		t.Fatal("unknown kind accepted")
	}

	// oeffentliche Seite: Trennlinie, Ueberschrift, keine Sortierung nach Zustand (beta ist gestoert, bleibt hinter nas01)
	h := stRender(t, v, statusRenderOpts{Lang: "de"})
	if !strings.Contains(h, `<hr class="dv">`) || !strings.Contains(h, `<span class="gn">Host</span>`) || strings.Contains(h, `<h2 class="sec">`) {
		t.Fatalf("html: %s", h)
	}
	if i, j := strings.Index(h, `"lb">nas01<`), strings.Index(h, `"lb">Beta<`); i < 0 || j < 0 || i > j {
		t.Fatalf("order in html: nas01 %d, Beta %d", i, j)
	}
	if strings.Count(h, "<summary>") != 1 {
		t.Fatalf("headings: %d", strings.Count(h, "<summary>"))
	}
	// ohne Gliederung bleibt "Probleme zuerst"
	v.Ordered = false
	h = stRender(t, v, statusRenderOpts{Lang: "de"})
	if i, j := strings.Index(h, `"lb">nas01<`), strings.Index(h, `"lb">Beta<`); i < j {
		t.Fatal("auto mode: problems no longer first")
	}
}

func TestStatusOrderEditor(t *testing.T) {
	e := newSPEnv(t)
	f := m64Fake(time.Now())
	e.m.SetMonitor64Status(func() module.StatusFeed { return f })
	a, b := e.check("Alpha", "Web"), e.check("Beta", "Web")
	page := &StatusPage{Title: "Sortiert", Groups: []StatusGroup{{Items: []StatusItem{{Token: a}, {Token: b}, {Token: "m64:host:HOSTUID1"}, {Token: "m64:host:HOSTUID2"}}}}}
	post := func(p *StatusPage, op string, extra ...string) statusFormData {
		t.Helper()
		v := baseForm(p)
		v.Set("op", op)
		for i := 0; i+1 < len(extra); i += 2 {
			v.Set(extra[i], extra[i+1])
		}
		e.form("/healthchecks/status-pages/new", v)
		return e.formData()
	}
	toks := func(d statusFormData) string {
		var out []string
		for _, it := range d.PageList {
			s := it.Token
			if it.Kind != "" {
				s = it.Kind + "=" + it.Label
			}
			out = append(out, s)
		}
		return strings.Join(out, ",")
	}
	// ohne Gliederung: verschieben nur innerhalb des Abschnitts (Pfeile an der Grenze aus)
	d := post(page, "dn-0")
	if got := toks(d); d.Ordered || got != b+","+a+",m64:host:HOSTUID1,m64:host:HOSTUID2" {
		t.Fatalf("down: %s", got)
	}
	if l := d.PageList; l[0].Up || !l[0].Down || l[1].Down || l[2].Up || !l[2].Down || l[3].Down || l[0].Part != "c" || l[2].Part != "s" {
		t.Fatalf("arrows: %+v", l)
	}
	d = post(d.Page, "up-3")
	if got := toks(d); got != b+","+a+",m64:host:HOSTUID2,m64:host:HOSTUID1" {
		t.Fatalf("up: %s", got)
	}
	// Ueberschrift vor einem Eintrag, Trenner am Ende; ab dann ohne Abschnitte, alles verschiebbar
	d = post(d.Page, "add-heading", "new_heading", " Systeme ", "new_at", "2")
	if got := toks(d); !d.Ordered || got != b+","+a+",heading=Systeme,m64:host:HOSTUID2,m64:host:HOSTUID1" || d.Items != 4 {
		t.Fatalf("heading: %s (%d)", got, d.Items)
	}
	for _, it := range d.PageList {
		if it.Sec != "" || it.Part != "a" {
			t.Fatalf("ordered list with sections: %+v", it)
		}
	}
	if l := d.PageList; l[0].Up || !l[1].Down || !l[2].Up || l[4].Down {
		t.Fatalf("ordered arrows: %+v", l)
	}
	d = post(d.Page, "add-divider", "new_at", "end")
	d = post(d.Page, "up-3")
	if got := toks(d); got != b+","+a+",m64:host:HOSTUID2,heading=Systeme,m64:host:HOSTUID1,divider=" {
		t.Fatalf("divider/move: %s", got)
	}
	// Ueberschrift ohne Text: Hinweis am Feld, nichts eingefuegt
	d = post(d.Page, "add-heading", "new_heading", "  ")
	if d.Errors["groups"] == "" || len(d.PageList) != 6 {
		t.Fatalf("empty heading: %+v %d", d.Errors, len(d.PageList))
	}
	// entfernen zaehlt weiter nach der Position
	d = post(d.Page, "rm-5")
	if got := toks(d); strings.Contains(got, "divider") {
		t.Fatalf("rm: %s", got)
	}
	// speichern und wieder oeffnen: Reihenfolge und Gliederung bleiben
	if w := e.form("/healthchecks/status-pages/new", baseForm(d.Page)); w.Code != 303 {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	list, _ := e.m.st.StatusPages(t.Context())
	e.do("GET", "/healthchecks/status-pages/"+strconv.FormatInt(list[0].ID, 10)+"/edit", nil, "")
	if got := toks(e.formData()); got != b+","+a+",m64:host:HOSTUID2,heading=Systeme,m64:host:HOSTUID1" {
		t.Fatalf("reload: %s", got)
	}
	// Liste der Seiten zaehlt nur Eintraege
	items, _ := e.m.statusCounts(t.Context())
	if items[list[0].ID] != 4 {
		t.Fatalf("count: %d", items[list[0].ID])
	}
	// API: kind statt Token, Ausgabe mit kind
	id := strconv.FormatInt(list[0].ID, 10)
	code, body := e.api("PUT", "/api/status-pages/"+id, map[string]any{"groups": []map[string]any{{"items": []map[string]any{
		{"kind": "heading", "label": "Web"}, {"token": a}, {"kind": "divider"}, {"token": b}}}}})
	if code != 200 {
		t.Fatalf("api: %d %s", code, body)
	}
	var out StatusPage
	_ = json.Unmarshal(body, &out)
	if it := out.Groups[0].Items; len(it) != 4 || it[0].Token != statusHeadingTok || it[0].Kind != "heading" || it[2].Kind != "divider" || it[1].Kind != "" {
		t.Fatalf("api out: %s", body)
	}
	// Formular mit Gliederung laesst sich ausfuehren (Template)
	e.do("GET", "/healthchecks/status-pages/"+id+"/edit", nil, "")
	statusRenderFormTemplate(t, e.formData())
}

// Migration 0023: Reihenfolge wie bisher angezeigt (Healthchecks vor Monitor64, fruehere Gruppen nacheinander), alles in
// der ersten Gruppe.
func TestStatusOrderMigration(t *testing.T) {
	m, _ := newStatusModule(t)
	ctx := context.Background()
	up := scheduler.Runtime{State: scheduler.StateUp, LastCheck: time.Now()}
	c1, c2 := statusAddCheck(t, m, "eins", up), statusAddCheck(t, m, "zwei", up)
	p := statusSavePage(t, m, &StatusPage{Slug: "alt", Title: "Alt", Groups: []StatusGroup{
		{Name: "G1", Items: []StatusItem{{Token: "m64:host:HOSTUID1"}, {Token: c1.Token}}},
		{Name: "G2", Items: []StatusItem{{Token: c2.Token}, {Token: "m64:host:HOSTUID2"}}}}}, "")
	other := statusSavePage(t, m, &StatusPage{Slug: "andere", Title: "Andere", Groups: []StatusGroup{
		{Items: []StatusItem{{Token: "m64:host:HOSTUID3"}, {Token: c2.Token}}}}}, "")
	b, err := migrationFS.ReadFile("migrations/0023_status_order.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.st.w.ExecContext(ctx, string(b)); err != nil {
		t.Fatal(err)
	}
	got := func(id int64) string {
		p, err := m.st.StatusPage(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, g := range p.Groups {
			for _, it := range g.Items {
				out = append(out, g.Name+":"+it.Token)
			}
		}
		return strings.Join(out, ",")
	}
	if s := got(p.ID); s != "G1:"+c1.Token+",G1:"+c2.Token+",G1:m64:host:HOSTUID1,G1:m64:host:HOSTUID2" {
		t.Fatalf("migrated: %s", s)
	}
	if s := got(other.ID); s != ":"+c2.Token+",:m64:host:HOSTUID3" {
		t.Fatalf("other page: %s", s)
	}
}

// statusRenderFormTemplate fuehrt das Formular mit den Daten aus und prueft die Gliederung.
func statusRenderFormTemplate(t *testing.T, d statusFormData) {
	t.Helper()
	d.Layouts, d.Themes, d.DaysOpts = []string{"list"}, []string{"auto"}, []int{90}
	funcs := template.FuncMap{"add": func(a, b int) int { return a + b }, "split": strings.Fields}
	tpl := template.Must(template.New("root").Funcs(funcs).Parse(`{{template "content" .}}`))
	template.Must(tpl.ParseFS(templateFS, "templates/pages/status_page_form.html"))
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, fakeView{Data: d, CSRF: "c"}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{`name="it_tok" value="@heading"`, `name="it_lbl" value="Web"`, `name="it_tok" value="@divider"`, `value="up-1"`, `value="dn-2"`,
		`value="add-heading"`, `value="add-divider"`, `name="new_at"`, "hc.status.at_before", "data-sp-handle", "hc.status.order_hint_own", `data-part="a"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("form: %q missing in %s", want, out)
		}
	}
	if strings.Contains(out, `value="up-0" formaction`) && !strings.Contains(out, `value="up-0" formaction="/healthchecks/status-pages/`) {
		t.Fatal("up-0")
	}
}
