package healthchecks

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// stTestView baut eine Seite mit vielen Eintraegen (groups x per), Tagesbalken, Stoerungen, Wartungen, Ankuendigungen.
func stTestView(layout string, groups, per, days int) *StatusView {
	now := time.Date(2026, 10, 20, 14, 5, 0, 0, time.UTC)
	v := &StatusView{Slug: "demo", Title: "Demo <Status>", Description: "Status unserer **Dienste**.\n\n- Web\n- Mail",
		Footer: "Fragen? [Kontakt](https://example.org/kontakt)", Layout: layout, Theme: "auto", Accent: "#7c3aed",
		Days: days, ShowUptime: true, RefreshSec: 60, PoweredBy: true, Overall: "degraded", Generated: now}
	id := int64(0)
	for g := 0; g < groups; g++ {
		vg := StatusViewGroup{Name: fmt.Sprintf("Gruppe %d", g+1), Overall: "up"}
		for i := 0; i < per; i++ {
			id++
			st := "up"
			switch {
			case g == 1 && i == per-1:
				st, vg.Overall = "down", "down"
			case g == 2 && i == 3:
				st, vg.Overall = "degraded", "degraded"
			case g == 3 && i == 0:
				st, vg.Overall = "maintenance", "maintenance"
			case i == 5:
				st = "paused"
			}
			it := StatusViewItem{ID: id, Label: fmt.Sprintf("Dienst %d-%d", g+1, i+1), State: st, Uptime: 99.987}
			for d := 0; d < days; d++ {
				day := StatusViewDay{Day: now.AddDate(0, 0, d-days+1).Format("2006-01-02"), State: "up", Uptime: 100}
				switch {
				case d < 3:
					day.State, day.Uptime = "none", -1
				case (int(id)+d)%37 == 0:
					day.State, day.Uptime, day.DownMins = "down", 96.5, 50
				case (int(id)+d)%23 == 0:
					day.State, day.Uptime, day.DownMins = "partial", 99.6, 6
				case (int(id)+d)%71 == 0:
					day.State = "maintenance"
				}
				it.Bars = append(it.Bars, day)
			}
			vg.Items = append(vg.Items, it)
		}
		v.Groups = append(v.Groups, vg)
	}
	v.Notices = []StatusNotice{
		{ID: 1, Title: "Umzug Rechenzentrum", Level: "warning", CreatedAt: now.Add(-2 * time.Hour),
			Updates: []StatusNoticeUpdate{{Time: now.Add(-2 * time.Hour), Text: "Wir ziehen um."}, {Time: now.Add(-time.Hour), Text: "Halbzeit, *alles* gut."}}},
		{ID: 2, Title: "Mail langsam", Level: "danger", CreatedAt: now.AddDate(0, 0, -3), ResolvedAt: now.AddDate(0, 0, -2),
			Updates: []StatusNoticeUpdate{{Time: now.AddDate(0, 0, -3), Text: "Wir pruefen."}}},
	}
	v.Maintenance = []StatusViewMaint{
		{Title: "Kernel-Update", Start: now.Add(-10 * time.Minute), End: now.Add(50 * time.Minute), Active: true, Items: []string{"Dienst 4-1"}},
		{Title: "Router", Start: now.AddDate(0, 0, 2), End: now.AddDate(0, 0, 2).Add(time.Hour), Items: []string{"Dienst 1-1", "Dienst 1-2"}},
	}
	v.Incidents = []StatusViewIncid{
		{Item: "Dienst 2-1", Start: now.Add(-30 * time.Minute), Reason: "timeout"},
		{Item: "Dienst 1-3", Start: now.AddDate(0, 0, -4), End: now.AddDate(0, 0, -4).Add(28 * time.Minute), Reason: "hc.reasons.connect_failed"},
	}
	return v
}

func stTestT(key string, args ...any) string {
	if len(args) == 0 {
		return key
	}
	return key + fmt.Sprint(args...)
}

func stRender(t *testing.T, v *StatusView, o statusRenderOpts) string {
	t.Helper()
	if o.T == nil {
		o.T = stTestT
	}
	if o.Nonce == "" {
		o.Nonce = "N0nc3"
	}
	var b bytes.Buffer
	if err := renderStatusHTML(&b, v, o); err != nil {
		t.Fatalf("render: %v", err)
	}
	return b.String()
}

var stURLRe = regexp.MustCompile(`(?i)(?:https?:)?//[a-z0-9.-]+`)

// stCheckCommon prueft Nonce und dass keine externen Ressourcen geladen werden.
func stCheckCommon(t *testing.T, h string, allow ...string) {
	t.Helper()
	if !strings.Contains(h, `<style nonce="N0nc3">`) {
		t.Error("style ohne nonce")
	}
	for _, m := range stURLRe.FindAllString(h, -1) {
		ok := m == "https://node64.de"
		for _, a := range allow {
			ok = ok || m == a
		}
		if !ok {
			t.Errorf("externe URL %q", m)
		}
	}
	for _, bad := range []string{"<link", "src=", "@import", "url(http"} {
		if strings.Contains(h, bad) {
			t.Errorf("enthaelt %q", bad)
		}
	}
	if strings.Count(h, "<script") != strings.Count(h, `<script nonce="N0nc3">`)+strings.Count(h, `<script type="application/json"`) {
		t.Error("script ohne nonce")
	}
}

func TestStatusHTMLList(t *testing.T) {
	v := stTestView("list", 8, 30, 90) // 240 Eintraege
	h := stRender(t, v, statusRenderOpts{Base: "/status/demo", Lang: "de", NoIndex: true})
	stCheckCommon(t, h, "https://example.org")
	if !strings.Contains(h, `<script nonce="N0nc3">`) {
		t.Error("script ohne nonce")
	}
	for _, want := range []string{`<html lang="de" class="l-list">`, `content="noindex,nofollow"`, "Demo &lt;Status&gt;",
		"<strong>Dienste</strong>", "hc.status.pub.overall.degraded", `class="ban s-degraded"`, `--ac:#7c3aed`,
		`href="#i60"`, "Umzug Rechenzentrum", "Kernel-Update", "hc.status.pub.maint.planned", "Router",
		"hc.status.pub.history.incidents", "· timeout", "hc.reasons.connect_failed", "hc.status.pub.inc.running",
		`href="https://node64.de"`, `rel="noopener nofollow"`, `"base":"/status/demo"`, `"refresh":60`} {
		if !strings.Contains(h, want) {
			t.Errorf("fehlt %q", want)
		}
	}
	if n := strings.Count(h, `<li class="it `); n != 240 {
		t.Errorf("Eintraege %d, erwartet 240", n)
	}
	// 240 Eintraege: nur Gruppen mit Problemen/Wartung offen
	if n := strings.Count(h, `<details class="grp`); n != 8 {
		t.Errorf("Gruppen %d", n)
	}
	if n := strings.Count(h, " open><summary>"); n != 3 {
		t.Errorf("offene Gruppen %d, erwartet 3", n)
	}
	// Probleme zuerst: in Gruppe 2 steht der gestoerte Eintrag (zuletzt angelegt) vorn
	g2 := h[strings.Index(h, "Gruppe 2"):]
	if strings.Index(g2, `id="i60"`) > strings.Index(g2, `id="i31"`) {
		t.Error("gestoerter Eintrag nicht zuerst")
	}
	if !strings.Contains(h, `<span class="tag">hc.status.pub.state.down</span>`) {
		t.Error("Zustand nicht als Text")
	}
	// Tagesbalken: genau 90 je Eintrag, auffaellige Tage mit title
	first := h[strings.Index(h, `<span class="bars"`):]
	first = first[:strings.Index(first, "</span>")]
	if n := strings.Count(first, "></"); n != 90 {
		t.Errorf("Balken %d", n)
	}
	if !strings.Contains(h, `<b title="`) || !strings.Contains(h, `data-s="2026-07-23"`) {
		t.Error("Balken-Details fehlen")
	}
	// erledigte Ankuendigung unten
	if !strings.Contains(h, "hc.status.pub.history.notices") || !strings.Contains(h, "Mail langsam") {
		t.Error("Verlauf Ankuendigungen fehlt")
	}
	t.Logf("Liste 240 Eintraege x 90 Tage: %d KB", len(h)/1024)
}

func TestStatusHTMLSmallOpen(t *testing.T) {
	v := stTestView("list", 2, 6, 30)
	v.Overall = "up"
	h := stRender(t, v, statusRenderOpts{Lang: "en"})
	if n := strings.Count(h, " open><summary>"); n != 2 {
		t.Errorf("wenige Eintraege: alle Gruppen offen, %d", n)
	}
	if !strings.Contains(h, `<html lang="en"`) || !strings.Contains(h, "hc.status.pub.overall.up") {
		t.Error("Sprache/Banner")
	}
	if !strings.Contains(h, "99.98%") {
		t.Error("Uptime-Format en")
	}
	if strings.Contains(h, "noindex") {
		t.Error("noindex ohne Wunsch")
	}
}

func TestStatusHTMLTiles(t *testing.T) {
	v := stTestView("tiles", 4, 25, 90)
	v.Theme = "dark"
	h := stRender(t, v, statusRenderOpts{Base: "/status/demo", Lang: "de"})
	stCheckCommon(t, h, "https://example.org")
	if !strings.Contains(h, `class="l-tiles t-dark"`) || !strings.Contains(h, `content="dark"`) {
		t.Error("Klasse/Theme")
	}
	if n := strings.Count(h, `<li class="it tl `); n != 100 {
		t.Errorf("Kacheln %d", n)
	}
	if strings.Contains(h, `class="bars"`) {
		t.Error("Kacheln ohne Balken")
	}
	if !strings.Contains(h, `<li class="it tl s-down"`) || !strings.Contains(h, "99,98\u202f%") {
		t.Error("gestoerte Kachel/Uptime")
	}
}

func TestStatusHTMLCompact(t *testing.T) {
	v := stTestView("compact", 5, 20, 60)
	h := stRender(t, v, statusRenderOpts{Base: "/status/demo", Lang: "de"})
	stCheckCommon(t, h, "https://example.org")
	if n := strings.Count(h, `<span class="cnt">`); n != 5 {
		t.Errorf("Gruppenzeilen %d", n)
	}
	for _, no := range []string{`class="it`, "Umzug Rechenzentrum", "hc.status.pub.history.incidents", "<h1>"} {
		if strings.Contains(h, no) {
			t.Errorf("kompakt enthaelt %q", no)
		}
	}
	if !strings.Contains(h, `<base target="_blank">`) {
		t.Error("kompakt: Links verlassen den iframe nicht")
	}
	if !strings.Contains(h, "hc.status.pub.count.down") || !strings.Contains(h, "hc.status.pub.overall.degraded") {
		t.Error("Zaehler/Banner")
	}
	if len(h) > 40<<10 {
		t.Errorf("kompakt zu gross: %d", len(h))
	}
}

func TestStatusHTMLSize(t *testing.T) {
	v := &StatusView{Title: "x", Overall: "up", Layout: "list", Generated: time.Now()}
	h := stRender(t, v, statusRenderOpts{Lang: "de"})
	if len(h) > 25<<10 {
		t.Errorf("Grundgeruest %d Bytes > 25 KB", len(h))
	}
	t.Logf("Grundgeruest ohne Daten: %d Bytes (CSS %d, JS %d)", len(h), len(stCSS), len(stJS))
}

func TestStatusHTMLPassword(t *testing.T) {
	h := stRender(t, nil, statusRenderOpts{Base: "/status/demo", Lang: "de", NeedPassword: true, PasswordWrong: true})
	stCheckCommon(t, h)
	for _, want := range []string{`action="/status/demo/login"`, `method="post"`, `name="password"`, `type="password"`,
		"hc.status.pub.pw.wrong", `role="alert"`} {
		if !strings.Contains(h, want) {
			t.Errorf("fehlt %q", want)
		}
	}
	if strings.Contains(h, "<script") || strings.Contains(h, `class="ban`) {
		t.Error("Passwortseite zeigt Inhalt/Script")
	}
	h = stRender(t, nil, statusRenderOpts{Lang: "en", NeedPassword: true})
	if !strings.Contains(h, `action="/login"`) || strings.Contains(h, "pw.wrong") {
		t.Error("eigene Domain / ohne Fehler")
	}
}

func TestStatusHTMLPreview(t *testing.T) {
	v := stTestView("list", 1, 3, 30)
	h := stRender(t, v, statusRenderOpts{Lang: "de", Preview: true})
	if !strings.Contains(h, `<div class="pv" role="note">hc.status.pub.preview</div>`) {
		t.Error("Vorschau-Banner fehlt")
	}
	if !strings.Contains(h, `"refresh":0`) {
		t.Error("Vorschau laedt nicht neu")
	}
	h = stRender(t, v, statusRenderOpts{Lang: "de"})
	if strings.Contains(h, `class="pv"`) {
		t.Error("Banner ohne Vorschau")
	}
}

func TestStatusHTMLEscaping(t *testing.T) {
	v := stTestView("list", 1, 2, 30)
	v.Groups[0].Name = `<img src=x onerror=alert(1)>`
	v.Groups[0].Items[0].Label = `"><script>alert(1)</script>`
	v.Accent = `red;}body{display:none`
	v.Incidents[0].Item = "<b>x</b>"
	h := stRender(t, v, statusRenderOpts{Lang: "de", Base: `/status/a"b`})
	for _, bad := range []string{"<img src=x", "<script>alert", "<b>x</b>", `/status/a"b`, "red;}body"} {
		if strings.Contains(h, bad) {
			t.Errorf("nicht entschaerft: %q", bad)
		}
	}
}

func TestStatusMarkdown(t *testing.T) {
	cases := []struct{ in, want string }{
		{"**fett** und *kursiv* und `a<b`", "<p><strong>fett</strong> und <em>kursiv</em> und <code>a&lt;b</code></p>"},
		{"Zeile 1\nZeile 2\n\nAbsatz", "<p>Zeile 1<br>Zeile 2</p><p>Absatz</p>"},
		{"Liste:\n- a\n- **b**", "<p>Liste:</p><ul><li>a</li><li><strong>b</strong></li></ul>"},
		{"[Doku](https://node64.de/docs?a=1&b=2)", `<p><a href="https://node64.de/docs?a=1&amp;b=2" rel="noopener nofollow">Doku</a></p>`},
		{"`**nicht fett**`", "<p><code>**nicht fett**</code></p>"},
		{"5 * 3 = 15", "<p>5 * 3 = 15</p>"},
		{"", ""},
	}
	for _, c := range cases {
		if got := string(statusMarkdown(c.in)); got != c.want {
			t.Errorf("%q:\n got %q\nwant %q", c.in, got, c.want)
		}
	}
	evil := []string{
		`<script>alert(1)</script>`,
		`[x](javascript:alert(1))`,
		`[x](JaVaScRiPt:alert(1))`,
		`[x](data:text/html,<script>alert(1)</script>)`,
		`[x](https://a.b/" onmouseover="alert(1))`,
		`<a href="javascript:alert(1)">x</a>`,
		`**<img src=x onerror=alert(1)>**`,
		"[a](https://x.y/\x00`)",
	}
	for _, e := range evil {
		got := string(statusMarkdown(e))
		if strings.Contains(got, "<script") || strings.Contains(got, "<img") || strings.Contains(got, `href="javascript`) ||
			strings.Contains(got, `href="data`) || strings.Contains(got, `" onmouseover`) || strings.Contains(got, "<a href=\"javascript") {
			t.Errorf("unsicher: %q -> %q", e, got)
		}
		if strings.Contains(strings.ToLower(got), "<a ") && !strings.Contains(got, `href="https://`) {
			t.Errorf("Link mit falschem Schema: %q -> %q", e, got)
		}
	}
}

func TestStatusBadgeSVG(t *testing.T) {
	type svg struct {
		XMLName xml.Name `xml:"svg"`
		Width   int      `xml:"width,attr"`
		Title   string   `xml:"title"`
		Texts   []string `xml:"g>text"`
	}
	for _, c := range []struct{ l, v, col string }{
		{"status", "up", "up"}, {"uptime", "99.98%", "#4c1"}, {"", "down", "red"},
		{`a<b>&"c'`, "\x01böse\x7f]]>", "javascript:alert(1)"}, {"latency", "123 ms", "#zzz"},
	} {
		b := statusBadgeSVG(c.l, c.v, c.col)
		var s svg
		if err := xml.Unmarshal(b, &s); err != nil {
			t.Fatalf("%q: kein gueltiges SVG: %v\n%s", c.l, err, b)
		}
		if s.Width <= 0 || len(s.Texts) == 0 {
			t.Errorf("%q: Breite/Text fehlt", c.l)
		}
		if strings.Contains(string(b), "javascript") || strings.Contains(string(b), "<b>") {
			t.Errorf("nicht escaped: %s", b)
		}
	}
	short, long := statusBadgeSVG("status", "up", "up"), statusBadgeSVG("status", "maintenance window", "up")
	var a, b struct {
		Width int `xml:"width,attr"`
	}
	_ = xml.Unmarshal(short, &a)
	_ = xml.Unmarshal(long, &b)
	if b.Width <= a.Width {
		t.Errorf("Breite waechst nicht mit dem Text: %d <= %d", b.Width, a.Width)
	}
	if !strings.Contains(string(statusBadgeSVG("s", "up", "down")), `fill="#e05d44"`) {
		t.Error("Zustandsfarbe")
	}
}

// TestStatusHTMLPreviewFiles schreibt Beispielseiten (nur mit STATUS_PREVIEW_DIR), Texte aus locales + tmp-JSON.
func TestStatusHTMLPreviewFiles(t *testing.T) {
	dir := os.Getenv("STATUS_PREVIEW_DIR")
	if dir == "" {
		t.Skip("STATUS_PREVIEW_DIR nicht gesetzt")
	}
	msgs := map[string]string{}
	var flat func(p string, in map[string]any)
	flat = func(p string, in map[string]any) {
		for k, v := range in {
			if m, ok := v.(map[string]any); ok {
				flat(p+k+".", m)
			} else if s, ok := v.(string); ok {
				msgs[p+k] = s
			}
		}
	}
	if b, err := os.ReadFile("../i18n/locales/de.json"); err == nil {
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		flat("", m)
	}
	if b, err := os.ReadFile("../../docs/tmp-status-i18n-oberflaeche.json"); err == nil {
		var m map[string]map[string]string
		_ = json.Unmarshal(b, &m)
		for k, v := range m["de"] {
			msgs[k] = v
		}
	}
	tr := func(key string, args ...any) string {
		s, ok := msgs[key]
		if !ok {
			return key
		}
		for i := 0; i+1 < len(args); i += 2 {
			s = strings.ReplaceAll(s, "{"+fmt.Sprint(args[i])+"}", fmt.Sprint(args[i+1]))
		}
		return s
	}
	for _, l := range []string{"list", "tiles", "compact"} {
		v := stTestView(l, 6, 14, 90)
		var b bytes.Buffer
		if err := renderStatusHTML(&b, v, statusRenderOpts{Base: ".", Lang: "de", Nonce: "x", T: tr}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "status-"+l+".html"), b.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var b bytes.Buffer
	_ = renderStatusHTML(&b, nil, statusRenderOpts{Base: ".", Lang: "de", NeedPassword: true, PasswordWrong: true, T: tr})
	_ = os.WriteFile(filepath.Join(dir, "status-login.html"), b.Bytes(), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "badge.svg"), statusBadgeSVG("status", "Betriebsbereit", "up"), 0o644)
}
