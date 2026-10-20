package healthchecks

import (
	"bytes"
	"embed"
	"encoding/xml"
	"fmt"
	"html"
	"html/template"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Statusseiten: HTML der oeffentlichen Seite (eigenstaendig, ohne die Oberflaeche der Node), Badges.
// Vorlage und Assets liegen in statuspublic/ und werden mit Nonce eingebettet (keine externen Ressourcen).

// statusRenderOpts steuert die Ausgabe der oeffentlichen Seite.
type statusRenderOpts struct {
	Base          string                               // URL-Praefix der Seite: "/status/<slug>" (Node-Port) oder "" (eigene Domain)
	Lang          string                               // de | en
	Nonce         string                               // CSP-Nonce fuer das eingebettete <style>/<script>
	NoIndex       bool                                 // <meta name="robots" content="noindex">
	NeedPassword  bool                                 // statt der Seite das Passwortformular zeigen
	PasswordWrong bool                                 // Hinweis "Passwort falsch"
	Preview       bool                                 // Vorschau in der Verwaltung (Banner "Vorschau")
	T             func(key string, args ...any) string // Uebersetzung (hc.status.pub.*, hc.reasons.*)
}

//go:embed statuspublic
var stPublicFS embed.FS

var (
	stTpl = template.Must(template.New("page.html").ParseFS(stPublicFS, "statuspublic/page.html"))
	stCSS = template.CSS(stAsset("statuspublic/style.css", true))
	stJS  = template.JS(stAsset("statuspublic/app.js", false))
)

// stAsset liest eine eingebettete Datei und entfernt Einrueckung und Kommentarzeilen (CSS: auch Zeilenumbrueche).
func stAsset(name string, css bool) string {
	b, err := stPublicFS.ReadFile(name)
	if err != nil {
		panic(err)
	}
	var out []string
	for _, l := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "//") || (css && strings.HasPrefix(l, "/*") && strings.HasSuffix(l, "*/")) {
			continue
		}
		out = append(out, l)
	}
	if css {
		return strings.Join(out, "")
	}
	return strings.Join(out, "\n")
}

// Grenzen, damit die Seite bei sehr vielen Checks schlank bleibt.
const (
	stMaxProblems  = 12  // Liste "Betroffen" unter dem Banner
	stMaxIncidents = 100 // Verlauf unten
	stOpenAllMax   = 40  // bis zu so vielen Eintraegen sind auch ungestoerte Gruppen aufgeklappt
)

// stPage sind die aufbereiteten Daten fuer page.html.
type stPage struct {
	o             statusRenderOpts
	showUptime    bool
	Lang          string
	Nonce         string
	Base          string
	Title         string
	HTMLClass     string
	Scheme        string
	Layout        string
	NoIndex       bool
	Preview       bool
	NeedPassword  bool
	PasswordWrong bool
	CSS           template.CSS
	JS            template.JS
	JSL           map[string]any
	Desc          template.HTML
	Footer        template.HTML
	Overall       string
	OverallText   string
	Generated     time.Time
	Problems      []stRef
	ProblemMore   int
	Active        []stMaint
	Planned       []stMaint
	OpenNotices   []stNotice
	OldNotices    []stNotice
	Groups        []stGroup
	Incidents     []stIncid
	IncMore       int
	PoweredBy     bool
}

type stRef struct {
	ID        int64
	Label     string
	State     string
	StateText string
}

type stGroup struct {
	Name        string
	Overall     string
	OverallText string
	Key         string
	Open        bool
	Counts      string
	Items       []stItem
}

type stItem struct {
	ID        int64
	Label     string
	State     string
	StateText string
	Problem   bool
	Uptime    string
	Bars      template.HTML
	BarsLabel string
	FirstDay  string
}

type stMaint struct {
	Title      string
	Start, End time.Time
	Items      string
}

type stNotice struct {
	P         *stPage
	Title     string
	Level     string
	LevelText string
	Done      bool
	DoneText  string
	Resolved  time.Time
	Updates   []stUpdate
}

type stUpdate struct {
	Time time.Time
	Text template.HTML
}

type stIncid struct {
	Item    string
	Start   time.Time
	Dur     string
	Running bool
	Reason  string
}

// T uebersetzt (ohne Uebersetzer kommt der Schluessel zurueck).
func (p *stPage) T(key string, args ...any) string {
	if p.o.T == nil {
		return key
	}
	return p.o.T(key, args...)
}

// ISO liefert die Zeit fuer <time datetime> (der Browser formatiert lokal).
func (p *stPage) ISO(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

// When ist die Anzeige ohne JS (Zeitzone der Node).
func (p *stPage) When(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	if p.Lang == "de" {
		return t.Format("02.01.2006 15:04")
	}
	return t.Format("2006-01-02 15:04")
}

// Clock ist die Uhrzeit ohne JS.
func (p *stPage) Clock(t time.Time) string {
	if t.IsZero() {
		return "–"
	}
	return t.Format("15:04")
}

// pct formatiert eine Verfuegbarkeit (abgerundet auf 2 Stellen, damit 99,999 nie als 100 erscheint).
func (p *stPage) pct(x float64) string {
	if x < 0 || math.IsNaN(x) {
		return "–"
	}
	var s string
	if x >= 100 {
		s = "100"
	} else {
		s = strconv.FormatFloat(math.Floor(x*100)/100, 'f', 2, 64)
	}
	if p.Lang == "de" {
		return strings.Replace(s, ".", ",", 1) + " %"
	}
	return s + "%"
}

// dur formatiert eine Dauer grob (min, h, Tage).
func (p *stPage) dur(d time.Duration) string {
	m := int(d.Round(time.Minute) / time.Minute)
	if m < 1 {
		m = 1
	}
	switch {
	case m < 60:
		return p.T("hc.status.pub.dur.m", "m", m)
	case m < 1440:
		return p.T("hc.status.pub.dur.h", "h", m/60, "m", m%60)
	}
	return p.T("hc.status.pub.dur.d", "d", m/1440, "h", (m%1440)/60)
}

// reason uebersetzt einen allgemeinen Grund ("timeout" oder "hc.reasons.timeout"); bereits uebersetzte Texte bleiben.
func (p *stPage) reason(r string) string {
	r = strings.TrimSpace(r)
	if r == "" {
		return ""
	}
	key := r
	if !strings.HasPrefix(key, "hc.reasons.") {
		key = "hc.reasons." + r
	}
	if t := p.T(key); t != key {
		return t
	}
	return r
}

var stColorRe = regexp.MustCompile(`^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)

// renderStatusHTML schreibt die ganze Seite (v darf bei NeedPassword nil sein).
func renderStatusHTML(w io.Writer, v *StatusView, o statusRenderOpts) error {
	p := stBuildPage(v, o)
	var buf bytes.Buffer
	buf.Grow(32 << 10)
	if err := stTpl.Execute(&buf, p); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}

func stBuildPage(v *StatusView, o statusRenderOpts) *stPage {
	if v == nil {
		v = &StatusView{Overall: "unknown"}
	}
	p := &stPage{o: o, Lang: o.Lang, Nonce: o.Nonce, Base: strings.TrimRight(o.Base, "/"), NoIndex: o.NoIndex,
		Preview: o.Preview, NeedPassword: o.NeedPassword, PasswordWrong: o.PasswordWrong, PoweredBy: v.PoweredBy,
		showUptime: v.ShowUptime}
	if p.Lang != "en" {
		p.Lang = "de"
	}
	p.Title = strings.TrimSpace(v.Title)
	if p.Title == "" {
		p.Title = p.T("hc.status.pub.title")
	}
	p.Layout = v.Layout
	if p.Layout != "tiles" && p.Layout != "compact" {
		p.Layout = "list"
	}
	p.Scheme = "light dark"
	cls := []string{"l-" + p.Layout}
	switch v.Theme {
	case "light", "dark":
		p.Scheme = v.Theme
		cls = append(cls, "t-"+v.Theme)
	}
	p.HTMLClass = strings.Join(cls, " ")
	css := string(stCSS)
	if stColorRe.MatchString(v.Accent) {
		css += ":root{--ac:" + v.Accent + "}"
	}
	p.CSS = template.CSS(css)
	p.JS = stJS
	if o.NeedPassword {
		return p
	}

	p.Overall = stKnownOverall(v.Overall)
	p.OverallText = p.T("hc.status.pub.overall." + p.Overall)
	p.Generated = v.Generated
	p.Desc = statusMarkdown(v.Description)
	p.Footer = statusMarkdown(v.Footer)

	total := 0
	for _, g := range v.Groups {
		total += len(g.Items)
	}
	for _, g := range v.Groups {
		p.Groups = append(p.Groups, p.group(g, total))
	}
	for _, g := range p.Groups {
		for _, it := range g.Items {
			if !it.Problem {
				continue
			}
			if len(p.Problems) >= stMaxProblems {
				p.ProblemMore++
				continue
			}
			p.Problems = append(p.Problems, stRef{ID: it.ID, Label: it.Label, State: it.State, StateText: it.StateText})
		}
	}

	for _, m := range v.Maintenance {
		sm := stMaint{Title: m.Title, Start: m.Start, End: m.End, Items: strings.Join(m.Items, ", ")}
		if sm.Title == "" {
			sm.Title = p.T("hc.status.pub.maint.title")
		}
		if m.Active {
			p.Active = append(p.Active, sm)
		} else {
			p.Planned = append(p.Planned, sm)
		}
	}
	sort.SliceStable(p.Planned, func(i, j int) bool { return p.Planned[i].Start.Before(p.Planned[j].Start) })

	for _, n := range v.Notices {
		sn := p.notice(n)
		if sn.Done {
			p.OldNotices = append(p.OldNotices, sn)
		} else {
			p.OpenNotices = append(p.OpenNotices, sn)
		}
	}

	inc := append([]StatusViewIncid(nil), v.Incidents...)
	sort.SliceStable(inc, func(i, j int) bool { return inc[i].Start.After(inc[j].Start) })
	for _, x := range inc {
		if len(p.Incidents) >= stMaxIncidents {
			p.IncMore++
			continue
		}
		si := stIncid{Item: x.Item, Start: x.Start, Reason: p.reason(x.Reason)}
		if x.End.IsZero() {
			si.Running = true
			si.Dur = p.T("hc.status.pub.inc.running")
		} else {
			si.Dur = p.dur(x.End.Sub(x.Start))
		}
		p.Incidents = append(p.Incidents, si)
	}

	refresh := v.RefreshSec
	if o.Preview || refresh < 0 {
		refresh = 0
	} else if refresh > 0 && refresh < 10 {
		refresh = 10
	}
	p.JSL = map[string]any{
		"base": p.Base, "refresh": refresh,
		"b": map[string]string{"i": p.T("hc.status.pub.bar.up"), "s": p.T("hc.status.pub.bar.partial"),
			"b": p.T("hc.status.pub.bar.down"), "u": p.T("hc.status.pub.bar.maintenance"), "q": p.T("hc.status.pub.bar.none")},
		"h24": p.T("hc.status.pub.det.h24"), "d7": p.T("hc.status.pub.det.d7"), "d30": p.T("hc.status.pub.det.d30"),
		"lat": p.T("hc.status.pub.det.latency"), "since": p.T("hc.status.pub.det.since"), "hrs": p.T("hc.status.pub.det.hours"),
		"inc": p.T("hc.status.pub.det.incidents"), "noinc": p.T("hc.status.pub.det.noinc"), "run": p.T("hc.status.pub.inc.running"),
		"load": p.T("hc.status.pub.det.loading"), "nodet": p.T("hc.status.pub.det.unavailable"), "stale": p.T("hc.status.pub.stale"),
		"dm": p.T("hc.status.pub.dur.m", "m", "{m}"), "dh": p.T("hc.status.pub.dur.h", "h", "{h}", "m", "{m}"),
		"dd": p.T("hc.status.pub.dur.d", "d", "{d}", "h", "{h}"),
	}
	return p
}

func stKnownOverall(s string) string {
	switch s {
	case "up", "degraded", "down", "maintenance":
		return s
	}
	return "unknown"
}

// stItemRank: Probleme zuerst (gestoert, eingeschraenkt, Wartung), sonst eigene Reihenfolge.
func stItemRank(state string) int {
	switch state {
	case "down":
		return 0
	case "degraded":
		return 1
	case "maintenance":
		return 2
	}
	return 3
}

var stItemStates = []string{"up", "down", "degraded", "maintenance", "paused", "unknown"}

func (p *stPage) group(g StatusViewGroup, total int) stGroup {
	sg := stGroup{Name: g.Name, Overall: stKnownOverall(g.Overall)}
	sg.OverallText = p.T("hc.status.pub.overall." + sg.Overall)
	items := append([]StatusViewItem(nil), g.Items...)
	sort.SliceStable(items, func(i, j int) bool { return stItemRank(items[i].State) < stItemRank(items[j].State) })
	counts := map[string]int{}
	flag := false
	for _, it := range items {
		st := it.State
		if !stValidItemState(st) {
			st = "unknown"
		}
		counts[st]++
		si := stItem{ID: it.ID, Label: it.Label, State: st, StateText: p.T("hc.status.pub.state." + st),
			Problem: st == "down" || st == "degraded"}
		if st != "up" && st != "paused" && st != "unknown" {
			flag = true
		}
		if it.Uptime >= 0 && p.showUptime {
			si.Uptime = p.pct(it.Uptime)
		}
		if p.Layout == "list" && len(it.Bars) > 0 {
			si.Bars, si.BarsLabel = p.bars(it.Bars)
			si.FirstDay = it.Bars[0].Day
		}
		sg.Items = append(sg.Items, si)
	}
	var parts []string
	for _, st := range stItemStates {
		if counts[st] > 0 {
			parts = append(parts, p.T("hc.status.pub.count."+st, "count", counts[st]))
		}
	}
	sg.Counts = strings.Join(parts, " · ")
	sg.Key = g.Name + "|0"
	if flag {
		sg.Key = g.Name + "|1"
	}
	sg.Open = flag || total <= stOpenAllMax
	return sg
}

func stValidItemState(s string) bool {
	for _, x := range stItemStates {
		if x == s {
			return true
		}
	}
	return false
}

// stBarTag: je Zustand ein eigenes kurzes Element (spart Bytes bei vielen Eintraegen x 90 Tagen):
// i = ok, s = teilweise, b = gestoert, u = Wartung, q = keine Daten.
func stBarTag(state string) string {
	switch state {
	case "up":
		return "i"
	case "partial":
		return "s"
	case "down":
		return "b"
	case "maintenance":
		return "u"
	}
	return "q"
}

var stBarTagState = map[string]string{"i": "up", "s": "partial", "b": "down", "u": "maintenance", "q": "none"}

// bars rendert die Tagesbalken kompakt: Tage ohne Auffaelligkeit ohne title (den setzt das JS beim Darueberfahren),
// auffaellige Tage mit Datum, Verfuegbarkeit und Ausfall-Minuten (auch ohne JS sichtbar).
func (p *stPage) bars(days []StatusViewDay) (template.HTML, string) {
	var b strings.Builder
	b.Grow(len(days) * 8)
	bad := 0
	for _, d := range days {
		c := stBarTag(d.State)
		if c == "i" && d.DownMins == 0 || c == "q" {
			b.WriteString("<" + c + "></" + c + ">")
			continue
		}
		if c == "s" || c == "b" {
			bad++
		}
		t := p.day(d.Day) + ": " + p.T("hc.status.pub.bar."+stBarTagState[c])
		if d.Uptime >= 0 {
			t += " · " + p.pct(d.Uptime)
		}
		if d.DownMins > 0 {
			t += " · " + p.T("hc.status.pub.bar.downmin", "dur", p.dur(time.Duration(d.DownMins)*time.Minute))
		}
		b.WriteString("<" + c + ` title="` + html.EscapeString(t) + `"></` + c + ">")
	}
	return template.HTML(b.String()), p.T("hc.status.pub.bars.aria", "days", len(days), "count", bad)
}

// day formatiert "2006-01-02" fuer die Anzeige.
func (p *stPage) day(s string) string {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return s
	}
	if p.Lang == "de" {
		return t.Format("02.01.2006")
	}
	return s
}

func (p *stPage) notice(n StatusNotice) stNotice {
	lv := n.Level
	if lv != "warning" && lv != "danger" {
		lv = "info"
	}
	sn := stNotice{P: p, Title: n.Title, Level: lv, LevelText: p.T("hc.status.pub.level." + lv),
		Done: !n.ResolvedAt.IsZero(), Resolved: n.ResolvedAt, DoneText: p.T("hc.status.pub.notice.resolved")}
	ups := append([]StatusNoticeUpdate(nil), n.Updates...)
	sort.SliceStable(ups, func(i, j int) bool { return ups[i].Time.After(ups[j].Time) })
	for _, u := range ups {
		sn.Updates = append(sn.Updates, stUpdate{Time: u.Time, Text: statusMarkdown(u.Text)})
	}
	return sn
}

// Mini-Markdown (sicher): erst HTML-escapen, dann nur **fett**, *kursiv*, `code`, [Text](http(s)://...),
// Zeilenumbrueche, Absaetze und Listen ("- "). Keine rohen Tags, keine anderen Link-Schemata.
var (
	stMdCodeRe = regexp.MustCompile("`([^`\n]+)`")
	stMdLinkRe = regexp.MustCompile(`\[([^\]\n]+)\]\((https?://[^\s()<>]+)\)`)
	stMdBoldRe = regexp.MustCompile(`\*\*([^*\n]+)\*\*`)
	stMdEmRe   = regexp.MustCompile(`\*([^*\s][^*\n]*)\*`)
	stMdHoldRe = regexp.MustCompile("\x00([0-9]+)\x00")
)

func statusMarkdown(src string) template.HTML {
	src = strings.ReplaceAll(strings.ReplaceAll(src, "\r\n", "\n"), "\x00", "")
	if strings.TrimSpace(src) == "" {
		return ""
	}
	var out strings.Builder
	var para, list []string
	flush := func() {
		if len(para) > 0 {
			out.WriteString("<p>" + strings.Join(para, "<br>") + "</p>")
			para = nil
		}
		if len(list) > 0 {
			out.WriteString("<ul>")
			for _, l := range list {
				out.WriteString("<li>" + l + "</li>")
			}
			out.WriteString("</ul>")
			list = nil
		}
	}
	for _, line := range strings.Split(src, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case t == "":
			flush()
		case strings.HasPrefix(t, "- ") || strings.HasPrefix(t, "* "):
			if len(para) > 0 {
				flush()
			}
			list = append(list, stMdInline(strings.TrimSpace(t[2:])))
		default:
			if len(list) > 0 {
				flush()
			}
			para = append(para, stMdInline(t))
		}
	}
	flush()
	return template.HTML(out.String())
}

func stMdInline(s string) string {
	s = html.EscapeString(s)
	var keep []string
	hold := func(x string) string {
		keep = append(keep, x)
		return "\x00" + strconv.Itoa(len(keep)-1) + "\x00"
	}
	s = stMdCodeRe.ReplaceAllStringFunc(s, func(m string) string { return hold("<code>" + m[1:len(m)-1] + "</code>") })
	s = stMdLinkRe.ReplaceAllStringFunc(s, func(m string) string {
		sm := stMdLinkRe.FindStringSubmatch(m)
		return hold(`<a href="` + sm[2] + `" rel="noopener nofollow">` + sm[1] + `</a>`)
	})
	s = stMdBoldRe.ReplaceAllString(s, "<strong>$1</strong>")
	s = stMdEmRe.ReplaceAllString(s, "<em>$1</em>")
	return stMdHoldRe.ReplaceAllStringFunc(s, func(m string) string {
		i, _ := strconv.Atoi(m[1 : len(m)-1])
		if i < len(keep) {
			return keep[i]
		}
		return ""
	})
}

// Badge-Farben: Namen wie bei shields.io und die Zustaende der Statusseite.
var stBadgeColors = map[string]string{
	"brightgreen": "#4c1", "green": "#97ca00", "yellowgreen": "#a4a61d", "yellow": "#dfb317", "orange": "#fe7d37",
	"red": "#e05d44", "blue": "#007ec6", "grey": "#9f9f9f", "gray": "#9f9f9f", "lightgrey": "#9f9f9f",
	"up": "#4c1", "degraded": "#dfb317", "partial": "#dfb317", "down": "#e05d44", "maintenance": "#007ec6",
	"paused": "#9f9f9f", "unknown": "#9f9f9f",
}

// statusBadgeSVG erzeugt ein Badge im ueblichen Stil (links label, rechts value in color).
func statusBadgeSVG(label, value, color string) []byte {
	c, ok := stBadgeColors[strings.ToLower(strings.TrimSpace(color))]
	if !ok {
		c = "#9f9f9f"
		if stColorRe.MatchString(color) {
			c = color
		}
	}
	label, value = stBadgeCut(label), stBadgeCut(value)
	lw, vw := 0, stBadgeTextWidth(value)+10
	if label != "" {
		lw = stBadgeTextWidth(label) + 10
	}
	w := lw + vw
	el, ev := stBadgeEsc(label), stBadgeEsc(value)
	title := ev
	if label != "" {
		title = el + ": " + ev
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20" role="img" aria-label="%s"><title>%s</title>`, w, title, title)
	b.WriteString(`<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>`)
	fmt.Fprintf(&b, `<clipPath id="r"><rect width="%d" height="20" rx="3" fill="#fff"/></clipPath><g clip-path="url(#r)">`, w)
	if lw > 0 {
		fmt.Fprintf(&b, `<rect width="%d" height="20" fill="#555"/>`, lw)
	}
	fmt.Fprintf(&b, `<rect x="%d" width="%d" height="20" fill="%s"/><rect width="%d" height="20" fill="url(#s)"/></g>`, lw, vw, c, w)
	b.WriteString(`<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">`)
	if lw > 0 {
		fmt.Fprintf(&b, `<text x="%.1f" y="15" fill="#010101" fill-opacity=".3">%s</text><text x="%.1f" y="14">%s</text>`, float64(lw)/2, el, float64(lw)/2, el)
	}
	vx := float64(lw) + float64(vw)/2
	fmt.Fprintf(&b, `<text x="%.1f" y="15" fill="#010101" fill-opacity=".3">%s</text><text x="%.1f" y="14">%s</text></g></svg>`, vx, ev, vx, ev)
	return b.Bytes()
}

func stBadgeCut(s string) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > 60 {
		s = string([]rune(s)[:59]) + "…"
	}
	return s
}

func stBadgeEsc(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// stBadgeTextWidth schaetzt die Breite in Verdana 11 px.
func stBadgeTextWidth(s string) int {
	w := 0.0
	for _, r := range s {
		switch {
		case strings.ContainsRune("iljI.,:;!|'` ", r):
			w += 3.6
		case strings.ContainsRune("frt()-/[]", r):
			w += 4.6
		case strings.ContainsRune("mwMW%@", r):
			w += 10
		case r >= 'A' && r <= 'Z':
			w += 7.6
		case r >= '0' && r <= '9':
			w += 7
		case r < 128:
			w += 6.5
		default:
			w += 7.5
		}
	}
	return int(math.Ceil(w))
}
