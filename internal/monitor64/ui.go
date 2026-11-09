package monitor64

import (
	"context"
	"embed"
	"io/fs"
	"net/http"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/monitor64/eval"
)

//go:embed templates
var templateFS embed.FS

//go:embed static/monitor64.js
var bundleJS []byte

//go:embed static/monitor64.css
var bundleCSS []byte

// Templates liefert die Seiten des Moduls (module.Templater).
func (m *Module) Templates() fs.FS {
	sub, _ := fs.Sub(templateFS, "templates")
	return sub
}

// uiRoutes registriert Seiten, Skript/Stil (CSP: nur von der eigenen Adresse) und die JSON-API.
func (m *Module) uiRoutes(mux *http.ServeMux, g module.Guards) {
	page := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /monitor64", page(m.pageOverview))
	mux.Handle("GET /monitor64/host/{uid}", page(m.pageHost))
	mux.Handle("GET /monitor64/problems", page(m.pageProblems))
	mux.Handle("GET /monitor64/maintenance", page(m.pageMaint))
	mux.Handle("GET /monitor64/rules", page(m.pageRules))
	mux.Handle("GET /monitor64/notify", page(m.pageNotify))
	mux.Handle("GET /monitor64/settings", page(m.pageSettings))
	mux.Handle("GET /monitor64/new", page(m.pageNew))
	mux.Handle("GET /monitor64/monitor64.js", page(m.serveAsset(bundleJS, "text/javascript; charset=utf-8")))
	mux.Handle("GET /monitor64/monitor64.css", page(m.serveAsset(bundleCSS, "text/css; charset=utf-8")))

	api := page
	mux.Handle("GET /api/monitor64/status", api(m.apiStatus))
	mux.Handle("GET /api/monitor64/overview", api(m.apiOverview))
	mux.Handle("GET /api/monitor64/sparks", api(m.apiSparks))
	mux.Handle("GET /api/monitor64/series", api(m.apiSeries))
	mux.Handle("GET /api/monitor64/nodeaddr", api(m.apiNodeAddr))
	mux.Handle("POST /api/monitor64/test", api(m.apiTest))

	mux.Handle("GET /api/monitor64/hosts", api(m.apiHosts))
	mux.Handle("POST /api/monitor64/hosts", api(m.apiHostCreate))
	mux.Handle("GET /api/monitor64/hosts/{uid}", api(m.apiHost))
	mux.Handle("PUT /api/monitor64/hosts/{uid}", api(m.apiHostUpdate))
	mux.Handle("DELETE /api/monitor64/hosts/{uid}", api(m.apiHostDelete))
	mux.Handle("POST /api/monitor64/hosts/{uid}/discover", api(m.apiDiscover))
	mux.Handle("POST /api/monitor64/hosts/{uid}/access", api(m.apiAccessCreate))
	mux.Handle("POST /api/monitor64/hosts/{uid}/services/adopt", api(m.apiServicesAdopt))
	mux.Handle("POST /api/monitor64/hosts/{uid}/services/remove", api(m.apiServicesRemove))
	mux.Handle("PUT /api/monitor64/hosts/{uid}/service", api(m.apiServiceUpdate))

	mux.Handle("PUT /api/monitor64/access/{uid}", api(m.apiAccessUpdate))
	mux.Handle("DELETE /api/monitor64/access/{uid}", api(m.apiAccessDelete))
	mux.Handle("POST /api/monitor64/access/{uid}/test", api(m.apiAccessTest))
	mux.Handle("POST /api/monitor64/access/{uid}/hostkey-reset", api(m.apiAccessHostKey))

	mux.Handle("GET /api/monitor64/problems", api(m.apiProblems))
	mux.Handle("GET /api/monitor64/problems.csv", api(m.apiProblemsCSV))
	mux.Handle("GET /api/monitor64/problems/{uid}", api(m.apiProblem))
	mux.Handle("POST /api/monitor64/problems/action", api(m.apiProblemAction))

	mux.Handle("GET /api/monitor64/rules", api(m.apiRules))
	mux.Handle("PUT /api/monitor64/rules/std", api(m.apiRulesStd))
	mux.Handle("POST /api/monitor64/rules/preview", api(m.apiRulePreview))
	mux.Handle("POST /api/monitor64/rules/overrides", api(m.apiRuleOverrideSave))
	mux.Handle("PUT /api/monitor64/rules/overrides/{uid}", api(m.apiRuleOverrideSave))
	mux.Handle("DELETE /api/monitor64/rules/overrides/{uid}", api(m.apiOverrideDelete("rule")))
	mux.Handle("POST /api/monitor64/rules/overrides/{uid}/move", api(m.apiOverrideMove("rule")))

	mux.Handle("GET /api/monitor64/notify", api(m.apiNotify))
	mux.Handle("PUT /api/monitor64/notify", api(m.apiNotifySave))
	mux.Handle("POST /api/monitor64/notify/test", api(m.apiNotifyTest))
	mux.Handle("POST /api/monitor64/notify/overrides", api(m.apiNotifyOverrideSave))
	mux.Handle("PUT /api/monitor64/notify/overrides/{uid}", api(m.apiNotifyOverrideSave))
	mux.Handle("DELETE /api/monitor64/notify/overrides/{uid}", api(m.apiOverrideDelete("notify")))
	mux.Handle("POST /api/monitor64/notify/overrides/{uid}/move", api(m.apiOverrideMove("notify")))

	mux.Handle("GET /api/monitor64/maintenance", api(m.apiMaint))
	mux.Handle("POST /api/monitor64/maintenance", api(m.apiMaintSave))
	mux.Handle("PUT /api/monitor64/maintenance/{uid}", api(m.apiMaintSave))
	mux.Handle("POST /api/monitor64/maintenance/{uid}/end", api(m.apiMaintEnd))
	mux.Handle("DELETE /api/monitor64/maintenance/{uid}", api(m.apiMaintDelete))

	mux.Handle("GET /api/monitor64/settings", api(m.apiSettings))
	mux.Handle("PUT /api/monitor64/settings", api(m.apiSettingsSave))
	mux.Handle("GET /api/monitor64/traps", api(m.apiTraps))
	mux.Handle("DELETE /api/monitor64/traps/unknown", api(m.apiTrapsUnknownClear))
	mux.Handle("GET /api/monitor64/hosts/{uid}/traps", api(m.apiHostTraps))
	mux.Handle("POST /api/monitor64/hosts/{uid}/traps/reset", api(m.apiHostTrapsReset))
}

// statusView ist der technische Stand (Planer, Verlauf, Lastgenerator) – unter Einstellungen.
type statusView struct {
	Version   string     `json:"version"`
	Uptime    string     `json:"uptime"`
	Sched     SchedStats `json:"scheduler"`
	HistoryMB float64    `json:"history_mb"`
	LoadHosts int        `json:"loadgen_hosts"`
	LoadRate  float64    `json:"loadgen_points_per_sec"`
	HeapMB    float64    `json:"heap_mb"`
	Routines  int        `json:"goroutines"`
}

func (m *Module) status() statusView {
	v := statusView{Version: version}
	m.mu.Lock()
	sched, ser, lg, start := m.sched, m.series, m.load, m.start
	m.mu.Unlock()
	if !start.IsZero() {
		v.Uptime = time.Since(start).Truncate(time.Second).String()
	}
	if sched != nil {
		v.Sched = sched.Stats()
	}
	if ser != nil {
		v.HistoryMB = float64(ser.Size()) / (1 << 20)
	}
	if lg != nil {
		v.LoadHosts, v.LoadRate = lg.n, lg.rate()
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	v.HeapMB, v.Routines = float64(ms.HeapAlloc)/(1<<20), runtime.NumGoroutine()
	return v
}

func (m *Module) apiStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, m.status())
}

func (m *Module) serveAsset(b []byte, ctype string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(b)
	}
}

// ---------------------------------------------------------------------------------------------------------
// Seiten: Go-Templates liefern Geruest, feste Texte und Startdaten (JSON im Element #m64-data); das Skript
// monitor64.js zeichnet Listen, Diagramme und Dialoge und spricht die API an.

// tab ist ein Reiter der Modulseiten (Untermenue wie im Entwurf).
type tab struct {
	Path     string
	Icon     string
	TitleKey string
	Active   bool
	Badge    int
}

func (m *Module) tabs(ctx context.Context, active string) []tab {
	t := []tab{{Path: "/monitor64", Icon: "bi-grid-1x2", TitleKey: "monitor64.tab.overview"},
		{Path: "/monitor64/problems", Icon: "bi-exclamation-triangle", TitleKey: "monitor64.tab.problems", Badge: m.store.openUnackedCount(ctx)},
		{Path: "/monitor64/maintenance", Icon: "bi-cone-striped", TitleKey: "monitor64.tab.maint"},
		{Path: "/monitor64/rules", Icon: "bi-sliders", TitleKey: "monitor64.tab.rules"},
		{Path: "/monitor64/notify", Icon: "bi-bell", TitleKey: "monitor64.tab.notify"},
		{Path: "/monitor64/settings", Icon: "bi-gear", TitleKey: "monitor64.tab.settings"}}
	for i := range t {
		t[i].Active = t[i].Path == active
	}
	return t
}

// pageData sind die Daten aller Seiten des Moduls.
type pageData struct {
	Page      string
	Tabs      []tab
	Title     string // letzte Stufe der Brotkrumen
	JS        map[string]any
	Host      *Host
	Settings  settingsOut
	Kinds     []ruleKind
	Groups    []string
	HostKinds []hostKind
	PublicKey string
	Port      int
	Running   bool
	Std       []stdGroup
	Fixed     []fixedRow
}

// Zeilen der Standard-Tabelle (Seite Schwellen, serverseitig mit den geltenden Werten).
type durOpt struct {
	Sec   int
	Label string
}

type stdRow struct {
	Kind, Label, Unit, Warn, Crit string
	For                           int
	ForOpts                       []durOpt
	NoFor                         bool
	Factor                        float64
}

type stdGroup struct {
	Group string
	Rows  []stdRow
}

type fixedRow struct {
	Kind, Label, Severity string
}

var durChoices = []int{0, 60, 300, 900, 1800, 3600, 86400}

// fmtLimit zeigt eine Schwelle im Eingabefeld (leer = keine; Dezimalkomma auf Deutsch).
func fmtLimit(l eval.Limit, factor float64, lang string) string {
	if l.Off {
		return ""
	}
	v := l.V
	if factor > 0 {
		v /= factor
	}
	s := strconv.FormatFloat(v, 'f', -1, 64)
	if lang == "de" {
		s = strings.Replace(s, ".", ",", 1)
	}
	return s
}

func (m *Module) stdRows(r *http.Request, std eval.Table, lang string) ([]stdGroup, []fixedRow) {
	durs := func(cur int) []durOpt {
		out := []durOpt{}
		found := false
		for _, s := range durChoices {
			out = append(out, durOpt{Sec: s, Label: m.t(r, "monitor64.dur."+strconv.Itoa(s))})
			found = found || s == cur
		}
		if !found {
			out = append(out, durOpt{Sec: cur, Label: m.t(r, "monitor64.dur.custom", "n", strconv.Itoa(cur/60))})
		}
		return out
	}
	var groups []stdGroup
	for _, g := range ruleGroups {
		sg := stdGroup{Group: g}
		for _, k := range ruleKinds {
			if k.Group != g {
				continue
			}
			rule := std[k.Kind]
			e := eval.Resolve(eval.Table{k.Kind: rule}, nil, eval.HostRef{}, eval.HostLevel{}, k.Kind)
			unit := k.Unit
			if unit == "days" || unit == "min" {
				unit = m.t(r, "monitor64.unit."+unit)
			}
			sec := int(time.Duration(e.For) / time.Second)
			sg.Rows = append(sg.Rows, stdRow{Kind: k.Kind, Label: m.t(r, "monitor64.kind."+kindKey(k.Kind)), Unit: unit, Warn: fmtLimit(e.Warn, k.Factor, lang),
				Crit: fmtLimit(e.Crit, k.Factor, lang), For: sec, ForOpts: durs(sec), NoFor: k.NoFor, Factor: k.Factor})
		}
		groups = append(groups, sg)
	}
	var fixed []fixedRow
	for _, k := range ruleKinds {
		if !k.State {
			continue
		}
		e := eval.Resolve(eval.Table{k.Kind: std[k.Kind]}, nil, eval.HostRef{}, eval.HostLevel{}, k.Kind)
		fixed = append(fixed, fixedRow{Kind: k.Kind, Label: m.t(r, "monitor64.kind."+kindKey(k.Kind)), Severity: string(e.Severity)})
	}
	return groups, fixed
}

// Crumb liefert die letzte Stufe der Brotkrumen (z. B. den Host-Namen).
func (d *pageData) Crumb() string { return d.Title }

var (
	reJSKey    = regexp.MustCompile(`\bL\('([a-z0-9_.]+)'`)
	jsKeysOnce sync.Once
	jsKeys     []string
)

// textKeys sind alle Texte, die das Skript nutzt (L('...') im Skript, unter monitor64.*).
func textKeys() []string {
	jsKeysOnce.Do(func() {
		seen := map[string]bool{}
		for _, mm := range reJSKey.FindAllSubmatch(bundleJS, -1) {
			k := string(mm[1])
			if !seen[k] {
				seen[k] = true
				jsKeys = append(jsKeys, k)
			}
		}
		sort.Strings(jsKeys)
	})
	return jsKeys
}

func (m *Module) t(r *http.Request, key string, args ...any) string {
	if m.g.T == nil {
		return key
	}
	return m.g.T(r, key, args...)
}

// basePage baut die gemeinsamen Daten einer Seite (Reiter, Texte und Beschreibungen fuer das Skript).
func (m *Module) basePage(r *http.Request, page, active string) *pageData {
	ctx := r.Context()
	texts := map[string]string{}
	for _, k := range textKeys() {
		texts[k] = m.t(r, "monitor64."+k)
	}
	for _, k := range coreTexts {
		texts[k] = m.t(r, "monitor64."+k)
	}
	kinds := map[string]string{}
	for _, k := range ruleKinds {
		kinds[k.Kind] = m.t(r, "monitor64.kind."+kindKey(k.Kind))
	}
	cats := map[string]string{}
	for _, c := range svcCategories {
		cats[c] = m.t(r, "monitor64.cat."+c)
	}
	hk := map[string][2]string{}
	for _, k := range hostKinds {
		hk[k.Kind] = [2]string{m.t(r, "monitor64.hostkind."+k.Kind+".title"), m.t(r, "monitor64.hostkind."+k.Kind+".sub")}
	}
	acc := map[string]string{}
	for _, a := range accessTypes {
		acc[a] = m.t(r, "monitor64.access."+a)
	}
	csrf, lang := "", "de"
	if m.g.CSRF != nil {
		csrf = m.g.CSRF(r)
	}
	if m.g.Lang != nil {
		lang = m.g.Lang(r)
	}
	running := m.scheduler() != nil
	return &pageData{Page: page, Tabs: m.tabs(ctx, active), Running: running, JS: map[string]any{
		"page": page, "csrf": csrf, "lang": lang, "t": texts, "kinds": ruleKinds, "kind_labels": kinds, "cats": cats, "cat_order": svcCategories,
		"host_kinds": hostKinds, "host_kind_labels": hk, "access_labels": acc, "running": running,
	}}
}

func (m *Module) render(w http.ResponseWriter, r *http.Request, name, titleKey string, d *pageData) {
	if d.Title == "" {
		d.Title = m.t(r, titleKey)
	}
	m.g.Render(w, r, http.StatusOK, "monitor64/"+name, titleKey, d)
}

func (m *Module) pageOverview(w http.ResponseWriter, r *http.Request) {
	d := m.basePage(r, "overview", "/monitor64")
	d.JS["overview"] = m.overview(r.Context())
	m.render(w, r, "overview", "nav.monitor64", d)
}

func (m *Module) pageHost(w http.ResponseWriter, r *http.Request) {
	hd, err := m.hostDetail(r.Context(), r.PathValue("uid"))
	if err != nil {
		http.Redirect(w, r, "/monitor64", http.StatusSeeOther)
		return
	}
	d := m.basePage(r, "host", "/monitor64")
	d.Host, d.Title = hd.Host, hd.Host.Name
	d.JS["host"] = hd
	d.JS["targets"] = m.targets(r.Context())
	m.render(w, r, "host", "monitor64.tab.overview", d)
}

func (m *Module) pageProblems(w http.ResponseWriter, r *http.Request) {
	m.render(w, r, "problems", "monitor64.tab.problems", m.basePage(r, "problems", "/monitor64/problems"))
}

func (m *Module) pageMaint(w http.ResponseWriter, r *http.Request) {
	m.render(w, r, "maintenance", "monitor64.tab.maint", m.basePage(r, "maint", "/monitor64/maintenance"))
}

func (m *Module) pageRules(w http.ResponseWriter, r *http.Request) {
	d := m.basePage(r, "rules", "/monitor64/rules")
	d.Kinds, d.Groups = ruleKinds, ruleGroups
	std := m.config().std
	lang, _ := d.JS["lang"].(string)
	d.Std, d.Fixed = m.stdRows(r, std, lang)
	d.JS["std"] = std
	m.render(w, r, "rules", "monitor64.tab.rules", d)
}

func (m *Module) pageNotify(w http.ResponseWriter, r *http.Request) {
	m.render(w, r, "notify", "monitor64.tab.notify", m.basePage(r, "notify", "/monitor64/notify"))
}

func (m *Module) pageSettings(w http.ResponseWriter, r *http.Request) {
	d := m.basePage(r, "settings", "/monitor64/settings")
	d.Settings = m.settings(r.Context())
	d.JS["traps"] = d.Settings.Traps
	m.render(w, r, "settings", "monitor64.tab.settings", d)
}

func (m *Module) pageNew(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d := m.basePage(r, "new", "/monitor64")
	d.HostKinds, d.Port = hostKinds, m64proto.DefaultPort
	if d.Running {
		d.PublicKey, _ = m.PublicKeyLine(ctx)
	}
	d.JS["public_key"] = d.PublicKey
	d.JS["port"] = d.Port
	d.JS["interval"] = m.defaultInterval(ctx)
	d.JS["targets"] = m.targets(ctx)
	m.render(w, r, "new", "monitor64.new.title", d)
}
