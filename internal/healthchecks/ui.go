package healthchecks

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/scheduler"
)

//go:embed templates
var templateFS embed.FS

// Templates liefert die Seiten des Moduls (module.Templater).
func (m *Module) Templates() fs.FS {
	sub, _ := fs.Sub(templateFS, "templates")
	return sub
}

// uiRoutes registriert die Seiten.
func (m *Module) uiRoutes(mux *http.ServeMux, g module.Guards) {
	m.g = g
	page := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /healthchecks", page(m.pageList))
	mux.Handle("GET /healthchecks/new", page(m.pageForm))
	mux.Handle("POST /healthchecks/new", page(m.pageFormSubmit))
	mux.Handle("POST /healthchecks/online-test", page(m.uiOnlineTest))
	mux.Handle("POST /healthchecks/bulk", page(m.pageBulk))
	mux.Handle("GET /healthchecks/{token}", page(m.pageDetail))
	mux.Handle("GET /healthchecks/{token}/edit", page(m.pageForm))
	mux.Handle("POST /healthchecks/{token}/edit", page(m.pageFormSubmit))
	mux.Handle("POST /healthchecks/{token}/action", page(m.pageAction))
	m.maintenanceRoutes(mux, page)
	m.incidentsRoutes(mux, page)
	m.statusPagesRoutes(mux, page)
	m.pveRoutes(mux, page)
	m.dockerRoutes(mux, page)
}

// ---------------------------------------------------------------- Darstellung

// Pill ist eine Messung in der Pillenleiste.
type Pill struct {
	Class   string // up, down, maintenance, dependent
	Label   string // Statuswort fuer den Tooltip
	When    string // Zeitpunkt, formatiert
	Latency string // "12.3 ms" oder leer
	Message string // gekuerzte Meldung
}

type row struct {
	Check    *Check
	State    string
	Status   string
	Latency  float64
	Pills    []Pill
	Changed  time.Time
	NextPush bool   // NextAt ist die Frist fuer den naechsten Push
	SyncErr  string // ipv64 hat die letzte Aenderung abgelehnt (z. B. Online-Limit)
	NextEst  bool   // NextAt geschaetzt (misst eine andere Messstelle: letzte Messung + Intervall)
	NextAt   time.Time
	Reason   string
	Message  string
	Maint    bool
	Retrying bool
	Stale    bool      // seit 3 Intervallen (mind. 5 min) nicht gemessen, z. B. messende Node offline
	LastAt   time.Time // letzte Messung
	LastSeen string    // Zustand bei der letzten Messung (bei Stale steht in State "unchecked")
	Quota    bool      // Stale, weil das Tageskontingent aufgebraucht ist (Online-Check, State "quota")
	CertDays int       // Restlaufzeit des Zertifikats (HTTPS), -1 = unbekannt
	CertTill time.Time // Ablaufdatum
}

// RowClass: leichte Farbe der Zeile – nicht geprueft (gelb) vor gestoert (rot) vor instabil bzw. teilweise
// gestoert (orange); sonst keine.
func (r row) RowClass() string {
	switch {
	case r.Stale:
		return "hc-row-stale"
	case r.State == "down":
		return "hc-row-down"
	case r.State == "flapping" || r.State == "degraded":
		return "hc-row-warn"
	}
	return ""
}

// CertClass: Farbe fuer die Restlaufzeit.
func (r row) CertClass() string {
	switch {
	case r.CertDays <= 7:
		return "danger"
	case r.CertDays <= 21:
		return "warning"
	}
	return "success"
}

// group ist ein Abschnitt der Liste (eine frei benannte Gruppe). Parts teilt sie weiter auf: in den Gruppen
// „Proxmox VE“ und „Docker“ je System bzw. Docker-Host (aufklappbar), sonst ein Teil ohne Namen.
type group struct {
	Key, Name        string
	Rows             []row
	Up, Down, Others int
	Parts            []group
}

// count zaehlt eine Zeile in die Zustaende der Gruppe.
func (g *group) count(r row) {
	g.Rows = append(g.Rows, r)
	switch r.State {
	case "up":
		g.Up++
	case "down", "flapping":
		g.Down++
	default:
		g.Others++
	}
}

type listData struct {
	Groups     []group
	Grouped    bool     // mindestens ein Check hat eine Gruppe
	QuotaToday int      // Online-Messungen heute (Tageskontingent)
	QuotaLimit int      // Tageskontingent (0 = unbegrenzt/standalone)
	QuotaNear  bool     // mindestens 90 % verbraucht
	Quota      *hcQuota // Karte unter der Tabelle (nur mit Tageskontingent, z. B. Free und Home/Supporter)
	// Online-Checks direkt ueber die API (Key hinterlegt, kein Sync)
	APIMode   bool
	Online    []onlineRow
	OnlineErr string
	AllGrps   []string // alle Gruppennamen (Filter, Vorschlaege)
	Rows      []row
	Types     []checks.Type
	Tags      []string
	States    []string
	Filter    map[string]string
	Sort      string
	Dir       string
	Counts    map[string]int
	Total     int
	// Konto-Leiste (verknuepft) und Filter nach Ausfuehrungsort/Node
	Acct  *acctBar
	Peers []Peer
}

// acctBar: Klasse, belegte Online-Messstellen, Ausfuehrungsorte und Nodes (wie im Portal).
type acctBar struct {
	Plan                  string
	Used, Limit, Locs     int
	Online, Local, Hybrid int
	NodesOn, NodesAll     int
}

var listStates = []string{"up", "down", "stabilizing", "flapping", "dependent", "unchecked", "quota", "pending", "paused"}

func (m *Module) liveRuntime(c *Check) scheduler.Runtime {
	if s := m.scheduler(); s != nil {
		if rt, ok := s.Runtime(c.Token); ok {
			return rt
		}
	}
	return c.Runtime
}

func (m *Module) rowOf(ctx context.Context, lang string, c *Check, pills map[string][]Pill) row {
	rt := m.liveRuntime(c)
	r := row{Check: c, State: string(rt.State), Status: string(rt.LastStatus), Latency: msf(rt.LastLatency), Pills: pills[c.Token],
		Changed: rt.Since, NextAt: rt.NextCheck, Reason: string(rt.LastReason), Message: rt.LastMessage,
		Maint: m.st.InMaintenance(ctx, c.Token, time.Now()), Retrying: rt.State == scheduler.StateUp && rt.ConsecutiveFail > 0, CertDays: -1}
	if r.State == "" {
		r.State = "pending"
	}
	r.LastAt, r.Stale = rt.LastCheck, stale(c, rt.LastCheck, r.State)
	if r.Stale { // nicht ueberwacht: der letzte Zustand ist unbekannt geworden, nicht mehr "OK"
		r.LastSeen, r.State = r.State, "unchecked"
		if c.Execution == "online" && m.quotaReached() { // Online-Check: ipv64 misst bis Mitternacht nicht
			r.State, r.Quota = "quota", true
		}
	}
	switch {
	case c.Type == checks.TypePush:
		r.NextAt, r.NextPush = time.Time{}, true
		if !rt.LastPush.IsZero() {
			period, grace := checks.PushWindow(c.Params)
			r.NextAt = rt.LastPush.Add(time.Duration(period+grace) * time.Second)
		}
	case !c.MeasuredHere() && !rt.LastCheck.IsZero() && c.Interval > 0:
		r.NextAt, r.NextEst = rt.LastCheck.Add(c.Interval), true
	}
	return r
}

// pillsFor liefert die letzten n Messungen je Check als Pillen (aelteste zuerst).
func (m *Module) pillsFor(ctx context.Context, lang string, loc *time.Location, n int) (map[string][]Pill, error) {
	tr := m.translator(lang)
	// je Check die letzten n Messungen ueber den Index (token, time) – nicht die ganze Tabelle durchnummerieren (das
	// dauerte mit wachsender Aufbewahrung bei jedem Aufruf der Uebersicht spuerbar)
	rows, err := m.st.r.QueryContext(ctx, `SELECT m.token, m.time, m.status, m.latency_ms, m.flags, m.reason, m.message FROM hc_checks c
		JOIN hc_measurements m ON m.node_seq IN (SELECT node_seq FROM hc_measurements WHERE token = c.token ORDER BY time DESC LIMIT ?)
		ORDER BY m.token, m.time`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]Pill{}
	for rows.Next() {
		var token, t, reason, message string
		var status, flags int
		var lat float64
		if err := rows.Scan(&token, &t, &status, &lat, &flags, &reason, &message); err != nil {
			return nil, err
		}
		class, label := "down", tr("hc.state.down")
		if status == 1 {
			class, label = "up", tr("hc.state.up")
		}
		if flags&FlagMaintenance != 0 {
			class = "maintenance"
			label += " · " + tr("hc.maintenance")
		} else if flags&FlagDependent != 0 {
			class = "dependent"
			label += " · " + tr("hc.state.dependent")
		}
		ts := pt(t)
		if loc != nil {
			ts = ts.In(loc)
		}
		when := ts.Format("02.01.2006 15:04:05")
		if lang != "de" {
			when = ts.Format("2006-01-02 15:04:05")
		}
		pl := Pill{Class: class, Label: label, When: when, Message: message}
		if lat > 0 {
			pl.Latency = fmt.Sprintf("%.1f ms", lat)
		}
		if r := []rune(message); len(r) > 90 {
			pl.Message = string(r[:90]) + "…"
		}
		out[token] = append(out[token], pl)
	}
	return out, rows.Err()
}

func (m *Module) pageList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	lang := m.g.Lang(r)
	list, err := m.st.Checks(ctx)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	pills, err := m.pillsFor(ctx, lang, m.g.Timezone(r), 30)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	certs := m.st.CertExpiries(ctx)
	q := r.URL.Query()
	f := map[string]string{"state": q.Get("state"), "type": q.Get("type"), "tag": q.Get("tag"), "group": q.Get("group"), "q": strings.TrimSpace(q.Get("q")),
		"exec": q.Get("exec"), "node": q.Get("node")}
	d := listData{Types: checks.Types, States: listStates, Filter: f, Sort: q.Get("sort"), Dir: q.Get("dir"), Counts: map[string]int{}}
	tagSet, grpSet := map[string]bool{}, map[string]bool{}
	if m.quota != nil {
		var locs int
		d.QuotaToday, d.QuotaLimit, locs = m.quota()
		d.QuotaNear = d.QuotaLimit > 0 && d.QuotaToday*10 >= d.QuotaLimit*9
		if d.QuotaLimit > 0 {
			perDay := 0
			for _, c := range list {
				perDay += CheckDailyCost(c, locs)
			}
			d.Quota = newHCQuota(d.QuotaToday, d.QuotaLimit, perDay, time.Now())
		}
	}
	if m.linked != nil && m.linked() {
		d.Peers = m.peers(ctx)
		a := &acctBar{NodesAll: len(d.Peers)}
		for _, p := range d.Peers {
			if p.Online || p.Self {
				a.NodesOn++
			}
		}
		if m.account != nil {
			a.Plan, a.Limit = m.account()
		}
		if m.quota != nil {
			_, _, a.Locs = m.quota()
		}
		a.Used = m.OnlinePoints(ctx, "", a.Locs)
		for _, c := range list {
			switch c.Execution {
			case "online":
				a.Online++
			case "both":
				a.Hybrid++
			default:
				a.Local++
			}
		}
		d.Acct = a
	}
	syncErrs := m.OutboxErrors(ctx)
	if key, cl := m.apiMode(ctx); key != "" {
		d.APIMode = true
		d.Online, d.OnlineErr = m.onlineChecks(ctx, key, cl)
	}
	viaAPI := map[string]bool{} // Online-Checks aus der API (Kopien aus der lokalen Gruppe nicht doppelt zeigen)
	for _, o := range d.Online {
		viaAPI[o.Token] = true
	}
	for _, c := range list {
		if viaAPI[c.Token] {
			continue
		}
		for _, t := range c.Tags {
			tagSet[t] = true
		}
		if c.Group != "" {
			grpSet[c.Group] = true
		}
		rw := m.rowOf(ctx, lang, c, pills)
		rw.SyncErr = syncErrs[c.Token]
		if t, ok := certs[c.Token]; ok {
			rw.CertTill, rw.CertDays = t, int(time.Until(t).Hours()/24)
		}
		d.Counts[rw.State]++
		d.Total++
		if st := f["state"]; st != "" && rw.State != st && (st != "problem" || !problemState(rw.State)) {
			continue
		}
		if f["type"] != "" && string(c.Type) != f["type"] {
			continue
		}
		if f["tag"] != "" && !contains(c.Tags, f["tag"]) {
			continue
		}
		if f["group"] != "" && c.Group != f["group"] {
			continue
		}
		if f["exec"] != "" && c.Execution != f["exec"] {
			continue
		}
		if f["node"] != "" && !measuredBy(c, f["node"]) {
			continue
		}
		if f["q"] != "" && !strings.Contains(strings.ToLower(c.Name+" "+c.Target+" "+c.Group+" "+strings.Join(c.Tags, " ")), strings.ToLower(f["q"])) {
			continue
		}
		d.Rows = append(d.Rows, rw) // Docker-Checks als normale Zeilen; Container des Hosts auf /healthchecks/docker
	}
	for t := range tagSet {
		d.Tags = append(d.Tags, t)
	}
	sort.Strings(d.Tags)
	for g := range grpSet {
		d.AllGrps = append(d.AllGrps, g)
	}
	sort.Slice(d.AllGrps, func(i, j int) bool { return strings.ToLower(d.AllGrps[i]) < strings.ToLower(d.AllGrps[j]) })
	sortRows(d.Rows, d.Sort, d.Dir == "desc")
	d.Grouped = len(d.AllGrps) > 0
	d.Groups = groupRows(d.Rows, d.AllGrps, m.g.T(r, "hc.group.none"), m.subGroupOf(ctx, r))
	m.g.Render(w, r, http.StatusOK, Name+"/list", "nav.healthchecks", d)
}

// groupRows verteilt die (schon sortierten) Zeilen auf Gruppen; Checks ohne Gruppe kommen zuletzt. sub liefert je
// Zeile der Gruppen „Proxmox VE“ und „Docker“ den Namen des Systems bzw. Docker-Hosts (nil bzw. "" = kein Teil).
func groupRows(rows []row, names []string, none string, sub func(row) string) []group {
	idx := map[string]int{}
	var out []group
	for i, n := range names {
		idx[n] = i
		out = append(out, group{Key: "g" + strconv.Itoa(i), Name: n})
	}
	out = append(out, group{Key: "g-none", Name: none})
	for _, r := range rows {
		i, ok := idx[r.Check.Group]
		if !ok {
			i = len(out) - 1
		}
		out[i].count(r)
	}
	res := out[:0]
	for _, g := range out {
		if len(g.Rows) == 0 {
			continue
		}
		g.Parts = []group{{Key: g.Key + "-p", Rows: g.Rows}}
		if sub != nil && (g.Name == pveCheckGroup || g.Name == dockerCheckGroup) {
			parts, pi := []group{{Key: g.Key + "-p"}}, map[string]int{"": 0}
			for _, r := range g.Rows {
				n := sub(r)
				i, ok := pi[n]
				if !ok {
					i = len(parts)
					pi[n] = i
					parts = append(parts, group{Key: g.Key + "-s" + strconv.Itoa(i), Name: n})
				}
				parts[i].count(r)
			}
			named := parts[1:]
			sort.SliceStable(named, func(i, j int) bool { return strings.ToLower(named[i].Name) < strings.ToLower(named[j].Name) })
			g.Parts = parts[:0]
			for _, p := range parts {
				if len(p.Rows) > 0 {
					g.Parts = append(g.Parts, p)
				}
			}
		}
		res = append(res, g)
	}
	return res
}

var stateOrder = map[string]int{"down": 0, "flapping": 1, "dependent": 2, "degraded": 2, "unchecked": 3, "stabilizing": 3, "quota": 4, "pending": 4, "up": 5, "paused": 6}

func sortRows(rows []row, key string, desc bool) {
	less := func(i, j int) bool {
		a, b := rows[i], rows[j]
		switch key {
		case "state":
			if stateOrder[a.State] != stateOrder[b.State] {
				return stateOrder[a.State] < stateOrder[b.State]
			}
		case "type":
			if a.Check.Type != b.Check.Type {
				return a.Check.Type < b.Check.Type
			}
		case "latency":
			if a.Latency != b.Latency {
				return a.Latency < b.Latency
			}
		case "changed":
			if !a.Changed.Equal(b.Changed) {
				return a.Changed.After(b.Changed)
			}
		case "next": // naechster Termin zuerst, ohne Termin ans Ende
			if a.NextAt.IsZero() != b.NextAt.IsZero() {
				return !a.NextAt.IsZero()
			}
			if !a.NextAt.Equal(b.NextAt) {
				return a.NextAt.Before(b.NextAt)
			}
		}
		return strings.ToLower(a.Check.Name) < strings.ToLower(b.Check.Name)
	}
	if desc {
		sort.SliceStable(rows, func(i, j int) bool { return less(j, i) })
	} else {
		sort.SliceStable(rows, less)
	}
}

// ---------------------------------------------------------------- Detailseite

type rangeStat struct {
	Range     string
	UpPercent float64
	AvgMS     float64
	Count     int
}

type detailData struct {
	StaleNodes string // nicht ueberwacht: die messenden Nodes (Hinweis auf der Detailseite)
	Channels   []channelOpt
	Row        row
	JSON       checkJSON
	Pills      []Pill
	Ranges     []rangeStat
	Events     []Event
	Incidents  []Incident
	Last       *Measurement
	LastJSON   string
	Params     map[string]any
	ParentName string
	Children   []*Check
	PushURL    string      // lokal an dieser Node (nur wenn sie den Push-Check misst)
	PushOnline string      // ueber ipv64 (verknuepft)
	Sources    []SourceRow // Messstellen (leer = nur diese Node)
	NodeNames  []string    // messende Nodes (mehrere moeglich)
	Diagnosis  string
	Notifier   string // wer benachrichtigt: Schluessel unter hc.notifier (groupnotify.go)
	NotifierBy string // Name der Node
}

func (m *Module) loadPage(w http.ResponseWriter, r *http.Request) *Check {
	token := r.PathValue("token")
	if !tokenRe.MatchString(token) {
		m.g.Render(w, r, http.StatusNotFound, Name+"/missing", "hc.missing", nil)
		return nil
	}
	c, err := m.st.Check(r.Context(), token)
	if err != nil {
		m.fail(w, r, err)
		return nil
	}
	if c == nil {
		m.g.Render(w, r, http.StatusNotFound, Name+"/missing", "hc.missing", nil)
		return nil
	}
	return c
}

func (m *Module) pageDetail(w http.ResponseWriter, r *http.Request) {
	c := m.loadPage(w, r)
	if c == nil {
		return
	}
	ctx := r.Context()
	lang := m.g.Lang(r)
	pills, err := m.pillsFor(ctx, lang, m.g.Timezone(r), 300) // reicht auch fuer breite Bildschirme
	if err != nil {
		m.fail(w, r, err)
		return
	}
	d := detailData{Row: m.rowOf(ctx, lang, c, pills), JSON: m.toJSON(c, r), Pills: pills[c.Token], PushURL: ""}
	if d.Row.Stale && c.Execution != "online" {
		d.StaleNodes = strings.Join(m.nodeNames(ctx, c.Nodes), ", ")
	}
	d.Row.SyncErr = m.OutboxErrors(ctx)[c.Token]
	d.Row.CertDays = -1
	if t, ok := m.st.CertExpiries(ctx)[c.Token]; ok {
		d.Row.CertTill, d.Row.CertDays = t, int(time.Until(t).Hours()/24)
	}
	now := time.Now().UTC()
	for _, rg := range []string{"24h", "30d", "1y"} {
		st, err := m.st.Stats(ctx, c.Token, rg, now)
		if err == nil {
			d.Ranges = append(d.Ranges, rangeStat{Range: rg, UpPercent: st.UpPercent, AvgMS: st.AvgMS, Count: st.Count})
		}
	}
	tr := m.translator(lang)
	d.Sources = m.sources(ctx, c, tr("hc.sources.this_node"))
	d.Diagnosis = diagnosis(d.Sources, tr)
	if c.Execution != "online" && len(c.Nodes) > 0 {
		d.NodeNames = m.nodeNames(ctx, c.Nodes)
	}
	d.Notifier, d.NotifierBy = m.notifiedBy(ctx, c)
	d.Events, _ = m.st.Events(ctx, c.Token, 50, 0)
	if m.hubEvents != nil && m.linked != nil && m.linked() {
		hctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		if hub, err := m.hubEvents(hctx, c.Token); err == nil {
			d.Events = mergeEvents(d.Events, hub, 50)
		}
		cancel()
	}
	d.Incidents, _ = m.st.Incidents(ctx, c.Token, 10)
	if ms, err := m.st.Measurements(ctx, c.Token, time.Time{}, time.Time{}, 1, 0); err == nil && len(ms) > 0 {
		d.Last = &ms[0]
		if b, err := json.MarshalIndent(ms[0].Details, "", "  "); err == nil {
			d.LastJSON = string(b)
		}
	}
	_ = json.Unmarshal(c.Params, &d.Params)
	if c.Parent != "" {
		if p, _ := m.st.Check(ctx, c.Parent); p != nil {
			d.ParentName = p.Name
		}
	}
	all, _ := m.st.Checks(ctx)
	for _, x := range all {
		if x.Parent == c.Token {
			d.Children = append(d.Children, x)
		}
	}
	if c.Type == checks.TypePush {
		if c.MeasuredHere() || (m.linked != nil && m.linked()) {
			d.PushURL = d.JSON.PushURL // misst sie nicht selbst, reicht die Node den Push ueber ipv64 weiter
		}
		if (m.linked != nil && m.linked()) || c.Execution == "online" {
			d.PushOnline = OnlinePushURL + c.Token
		}
	}
	if chans, err := m.channels(ctx); err == nil {
		for _, ch := range chans {
			sel := false
			for _, id := range c.Channels {
				if id == ch.ID {
					sel = true
				}
			}
			if sel || (len(c.Channels) == 0 && ch.Default) {
				d.Channels = append(d.Channels, channelOpt{ID: ch.ID, Name: ch.Name, Type: string(ch.Type), Default: ch.Default, Selected: sel})
			}
		}
	}
	m.g.Render(w, r, http.StatusOK, Name+"/detail", "nav.healthchecks", d)
}

// ---------------------------------------------------------------- Formular

// Crumb: Name des Checks in den Brotkrumen.
func (d detailData) Crumb() string {
	if d.Row.Check != nil {
		return d.Row.Check.Name
	}
	return ""
}

type formData struct {
	Edit        bool
	Token       string
	Form        map[string]string
	Errors      map[string]string
	Types       []checks.Type
	Parents     []*Check
	Groups      []string           // vorhandene Gruppen (Vorschlaege)
	Containers  []checks.Container // Docker: Container des Hosts (Vorschlaege)
	DockerErr   string
	DockerHost  string
	IPModes     []string
	Error       string
	Channels    []channelOpt
	ChanDefault string   // Namen der Standardkanaele (gelten ohne Auswahl)
	SysChan     *sysChan // Check „als Check“ eines Systems: Kanaele kommen aus dessen Regeln
	// Hybrid-Vorbereitung: Messstellen und Bewertung (aktiv erst mit ipv64-Verknuepfung)
	Policies   []string
	Locations  []string
	Executions []string
	Linked     bool
	Peers      []Peer // Nodes des Accounts (messende Nodes waehlen)
	// Tageskontingent: Vorschau im Formular (Verbrauch der uebrigen Checks, heute, Limit, Standorte je Check)
	ProjOther, QuotaToday, QuotaLimit, AccLocs int
	APIMode                                    bool // Online-Check direkt ueber die API v2 (online_api.go)
	ViaCluster                                 bool // nicht verknuepft: Online/Hybrid ueber die weiterreichende Node des Clusters
	// DNS-Check: Auswahl im Formular
	DNSRecordTypes, DNSExpects []string
	WhoisSources               []string
	// Online-Messstellen des Accounts ohne diesen Check und Limit der Klasse (0 = unbegrenzt/unbekannt)
	PointsUsed, PointsLimit int
	// Neuer Check aus einem ueberwachten System (form_systems.go)
	PickPVE, PickDocker []sysPick
}

type channelOpt struct {
	ID       int64
	Name     string
	Type     string
	Default  bool
	Selected bool
}

// formDefaults sind die Vorgaben eines neuen Checks.
func formDefaults() map[string]string {
	return map[string]string{
		"type": "http", "interval_seconds": "60", "retry_interval_seconds": "20", "retries": "1", "stabilize": "3",
		"connect_timeout_seconds": "5", "timeout_seconds": "10", "ip_mode": "auto", "notify_down": "on", "notify_up": "on",
		"execution": "local", "policy": PolicyAll, "locations": "nbg,fsn",
		"method": "GET", "accept_status": "200-299", "follow_redirects": "on", "max_redirects": "5",
		"count": "3", "max_loss_percent": "50", "cert_port": "443", "min_days": "14", "port_expect": "open",
		"period_seconds": "3600", "grace_seconds": "600", "cert_min_days": "14",
	}
}

// formFromCheck fuellt das Formular aus einem Check.
func formFromCheck(c *Check) map[string]string {
	f := formDefaults()
	f["name"], f["type"], f["target"] = c.Name, string(c.Type), c.Target
	f["interval_seconds"] = strconv.Itoa(int(c.Interval.Seconds()))
	f["retry_interval_seconds"] = strconv.Itoa(int(c.RetryInterval.Seconds()))
	f["retries"], f["stabilize"] = strconv.Itoa(c.Retries), strconv.Itoa(c.Stabilize)
	f["connect_timeout_seconds"] = strconv.FormatFloat(c.ConnectTimeout.Seconds(), 'f', -1, 64)
	f["timeout_seconds"] = strconv.FormatFloat(c.TotalTimeout.Seconds(), 'f', -1, 64)
	f["ip_mode"], f["tags"], f["description"], f["parent"] = string(c.IPMode), strings.Join(c.Tags, ", "), c.Description, c.Parent
	f["group"] = c.Group
	f["invert"], f["critical"], f["paused"] = onOff(c.Invert), onOff(c.Critical), onOff(c.Paused)
	f["notify_down"], f["notify_up"] = onOff(c.NotifyDown), onOff(c.NotifyUp)
	f["repeat_minutes"] = strconv.Itoa(c.RepeatMinutes)
	f["execution"], f["policy"], f["notify_degraded"] = c.Execution, c.Policy, onOff(c.NotifyDegraded)
	f["nodes"] = strings.Join(c.Nodes, ",")
	if len(c.Locations) > 0 {
		f["locations"] = strings.Join(c.Locations, ",")
	}
	ids := make([]string, 0, len(c.Channels))
	for _, id := range c.Channels {
		ids = append(ids, strconv.FormatInt(id, 10))
	}
	f["channels"] = strings.Join(ids, ",")
	var p map[string]any
	_ = json.Unmarshal(c.Params, &p)
	str := func(k string) string {
		if v, ok := p[k]; ok && v != nil {
			switch t := v.(type) {
			case float64:
				return strconv.FormatFloat(t, 'f', -1, 64)
			case bool:
				return onOff(t)
			case string:
				return t
			}
		}
		return ""
	}
	set := func(form, key string) {
		if v := str(key); v != "" {
			f[form] = v
		}
	}
	switch c.Type {
	case checks.TypeHTTP, checks.TypeKeyword, checks.TypeJSON:
		set("method", "method")
		set("accept_status", "accept_status")
		if v, ok := p["follow_redirects"]; ok {
			f["follow_redirects"] = onOff(v == true)
		}
		set("max_redirects", "max_redirects")
		f["insecure_tls"] = str("insecure_tls")
		set("body", "body")
		set("basic_user", "basic_user")
		set("basic_password", "basic_password")
		set("keyword", "keyword")
		f["keyword_absent"] = str("keyword_absent")
		var hp checks.HTTPParams
		if json.Unmarshal(c.Params, &hp) == nil {
			f["json_rules"] = checks.FormatJSONRules(hp.JSONRules)
			f["json_any"] = onOff(hp.JSONAny)
		}
		f["cert_min_days"] = str("cert_min_days")
		if f["cert_min_days"] == "" {
			f["cert_min_days"] = "0"
		}
		if h, ok := p["headers"].(map[string]any); ok {
			var lines []string
			for k, v := range h {
				lines = append(lines, k+": "+fmt.Sprint(v))
			}
			sort.Strings(lines)
			f["headers"] = strings.Join(lines, "\n")
		}
	case checks.TypeICMP:
		set("count", "count")
		set("max_loss_percent", "max_loss_percent")
		set("max_latency_ms", "max_latency_ms")
	case checks.TypeTCP:
		set("tcp_port", "port")
		set("send", "send")
		set("expect", "expect")
		f["tcp_tls"] = str("tls")
	case checks.TypePort:
		set("port_port", "port")
		set("port_expect", "expect")
	case checks.TypeCert:
		set("cert_port", "port")
		set("min_days", "min_days")
		set("server_name", "server_name")
		f["skip_chain"], f["skip_hostname"] = str("skip_chain"), str("skip_hostname")
	case checks.TypePush:
		set("period_seconds", "period_seconds")
		set("grace_seconds", "grace_seconds")
	case checks.TypeDocker:
		set("docker_host", "host")
		set("docker_system", "system") // Anzeige-Name des Docker-Hosts bleibt beim Bearbeiten erhalten
	case checks.TypeProxmox:
		f["pve_params"] = string(c.Params) // System und Gast stehen fest (Proxmox VE → „als Check“)
	case checks.TypeWhois:
		var wp checks.WhoisParams
		_ = json.Unmarshal(c.Params, &wp)
		f["whois_source"] = wp.Source
		if wp.MinDays != nil {
			f["whois_min_days"] = strconv.Itoa(*wp.MinDays)
		}
		f["whois_contains"] = strings.Join(wp.Contains, "\n")
	case checks.TypeDNS:
		var dp checks.DNSParams
		_ = json.Unmarshal(c.Params, &dp)
		f["dns_record_type"], f["dns_resolver"], f["dns_server"], f["dns_expect"] = dp.RecordType, dp.Resolver, dp.Server, dp.Expect
		f["dns_values"] = strings.Join(dp.Values, "\n")
		f["dns_dnssec"] = onOff(dp.DNSSEC)
		if dp.MinTTL > 0 {
			f["dns_min_ttl"] = strconv.Itoa(dp.MinTTL)
		}
	}
	return f
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return ""
}

// checkFromForm baut die API-Eingabe aus dem Formular.
func checkFromForm(r *http.Request) (checkJSON, error) {
	v := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	on := func(k string) bool { return r.PostFormValue(k) == "on" }
	intp := func(k string) (*int, error) {
		s := v(k)
		if s == "" {
			return nil, nil
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return nil, fmt.Errorf("%s: not a number", k)
		}
		return &n, nil
	}
	floatp := func(k string) (*float64, error) {
		s := v(k)
		if s == "" {
			return nil, nil
		}
		f, err := strconv.ParseFloat(strings.ReplaceAll(s, ",", "."), 64)
		if err != nil {
			return nil, fmt.Errorf("%s: not a number", k)
		}
		return &f, nil
	}
	var err error
	in := checkJSON{Name: v("name"), Type: v("type"), Target: v("target"), IPMode: v("ip_mode"), Description: v("description"),
		Execution: v("execution"), Policy: v("policy"), Locations: r.Form["locations"]}
	if in.Locations == nil {
		in.Locations = []string{}
	}
	if v("nodes_present") == "1" {
		in.Nodes = r.Form["nodes"]
		if in.Nodes == nil {
			in.Nodes = []string{selfNodeID()} // nichts gewaehlt: diese Node
		}
	}
	if in.IntervalSeconds, err = intp("interval_seconds"); err != nil {
		return in, err
	}
	if in.RetryIntervalSeconds, err = intp("retry_interval_seconds"); err != nil {
		return in, err
	}
	if in.Retries, err = intp("retries"); err != nil {
		return in, err
	}
	if in.Stabilize, err = intp("stabilize"); err != nil {
		return in, err
	}
	if in.ConnectTimeoutSeconds, err = floatp("connect_timeout_seconds"); err != nil {
		return in, err
	}
	if in.TimeoutSeconds, err = floatp("timeout_seconds"); err != nil {
		return in, err
	}
	if in.RepeatMinutes, err = intp("repeat_minutes"); err != nil {
		return in, err
	}
	b := func(x bool) *bool { return &x }
	in.Invert, in.Critical, in.Paused = b(on("invert")), b(on("critical")), b(on("paused"))
	in.NotifyDown, in.NotifyUp, in.NotifyDegraded = b(on("notify_down")), b(on("notify_up")), b(on("notify_degraded"))
	parent := v("parent")
	in.Parent = &parent
	grp := v("group")
	in.Group = &grp
	in.Tags = []string{}
	for _, t := range strings.Split(v("tags"), ",") {
		if t = strings.TrimSpace(t); t != "" {
			in.Tags = append(in.Tags, t)
		}
	}
	in.Channels = []int64{}
	_ = r.ParseForm()
	for _, id := range r.PostForm["channels"] {
		if n, err := strconv.ParseInt(id, 10, 64); err == nil {
			in.Channels = append(in.Channels, n)
		}
	}
	p := map[string]any{}
	num := func(key, form string) error {
		if s := v(form); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil {
				return fmt.Errorf("%s: not a number", form)
			}
			p[key] = n
		}
		return nil
	}
	switch checks.Type(in.Type) {
	case checks.TypeHTTP, checks.TypeKeyword, checks.TypeJSON:
		if s := v("method"); s != "" {
			p["method"] = s
		}
		if s := v("accept_status"); s != "" {
			p["accept_status"] = s
		}
		p["follow_redirects"] = on("follow_redirects")
		if err := num("max_redirects", "max_redirects"); err != nil {
			return in, err
		}
		if on("insecure_tls") {
			p["insecure_tls"] = true
		}
		if s := r.PostFormValue("body"); strings.TrimSpace(s) != "" {
			p["body"] = s
		}
		if s := v("basic_user"); s != "" {
			p["basic_user"] = s
			p["basic_password"] = r.PostFormValue("basic_password")
		}
		if h := strings.TrimSpace(r.PostFormValue("headers")); h != "" {
			hm := map[string]string{}
			for _, line := range strings.Split(h, "\n") {
				if k, val, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) != "" {
					hm[strings.TrimSpace(k)] = strings.TrimSpace(val)
				}
			}
			p["headers"] = hm
		}
		if checks.Type(in.Type) == checks.TypeKeyword {
			p["keyword"] = v("keyword")
			if on("keyword_absent") {
				p["keyword_absent"] = true
			}
		}
		if checks.Type(in.Type) == checks.TypeJSON {
			rules, err := checks.ParseJSONRules(r.PostFormValue("json_rules"))
			if err != nil {
				return in, fmt.Errorf("json_rules: %w", err)
			}
			p["json_rules"] = rules
			if on("json_any") {
				p["json_any"] = true
			}
		}
		if n, err := strconv.Atoi(strings.TrimSpace(v("cert_min_days"))); err == nil && n > 0 {
			p["cert_min_days"] = n
		}
	case checks.TypeICMP:
		for _, k := range []string{"count", "max_loss_percent", "max_latency_ms"} {
			if err := num(k, k); err != nil {
				return in, err
			}
		}
	case checks.TypeTCP:
		if err := num("port", "tcp_port"); err != nil {
			return in, err
		}
		if s := v("send"); s != "" {
			p["send"] = s
		}
		if s := v("expect"); s != "" {
			p["expect"] = s
		}
		if on("tcp_tls") {
			p["tls"] = true
		}
	case checks.TypePort:
		if err := num("port", "port_port"); err != nil {
			return in, err
		}
		p["expect"] = v("port_expect")
	case checks.TypeCert:
		if err := num("port", "cert_port"); err != nil {
			return in, err
		}
		if err := num("min_days", "min_days"); err != nil {
			return in, err
		}
		if s := v("server_name"); s != "" {
			p["server_name"] = s
		}
		if on("skip_chain") {
			p["skip_chain"] = true
		}
		if on("skip_hostname") {
			p["skip_hostname"] = true
		}
	case checks.TypeDocker:
		if s := strings.TrimSpace(v("docker_host")); s != "" {
			p["host"] = s
		}
		if s := v("docker_system"); s != "" {
			p["system"] = s
		}
	case checks.TypeWhois:
		if s := v("whois_source"); s != "" && s != "auto" {
			p["source"] = s
		}
		if err := num("min_days", "whois_min_days"); err != nil {
			return in, err
		}
		var rules []string
		for _, line := range strings.Split(r.PostFormValue("whois_contains"), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				rules = append(rules, line)
			}
		}
		if len(rules) > 0 {
			p["contains"] = rules
		}
	case checks.TypeDNS:
		p["record_type"], p["resolver"], p["expect"] = v("dns_record_type"), v("dns_resolver"), v("dns_expect")
		if v("dns_resolver") == "server" {
			p["server"] = v("dns_server")
		}
		var vals []string
		for _, line := range strings.Split(r.PostFormValue("dns_values"), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				vals = append(vals, line)
			}
		}
		if len(vals) > 0 {
			p["values"] = vals
		}
		if on("dns_dnssec") {
			p["dnssec"] = true
		}
		if err := num("min_ttl", "dns_min_ttl"); err != nil {
			return in, err
		}
	case checks.TypePush:
		if err := num("period_seconds", "period_seconds"); err != nil {
			return in, err
		}
		if err := num("grace_seconds", "grace_seconds"); err != nil {
			return in, err
		}
	case checks.TypeProxmox: // unveraendert aus dem verborgenen Feld; das Ziel ist der Key
		var pp checks.ProxmoxParams
		if err := json.Unmarshal([]byte(v("pve_params")), &pp); err != nil {
			return in, fmt.Errorf("proxmox: %w", err)
		}
		in.Target = pp.Key
		in.Params, _ = json.Marshal(pp)
		return in, nil
	}
	in.Params, _ = json.Marshal(p)
	return in, nil
}

func (m *Module) formPage(w http.ResponseWriter, r *http.Request, status int, d formData) {
	all, _ := m.st.Checks(r.Context())
	seen := map[string]bool{}
	for _, c := range all {
		if c.Token != d.Token {
			d.Parents = append(d.Parents, c)
		}
		if c.Group != "" && !seen[c.Group] {
			seen[c.Group] = true
			d.Groups = append(d.Groups, c.Group)
		}
	}
	sort.Strings(d.Groups)
	d.DockerHost = checks.DefaultDockerHost()
	cctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	var derr error
	if d.Containers, derr = checks.ListContainersVia(cctx, m.dockerRemote, d.Form["docker_host"]); derr != nil {
		d.DockerErr = derr.Error()
	}
	cancel()
	d.Types = checks.Types
	if d.Form["type"] == string(checks.TypeProxmox) { // nur ueber Proxmox VE angelegt, hier nur bearbeiten
		d.Types = append(append([]checks.Type{}, checks.Types...), checks.TypeProxmox)
	}
	if !d.Edit && !d.APIMode { // neu: Docker-Container und Proxmox-Maschinen aus den ueberwachten Systemen waehlen
		d.Types = nil
		for _, t := range checks.Types {
			if t != checks.TypeDocker {
				d.Types = append(d.Types, t)
			}
		}
		d.Types = append(d.Types, sysTypePVE, sysTypeDocker)
		d.PickPVE, d.PickDocker = m.sysPicks(r.Context(), false), m.sysPicks(r.Context(), true)
		if d.Form["type"] == string(checks.TypeDocker) { // alte Links (?type=docker): Auswahl ueber den Docker-Host
			d.Form["type"] = string(sysTypeDocker)
		}
	}
	d.IPModes = []string{"auto", "ipv4", "ipv6", "both"}
	d.DNSRecordTypes, d.DNSExpects = checks.DNSRecordTypes, checks.DNSExpects
	d.WhoisSources = checks.WhoisSources
	d.Policies, d.Locations, d.Executions = Policies, KnownLocations, []string{"local", "online", "both"}
	d.Linked = m.linked != nil && m.linked()
	d.ViaCluster = !d.Linked && m.onlineOK()
	if d.Linked && m.quota != nil {
		d.QuotaToday, d.QuotaLimit, d.AccLocs = m.quota()
		d.ProjOther = m.DailyProjection(r.Context(), d.Token, d.AccLocs)
		d.PointsUsed = m.OnlinePoints(r.Context(), d.Token, d.AccLocs)
		if m.account != nil {
			_, d.PointsLimit = m.account()
		}
	}
	if d.Linked || (m.groupPeers != nil && len(m.groupPeers(r.Context())) > 0) { // auch in der lokalen Gruppe ohne hub
		d.Peers = m.peers(r.Context())
		for _, item := range []string{ClusterItemProxmox, ClusterItemDocker} { // Docker/Proxmox: nur diese Nodes waehlbar
			for _, p := range m.clusterMembers(r.Context(), item) {
				for i := range d.Peers {
					if d.Peers[i].ID == p.ID {
						d.Peers[i].Cluster = strings.TrimSpace(d.Peers[i].Cluster + " " + item)
					}
				}
			}
		}
		if d.Form["nodes"] == "" {
			d.Form["nodes"] = selfNodeID() // neu bzw. bisher nur diese Node
		}
	}
	if m.dispatcher != nil {
		selected := map[string]bool{}
		for _, id := range strings.Split(d.Form["channels"], ",") {
			selected[strings.TrimSpace(id)] = true
		}
		if chans, err := m.channels(r.Context()); err == nil {
			var defs []string
			for _, ch := range chans {
				d.Channels = append(d.Channels, channelOpt{ID: ch.ID, Name: ch.Name, Type: string(ch.Type), Default: ch.Default, Selected: selected[strconv.FormatInt(ch.ID, 10)]})
				if ch.Default {
					defs = append(defs, ch.Name)
				}
			}
			d.ChanDefault = strings.Join(defs, ", ")
		}
	}
	if d.Edit {
		d.SysChan = m.sysChanOf(r.Context(), d.Token)
	}
	if d.APIMode { // Online-Check bei ipv64: nur online, ohne lokale Kanaele, Eltern-Checks und Docker
		d.Executions, d.Channels, d.Parents, d.Peers = []string{"online"}, nil, nil, nil
		d.Types = nil
		for _, t := range checks.Types {
			if t != checks.TypeDocker {
				d.Types = append(d.Types, t)
			}
		}
	}
	if d.Errors == nil {
		d.Errors = map[string]string{}
	}
	title := "hc.new"
	if d.Edit {
		title = "hc.edit"
	}
	m.g.Render(w, r, status, Name+"/form", title, d)
}

func (m *Module) pageForm(w http.ResponseWriter, r *http.Request) {
	d := formData{Form: formDefaults()}
	if r.PathValue("token") != "" {
		c := m.loadPage(w, r)
		if c == nil {
			return
		}
		d.Edit, d.Token, d.Form = true, c.Token, formFromCheck(c)
	} else if t := r.URL.Query().Get("type"); t != "" {
		d.Form["type"] = t
		if v := strings.TrimSpace(r.URL.Query().Get("target")); v != "" {
			d.Form["target"] = v
		}
		if v := strings.TrimSpace(r.URL.Query().Get("name")); v != "" {
			d.Form["name"] = v
		}
		if v := strings.TrimSpace(r.URL.Query().Get("sys")); v != "" { // vorgewaehltes System (Docker-/Proxmox-Seite)
			d.Form["sys_id_docker"], d.Form["sys_id_proxmox"] = v, v
		}
	}
	m.formPage(w, r, http.StatusOK, d)
}

func (m *Module) pageFormSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var c *Check
	edit := r.PathValue("token") != ""
	if edit {
		if c = m.loadPage(w, r); c == nil {
			return
		}
	} else {
		if kind, ok := strings.CutPrefix(r.PostFormValue("type"), "sys:"); ok && (kind == "proxmox" || kind == "docker") {
			m.formSystemCheck(w, r, kind)
			return
		}
		c = &Check{Token: NewToken()}
	}
	d := formData{Edit: edit, Token: c.Token}
	in, err := checkFromForm(r)
	if err == nil && edit && m.sysChanOf(ctx, c.Token) != nil {
		in.Channels = nil // Kanaele kommen aus den Regeln des Systems (Formular zeigt sie nur an)
	}
	if err == nil {
		c.UpdatedBy = m.g.Actor(r)
		oldType := c.Type
		if err = splitPort(c, &in); err == nil {
			err = m.apply(c, in, !edit)
		}
		if err == nil && c.Parent != "" {
			if cyc, cerr := m.parentCycle(r, c.Token, c.Parent); cerr != nil || cyc {
				err = fmt.Errorf("parent: %s", errText(cerr, "would create a cycle"))
			}
		}
		if err == nil {
			if edit {
				err = m.st.Update(ctx, c)
			} else {
				err = m.st.Insert(ctx, c)
			}
			if err == nil {
				c, _ = m.st.Check(ctx, c.Token)
				if s := m.scheduler(); s != nil {
					var rt *scheduler.Runtime
					if edit && oldType == c.Type {
						if live, ok := s.Runtime(c.Token); ok {
							rt = &live
						}
					}
					upsertSched(s, c, rt)
				}
				m.audit(r, map[bool]string{true: "check.update", false: "check.create"}[edit], c)
				m.g.Flash(w, r, "success", m.g.T(r, "common.saved"))
				http.Redirect(w, r, "/healthchecks/"+c.Token, http.StatusSeeOther)
				return
			}
		}
	}
	// Fehler: Formular mit Eingaben und Meldung erneut zeigen
	_ = r.ParseForm()
	d.Form = formDefaults()
	for k := range r.PostForm {
		d.Form[k] = r.PostFormValue(k)
	}
	for _, k := range []string{"invert", "critical", "paused", "notify_down", "notify_up", "follow_redirects", "insecure_tls", "keyword_absent", "tcp_tls", "skip_chain", "skip_hostname"} {
		if r.PostFormValue(k) != "on" {
			d.Form[k] = ""
		}
	}
	d.Form["channels"] = strings.Join(r.PostForm["channels"], ",")
	d.Error = err.Error()
	m.formPage(w, r, http.StatusUnprocessableEntity, d)
}

// ---------------------------------------------------------------- Aktionen

// Foreign: Check einer anderen Node. Jede Node des Accounts darf ihn trotzdem bearbeiten, pausieren,
// loeschen und messen lassen; nur die Messstelle eines Docker-Checks bleibt bei der Container-Node.
func (c *Check) Foreign() bool { return c.Owner == "other" }

// DisplayTarget: Ziel fuer die Uebersicht (mit Port bei TCP/Port).
func (c *Check) DisplayTarget() string { return checks.DisplayTarget(c.Definition()) }

// TargetBadge: Symbol und Kurztext des Ziels fuer die Uebersicht (URL ohne https:// und ohne "/" am Ende).
func (c *Check) TargetBadge() Badge {
	t := c.DisplayTarget()
	switch c.Type {
	case checks.TypeHTTP, checks.TypeKeyword, checks.TypeJSON:
		icon := "bi-lock-fill"
		if strings.HasPrefix(strings.ToLower(t), "http://") {
			icon = "bi-unlock"
		}
		short := t
		if i := strings.Index(short, "://"); i >= 0 {
			short = short[i+3:]
		}
		return Badge{Text: strings.TrimSuffix(short, "/"), Class: icon}
	case checks.TypeTCP, checks.TypePort:
		return Badge{Text: t, Class: "bi-plug"}
	case checks.TypeICMP:
		return Badge{Text: t, Class: "bi-broadcast-pin"}
	case checks.TypeCert:
		return Badge{Text: t, Class: "bi-shield-lock"}
	case checks.TypeWhois:
		return Badge{Text: t, Class: "bi-person-vcard"}
	case checks.TypeDocker:
		return Badge{Text: t, Class: "bi-box"}
	case checks.TypeProxmox:
		return Badge{Text: t, Class: "bi-hdd-rack"}
	case checks.TypeDNS:
		var p checks.DNSParams
		_ = json.Unmarshal(c.Params, &p)
		rt := strings.ToUpper(p.RecordType)
		if rt == "" {
			rt = "A"
		}
		return Badge{Text: rt + " " + strings.TrimSuffix(t, "."), Class: "bi-signpost-split"}
	}
	return Badge{Text: t, Class: "bi-bullseye"}
}

// Runnable: "Jetzt pruefen" geht bei allen Checks mit Node-Messstellen (hier oder ueber den hub).
func (c *Check) Runnable() bool { return c.Type != checks.TypePush && c.Execution != "online" }

// runNow misst sofort: hier, wenn diese Node misst, und ueber den hub bei den anderen messenden Nodes.
func (m *Module) runNow(c *Check) error {
	ran := false
	if c.MeasuredHere() {
		if s := m.scheduler(); s != nil && s.RunNow(c.Token) {
			ran = true
		}
	}
	if m.runRemote != nil && m.linked != nil && m.linked() && (!c.MeasuredHere() || len(c.Nodes) > 1) && m.runRemote(c.Token) {
		ran = true
	}
	if !ran {
		return errors.New("no measuring node reachable")
	}
	return nil
}

func (m *Module) pageAction(w http.ResponseWriter, r *http.Request) {
	c := m.loadPage(w, r)
	if c == nil {
		return
	}
	action := r.PostFormValue("action")
	back := "/healthchecks/" + c.Token
	if r.PostFormValue("back") == "list" {
		back = "/healthchecks"
	} else if r.PostFormValue("back") == "docker" {
		back = dockerPath
	}
	if err := m.doAction(r, c, action); err != nil {
		m.g.Flash(w, r, "danger", err.Error())
	} else {
		m.g.Flash(w, r, "success", m.g.T(r, "hc.done."+action, "name", c.Name))
	}
	if action == "delete" && back != dockerPath {
		back = "/healthchecks"
	}
	if action == "clone" {
		if last := r.Header.Get("X-Clone-Token"); last != "" {
			back = "/healthchecks/" + last + "/edit"
		}
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

func (m *Module) doAction(r *http.Request, c *Check, action string) error {
	ctx := r.Context()
	if action == "run" && !c.Runnable() && c.Type != checks.TypePush {
		return fmt.Errorf("%s", m.g.T(r, "hc.run_remote"))
	}
	switch action {
	case "pause", "resume":
		paused := action == "pause"
		if err := m.st.SetPaused(ctx, c.Token, paused, m.actor(r)); err != nil {
			return err
		}
		nc, _ := m.st.Check(ctx, c.Token)
		if s := m.scheduler(); s != nil && nc != nil {
			upsertSched(s, nc, nil)
		}
		m.PushState(c.Token)
		m.audit(r, "check."+action, c)
	case "run":
		if c.Type == checks.TypePush {
			return fmt.Errorf("%s", m.g.T(r, "hc.run_push"))
		}
		if err := m.runNow(c); err != nil {
			return fmt.Errorf("%s", m.g.T(r, "hc.run_unreachable"))
		}
		m.audit(r, "check.run", c)
	case "clone":
		n := *c
		n.Token, n.Name, n.Paused, n.Revision, n.UpdatedBy, n.Runtime = NewToken(), c.Name+" (copy)", true, 0, m.actor(r), scheduler.Runtime{}
		if c.Owner == "other" {
			n.Execution = "local" // Kopie eines Checks einer anderen Node misst diese Node selbst
		}
		n.Owner = "self"
		if err := m.st.Insert(ctx, &n); err != nil {
			return err
		}
		if nc, _ := m.st.Check(ctx, n.Token); nc != nil {
			if s := m.scheduler(); s != nil {
				upsertSched(s, nc, nil)
			}
			m.audit(r, "check.clone", nc)
			r.Header.Set("X-Clone-Token", n.Token)
		}
	case "delete":
		if s := m.scheduler(); s != nil {
			s.Remove(c.Token)
		}
		if err := m.st.Delete(ctx, c.Token); err != nil {
			return err
		}
		m.audit(r, "check.delete", c)
	default:
		return fmt.Errorf("unknown action")
	}
	return nil
}

func (m *Module) pageBulk(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	action := r.PostFormValue("action")
	n := 0
	for _, token := range r.PostForm["tokens"] {
		if !tokenRe.MatchString(token) {
			continue
		}
		c, err := m.st.Check(r.Context(), token)
		if err != nil || c == nil {
			continue
		}
		if action == "clone" {
			continue
		}
		if action == "tag" || action == "untag" {
			if m.bulkTag(r, c, action == "tag", r.PostFormValue("tag")) {
				n++
			}
			continue
		}
		if err := m.doAction(r, c, action); err == nil {
			n++
		}
	}
	if action != "clone" {
		m.auditBulk(r, action, r.PostFormValue("tag"), n, len(r.PostForm["tokens"]))
	}
	m.g.Flash(w, r, "success", m.g.T(r, "hc.bulk.done", "count", n))
	http.Redirect(w, r, "/healthchecks", http.StatusSeeOther)
}

func (m *Module) fail(w http.ResponseWriter, r *http.Request, err error) {
	m.log.Error("page failed", "path", r.URL.Path, "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// ---------------------------------------------------------------- Dashboard

func (m *Module) Dashboard(ctx context.Context) (*module.DashboardInfo, error) {
	list, err := m.st.Checks(ctx)
	if err != nil {
		return nil, err
	}
	info := &module.DashboardInfo{Module: Name, TitleKey: "nav.healthchecks", Path: "/healthchecks"}
	names := map[string]string{}
	for _, c := range list {
		names[c.Token] = c.Name
		rt := m.liveRuntime(c)
		if stale(c, rt.LastCheck, string(rt.State)) {
			info.Unchecked++ // nicht "OK": ob der Dienst erreichbar ist, ist unbekannt
			continue
		}
		switch rt.State {
		case scheduler.StateUp:
			info.OK++
		case scheduler.StateDown, scheduler.StateFlapping, scheduler.StateDependent:
			info.Down++
		case scheduler.StatePaused:
			info.Paused++
		default:
			info.Other++
		}
	}
	inc, _ := m.st.Incidents(ctx, "", 8)
	for _, i := range inc {
		info.Incidents = append(info.Incidents, module.IncidentInfo{Name: names[i.Token], Path: "/healthchecks/" + i.Token, StartedAt: i.StartedAt, EndedAt: i.EndedAt, Open: i.Open, Message: i.Message})
	}
	return info, nil
}

// channels liefert die Kanaele des Kerns (fuer Formular und Detailseite).
func (m *Module) channels(ctx context.Context) ([]*notify.Channel, error) {
	if m.notifyStore == nil {
		return nil, nil
	}
	return m.notifyStore.Channels(ctx)
}

// translator liefert eine Uebersetzungsfunktion fuer eine feste Sprache.
func (m *Module) translator(lang string) func(key string, args ...any) string {
	return func(key string, args ...any) string {
		if m.g.Translate != nil {
			return m.g.Translate(lang, key, args...)
		}
		return key
	}
}

// bulkTag setzt oder entfernt einen Tag (Massenaktion); fremde Checks bleiben unberuehrt.
func (m *Module) bulkTag(r *http.Request, c *Check, add bool, tag string) bool {
	tag = strings.TrimSpace(tag)
	if tag == "" || len(tag) > 40 || strings.ContainsAny(tag, ", \t") {
		return false
	}
	has := false
	var keep []string
	for _, t := range c.Tags {
		if t == tag {
			has = true
			continue
		}
		keep = append(keep, t)
	}
	switch {
	case add && !has:
		c.Tags = append(c.Tags, tag)
	case !add && has:
		c.Tags = keep
	default:
		return false
	}
	c.UpdatedBy = m.actor(r)
	if err := m.st.Update(r.Context(), c); err != nil {
		return false
	}
	m.audit(r, "check.update", c)
	return true
}

// measuredBy: misst diese Node den Check (leere Node-Liste = der Besitzer)?
func measuredBy(c *Check, node string) bool {
	if c.Execution == "online" {
		return false
	}
	if len(c.Nodes) == 0 {
		return node == selfNodeID() && (c.Owner == "" || c.Owner == "self")
	}
	return contains(c.Nodes, node)
}

// quotaReached: Tageskontingent der Online-Messungen aufgebraucht (nur verknuepft).
func (m *Module) quotaReached() bool {
	if m.quota == nil {
		return false
	}
	today, limit, _ := m.quota()
	return limit > 0 && today >= limit
}

// stale: der Check wird nicht mehr gemessen – die letzte Messung ist aelter als 3 Intervalle (mind. 5 min), etwa
// weil die einzige messende Node offline ist. Pausierte und noch nie gemessene Checks zaehlen nicht.
func stale(c *Check, last time.Time, state string) bool { return staleAt(c, last, state, time.Now()) }

// staleAt wie stale, zur Uhrzeit now (Statusseiten rechnen mit ihrer eigenen Uhr).
func staleAt(c *Check, last time.Time, state string, now time.Time) bool {
	if c.Paused || state == "paused" || last.IsZero() {
		return false
	}
	every := c.Interval
	if c.Type == checks.TypePush {
		period, grace := checks.PushWindow(c.Params)
		every = time.Duration(period+grace) * time.Second
	}
	window := 3 * every
	if window < 5*time.Minute {
		window = 5 * time.Minute
	}
	return now.Sub(last) > window
}

// mergeEvents: lokale und von ipv64 bewertete Ereignisse nach Zeit (neueste zuerst), ohne doppelte Ereignis-IDs.
func mergeEvents(local, hub []Event, limit int) []Event {
	seen := map[string]bool{}
	out := make([]Event, 0, len(local)+len(hub))
	for _, e := range append(append([]Event{}, local...), hub...) {
		if e.EventID != "" && seen[e.EventID] {
			continue
		}
		seen[e.EventID] = true
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// problemState: Zustaende, die die Kachel „Gestoert“ zusammenzaehlt (Filter state=problem).
func problemState(st string) bool {
	return st == string(scheduler.StateDown) || st == string(scheduler.StateFlapping) || st == string(scheduler.StateDependent)
}
