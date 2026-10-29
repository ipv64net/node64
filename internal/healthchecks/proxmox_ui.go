package healthchecks

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/proxmox"
)

// Proxmox VE: Oberflaeche unter /healthchecks/proxmox (Menuepunkt unter Healthchecks wie die Statusseiten).
// Uebersicht der Systeme, je System Nodes und Gaeste (Filter ohne JavaScript), Detailseite je Gast/Node mit Graphen
// (proxmox.js, Chart.js wie die Healthchecks-Diagramme) und Regeln mit sichtbarer Vererbung, Assistent zum Anlegen
// (Verbindung testen → Fingerabdruck bestaetigen) und Bearbeiten.

const pvePath = "/healthchecks/proxmox"

func (m *Module) pveRoutes(mux *http.ServeMux, page func(http.HandlerFunc) http.Handler) {
	mux.Handle("GET "+pvePath, page(m.pagePVE))
	mux.Handle("GET "+pvePath+"/new", page(m.pagePVEForm))
	mux.Handle("POST "+pvePath+"/new", page(m.pagePVESave))
	mux.Handle("GET "+pvePath+"/system/{id}", page(m.pagePVESystem))
	mux.Handle("GET "+pvePath+"/system/{id}/edit", page(m.pagePVEForm))
	mux.Handle("POST "+pvePath+"/system/{id}/edit", page(m.pagePVESave))
	mux.Handle("POST "+pvePath+"/system/{id}/delete", page(m.pagePVEDelete))
	mux.Handle("POST "+pvePath+"/system/{id}/toggle", page(m.pagePVEToggle))
	mux.Handle("POST "+pvePath+"/system/{id}/settings", page(m.pagePVESettings))
	mux.Handle("POST "+pvePath+"/system/{id}/ascheck", page(m.pagePVEAsCheck))
	mux.Handle("POST "+pvePath+"/system/{id}/ack", page(m.pagePVEAck))
	mux.Handle("GET "+pvePath+"/system/{id}/res/{type}/{name}", page(m.pagePVEResource))
}

// ---------------------------------------------------------------- Darstellung

// pveSysRow ist ein System mit seinem Zustand.
type pveSysRow struct {
	Sys         *proxmox.System
	Path        string
	State       string // ok, warn, down, error, off, pending
	Error       string
	Snap        *proxmox.Snapshot
	Nodes       int
	NodesOnline int
	Guests      int
	Running     int
	Bad         int
	SysProblem  bool // eigenes Problem des Systems: nicht erreichbar bzw. abfragbar, Node offline, Quorum weg
	Settings    *proxmox.SystemSettings
	CPUCores    float64 // belegte Kerne der Nodes (online)
	CPUMax      float64
	Mem, MemMax int64
}

// CPUText: belegte CPU bezogen auf die Kerne (Nodes bzw. Docker-Host), "" ohne Werte.
func (r pveSysRow) CPUText() string {
	if r.CPUMax <= 0 {
		return ""
	}
	return pvePctText(r.CPUCores * 100 / r.CPUMax)
}

// Class: Farbe des Zustands (Badge).
func (r pveSysRow) Class() string { return pveStateClass(r.State) }

// Quorum: "", "ok" oder "lost" (nur Cluster).
func (r pveSysRow) Quorum() string {
	if r.Snap == nil || r.Snap.Quorate == nil {
		return ""
	}
	if *r.Snap.Quorate {
		return "ok"
	}
	return "lost"
}

// ClusterUnknown: mehrere Nodes, aber Clustername und Quorum unbekannt (cluster/status ohne Recht Sys.Audit auf „/“).
func (r pveSysRow) ClusterUnknown() bool {
	return r.Nodes > 1 && r.Quorum() == "" && (r.Snap == nil || r.Snap.Cluster == "")
}

// TokenUser und TokenName: Teile der Token-ID (user@realm!name) fuer die pveum-Befehle im Rechte-Hinweis.
func (r pveSysRow) TokenUser() string { u, _, _ := strings.Cut(r.Sys.TokenID, "!"); return u }

func (r pveSysRow) TokenName() string { _, n, _ := strings.Cut(r.Sys.TokenID, "!"); return n }

// PinFmt zeigt den gepinnten Fingerabdruck mit Doppelpunkten.
func (r pveSysRow) PinFmt() string { return pveFingerprint(r.Sys.PinSHA256) }

func pveStateClass(s string) string {
	switch s {
	case "ok":
		return "text-bg-success"
	case "warn":
		return "text-bg-warning"
	case "down", "error":
		return "text-bg-danger"
	}
	return "text-bg-secondary"
}

// pveResRow ist ein Node oder Gast in der Tabelle.
type pveResRow struct {
	R          proxmox.Resource
	Key        string
	Path       string
	Label      string // i18n-Schluessel des Zustands
	Class      string // Badge
	Bad        bool   // gestoert (zaehlt)
	Excluded   bool   // Vorlage bzw. Tag nomonitor
	Muted      bool
	AsCheck    bool
	CheckToken string
	Ack        bool // gestoert, weil gestoppt bzw. beendet: „gestoppt ist richtig“ anbieten (ExpectRunning aus)
	ExpectOff  bool // fest „soll nicht laufen“ (zuruecknehmen in den Einstellungen des Gasts)
	Measured   bool // Werte aussagekraeftig (laeuft bzw. online)
	CPU        string
	Mem        string
	Disk       string
	Rates      bool  // Gaeste: Netz und Disk-I/O in Byte/s (Anzeige mit $.Bytes, Locale wie die uebrige Seite)
	NetIn      int64 // Byte/s
	NetOut     int64
	DiskRd     int64
	DiskWr     int64
	Uptime     time.Duration
	Spark      template.HTML
	GuestsOn   int // Nodes: Gaeste auf diesem Node
	TypeLabel  string
}

func pveFingerprint(hex string) string {
	if len(hex) != 64 {
		return hex
	}
	var b strings.Builder
	for i := 0; i < 64; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(strings.ToUpper(hex[i : i+2]))
	}
	return b.String()
}

func pvePctText(v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return "–"
	}
	if v < 10 && v > 0 {
		return strconv.FormatFloat(v, 'f', 1, 64) + " %"
	}
	return strconv.FormatFloat(v, 'f', 0, 64) + " %"
}

// pveRate rundet Byte/s fuer die Anzeige mit $.Bytes.
func pveRate(v float64) int64 {
	if math.IsNaN(v) || v < 0 {
		return 0
	}
	return int64(math.Round(v))
}

// pveExpected: gestoppt ist eine Stoerung (fest eingestellt bzw. lief schon einmal).
func pveExpected(it *proxmox.Settings) bool {
	if it == nil {
		return false
	}
	if it.ExpectRunning != nil {
		return *it.ExpectRunning
	}
	return it.SeenRunning
}

// pveRow bewertet eine Ressource fuer die Anzeige.
func pveRow(id int64, r proxmox.Resource, set *proxmox.SystemSettings) pveResRow {
	row := pveResRow{R: r, Key: r.Key(), TypeLabel: "pve.type." + r.Type}
	docker := r.Type == proxmox.TypeDocker
	row.Path = pveResPath(id, row.Key)
	it := set.Item(row.Key)
	row.Excluded = r.Excluded()
	if it != nil {
		row.Muted, row.AsCheck, row.CheckToken = it.Muted, it.AsCheck, it.CheckToken
	}
	row.Label = "pve.state." + string(r.State)
	if docker { // Docker: Ursache statt „abgestuerzt“ (unhealthy, restarting, exited, oom, dead)
		row.Label = "docker.state." + string(r.State)
		if r.State == proxmox.StateError && r.Detail != "" {
			row.Label = "docker.state." + r.Detail
		}
	}
	switch r.State {
	case proxmox.StateRunning, proxmox.StateOnline:
		row.Class = "text-bg-success"
	case proxmox.StateBackup, proxmox.StateLocked:
		row.Class = "text-bg-info"
	case proxmox.StateStopped:
		row.Class = "text-bg-secondary"
		if pveExpected(it) {
			row.Class, row.Bad = "text-bg-danger", true
		}
	case proxmox.StatePaused, proxmox.StateSuspended:
		row.Class, row.Bad = "text-bg-warning", true
	case proxmox.StateError, proxmox.StateOffline:
		row.Class, row.Bad = "text-bg-danger", true
		if docker && r.DockerDown() && !pveExpected(it) { // beendet, soll aber nicht laufen: wie die Regeln
			row.Class, row.Bad = "text-bg-secondary", false
		}
	default:
		row.Class = "text-bg-secondary"
	}
	if row.Excluded {
		row.Bad = false
	}
	row.ExpectOff = it != nil && it.ExpectRunning != nil && !*it.ExpectRunning
	row.Ack = row.Bad && !row.AsCheck && !row.Muted && (r.State == proxmox.StateStopped || docker && r.DockerDown())
	row.Measured = r.Measurable() // wie die Regeln (Schwellen)
	if row.Measured {
		row.CPU = pvePctText(r.CPU * 100)
		if v, ok := r.MemPercent(); ok {
			row.Mem = pvePctText(v)
		}
		if v, ok := r.DiskPercent(); ok {
			row.Disk = pvePctText(v)
		}
		if r.Type != proxmox.TypeNode {
			row.Rates = true
			row.NetIn, row.NetOut, row.DiskRd, row.DiskWr = pveRate(r.NetIn), pveRate(r.NetOut), pveRate(r.DiskRead), pveRate(r.DiskWrite)
		}
		row.Uptime = time.Duration(r.Uptime) * time.Second
	}
	return row
}

// pveSysView baut die Zeile eines Systems (mit Zaehlern aus dem letzten Snapshot).
func (m *Module) pveSysView(ctx context.Context, sys *proxmox.System) pveSysRow {
	row := pveSysRow{Sys: sys, Path: pveKeyPath(sys.Kind, sys.ID, "")}
	set, _ := m.pve.st.Settings(ctx, sys.ID)
	if set == nil {
		set = &proxmox.SystemSettings{SystemID: sys.ID, Name: sys.Name}
	}
	row.Settings = set
	pp, reason := m.pvePollOf(sys.ID)
	switch {
	case !sys.Enabled:
		row.State = "off"
		return row
	case reason != "":
		row.State, row.Error, row.SysProblem = "error", reason, true
		return row
	case pp == nil:
		row.State = "pending"
		return row
	}
	s := pp.p.Last()
	row.Snap = s
	if s == nil {
		row.State = "pending"
		return row
	}
	if !s.OK {
		row.State, row.Error, row.SysProblem = "down", s.Error, true
		return row
	}
	row.State = "ok"
	for _, r := range s.Resources {
		x := pveRow(sys.ID, r, set)
		if r.Type == proxmox.TypeNode {
			row.Nodes++
			if r.State == proxmox.StateOnline {
				row.NodesOnline++
				row.CPUCores += r.CPU * r.MaxCPU
				row.CPUMax += r.MaxCPU
				row.Mem += r.Mem
				row.MemMax += r.MaxMem
			}
			continue
		}
		if x.Excluded {
			continue
		}
		row.Guests++
		if r.Status == "running" && !x.Bad {
			row.Running++
		}
		if x.Bad && !x.Muted {
			row.Bad++
		}
	}
	row.SysProblem = row.NodesOnline < row.Nodes || row.Quorum() == "lost"
	if row.SysProblem || row.Bad > 0 {
		row.State = "warn"
	}
	return row
}

// pveSparks liefert je Key die CPU der letzten Stunde (1-Minuten-Werte) als kleine SVG-Linie.
func (m *Module) pveSparks(ctx context.Context, id int64) map[string]template.HTML {
	out := map[string]template.HTML{}
	since := time.Now().Add(-time.Hour).Unix()
	// Index (system_id, t) aus 0016: nach t sortiert, je Key bleibt die Reihenfolge zeitlich
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT key, t, cpu FROM pve_hist_1m WHERE system_id = ? AND t >= ? ORDER BY t`, id, since)
	if err != nil {
		return out
	}
	defer rows.Close()
	pts := map[string][][2]int64{}
	for rows.Next() {
		var k string
		var t, cpu int64
		if rows.Scan(&k, &t, &cpu) == nil {
			pts[k] = append(pts[k], [2]int64{t, cpu})
		}
	}
	for k, p := range pts {
		out[k] = pveSparkSVG(p, since)
	}
	return out
}

// pveSparkSVG zeichnet die Werte (t, 1/10000) in ein 80×20-Feld (Zeitachse: eine Stunde ab since).
func pveSparkSVG(p [][2]int64, since int64) template.HTML {
	if len(p) < 2 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<svg class="pve-spark" viewBox="0 0 80 20" width="80" height="20" aria-hidden="true"><polyline fill="none" stroke="currentColor" stroke-width="1.2" points="`)
	for i, x := range p {
		if i > 0 {
			b.WriteByte(' ')
		}
		fx := float64(x[0]-since) * 80 / 3600
		fy := 19 - float64(min(max(x[1], 0), 10000))*18/10000
		fmt.Fprintf(&b, "%.1f,%.1f", fx, fy)
	}
	b.WriteString(`"/></svg>`)
	return template.HTML(b.String()) //nolint:gosec // nur Zahlen
}

// ---------------------------------------------------------------- Uebersicht

type pveOverviewData struct {
	Systems []pveSysRow
	NoBox   bool // kein secret.key: Systeme lassen sich nicht speichern
	Last    *pveIncident
	LastURL string
	Sum     pveSum // Kacheln ueber alle Systeme
}

// pveSum sind die Kennzahlen aller Systeme (Kacheln der Uebersicht; Docker-Seite mit mehreren Hosts ebenso).
type pveSum struct {
	Systems, SysBad      int // SysBad: eigenes Problem (nicht erreichbar, Node offline, Quorum weg)
	Nodes, NodesOnline   int
	Guests, Running, Bad int
	CPUCores, CPUMax     float64
	Mem, MemMax          int64
}

func (s *pveSum) add(r pveSysRow) {
	s.Systems++
	if r.SysProblem {
		s.SysBad++
	}
	s.Nodes += r.Nodes
	s.NodesOnline += r.NodesOnline
	s.Guests += r.Guests
	s.Running += r.Running
	s.Bad += r.Bad
	s.CPUCores += r.CPUCores
	s.CPUMax += r.CPUMax
	s.Mem += r.Mem
	s.MemMax += r.MemMax
}

// CPUText: belegte CPU aller Nodes (online) bezogen auf ihre Kerne.
func (s pveSum) CPUText() string {
	if s.CPUMax <= 0 {
		return ""
	}
	return pvePctText(s.CPUCores * 100 / s.CPUMax)
}

func (m *Module) pagePVE(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	list, err := m.pve.st.Systems(ctx)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	d := pveOverviewData{NoBox: m.pve.box == nil, Last: m.pveLastIncident(ctx)}
	for _, sys := range list {
		if sys.IsDocker() {
			continue // Docker-Hosts stehen unter /healthchecks/docker
		}
		row := m.pveSysView(ctx, sys)
		d.Sum.add(row)
		d.Systems = append(d.Systems, row)
	}
	if d.Last != nil {
		d.LastURL = pveResPath(d.Last.SystemID, d.Last.Key)
	}
	m.g.Render(w, r, http.StatusOK, Name+"/proxmox", "nav.proxmox", d)
}

// ---------------------------------------------------------------- System

type pveSystemData struct {
	pveSysRow
	NodeRows  []pveResRow
	GuestRows []pveResRow // gefiltert (nicht „Guests“: das ueberdeckte die Zahl aus pveSysRow in den Kacheln)
	Total     int         // Gaeste ohne Filter
	Filter    map[string]string
	NodeNames []string
	States    []string
	Rules     pveRulesForm
}

func (d pveSystemData) Crumb() string { return d.Sys.Name }

// pveFilterStates sind die Zustaende im Filter („problem“ = gestoert).
var pveFilterStates = []string{"problem", "running", "stopped", "paused", "suspended", "error", "backup", "locked", "unknown"}

func (m *Module) pveSystemOf(w http.ResponseWriter, r *http.Request) *proxmox.System {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		var sys *proxmox.System
		if sys, err = m.pve.st.System(r.Context(), id); err == nil {
			return sys
		}
	}
	if err != nil && !errors.Is(err, proxmox.ErrNotFound) && !errors.Is(err, strconv.ErrSyntax) && !errors.Is(err, strconv.ErrRange) {
		m.fail(w, r, err)
		return nil
	}
	m.g.Flash(w, r, "warning", m.g.T(r, "pve.not_found"))
	http.Redirect(w, r, pvePath, http.StatusSeeOther)
	return nil
}

func (m *Module) pagePVESystem(w http.ResponseWriter, r *http.Request) {
	sys := m.pveSystemOf(w, r)
	if sys == nil {
		return
	}
	if sys.IsDocker() {
		http.Redirect(w, r, dockerSysPath(sys.ID), http.StatusSeeOther)
		return
	}
	ctx := r.Context()
	d := pveSystemData{pveSysRow: m.pveSysView(ctx, sys), States: pveFilterStates}
	q := r.URL.Query()
	d.Filter = map[string]string{"state": q.Get("state"), "node": q.Get("node"), "type": q.Get("type"), "q": strings.TrimSpace(q.Get("q"))}
	d.Rules = pveRulesFor(d.Settings, "", "", d.Path+"/settings")
	m.pveRulesChannels(ctx, &d.Rules, d.Settings, "", "")
	if d.Snap != nil && d.Snap.OK {
		sparks := m.pveSparks(ctx, sys.ID)
		perNode := map[string]int{}
		for _, res := range d.Snap.Resources {
			if res.Type != proxmox.TypeNode && !res.Excluded() { // wie die Summe der Gaeste
				perNode[res.Node]++
			}
		}
		for _, res := range d.Snap.Resources {
			row := pveRow(sys.ID, res, d.Settings)
			row.Spark = sparks[row.Key]
			if res.Type == proxmox.TypeNode {
				row.GuestsOn = perNode[res.Node]
				d.NodeRows = append(d.NodeRows, row)
				d.NodeNames = append(d.NodeNames, res.Node)
				continue
			}
			d.Total++
			if pveMatch(row, d.Filter) {
				d.GuestRows = append(d.GuestRows, row)
			}
		}
		sort.Strings(d.NodeNames)
	}
	m.g.Render(w, r, http.StatusOK, Name+"/proxmox_system", "nav.proxmox", d)
}

// pveMatch prueft den Filter (Zustand, Node, Typ, Suche in Name, ID und Tags).
func pveMatch(row pveResRow, f map[string]string) bool {
	switch st := f["state"]; st {
	case "":
	case "problem":
		if !row.Bad {
			return false
		}
	default:
		if string(row.R.State) != st {
			return false
		}
	}
	if f["node"] != "" && row.R.Node != f["node"] {
		return false
	}
	if f["type"] != "" && row.R.Type != f["type"] {
		return false
	}
	if q := strings.ToLower(f["q"]); q != "" {
		hay := strings.ToLower(row.R.Name + " " + strconv.Itoa(row.R.VMID) + " " + strings.Join(row.R.Tags, " ") + " " + row.R.Node)
		if !strings.Contains(hay, q) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- Gast / Node

type pveResourceData struct {
	Sys      *proxmox.System
	SysPath  string
	Key      string
	Type     string
	Found    bool
	Row      pveResRow
	Rules    pveRulesForm
	Ranges   []string
	Reach    bool // System erreichbar
	SysState string
}

func (d pveResourceData) Crumb() string {
	name := d.Key
	if d.Row.R.Name != "" {
		name = d.Row.R.Name
	}
	return d.Sys.Name + " – " + name
}

func (m *Module) pagePVEResource(w http.ResponseWriter, r *http.Request) {
	sys := m.pveSystemOf(w, r)
	if sys == nil {
		return
	}
	ctx := r.Context()
	key := r.PathValue("type") + "/" + r.PathValue("name")
	if key == "/" || !proxmox.ValidKey(key) {
		http.NotFound(w, r)
		return
	}
	if sys.IsDocker() {
		http.Redirect(w, r, pveKeyPath(sys.Kind, sys.ID, key), http.StatusSeeOther)
		return
	}
	set, err := m.pve.st.Settings(ctx, sys.ID)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	d := pveResourceData{Sys: sys, SysPath: pveResPath(sys.ID, ""), Key: key, Type: pveKeyType(key), Ranges: []string{"1h", "24h", "7d", "30d"}}
	node := ""
	if s := m.pveLast(sys.ID); s != nil {
		d.Reach = s.OK
		for _, res := range s.Resources {
			if res.Key() == key {
				d.Found, d.Row = true, pveRow(sys.ID, res, set)
				node = res.Node
				break
			}
		}
	}
	if !d.Found {
		d.Row = pveResRow{Key: key, Path: pveResPath(sys.ID, key), TypeLabel: "pve.type." + d.Type}
		if it := set.Item(key); it != nil {
			d.Row.AsCheck, d.Row.CheckToken, d.Row.Muted = it.AsCheck, it.CheckToken, it.Muted
		}
	}
	d.Rules = pveRulesFor(set, key, node, d.SysPath+"/settings")
	m.pveRulesChannels(ctx, &d.Rules, set, key, node)
	m.g.Render(w, r, http.StatusOK, Name+"/proxmox_resource", "nav.proxmox", d)
}

// ---------------------------------------------------------------- Regeln mit Vererbung

// pveRuleField ist eine Zeile im Regelformular.
type pveRuleField struct {
	Name   string // Formularfeld r_<Name>
	Label  string // i18n-Schluessel
	Kind   string // bool, thr, int
	Own    string // eigener Wert: bool "1"/"0", thr Prozent, int Zahl; leer = erben
	OwnMin string // thr: Minuten
	Inh    string // geerbter Wert (Anzeige)
	InhKey string // bool: i18n-Schluessel des geerbten Werts
	From   string // i18n-Schluessel der Herkunft (Standard, System, Node)
}

// pveRulesForm ist das Regelformular einer Ebene.
type pveRulesForm struct {
	Level  string // system, node, guest
	Text   string // Texte (pve.rules.level_<Text> …): wie Level, Docker: docker_system bzw. container
	Key    string
	Action string
	Muted  bool
	Expect string // Gaeste: "", "1", "0" (gestoppt ist eine Stoerung: automatisch, ja, nein)
	Seen   bool   // Gaeste: lief schon einmal (automatisch erwartet)
	Fields []pveRuleField
	// Kanaele wie im Check-Formular (keine Auswahl = Standardkanaele): ChanOwn = eigene Auswahl dieser Ebene (System:
	// immer), sonst geerbt; Channels zur Auswahl (vorgewaehlt: eigene bzw. geerbte), ChanInh die geerbten Namen
	// (leer = Standardkanaele) mit Herkunft ChanFrom, ChanDefault die Namen der Standardkanaele
	ChanOwn     bool
	Channels    []channelOpt
	ChanInh     string
	ChanFrom    string
	ChanDefault string
}

type pveRuleDef struct {
	name, kind string
	levels     string // s, n, g
	b          func(*proxmox.RuleSet) **bool
	t          func(*proxmox.RuleSet) **proxmox.Threshold
	i          func(*proxmox.RuleSet) **int
	rb         func(proxmox.Rule) bool
	rt         func(proxmox.Rule) proxmox.Threshold
	ri         func(proxmox.Rule) int
}

var pveRuleDefs = []pveRuleDef{
	{name: "crashed", kind: "bool", levels: "sng", b: func(r *proxmox.RuleSet) **bool { return &r.Crashed }, rb: func(r proxmox.Rule) bool { return r.Crashed }},
	{name: "stopped", kind: "bool", levels: "sng", b: func(r *proxmox.RuleSet) **bool { return &r.Stopped }, rb: func(r proxmox.Rule) bool { return r.Stopped }},
	{name: "paused", kind: "bool", levels: "sng", b: func(r *proxmox.RuleSet) **bool { return &r.Paused }, rb: func(r proxmox.Rule) bool { return r.Paused }},
	{name: "suspended", kind: "bool", levels: "sng", b: func(r *proxmox.RuleSet) **bool { return &r.Suspended }, rb: func(r proxmox.Rule) bool { return r.Suspended }},
	{name: "offline", kind: "bool", levels: "sn", b: func(r *proxmox.RuleSet) **bool { return &r.Offline }, rb: func(r proxmox.Rule) bool { return r.Offline }},
	{name: "unreachable", kind: "bool", levels: "s", b: func(r *proxmox.RuleSet) **bool { return &r.Unreachable }, rb: func(r proxmox.Rule) bool { return r.Unreachable }},
	{name: "restarted", kind: "bool", levels: "sng", b: func(r *proxmox.RuleSet) **bool { return &r.Restarted }, rb: func(r proxmox.Rule) bool { return r.Restarted }},
	{name: "cpu", kind: "thr", levels: "sng", t: func(r *proxmox.RuleSet) **proxmox.Threshold { return &r.CPU }, rt: func(r proxmox.Rule) proxmox.Threshold { return r.CPU }},
	{name: "mem", kind: "thr", levels: "sng", t: func(r *proxmox.RuleSet) **proxmox.Threshold { return &r.Mem }, rt: func(r proxmox.Rule) proxmox.Threshold { return r.Mem }},
	{name: "disk", kind: "thr", levels: "sng", t: func(r *proxmox.RuleSet) **proxmox.Threshold { return &r.Disk }, rt: func(r proxmox.Rule) proxmox.Threshold { return r.Disk }},
	{name: "delay", kind: "int", levels: "sng", i: func(r *proxmox.RuleSet) **int { return &r.Delay }, ri: func(r proxmox.Rule) int { return r.Delay }},
}

func pveLevel(key string) string {
	switch {
	case key == "":
		return "system"
	case strings.HasPrefix(key, "node/"):
		return "node"
	}
	return "guest"
}

func pveThrText(t proxmox.Threshold) string {
	if t.Percent <= 0 {
		return "off"
	}
	s := strconv.FormatFloat(t.Percent, 'f', -1, 64) + " %"
	if t.Minutes > 0 {
		s += " · " + strconv.Itoa(t.Minutes) + " min"
	}
	return s
}

// pveRulesFor baut das Formular einer Ebene: eigene Werte und was sie sonst erben wuerde (mit Herkunft).
func pveRulesFor(set *proxmox.SystemSettings, key, node, action string) pveRulesForm {
	level := pveLevel(key)
	f := pveRulesForm{Level: level, Key: key, Action: action, Text: level}
	docker := set != nil && set.Kind == proxmox.KindDocker
	if docker {
		f.Text = map[string]string{"system": "docker_system", "guest": "container"}[level]
	}
	if it := set.Item(key); it != nil {
		f.Muted, f.Seen = it.Muted, it.SeenRunning
		if it.ExpectRunning != nil {
			f.Expect = map[bool]string{true: "1", false: "0"}[*it.ExpectRunning]
		}
	}
	// Kette der Vorfahren: Standard → System → Node (fuer Gaeste)
	type anc struct {
		from string
		rs   *proxmox.RuleSet
	}
	var chain []anc
	if level != "system" {
		if it := set.Item(""); it != nil {
			chain = append(chain, anc{"pve.rules.from_system", &it.Rules})
		}
	}
	if level == "guest" && node != "" {
		if it := set.Item("node/" + node); it != nil {
			chain = append(chain, anc{"pve.rules.from_node", &it.Rules})
		}
	}
	def := proxmox.DefaultRule()
	lv := level[:1]
	for _, rd := range pveRuleDefs {
		if !strings.Contains(rd.levels, lv) {
			continue
		}
		if docker && (rd.name == "suspended" || rd.name == "offline" || rd.name == "disk") {
			continue // gibt es bei Docker nicht
		}
		fl := pveRuleField{Name: rd.name, Label: "pve.rule." + rd.name, Kind: rd.kind, From: "pve.rules.from_default"}
		if docker && (rd.name == "crashed" || rd.name == "unreachable") {
			fl.Label = "docker.rule." + rd.name
		}
		var own *proxmox.RuleSet
		if it := set.Item(key); it != nil {
			own = &it.Rules
		}
		switch rd.kind {
		case "bool":
			v := rd.rb(def)
			for _, a := range chain {
				if p := *rd.b(a.rs); p != nil {
					v, fl.From = *p, a.from
				}
			}
			fl.InhKey = map[bool]string{true: "common.on", false: "common.off"}[v]
			if own != nil {
				if p := *rd.b(own); p != nil {
					fl.Own = map[bool]string{true: "1", false: "0"}[*p]
				}
			}
		case "thr":
			v := rd.rt(def)
			for _, a := range chain {
				if p := *rd.t(a.rs); p != nil {
					v, fl.From = *p, a.from
				}
			}
			fl.Inh = pveThrText(v)
			if fl.Inh == "off" {
				fl.Inh, fl.InhKey = "", "common.off"
			}
			if own != nil {
				if p := *rd.t(own); p != nil {
					fl.Own, fl.OwnMin = strconv.FormatFloat(p.Percent, 'f', -1, 64), strconv.Itoa(p.Minutes)
				}
			}
		case "int":
			v := rd.ri(def)
			for _, a := range chain {
				if p := *rd.i(a.rs); p != nil {
					v, fl.From = *p, a.from
				}
			}
			fl.Inh = strconv.Itoa(v)
			if own != nil {
				if p := *rd.i(own); p != nil {
					fl.Own = strconv.Itoa(*p)
				}
			}
		}
		f.Fields = append(f.Fields, fl)
	}
	return f
}

// pveRulesChannels ergaenzt das Regelformular um die Kanalauswahl: eigene Auswahl bzw. was die Ebene erbt
// (Standard → System → Node). Ohne Kanaele entfaellt sie (wie im Check-Formular).
func (m *Module) pveRulesChannels(ctx context.Context, f *pveRulesForm, set *proxmox.SystemSettings, key, node string) {
	chans, err := m.channels(ctx)
	if err != nil || len(chans) == 0 {
		return
	}
	var own *[]int64
	if it := set.Item(key); it != nil {
		own = it.Rules.Channels
	}
	var inh []int64
	f.ChanFrom = "pve.rules.from_default"
	if f.Level != "system" {
		if it := set.Item(""); it != nil && it.Rules.Channels != nil {
			inh, f.ChanFrom = *it.Rules.Channels, "pve.rules.from_system"
		}
		if f.Level == "guest" && node != "" {
			if it := set.Item("node/" + node); it != nil && it.Rules.Channels != nil {
				inh, f.ChanFrom = *it.Rules.Channels, "pve.rules.from_node"
			}
		}
	}
	f.ChanOwn = f.Level == "system" || own != nil
	sel, inhSet := map[int64]bool{}, map[int64]bool{}
	for _, id := range inh {
		inhSet[id] = true
	}
	if own != nil {
		for _, id := range *own {
			sel[id] = true
		}
	} else {
		sel = inhSet
	}
	var names, defs []string
	for _, ch := range chans {
		f.Channels = append(f.Channels, channelOpt{ID: ch.ID, Name: ch.Name, Type: string(ch.Type), Default: ch.Default, Selected: sel[ch.ID]})
		if inhSet[ch.ID] {
			names = append(names, ch.Name)
		}
		if ch.Default {
			defs = append(defs, ch.Name)
		}
	}
	f.ChanInh = strings.Join(names, ", ") // geloeschte Kanaele zaehlen nicht
	f.ChanDefault = strings.Join(defs, ", ")
}

// pveRulesFromForm liest die Regeln einer Ebene aus dem Formular (leer = erben). Kanaele: Systemebene wie im
// Check-Formular (keine Auswahl = Standardkanaele), Node/Gast nur mit ch_mode=own (sonst erben).
func pveRulesFromForm(r *http.Request, level string) (proxmox.RuleSet, error) {
	var rs proxmox.RuleSet
	_ = r.ParseForm()
	if (level != "system" && r.PostFormValue("ch_mode") == "own") || (level == "system" && len(r.PostForm["channels"]) > 0) {
		ids := []int64{}
		for _, v := range r.PostForm["channels"] {
			n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return rs, &proxmox.FieldError{Field: "channels", Key: "pve.err.channels"}
			}
			ids = append(ids, n)
		}
		rs.Channels = &ids
	}
	lv := level[:1]
	for _, rd := range pveRuleDefs {
		if !strings.Contains(rd.levels, lv) {
			continue
		}
		v := strings.TrimSpace(r.PostFormValue("r_" + rd.name))
		switch rd.kind {
		case "bool":
			if v == "1" || v == "0" {
				b := v == "1"
				*rd.b(&rs) = &b
			}
		case "thr":
			mins := strings.TrimSpace(r.PostFormValue("r_" + rd.name + "_min"))
			if v == "" && mins == "" {
				continue
			}
			var t proxmox.Threshold
			if v != "" {
				p, err := strconv.ParseFloat(strings.ReplaceAll(v, ",", "."), 64)
				if err != nil {
					return rs, &proxmox.FieldError{Field: rd.name, Key: "pve.err.threshold"}
				}
				t.Percent = p
			}
			if mins != "" {
				n, err := strconv.Atoi(mins)
				if err != nil {
					return rs, &proxmox.FieldError{Field: rd.name, Key: "pve.err.threshold"}
				}
				t.Minutes = n
			}
			*rd.t(&rs) = &t
		case "int":
			if v == "" {
				continue
			}
			n, err := strconv.Atoi(v)
			if err != nil {
				return rs, &proxmox.FieldError{Field: rd.name, Key: "pve.err.delay"}
			}
			*rd.i(&rs) = &n
		}
	}
	return rs, rs.Validate()
}

// pagePVESettings speichert Regeln, Stummschaltung und „erwartet laeuft“ einer Ebene (key leer = System).
func (m *Module) pagePVESettings(w http.ResponseWriter, r *http.Request) {
	sys := m.pveSystemOf(w, r)
	if sys == nil {
		return
	}
	ctx := r.Context()
	key := strings.TrimSpace(r.PostFormValue("key"))
	back := pveKeyPath(sys.Kind, sys.ID, key)
	if !proxmox.ValidKey(key) {
		http.Error(w, "invalid key", http.StatusBadRequest)
		return
	}
	set, err := m.pve.st.Settings(ctx, sys.ID)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	it := set.Item(key)
	if it == nil {
		it = &proxmox.Settings{SystemID: sys.ID, Key: key}
	}
	if r.PostFormValue("op") == "reset" { // alles erben; „als Check“ bleibt
		if err := m.pve.st.ResetSettings(ctx, sys.ID, key); err != nil {
			m.fail(w, r, err)
			return
		}
	} else {
		rs, err := pveRulesFromForm(r, pveLevel(key))
		if err != nil {
			var fe *proxmox.FieldError
			msg := err.Error()
			if errors.As(err, &fe) {
				msg = m.g.T(r, fe.Key) + " (" + m.g.T(r, "pve.rule."+fe.Field) + ")"
			}
			m.g.Flash(w, r, "danger", msg)
			http.Redirect(w, r, back, http.StatusSeeOther)
			return
		}
		it.Rules, it.Muted = rs, r.PostFormValue("muted") == "on"
		if pveLevel(key) == "guest" {
			switch r.PostFormValue("expect") {
			case "1":
				t := true
				it.ExpectRunning = &t
			case "0":
				f := false
				it.ExpectRunning = &f
				m.pveAckIncident(ctx, sys.ID, key)
			default:
				it.ExpectRunning = nil
			}
		}
		if err := m.pve.st.SaveSettings(ctx, it); err != nil {
			m.fail(w, r, err)
			return
		}
	}
	m.pveSyncCheckChannels(ctx, sys.ID, m.actor(r)) // Checks „als Check“: Kanaele wie die Regeln
	m.auditText(r, "proxmox.settings", sys.Name+pveKeySuffix(key))
	m.g.Flash(w, r, "success", m.g.T(r, "common.saved"))
	http.Redirect(w, r, back, http.StatusSeeOther)
}

func pveKeySuffix(key string) string {
	if key == "" {
		return ""
	}
	return " / " + key
}

// pagePVEAck: „gestoppt ist richtig“ – der Gast bzw. Container soll nicht laufen (ExpectRunning aus). Die Zeile ist
// sofort in Ordnung, eine offene Stoerung erledigt sich mit der naechsten Abfrage still (Regeln, ohne Entwarnung).
// Zuruecknehmen in den Einstellungen des Gasts („Gestoppt ist eine Störung: automatisch“).
func (m *Module) pagePVEAck(w http.ResponseWriter, r *http.Request) {
	sys := m.pveSystemOf(w, r)
	if sys == nil {
		return
	}
	ctx := r.Context()
	key := strings.TrimSpace(r.PostFormValue("key"))
	back := r.PostFormValue("back")
	if !(strings.HasPrefix(back, pvePath+"/") || strings.HasPrefix(back, dockerPath)) || strings.Contains(back, "//") {
		back = pveKeyPath(sys.Kind, sys.ID, "")
	}
	if key == "" || !proxmox.ValidKey(key) || pveLevel(key) != "guest" {
		http.Error(w, "invalid key", http.StatusBadRequest)
		return
	}
	set, err := m.pve.st.Settings(ctx, sys.ID)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	it := set.Item(key)
	if it == nil {
		it = &proxmox.Settings{SystemID: sys.ID, Key: key}
	}
	f := false
	it.ExpectRunning = &f
	if err := m.pve.st.SaveSettings(ctx, it); err != nil {
		m.fail(w, r, err)
		return
	}
	m.pveAckIncident(ctx, sys.ID, key)
	m.auditText(r, "proxmox.ack", sys.Name+pveKeySuffix(key))
	m.g.Flash(w, r, "success", m.g.T(r, "pve.ack.done"))
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// pveAckIncident: Gast soll nicht laufen – war er die letzte Stoerung (Startseite), gilt sie als erledigt.
func (m *Module) pveAckIncident(ctx context.Context, systemID int64, key string) {
	for _, k := range []string{pveSettingLast, dockerSettingLast} {
		if inc := m.lastIncident(ctx, k); inc != nil && inc.SystemID == systemID && inc.Key == key {
			_ = m.core.SetSetting(ctx, k, "")
		}
	}
}

// pagePVEAsCheck schaltet „auch als Check fuehren“.
func (m *Module) pagePVEAsCheck(w http.ResponseWriter, r *http.Request) {
	sys := m.pveSystemOf(w, r)
	if sys == nil {
		return
	}
	key := strings.TrimSpace(r.PostFormValue("key"))
	on := r.PostFormValue("on") == "1"
	back := r.PostFormValue("back")
	if !(strings.HasPrefix(back, pvePath+"/") || strings.HasPrefix(back, dockerPath)) || strings.Contains(back, "//") {
		back = pveKeyPath(sys.Kind, sys.ID, "")
	}
	if err := m.pveSetAsCheck(r, sys, key, on); err != nil {
		var fe *proxmox.FieldError
		if errors.As(err, &fe) {
			m.g.Flash(w, r, "danger", m.g.T(r, fe.Key))
		} else {
			m.g.Flash(w, r, "danger", err.Error())
		}
	} else {
		m.g.Flash(w, r, "success", m.g.T(r, map[bool]string{true: "pve.check.added", false: "pve.check.removed"}[on]))
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// ---------------------------------------------------------------- Ein-/Ausschalten, Loeschen

func (m *Module) pagePVEToggle(w http.ResponseWriter, r *http.Request) {
	sys := m.pveSystemOf(w, r)
	if sys == nil {
		return
	}
	sys.Enabled = !sys.Enabled
	sys.Secret = "" // beim Aendern: gespeichertes Secret behalten
	if err := m.pveSaveSystem(r, sys); err != nil {
		m.g.Flash(w, r, "danger", m.pveErrText(r, err))
	} else {
		m.auditText(r, map[bool]string{true: "proxmox.enable", false: "proxmox.disable"}[sys.Enabled], sys.Name)
		m.g.Flash(w, r, "success", m.g.T(r, "common.saved"))
	}
	back := r.PostFormValue("back")
	if back != pvePath && back != dockerPath {
		back = pveKeyPath(sys.Kind, sys.ID, "")
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

func (m *Module) pagePVEDelete(w http.ResponseWriter, r *http.Request) {
	sys := m.pveSystemOf(w, r)
	if sys == nil {
		return
	}
	if err := m.pveDeleteSystem(r, sys.ID); err != nil {
		m.fail(w, r, err)
		return
	}
	m.auditText(r, "proxmox.delete", sys.Name)
	m.g.Flash(w, r, "success", m.g.T(r, "pve.deleted"))
	if sys.IsDocker() {
		http.Redirect(w, r, dockerPath, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, pvePath, http.StatusSeeOther)
}

// pveErrText uebersetzt Feldfehler.
func (m *Module) pveErrText(r *http.Request, err error) string {
	var fe *proxmox.FieldError
	switch {
	case errors.As(err, &fe):
		return m.g.T(r, fe.Key)
	case errors.Is(err, proxmox.ErrNoBox):
		return m.g.T(r, "pve.err.no_box")
	}
	return err.Error()
}

// ---------------------------------------------------------------- Assistent / Bearbeiten

type pveFormData struct {
	Sys        *proxmox.System
	Edit       bool
	Addresses  string
	Secret     string // nur im Assistenten zurueckgegeben (eben eingegeben), beim Bearbeiten nie
	HasSecret  bool   // gespeichertes Secret vorhanden (Bearbeiten)
	Probe      *proxmox.ProbeResult
	ProbePin   string // Fingerabdruck aus dem Test (hex)
	PinConfirm bool
	PinFmt     string
	ProbeFmt   string
	PinDiffers bool // gespeicherter Pin passt nicht zum gesehenen Zertifikat
	Errors     map[string]string
	Error      string
	NoBox      bool
	User       string // fuer die pveum-Befehle
	TokenName  string
	MinIv      int
	MaxIv      int
}

func (d pveFormData) Crumb() string {
	if d.Edit {
		return d.Sys.Name
	}
	return ""
}

func (m *Module) pveFormData(sys *proxmox.System, edit bool) pveFormData {
	d := pveFormData{Sys: sys, Edit: edit, Addresses: strings.Join(sys.Addresses, "\n"), NoBox: m.pve.box == nil, Errors: map[string]string{},
		MinIv: proxmox.MinInterval, MaxIv: proxmox.MaxInterval, PinFmt: pveFingerprint(sys.PinSHA256)}
	d.User, d.TokenName = "node64@pve", "monitor"
	if u, t, ok := strings.Cut(sys.TokenID, "!"); ok && u != "" && t != "" {
		d.User, d.TokenName = u, t
	}
	return d
}

func (m *Module) pagePVEForm(w http.ResponseWriter, r *http.Request) {
	sys := &proxmox.System{Interval: proxmox.DefaultInterval, Enabled: true}
	edit := r.PathValue("id") != ""
	if edit {
		if sys = m.pveSystemOf(w, r); sys == nil {
			return
		}
		if sys.IsDocker() { // Docker-Hosts haben ihr eigenes Formular
			http.Redirect(w, r, dockerSysPath(sys.ID)+"/edit", http.StatusSeeOther)
			return
		}
	}
	d := m.pveFormData(sys, edit)
	d.HasSecret = edit && sys.Secret != ""
	sys.Secret = ""
	m.renderPVEForm(w, r, http.StatusOK, d)
}

func (m *Module) renderPVEForm(w http.ResponseWriter, r *http.Request, status int, d pveFormData) {
	title := "pve.add"
	if d.Edit {
		title = "pve.edit"
	}
	m.g.Render(w, r, status, Name+"/proxmox_form", title, d)
}

// pveSystemFromForm liest die Felder des Formulars in sys (Secret leer = beim Bearbeiten behalten).
func pveSystemFromForm(r *http.Request, sys *proxmox.System) {
	sys.Name = strings.TrimSpace(r.PostFormValue("name"))
	sys.Addresses = strings.FieldsFunc(r.PostFormValue("addresses"), func(c rune) bool { return c == '\n' || c == '\r' || c == ',' || c == ' ' })
	sys.TokenID = strings.TrimSpace(r.PostFormValue("token_id"))
	sys.Secret = strings.TrimSpace(r.PostFormValue("secret"))
	sys.Interval, _ = strconv.Atoi(strings.TrimSpace(r.PostFormValue("interval")))
	sys.Enabled = r.PostFormValue("enabled") == "on"
	sys.PinSHA256 = strings.TrimSpace(r.PostFormValue("pin_sha256"))
}

// pveProbe ist austauschbar (Tests).
var pveProbe = proxmox.Probe

func (m *Module) pagePVESave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	edit := r.PathValue("id") != ""
	sys := &proxmox.System{}
	stored := ""
	var old *proxmox.System
	if edit {
		if old = m.pveSystemOf(w, r); old == nil {
			return
		}
		if old.IsDocker() {
			http.Redirect(w, r, dockerSysPath(old.ID)+"/edit", http.StatusSeeOther)
			return
		}
		sys.ID, sys.Created, stored = old.ID, old.Created, old.Secret
	}
	pveSystemFromForm(r, sys)
	d := m.pveFormData(sys, edit)
	d.HasSecret = edit && stored != ""
	if !edit {
		d.Secret = sys.Secret // im Assistenten fuer den naechsten Schritt behalten
	}
	d.ProbePin = strings.TrimSpace(r.PostFormValue("probe_pin"))
	d.PinConfirm = r.PostFormValue("pin_confirm") == "on"
	if r.PostFormValue("op") == "probe" {
		// Pin des Tests: im vorigen Test gesehener und bestaetigter Fingerabdruck, sonst das Feld (leer = System-CA;
		// ein unbestaetigtes Zertifikat bekommt dann nur den Fingerabdruck gezeigt, das Token geht nicht hin)
		test := *sys
		confirmed := ""
		if d.ProbePin != "" && d.PinConfirm {
			if p, ok := proxmox.NormalizePin(d.ProbePin); ok {
				confirmed = p
				test.PinSHA256 = p
			}
		}
		if test.Name == "" {
			test.Name = "probe"
		}
		err := proxmox.ValidateSystem(&test, false)
		if err == nil && test.Secret == "" {
			// gespeichertes Secret nur an dieselben Adressen mit demselben Pin, sonst neu eingeben
			if old != nil && proxmox.SameEndpoint(old, &test) {
				test.Secret = stored
			}
			if test.Secret == "" {
				key := "pve.err.secret"
				if edit {
					key = "pve.err.secret_reenter"
				}
				err = &proxmox.FieldError{Field: "secret", Key: key}
			}
		}
		if err != nil {
			var fe *proxmox.FieldError
			if errors.As(err, &fe) {
				d.Errors[fe.Field] = m.g.T(r, fe.Key)
			}
			d.Error = m.pveErrText(r, err)
			m.renderPVEForm(w, r, http.StatusUnprocessableEntity, d)
			return
		}
		pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		res := pveProbe(pctx, test)
		cancel()
		d.Probe = &res
		d.ProbePin, d.ProbeFmt = res.CertSHA256, pveFingerprint(res.CertSHA256)
		pin, _ := proxmox.NormalizePin(sys.PinSHA256)
		d.PinDiffers = pin != "" && res.CertSHA256 != "" && pin != res.CertSHA256
		// bestaetigt bleibt bestaetigt (gleiches Zertifikat)
		d.PinConfirm = confirmed != "" && confirmed == res.CertSHA256
		if sys.Name == "" && res.OK { // Name vorschlagen: Clustername bzw. erster Node
			switch {
			case res.Cluster != "":
				sys.Name = res.Cluster
			case len(res.Nodes) > 0:
				sys.Name = res.Nodes[0]
			}
		}
		m.renderPVEForm(w, r, http.StatusOK, d)
		return
	}
	// Speichern: ein im Test gesehener Fingerabdruck wird nur bestaetigt uebernommen
	if d.ProbePin != "" && d.PinConfirm {
		sys.PinSHA256 = d.ProbePin
	} else if d.ProbePin != "" && !edit && sys.PinSHA256 == "" && r.PostFormValue("probe_trusted") != "1" {
		d.Errors["pin_sha256"] = m.g.T(r, "pve.err.pin_confirm")
		d.Error = d.Errors["pin_sha256"]
		d.ProbeFmt = pveFingerprint(d.ProbePin)
		m.renderPVEForm(w, r, http.StatusUnprocessableEntity, d)
		return
	}
	if sys.Name == "" {
		sys.Name = pveHostOf(sys.Addresses)
	}
	if err := m.pveSaveSystem(r, sys); err != nil {
		var fe *proxmox.FieldError
		if errors.As(err, &fe) {
			d.Errors[fe.Field] = m.g.T(r, fe.Key)
		} else if !errors.Is(err, proxmox.ErrNoBox) {
			m.fail(w, r, err)
			return
		}
		d.Error = m.pveErrText(r, err)
		d.ProbeFmt = pveFingerprint(d.ProbePin)
		m.renderPVEForm(w, r, http.StatusUnprocessableEntity, d)
		return
	}
	m.auditText(r, map[bool]string{true: "proxmox.update", false: "proxmox.create"}[edit], sys.Name)
	m.g.Flash(w, r, "success", m.g.T(r, "common.saved"))
	http.Redirect(w, r, pveResPath(sys.ID, ""), http.StatusSeeOther)
}

// pveHostOf: Name aus der ersten Adresse (Host ohne Port).
func pveHostOf(addrs []string) string {
	for _, a := range addrs {
		if n, ok := proxmox.NormalizeAddress(a); ok {
			h := strings.TrimPrefix(n, "https://")
			if i := strings.LastIndex(h, ":"); i > 0 {
				h = h[:i]
			}
			return strings.Trim(h, "[]")
		}
	}
	return ""
}
