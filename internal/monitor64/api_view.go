package monitor64

import (
	"context"
	"encoding/csv"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/tsdb"
)

// Lesende API fuer die Seiten: Uebersicht, Host mit Diensten und Schwellen, Verlauf, Probleme (inkl. CSV).
// Uebersicht und Host lesen den Zustand aus dem Speicher (Views), nur Probleme und Verlauf fragen die Datenbank.

// ovMeter ist ein Balken auf der Host-Kachel (CPU, RAM, groesster Fuellstand).
type ovMeter struct {
	Label string  `json:"label"` // cpu, ram, disk
	Value float64 `json:"value"`
	State string  `json:"state"`
}

type maintBrief struct {
	Reason string    `json:"reason,omitempty"`
	End    time.Time `json:"end,omitzero"`
}

// ovHost ist ein Host auf der Uebersicht.
type ovHost struct {
	UID      string      `json:"uid"`
	Name     string      `json:"name"`
	Address  string      `json:"address"`
	Kind     string      `json:"kind"`
	Icon     string      `json:"icon"`
	Group    string      `json:"group"`
	Tags     []string    `json:"tags"`
	State    string      `json:"state"`
	View     string      `json:"view"`
	Problems int         `json:"problems"`
	Services int         `json:"services"`
	New      int         `json:"new"`
	Vanished int         `json:"vanished"`
	Paused   bool        `json:"paused,omitempty"`
	Maint    *maintBrief `json:"maint,omitempty"`
	Unreach  string      `json:"unreach,omitempty"`
	Meters   []ovMeter   `json:"meters"`
	Text     string      `json:"text,omitempty"`
	CPU      float64     `json:"cpu,omitempty"`
	RAM      float64     `json:"ram,omitempty"`
	HasCPU   bool        `json:"has_cpu,omitempty"`
	HasRAM   bool        `json:"has_ram,omitempty"`
	Checked  time.Time   `json:"checked,omitzero"`
}

// ovProblem ist ein offenes Problem auf der Uebersicht.
type ovProblem struct {
	HostUID string    `json:"host_uid"`
	Host    string    `json:"host"`
	Key     string    `json:"key"`
	Name    string    `json:"name"`
	State   string    `json:"state"`
	Detail  string    `json:"detail,omitempty"`
	Since   time.Time `json:"since,omitzero"`
	Acked   bool      `json:"acked,omitempty"`
	Maint   bool      `json:"maint,omitempty"`
	Unreach bool      `json:"unreach,omitempty"`
}

// ovRecent ist ein Eintrag "Zuletzt" (geloest, Wartung ...).
type ovRecent struct {
	Kind    string    `json:"kind"`
	HostUID string    `json:"host_uid,omitempty"`
	Host    string    `json:"host,omitempty"`
	Name    string    `json:"name,omitempty"`
	Text    string    `json:"text,omitempty"`
	By      Actor     `json:"by"`
	At      time.Time `json:"at"`
}

type ovData struct {
	Counts      map[string]int `json:"counts"`
	Hosts       []ovHost       `json:"hosts"`
	Problems    []ovProblem    `json:"problems"`
	Recent      []ovRecent     `json:"recent"`
	Groups      []string       `json:"groups"`
	Unreachable int            `json:"unreachable"`
	Services    int            `json:"services"`
	OpenUnacked int            `json:"open_unacked"`
	Running     bool           `json:"running"`
}

func stateName(s eval.State) string { return s.String() }

// sortedViews: Views nach Gruppe und Name.
func (m *Module) sortedViews() []*HostView {
	vs := m.Views()
	sort.SliceStable(vs, func(i, j int) bool {
		a, b := vs[i].Host, vs[j].Host
		if a.Group != b.Group {
			return strings.ToLower(a.Group) < strings.ToLower(b.Group)
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	return vs
}

func metricOf(s SvcView, name string) (MetricView, bool) {
	for _, mt := range s.Metrics {
		if mt.Name == name {
			return mt, true
		}
	}
	return MetricView{}, false
}

func unreachText(v *HostView) string {
	var errs []string
	for _, a := range v.Accesses {
		if !a.OK && a.Error != "" {
			errs = append(errs, a.Name+": "+a.Error)
		}
	}
	return strings.Join(errs, "; ")
}

// overview baut die Daten der Uebersicht.
func (m *Module) overview(ctx context.Context) ovData {
	d := ovData{Counts: map[string]int{"ok": 0, "warn": 0, "crit": 0, "unknown": 0}, Hosts: []ovHost{}, Problems: []ovProblem{}, Recent: []ovRecent{}, Groups: []string{},
		Running: m.scheduler() != nil}
	open, _ := m.store.OpenProblems(ctx)
	names := map[string]string{}
	svcNames := map[string]string{}
	for _, v := range m.sortedViews() {
		h := v.Host
		names[h.UID] = h.Name
		if !slices.Contains(d.Groups, h.Group) {
			d.Groups = append(d.Groups, h.Group)
		}
		o := ovHost{UID: h.UID, Name: h.Name, Address: h.Address, Kind: h.Kind, Icon: hostIcon(h.Kind), Group: h.Group, Tags: nonNil(h.Tags),
			State: stateName(v.State), View: string(v.View), New: v.New, Paused: h.Paused, Checked: v.Checked, Meters: []ovMeter{}}
		if v.Maint != nil {
			o.Maint = &maintBrief{Reason: v.Maint.Reason, End: v.Maint.End}
		}
		unreach := v.View == eval.ViewUnreachable
		if unreach {
			o.Unreach = unreachText(v)
			d.Unreachable++
			p := ovProblem{HostUID: h.UID, Host: h.Name, State: "unknown", Unreach: true, Detail: o.Unreach, Maint: v.Maint != nil}
			if op, ok := open[h.UID+"|"]; ok {
				p.Since, p.Acked = op.Opened, op.Ack != nil
			}
			d.Problems = append(d.Problems, p)
		}
		var disk *ovMeter
		for _, s := range v.Services {
			svcNames[h.UID+"|"+s.Key] = s.Name
			o.Services++
			st := s.State
			if unreach {
				st = eval.Unknown
			}
			d.Counts[stateName(st)]++
			if s.Vanished {
				o.Vanished++
			}
			if st != eval.OK && !s.ShowOnly {
				o.Problems++
				if !unreach {
					p := ovProblem{HostUID: h.UID, Host: h.Name, Key: s.Key, Name: s.Name, State: stateName(st), Detail: firstNonEmpty(s.Cause, s.Text), Acked: s.Acked, Maint: v.Maint != nil}
					if op, ok := open[h.UID+"|"+s.Key]; ok {
						p.Since = op.Opened
						p.Acked = p.Acked || op.Ack != nil
					}
					d.Problems = append(d.Problems, p)
				}
			}
			switch s.Kind {
			case "cpu":
				if mt, ok := metricOf(s, "util"); ok {
					o.CPU, o.HasCPU = mt.Value, true
					o.Meters = append(o.Meters, ovMeter{Label: "cpu", Value: mt.Value, State: stateName(mt.Status.Level)})
				}
			case "mem":
				if mt, ok := metricOf(s, "used"); ok {
					o.RAM, o.HasRAM = mt.Value, true
					o.Meters = append(o.Meters, ovMeter{Label: "ram", Value: mt.Value, State: stateName(mt.Status.Level)})
				}
			case "fs", "zfs", "store", "ds":
				if mt, ok := metricOf(s, "used"); ok && mt.Unit == "%" && (disk == nil || mt.Value > disk.Value) {
					disk = &ovMeter{Label: "disk", Value: mt.Value, State: stateName(mt.Status.Level)}
				}
			}
			if o.Text == "" && s.Text != "" {
				o.Text = s.Text
			}
		}
		if disk != nil {
			o.Meters = append(o.Meters, *disk)
		}
		d.Services += o.Services
		d.Hosts = append(d.Hosts, o)
	}
	sort.SliceStable(d.Problems, func(i, j int) bool {
		a, b := d.Problems[i], d.Problems[j]
		if a.Acked != b.Acked {
			return !a.Acked
		}
		return stateRank[a.State] > stateRank[b.State]
	})
	// Zuletzt: geloeste Probleme und Wartung
	if evs, err := m.store.RecentEvents(ctx, []string{"ok", "resolved", "maint", "maint_end"}, 8); err == nil {
		for _, e := range evs {
			rc := ovRecent{Kind: e.Kind, HostUID: e.HostUID, Host: names[e.HostUID], Text: e.Text, By: e.Actor, At: e.At}
			if e.Key != "" {
				rc.Name = firstNonEmpty(svcNames[e.HostUID+"|"+e.Key], e.Key)
			}
			d.Recent = append(d.Recent, rc)
		}
	}
	d.OpenUnacked = m.store.openUnackedCount(ctx)
	return d
}

// apiOverview: GET Daten der Uebersicht (Zaehler, Probleme, Zuletzt, Hosts).
func (m *Module) apiOverview(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, m.overview(r.Context()))
}

// ---------------------------------------------------------------------------------------------------------
// Host

// overrideBrief ist die wirksame Abweichung einer Schwelle.
type overrideBrief struct {
	Index      int       `json:"index"`
	UID        string    `json:"uid"`
	TargetType string    `json:"target_type"`
	Target     string    `json:"target"`
	Rule       eval.Rule `json:"rule"`
}

// levelsOut sind die Stufen einer Schwelle an einem Dienst (Plan "Schwellen und Regeln im Detail"), je Regel-Art:
// eine Messgroesse mit Schwelle oder eine Zustandsregel.
type levelsOut struct {
	Kind     string         `json:"kind"`             // Regel-Art
	Metric   string         `json:"metric,omitempty"` // Messgroesse (leer = Zustandsregel)
	State    bool           `json:"state,omitempty"`  // Zustandsregel
	Std      eval.Rule      `json:"std"`
	Override *overrideBrief `json:"override,omitempty"`
	HostKind *eval.Rule     `json:"host_kind,omitempty"` // alle Dienste dieses Hosts mit dieser Regel-Art
	Service  *eval.Rule     `json:"service,omitempty"`   // nur dieser Dienst
	Eff      eval.Effective `json:"eff"`
}

func (m *Module) levels(cfg *cfgCache, h *Host, row *ServiceRow, kind string) *levelsOut {
	hl := m.hostLevel(h.UID, parseHostRules(row.HostRule), kind)
	l := &levelsOut{Kind: kind, Std: cfg.std[kind], HostKind: hl.Kind, Service: hl.Service}
	l.Eff = eval.Resolve(cfg.std, cfg.overrides, hostRef(h), hl, kind)
	l.State = l.Eff.IsState
	if i := l.Eff.Override; i >= 0 && i < len(cfg.overrides) {
		o := cfg.overrides[i]
		tt, t := "group", o.Group
		if o.Tag != "" {
			tt, t = "tag", o.Tag
		}
		l.Override = &overrideBrief{Index: i, UID: o.ID, TargetType: tt, Target: t, Rule: o.Rule}
	}
	return l
}

// svcOut ist ein Dienst auf der Host-Seite.
type svcOut struct {
	SvcView
	Category   string       `json:"category"`
	Since      time.Time    `json:"since,omitzero"`
	Ack        *ackInfo     `json:"ack,omitempty"`
	CustomName string       `json:"custom_name,omitempty"`
	Soll       string       `json:"soll,omitempty"`
	Report     string       `json:"report,omitempty"`
	Guest      bool         `json:"guest,omitempty"`
	Primary    int          `json:"primary"`          // Index der ersten Messgroesse mit Schwelle (-1 = keine)
	Levels     *levelsOut   `json:"levels,omitempty"` // Schwelle der ersten Messgroesse (Spalte "Schwellen")
	Rules      []*levelsOut `json:"rules"`            // alle Regel-Arten des Dienstes: Messgroessen, dann Zustandsregeln
}

// chartDef ist ein Diagramm der Host-Seite.
type chartDef struct {
	ID     string        `json:"id"`
	Unit   string        `json:"unit"`
	Max    float64       `json:"max,omitempty"`
	Series []chartSeries `json:"series"`
	Warn   *float64      `json:"warn,omitempty"`
	Crit   *float64      `json:"crit,omitempty"`
}

type chartSeries struct {
	Label  string `json:"label"`
	Svc    string `json:"svc"`
	Metric string `json:"metric"`
}

// accessState ist ein Zugang auf der Host-Seite: gespeichert (ohne Geheimnis) mit Laufzeitstand.
type accessState struct {
	accessOut
	Name     string `json:"name"`
	OK       bool   `json:"ok"`
	Failures int    `json:"failures"`
	Error    string `json:"error,omitempty"`
	Known    bool   `json:"known"` // schon abgefragt
}

type hostDetail struct {
	Host     *Host         `json:"host"`
	Icon     string        `json:"icon"`
	State    string        `json:"state"`
	View     string        `json:"view"`
	Checked  time.Time     `json:"checked,omitzero"`
	Maint    *eval.Window  `json:"maint,omitempty"`
	Unreach  string        `json:"unreach,omitempty"`
	Services []svcOut      `json:"services"`
	Accesses []accessState `json:"accesses"`
	New      []*ServiceRow `json:"new"`
	Ignored  []*ServiceRow `json:"ignored"`
	Charts   []chartDef    `json:"charts"`
	Running  bool          `json:"running"`
}

// hostDetail baut die Daten der Host-Seite.
func (m *Module) hostDetail(ctx context.Context, uid string) (*hostDetail, error) {
	h, err := m.store.Host(ctx, uid)
	if err != nil {
		return nil, err
	}
	d := &hostDetail{Host: h, Icon: hostIcon(h.Kind), State: "unknown", View: string(eval.ViewUnknown), Services: []svcOut{}, Accesses: []accessState{},
		New: []*ServiceRow{}, Ignored: []*ServiceRow{}, Charts: []chartDef{}, Running: m.scheduler() != nil}
	v := m.viewOf(uid)
	if v != nil {
		d.State, d.View, d.Checked, d.Maint = stateName(v.State), string(v.View), v.Checked, v.Maint
		if v.View == eval.ViewUnreachable {
			d.Unreach = unreachText(v)
		}
	}
	rows, err := m.store.Services(ctx, uid)
	if err != nil {
		return nil, err
	}
	byKey := map[string]*ServiceRow{}
	for _, r := range rows {
		byKey[r.Key] = r
		switch r.Adopted {
		case 0:
			d.New = append(d.New, r)
		case -1:
			d.Ignored = append(d.Ignored, r)
		}
	}
	accs, err := m.store.Accesses(ctx, uid)
	if err != nil {
		return nil, err
	}
	for _, a := range accessOuts(accs) {
		as := accessState{accessOut: a, Name: accessName(a.Type)}
		if v != nil {
			for _, av := range v.Accesses {
				if av.UID == a.UID {
					as.OK, as.Failures, as.Error, as.Known = av.OK, av.Failures, av.Error, true
				}
			}
		}
		d.Accesses = append(d.Accesses, as)
	}
	open, _ := m.store.OpenProblems(ctx)
	cfg := m.config()
	if v != nil {
		for _, s := range v.Services {
			o := svcOut{SvcView: s, Category: svcCategory(s.Kind), Primary: -1, Guest: guestKind(s.Kind), Rules: []*levelsOut{}}
			if op, ok := open[uid+"|"+s.Key]; ok {
				o.Since, o.Ack = op.Opened, op.Ack
			}
			row := byKey[s.Key]
			if row == nil {
				row = &ServiceRow{HostUID: uid, Key: s.Key, Kind: s.Kind}
			}
			o.CustomName, o.Soll, o.Report = row.Name, row.Soll, row.Report
			seen := map[string]bool{}
			for i, mt := range s.Metrics {
				rk := firstNonEmpty(mt.RuleKind, mt.Metric.Rule)
				if rk == "" || seen[rk] {
					continue
				}
				seen[rk] = true
				l := m.levels(cfg, h, row, rk)
				l.Metric = mt.Name
				o.Rules = append(o.Rules, l)
				if o.Primary < 0 {
					o.Primary, o.Levels = i, l
				}
			}
			if s.Kind != "access" && byKey[s.Key] != nil { // Zugaenge sind keine Zeile in m64_services
				for _, k := range factKinds[s.Kind] {
					if !seen[k] {
						seen[k] = true
						o.Rules = append(o.Rules, m.levels(cfg, h, row, k))
					}
				}
			}
			d.Services = append(d.Services, o)
		}
		d.Charts = m.charts(cfg, h, byKey, v.Services)
	}
	return d, nil
}

// charts waehlt die Diagramme der Host-Seite: CPU, RAM, Netzwerk (bis zu zwei Ports), Platten-I/O (bis zu zwei).
func (m *Module) charts(cfg *cfgCache, h *Host, rows map[string]*ServiceRow, svcs []SvcView) []chartDef {
	out := []chartDef{}
	thr := func(c *chartDef, s SvcView, kind string) {
		row := rows[s.Key]
		if row == nil {
			row = &ServiceRow{HostUID: h.UID, Key: s.Key, Kind: s.Kind}
		}
		e := m.levels(cfg, h, row, kind).Eff
		w, cr, _, _ := e.Levels()
		if !w.Off && e.Mode != eval.ModeFree {
			c.Warn = &w.V
		}
		if !cr.Off && e.Mode != eval.ModeFree {
			c.Crit = &cr.V
		}
	}
	var nets, disks []chartSeries
	nNet, nDisk := 0, 0
	for _, s := range svcs {
		switch s.Kind {
		case "cpu":
			if _, ok := metricOf(s, "util"); ok {
				c := chartDef{ID: "cpu", Unit: "%", Max: 100, Series: []chartSeries{{Label: "CPU", Svc: s.Key, Metric: "util"}}}
				thr(&c, s, eval.KindCPUUtil)
				out = append(out, c)
			}
		case "mem":
			if _, ok := metricOf(s, "used"); ok {
				c := chartDef{ID: "ram", Unit: "%", Max: 100, Series: []chartSeries{{Label: "RAM", Svc: s.Key, Metric: "used"}}}
				thr(&c, s, eval.KindMemUsed)
				out = append(out, c)
			}
		case "if":
			if _, ok := metricOf(s, "in"); ok && nNet < 2 {
				nNet++
				nets = append(nets, chartSeries{Label: s.Name + " ↓", Svc: s.Key, Metric: "in"}, chartSeries{Label: s.Name + " ↑", Svc: s.Key, Metric: "out"})
			}
		case "disk":
			if _, ok := metricOf(s, "read"); ok && nDisk < 2 {
				nDisk++
				disks = append(disks, chartSeries{Label: s.Name + " R", Svc: s.Key, Metric: "read"}, chartSeries{Label: s.Name + " W", Svc: s.Key, Metric: "write"})
			}
		}
	}
	if len(nets) > 0 {
		out = append(out, chartDef{ID: "net", Unit: "Mbit/s", Series: nets})
	}
	if len(disks) > 0 {
		out = append(out, chartDef{ID: "disk", Unit: "B/s", Series: disks})
	}
	return out
}

// apiHost: GET Host mit Diensten, Zugaengen (ohne Geheimnisse), neuen und ignorierten Diensten.
func (m *Module) apiHost(w http.ResponseWriter, r *http.Request) {
	d, err := m.hostDetail(r.Context(), r.PathValue("uid"))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// ---------------------------------------------------------------------------------------------------------
// Verlauf

var ranges = map[string]time.Duration{"6h": 6 * time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour, "1y": 365 * 24 * time.Hour}

// seriesOut ist eine Reihe fuer ein Diagramm (Schluessel ohne Host: "dienst|messgroesse").
type seriesOut struct {
	S      string       `json:"s"`
	Res    string       `json:"res"`
	Step   int64        `json:"step"`
	Points []tsdb.Point `json:"points"`
}

// apiSeries: GET Verlauf eines Hosts: host, s=dienst|messgroesse (mehrfach), range (6h, 24h, 7d, 30d, 1y) mit off
// (Zeitraeume zurueck) oder from/to (Unix-Sekunden, Zoom), points (hoechstens 700).
func (m *Module) apiSeries(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	host := q.Get("host")
	ss := q["s"]
	if host == "" || len(ss) == 0 || len(ss) > 16 {
		m.fail(w, r, errBad("series"))
		return
	}
	hs := m.history()
	if hs == nil {
		m.fail(w, r, errNotRunning)
		return
	}
	now := time.Now()
	to, from := now, now.Add(-24*time.Hour)
	if d, ok := ranges[q.Get("range")]; ok {
		off, _ := strconv.Atoi(q.Get("off"))
		if off < 0 || off > 1000 {
			off = 0
		}
		to = now.Add(-time.Duration(off) * d)
		from = to.Add(-d)
	}
	if f, err := strconv.ParseInt(q.Get("from"), 10, 64); err == nil {
		if t, err := strconv.ParseInt(q.Get("to"), 10, 64); err == nil && t > f {
			from, to = time.Unix(f, 0), time.Unix(t, 0)
		}
	}
	pts, _ := strconv.Atoi(q.Get("points"))
	if pts <= 0 || pts > 700 {
		pts = 700
	}
	keys := make([]string, len(ss))
	for i, s := range ss {
		svc, metric, ok := strings.Cut(s, "|")
		if !ok || svc == "" || metric == "" {
			m.fail(w, r, errBad("series"))
			return
		}
		keys[i] = seriesKey(host, svc, metric)
	}
	res, err := hs.QueryMulti(r.Context(), keys, from, to, pts)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	out := make([]seriesOut, len(res))
	for i, s := range res {
		out[i] = seriesOut{S: ss[i], Res: s.Res, Step: s.Step, Points: s.Points}
	}
	writeJSON(w, http.StatusOK, map[string]any{"from": from.Unix(), "to": to.Unix(), "series": out})
}

// apiSparks: GET Mini-Verlaeufe (24 Std., 48 Punkte, Mittelwerte): ohne host die CPU je Host (Kacheln), mit host
// die erste Messgroesse mit Schwelle je Dienst (Spalte "24 Std.").
func (m *Module) apiSparks(w http.ResponseWriter, r *http.Request) {
	hs := m.history()
	out := map[string][]float64{}
	if hs == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	var ids, keys []string
	if host := r.URL.Query().Get("host"); host != "" {
		if v := m.viewOf(host); v != nil {
			for _, s := range v.Services {
				name := ""
				for _, mt := range s.Metrics {
					if mt.Metric.Rule != "" {
						name = mt.Name
						break
					}
				}
				if name == "" && len(s.Metrics) > 0 {
					name = s.Metrics[0].Name
				}
				if name != "" {
					ids, keys = append(ids, s.Key), append(keys, seriesKey(host, s.Key, name))
				}
			}
		}
	} else {
		for _, v := range m.Views() {
			for _, s := range v.Services {
				if s.Kind == "cpu" {
					ids, keys = append(ids, v.Host.UID), append(keys, seriesKey(v.Host.UID, s.Key, "util"))
					break
				}
			}
		}
	}
	if len(keys) == 0 {
		writeJSON(w, http.StatusOK, out)
		return
	}
	now := time.Now()
	res, err := hs.QueryMulti(r.Context(), keys, now.Add(-24*time.Hour), now, 48)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	for i, s := range res {
		vals := make([]float64, len(s.Points))
		for k, p := range s.Points {
			vals[k] = p.Avg
		}
		out[ids[i]] = vals
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------------------------------------
// Probleme

// problemOut ist ein Problem auf der Seite Probleme.
type problemOut struct {
	problemRow
	Host     string   `json:"host"`
	HostGone bool     `json:"host_gone,omitempty"`
	Name     string   `json:"name"`
	Duration int64    `json:"duration"` // Sekunden (offen: bis jetzt)
	Channels []string `json:"channels"` // Namen der Kanaele, an die gemeldet wurde
}

type problemsOut struct {
	Problems []problemOut `json:"problems"`
	People   []Actor      `json:"people"`
	Counts   struct {
		Open   int `json:"open"`
		Closed int `json:"closed"`
	} `json:"counts"`
}

// channelNames ordnet Kanal-IDs ihren Namen zu ("default" = Standardkanaele).
func (m *Module) channelNames(ctx context.Context) map[string]string {
	out := map[string]string{}
	chs, _ := m.store.Channels(ctx)
	for _, c := range chs {
		out[strconv.FormatInt(c.ID, 10)] = c.Name
	}
	return out
}

func actorMatches(a Actor, who string) bool {
	switch {
	case who == "":
		return true
	case who == "system":
		return a.Kind == "system"
	case who == "api":
		return a.Kind == "api"
	case strings.HasPrefix(who, "user:"):
		return a.Kind == "user" && (a.UID == who[5:] || a.Name == who[5:])
	}
	return false
}

func actorKey(a Actor) string {
	switch a.Kind {
	case "system", "api":
		return a.Kind
	case "user":
		return "user:" + firstNonEmpty(a.UID, a.Name)
	}
	return ""
}

// problems liest die Probleme mit den Filtern der Seite: status (open, closed, all), range, who, q, host.
func (m *Module) problems(r *http.Request) (problemsOut, error) {
	ctx := r.Context()
	q := r.URL.Query()
	out := problemsOut{Problems: []problemOut{}, People: []Actor{}}
	f := problemFilter{Status: q.Get("status"), HostUID: q.Get("host")}
	if f.Status == "" {
		f.Status = "open"
	}
	rg := q.Get("range")
	if rg == "" {
		rg = "7d"
	}
	if d, ok := ranges[rg]; ok {
		f.Since = time.Now().Add(-d)
	}
	status := f.Status
	f.Status = "all"
	list, err := m.store.Problems(ctx, f)
	if err != nil {
		return out, err
	}
	hosts := map[string]string{}
	if hl, err := m.store.Hosts(ctx); err == nil {
		for _, h := range hl {
			hosts[h.UID] = h.Name
		}
	}
	svcNames := map[string]string{}
	for _, v := range m.Views() {
		for _, s := range v.Services {
			svcNames[v.Host.UID+"|"+s.Key] = s.Name
		}
	}
	chNames := m.channelNames(ctx)
	who, search := q.Get("who"), strings.ToLower(strings.TrimSpace(q.Get("q")))
	seen := map[string]bool{}
	now := time.Now()
	for _, p := range list {
		o := problemOut{problemRow: p, Channels: []string{}}
		name, ok := hosts[p.HostUID]
		if !ok {
			name, o.HostGone = p.HostUID, true
		}
		o.Host = name
		if p.Key != "" {
			o.Name = firstNonEmpty(svcNames[p.HostUID+"|"+p.Key], p.Key)
		}
		end := now
		if !p.Closed.IsZero() {
			end = p.Closed
		}
		o.Duration = int64(end.Sub(p.Opened).Seconds())
		for _, id := range p.Notified {
			o.Channels = append(o.Channels, firstNonEmpty(chNames[id], id))
		}
		actors := []Actor{}
		if !p.Closed.IsZero() {
			actors = append(actors, p.ClosedBy)
		}
		if p.Ack != nil {
			actors = append(actors, p.Ack.By)
		}
		for _, a := range actors {
			if k := actorKey(a); k != "" && !seen[k] {
				seen[k] = true
				out.People = append(out.People, a)
			}
		}
		if p.Closed.IsZero() {
			out.Counts.Open++
		} else {
			out.Counts.Closed++
		}
		if (status == "open" && !p.Closed.IsZero()) || (status == "closed" && p.Closed.IsZero()) {
			continue
		}
		if who != "" && !slices.ContainsFunc(actors, func(a Actor) bool { return actorMatches(a, who) }) {
			continue
		}
		if search != "" {
			hay := strings.ToLower(o.Host + " " + o.Name + " " + p.Key)
			for _, a := range actors {
				hay += " " + strings.ToLower(a.Name)
			}
			if p.Ack != nil {
				hay += " " + strings.ToLower(p.Ack.Comment)
			}
			if !strings.Contains(hay, search) {
				continue
			}
		}
		out.Problems = append(out.Problems, o)
	}
	return out, nil
}

// apiProblems: GET Probleme mit Filtern.
func (m *Module) apiProblems(w http.ResponseWriter, r *http.Request) {
	out, err := m.problems(r)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// apiProblem: GET ein Problem mit Ablauf.
func (m *Module) apiProblem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := m.store.Problem(ctx, r.PathValue("uid"))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	evs, err := m.store.Events(ctx, p.UID)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	if evs == nil {
		evs = []eventRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"problem": p, "events": evs, "channels": m.channelNames(ctx)})
}

type problemActionIn struct {
	Host    string `json:"host"`
	Key     string `json:"key"`
	Action  string `json:"action"` // ack, unack, comment, resolve
	Comment string `json:"comment"`
}

// apiProblemAction: POST quittieren, Quittierung aufheben, kommentieren, als geloest markieren (mit Akteur).
func (m *Module) apiProblemAction(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in problemActionIn
	if err := decode(r, &in); err != nil {
		m.fail(w, r, err)
		return
	}
	comment := cleanText(in.Comment, 500)
	by := m.actor(r)
	var err error
	switch in.Action {
	case "ack":
		err = m.Ack(ctx, in.Host, in.Key, comment, by)
	case "unack":
		err = m.Unack(ctx, in.Host, in.Key, by)
	case "comment":
		if comment == "" {
			err = errBad("comment")
		} else {
			err = m.Comment(ctx, in.Host, in.Key, comment, by)
		}
	case "resolve":
		err = m.Resolve(ctx, in.Host, in.Key, comment, by)
	default:
		err = errBad("action")
	}
	if err != nil {
		m.fail(w, r, err)
		return
	}
	target := in.Host
	if h, err := m.store.Host(ctx, in.Host); err == nil {
		target = h.Name
	}
	if in.Key != "" {
		target += " · " + in.Key
	}
	m.audit(r, "problem."+in.Action, target, comment)
	if in.Action == "resolve" {
		m.repoll(in.Host)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// txReq uebersetzt Texte des Kerns im Format "i18n:<schluessel>?k=v" fuer Ausgaben ohne Browser (CSV); die
// Oberflaeche uebersetzt selbst (tx in monitor64.js).
func (m *Module) txReq(r *http.Request, s string) string {
	rest, ok := strings.CutPrefix(s, "i18n:")
	if !ok || m.g.T == nil {
		return s
	}
	key, query, _ := strings.Cut(rest, "?")
	if !strings.HasPrefix(key, "monitor64.") {
		return s
	}
	vals, err := url.ParseQuery(query)
	if err != nil {
		return s
	}
	var args []any
	for k, v := range vals {
		if len(v) > 0 {
			args = append(args, k, v[0])
		}
	}
	return m.g.T(r, key, args...)
}

// csvCell schuetzt vor Formel-Einschleusung (Tabellenprogramme werten = + - @ am Anfang aus).
func csvCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// apiProblemsCSV: GET Probleme als CSV (Filter wie die Liste; Semikolon, UTF-8 mit BOM fuer Tabellenprogramme).
func (m *Module) apiProblemsCSV(w http.ResponseWriter, r *http.Request) {
	out, err := m.problems(r)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	t := func(k string) string {
		if m.g.T != nil {
			return m.g.T(r, "monitor64.csv."+k)
		}
		return k
	}
	loc := time.Local
	if m.g.Timezone != nil {
		if l := m.g.Timezone(r); l != nil {
			loc = l
		}
	}
	tm := func(x time.Time) string {
		if x.IsZero() {
			return ""
		}
		return x.In(loc).Format("2006-01-02 15:04:05")
	}
	who := func(a Actor) string {
		switch a.Kind {
		case "system":
			return "System"
		case "api":
			return "API-Key " + a.Name
		case "":
			return ""
		}
		if a.Method != "" {
			return a.Name + " (" + a.Method + ")"
		}
		return a.Name
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="monitor64-probleme-`+time.Now().Format("20060102")+`.csv"`)
	_, _ = w.Write([]byte("\xef\xbb\xbf"))
	cw := csv.NewWriter(w)
	cw.Comma = ';'
	_ = cw.Write([]string{t("state"), t("worst"), t("host"), t("service"), t("opened"), t("closed"), t("duration_min"), t("how"), t("closed_by"), t("ack_by"), t("ack_comment"), t("notified")})
	for _, p := range out.Problems {
		ackBy, ackC := "", ""
		if p.Ack != nil {
			ackBy, ackC = who(p.Ack.By), p.Ack.Comment
		}
		closedBy := ""
		if !p.Closed.IsZero() {
			closedBy = who(p.ClosedBy)
		}
		row := []string{p.State, p.Worst, p.Host, firstNonEmpty(m.txReq(r, p.Name), "-"), tm(p.Opened), tm(p.Closed), strconv.FormatInt(p.Duration/60, 10), p.How, closedBy, ackBy, ackC, strings.Join(p.Channels, ", ")}
		for i := range row {
			row[i] = csvCell(row[i])
		}
		_ = cw.Write(row)
	}
	cw.Flush()
	m.audit(r, "problems.csv", "", fmt.Sprintf("rows=%d", len(out.Problems)))
}
