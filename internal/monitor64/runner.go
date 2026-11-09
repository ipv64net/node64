package monitor64

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/notify"
)

// Abfragerunde je Host (Plan "Kernmodell"): Zugaenge abfragen -> Dienste (Rangfolge Agent > SSH > API > SNMP >
// Prometheus) -> Dienste erkennen/verschwunden -> Messwerte bewerten (eval) -> Verlauf (tsdb) -> Probleme ->
// Benachrichtigung (eval.Notifier -> Dispatcher).

// collector liefert die Dienste eines Zugangs.
type collector interface {
	collect(ctx context.Context) ([]model.Service, error)
	close()
}

// accessName ist der Anzeigename eines Zugangs ("Zugang SSH").
func accessName(typ string) string {
	switch typ {
	case "agent":
		return "Agent"
	case "ssh":
		return "SSH"
	case "snmp":
		return "SNMP"
	case "prom":
		return "Prometheus"
	}
	return "API"
}

// accessRank: Rangfolge bei doppelten Diensten (kleiner = bevorzugt).
func accessRank(typ string) int {
	switch typ {
	case "agent":
		return 0
	case "ssh":
		return 1
	case "pve", "pbs", "docker":
		return 2
	case "snmp":
		return 3
	}
	return 4
}

// factKinds: welche Zustandsregeln eine Dienst-Art kennt (fehlt der Fact, ist die Bedingung nicht erfuellt).
var factKinds = map[string][]string{
	"disk":    {eval.KindSmartFailed, eval.KindSmartSectors, eval.KindSmartSectorsUp},
	"raid":    {eval.KindRAIDDegraded},
	"zfs":     {eval.KindRAIDDegraded},
	"bond":    {eval.KindBondMemberDown, eval.KindBondLACP},
	"updates": {eval.KindUpdatesSecurity},
	"reboot":  {eval.KindRebootRequired},
	"systemd": {eval.KindSystemdFailed},
	"vm":      {eval.KindGuestDown},
	"ct":      {eval.KindGuestDown},
	"ctr":     {eval.KindGuestDown, eval.KindCtrUnhealthy},
	"backup":  {eval.KindBackupOld},
	"job":     {eval.KindJobFailed},
	"store":   {eval.KindStoreInactive},
	"ds":      {eval.KindStoreInactive},
	"cluster": {eval.KindClusterQuorum, eval.KindClusterNodeDown},
	"ha":      {eval.KindHAError},
	"ceph":    {eval.KindCephWarn, eval.KindCephErr},
}

// factKind bildet einen Fact-Code auf die Art der Zustandsregel ab ("" = eigener Zustand ohne Regel).
func factKind(code string) string {
	switch code {
	case "smart_failed":
		return eval.KindSmartFailed
	case "smart_sectors":
		return eval.KindSmartSectors
	case "smart_sectors_rising":
		return eval.KindSmartSectorsUp
	case "raid_degraded", "zfs_degraded":
		return eval.KindRAIDDegraded
	case "bond_member_down":
		return eval.KindBondMemberDown
	case "lacp_mismatch":
		return eval.KindBondLACP
	case "updates_security":
		return eval.KindUpdatesSecurity
	case "reboot_required":
		return eval.KindRebootRequired
	case "systemd_failed":
		return eval.KindSystemdFailed
	case "guest_down":
		return eval.KindGuestDown
	case "ups_on_battery":
		return eval.KindUPSOnBattery
	case "ctr_unhealthy":
		return eval.KindCtrUnhealthy
	case "backup_old":
		return eval.KindBackupOld
	case "job_failed":
		return eval.KindJobFailed
	case "store_inactive":
		return eval.KindStoreInactive
	case "cluster_no_quorum":
		return eval.KindClusterQuorum
	case "cluster_node_down":
		return eval.KindClusterNodeDown
	case "ha_error":
		return eval.KindHAError
	case "ceph_warn":
		return eval.KindCephWarn
	case "ceph_err":
		return eval.KindCephErr
	}
	return ""
}

// MetricView ist eine bewertete Messgroesse fuer die Oberflaeche.
type MetricView struct {
	model.Metric
	Status   eval.Status `json:"status"`
	RuleKind string      `json:"rule_kind,omitempty"`
}

// SvcView ist ein Dienst fuer die Oberflaeche.
type SvcView struct {
	Key      string       `json:"key"`
	Name     string       `json:"name"`
	Kind     string       `json:"kind"`
	State    eval.State   `json:"state"`
	Text     string       `json:"text,omitempty"`
	Cause    string       `json:"cause,omitempty"`
	Via      string       `json:"via,omitempty"`
	Adopted  int          `json:"adopted"`
	Vanished bool         `json:"vanished,omitempty"`
	ShowOnly bool         `json:"show_only,omitempty"`
	Acked    bool         `json:"acked,omitempty"`
	Metrics  []MetricView `json:"metrics,omitempty"`
}

// HostView ist der aktuelle Stand eines Hosts fuer die Oberflaeche.
type HostView struct {
	Host     *Host             `json:"host"`
	View     eval.HostView     `json:"view"`
	State    eval.State        `json:"state"`
	Checked  time.Time         `json:"checked,omitzero"`
	Accesses []AccessView      `json:"accesses"`
	Services []SvcView         `json:"services"`
	New      int               `json:"new_services"`
	Maint    *eval.Window      `json:"maintenance,omitempty"`
	Errors   map[string]string `json:"errors,omitempty"`
}

// AccessView ist ein Zugang mit Laufzeitstand.
type AccessView struct {
	UID      string `json:"uid"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	OK       bool   `json:"ok"`
	Failures int    `json:"failures"`
	Error    string `json:"error,omitempty"`
}

// hostRT ist der Laufzeitstand eines Hosts (je Node, gespeichert in m64_runtime).
type hostRT struct {
	mu       sync.Mutex
	host     *Host
	accs     []*accRT
	Trackers map[string]*eval.Tracker `json:"trackers"`
	Failures map[string]int           `json:"failures"`
	LastDisc time.Time                `json:"last_disc,omitzero"`
	dirty    bool

	viewMu         sync.Mutex // eigene Sperre: die Oberflaeche wartet nicht auf eine laufende Abfrage
	view           *HostView
	lastSave       time.Time
	lastSavedState eval.State
	lastSavedView  eval.HostView
}

func (rt *hostRT) setView(v *HostView) {
	rt.viewMu.Lock()
	rt.view = v
	rt.viewMu.Unlock()
}

func (rt *hostRT) getView() *HostView {
	rt.viewMu.Lock()
	defer rt.viewMu.Unlock()
	return rt.view
}

type accRT struct {
	row *Access
	col collector
	err string
}

const discoverEvery = time.Hour

// poll ist eine Abfragerunde eines Hosts (vom Planer aufgerufen).
func (m *Module) poll(ctx context.Context, rt *hostRT) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	now := time.Now()
	h := rt.host
	if h.Paused {
		return
	}
	// 1. Zugaenge abfragen
	type got struct {
		svc  model.Service
		via  string
		rank int
	}
	found := map[string]got{}
	var accViews []AccessView
	var accInputs []eval.Access
	for _, a := range rt.accs {
		name := accessName(a.row.Type)
		av := AccessView{UID: a.row.UID, Type: a.row.Type, Name: name}
		var svcs []model.Service
		var err error
		if a.col == nil {
			err = fmt.Errorf("%s", a.err)
		} else {
			svcs, err = a.col.collect(ctx)
		}
		if err != nil && len(svcs) == 0 {
			rt.Failures[a.row.UID]++
			av.Error = err.Error()
		} else {
			rt.Failures[a.row.UID] = 0
			av.OK = true
			if err != nil { // Teilfehler (z. B. eine API-Abfrage)
				av.Error = err.Error()
			}
		}
		av.Failures = rt.Failures[a.row.UID]
		accViews = append(accViews, av)
		accInputs = append(accInputs, eval.Access{Name: name, Failures: av.Failures})
		rank := accessRank(a.row.Type)
		for _, s := range svcs {
			if g, ok := found[s.Key]; !ok || rank < g.rank {
				found[s.Key] = got{svc: s, via: name, rank: rank}
			}
		}
	}
	ref := hostRef(h)
	maint, win := m.inMaintenance(now, ref)
	hres0 := eval.HostState(eval.HostInput{Maintenance: maint, Accesses: accInputs})
	reachable := !hres0.Unreachable && len(found) > 0

	// 2. Dienste erkennen (beim ersten Mal und stuendlich); nie automatisch uebernehmen
	if reachable && (rt.LastDisc.IsZero() || now.Sub(rt.LastDisc) >= discoverEvery) {
		var offer []model.Service
		for _, g := range found {
			if g.svc.Default {
				offer = append(offer, g.svc)
			}
		}
		if _, err := m.store.UpsertDiscovered(ctx, h.UID, offer, nil, SystemActor); err != nil {
			m.log.Warn("monitor64: discover", "host", h.Name, "err", err)
		}
		rt.LastDisc, rt.dirty = now, true
	}
	rows, err := m.store.Services(ctx, h.UID)
	if err != nil {
		m.log.Warn("monitor64: services", "host", h.Name, "err", err)
		return
	}
	// verschwundene Dienste merken (nur wenn der Host antwortet)
	if reachable {
		var gone []string
		for _, r := range rows {
			if r.Adopted == 1 && r.VanishedAt.IsZero() {
				if _, ok := found[r.Key]; !ok && !strings.HasPrefix(r.Key, "access:") {
					gone = append(gone, r.Key)
					r.VanishedAt = now
				}
			}
		}
		if len(gone) > 0 {
			_ = m.store.MarkVanished(ctx, h.UID, gone, now)
		}
	}

	// 3. bewerten und speichern
	cfg := m.config()
	iv := time.Duration(h.IntervalSec) * time.Second
	var views []SvcView
	var states []eval.State
	var inputs []eval.ServiceInput
	newCount := 0
	acks := m.openAcks(h.UID)
	for _, r := range rows {
		if r.Adopted == 0 {
			newCount++
			continue
		}
		if r.Adopted < 0 {
			continue
		}
		g, ok := found[r.Key]
		sv := SvcView{Key: r.Key, Name: firstNonEmpty(r.Name, g.svc.Name, r.Key), Kind: r.Kind, Adopted: 1, Vanished: !r.VanishedAt.IsZero(), Via: g.via, Acked: acks[r.Key]}
		if ok {
			sv.Text = g.svc.Text
		}
		var ms []eval.MetricStatus
		hl := m.hostLevel(r)
		// Zahlenwerte
		for _, mt := range g.svc.Metrics {
			if ok {
				m.appendSeries(h.UID, r.Key, mt.Name, now, mt.Value)
			}
			mv := MetricView{Metric: mt}
			if mt.Rule != "" {
				e := eval.Resolve(cfg.std, cfg.overrides, ref, hl, mt.Rule)
				tr := rt.tracker(r.Key+"|"+mt.Name, iv)
				free := 0.0
				if mt.Max > 0 && mt.Unit == "%" {
					free = mt.Max * (100 - mt.Value) / 100
				}
				mv.Status = tr.Observe(e, eval.Sample{At: now, Value: mt.Value, Free: free})
				mv.RuleKind = mt.Rule
				ms = append(ms, eval.MetricStatus{Name: mt.Name, Status: mv.Status, Notify: e.Notify()})
			}
			sv.Metrics = append(sv.Metrics, mv)
		}
		// fehlende Messgroessen (Dienst nicht geliefert): Unbekannt nach 3 Intervallen
		if !ok {
			for key, tr := range rt.Trackers {
				if strings.HasPrefix(key, r.Key+"|") && !strings.Contains(key[len(r.Key)+1:], ":") {
					name := key[len(r.Key)+1:]
					kind := m.ruleKindOf(r, name)
					if kind == "" {
						continue
					}
					e := eval.Resolve(cfg.std, cfg.overrides, ref, hl, kind)
					st := tr.Status(e, now)
					ms = append(ms, eval.MetricStatus{Name: name, Status: st, Notify: e.Notify()})
				}
			}
		}
		// Zustandsregeln (Facts)
		facts := map[string]string{}
		for _, f := range g.svc.Facts {
			facts[f.Code] = f.Text
		}
		kinds := map[string]bool{}
		for _, k := range factKinds[r.Kind] {
			kinds[k] = true
		}
		for code := range facts {
			if k := factKind(code); k != "" {
				kinds[k] = true
			}
		}
		if !r.VanishedAt.IsZero() {
			kinds[eval.KindServiceGone] = true
		}
		kindList := make([]string, 0, len(kinds))
		for k := range kinds {
			kindList = append(kindList, k)
		}
		sort.Strings(kindList)
		for _, k := range kindList {
			cond := false
			text := ""
			for code, t := range facts {
				if factKind(code) == k {
					cond, text = true, t
				}
			}
			if k == eval.KindServiceGone {
				cond, text = true, "nicht mehr vorhanden seit "+r.VanishedAt.Local().Format("02.01. 15:04")
			}
			if k == eval.KindGuestDown && ok { // Soll-Zustand am Dienst geht vor dem Vorschlag (onboot/Neustart-Richtlinie)
				switch r.Soll {
				case "off":
					cond = false
				case "run":
					for _, mt := range g.svc.Metrics {
						if mt.Name == "running" {
							cond = mt.Value == 0
							if cond && text == "" {
								text = "läuft nicht (Soll: läuft)"
							}
						}
					}
				}
			}
			e := eval.Resolve(cfg.std, cfg.overrides, ref, hl, k)
			tr := rt.tracker(r.Key+"|state:"+k, iv)
			var st eval.Status
			if ok || k == eval.KindServiceGone {
				st = tr.Observe(e, eval.Sample{At: now, Value: eval.Bool(cond)})
			} else {
				st = tr.Status(e, now)
			}
			ms = append(ms, eval.MetricStatus{Name: k, Status: st, Notify: e.Notify()})
			if cond && st.State != eval.OK && text != "" {
				sv.Cause = text
			}
		}
		// eigene Skripte: Zustand direkt aus dem Skript
		for code, t := range facts {
			var s eval.State
			switch code {
			case "local_warn":
				s = eval.Warn
			case "local_crit":
				s = eval.Crit
			case "local_unknown":
				s = eval.Unknown
			default:
				continue
			}
			ms = append(ms, eval.MetricStatus{Name: code, Status: eval.Status{State: s, Level: s, At: now}, Notify: r.Report != "show"})
			sv.Cause = t
		}
		res := eval.ServiceState(ms)
		sv.State, sv.ShowOnly = res.State, res.ShowOnly || r.Report == "show"
		if res.Cause >= 0 && sv.Cause == "" {
			sv.Cause = describe(ms[res.Cause])
		}
		views = append(views, sv)
		states = append(states, res.State)
		notifyState := res.Notify
		if r.Report == "show" {
			notifyState = eval.OK
		}
		detail := sv.Cause
		if detail == "" {
			detail = sv.Text
		}
		inputs = append(inputs, eval.ServiceInput{Key: r.Key, Name: sv.Name, State: notifyState, ShowOnly: sv.ShowOnly, Acked: sv.Acked, Detail: detail})
	}
	// gestoerte Zugaenge als eigener Dienst "Zugang X"
	hres := eval.HostState(eval.HostInput{Maintenance: maint, Accesses: accInputs, Services: states})
	for _, name := range hres.FailedAccess {
		key := eval.AccessServiceKey(name)
		detail := ""
		for _, av := range accViews {
			if av.Name == name {
				detail = av.Error
			}
		}
		views = append(views, SvcView{Key: key, Name: "Zugang " + name, Kind: "access", State: eval.Warn, Cause: detail, Adopted: 1})
		inputs = append(inputs, eval.ServiceInput{Key: key, Name: "Zugang " + name, State: eval.Warn, Detail: detail})
	}

	// 4. Probleme und Benachrichtigung
	unreachDetail := ""
	if hres.Unreachable {
		var errs []string
		for _, av := range accViews {
			errs = append(errs, av.Name+": "+av.Error)
		}
		unreachDetail = strings.Join(errs, "; ")
	}
	m.syncProblems(ctx, h, inputs, hres, unreachDetail, now)
	round := eval.Round{At: now, Host: ref, Unreachable: hres.Unreachable, Maintenance: maint, Quiet: m.quietNow(now), Services: inputs}
	m.notifyMu.Lock()
	result := m.notifier.Round(round, eval.ResolveRouting(cfg.notify, cfg.notifyOverrides, ref))
	hostMem, _ := json.Marshal(m.notifier.Hosts[h.UID])
	m.notifyMu.Unlock()
	for _, k := range result.Unack {
		m.clearAck(ctx, h.UID, k)
	}
	m.recordNotified(ctx, h, result.Lines, now)
	for _, msg := range result.Messages {
		m.dispatch(h, msg, unreachDetail)
	}

	// 5. Stand fuer die Oberflaeche und speichern
	sort.SliceStable(views, func(i, j int) bool { return kindOrder(views[i].Kind) < kindOrder(views[j].Kind) })
	rt.setView(&HostView{Host: h, View: hres.View, State: hres.State, Checked: now, Accesses: accViews, Services: views, New: newCount, Maint: win})
	m.saveRuntime(ctx, rt, hostMem)
}

// describe formuliert die ausloesende Messgroesse ("91 % (ab 90 %)").
func describe(ms eval.MetricStatus) string {
	st := ms.Status
	if st.Threshold.Off {
		return ms.Name
	}
	return fmt.Sprintf("%s %s (Schwelle %s)", ms.Name, fmtNum(st.Value), fmtNum(st.Threshold.V))
}

func fmtNum(v float64) string {
	s := strconv.FormatFloat(v, 'f', 2, 64)
	s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	return strings.Replace(s, ".", ",", 1)
}

func (rt *hostRT) tracker(key string, iv time.Duration) *eval.Tracker {
	tr, ok := rt.Trackers[key]
	if !ok {
		tr = &eval.Tracker{}
		rt.Trackers[key] = tr
	}
	tr.Interval = eval.Dur(iv)
	return tr
}

func hostRef(h *Host) eval.HostRef {
	return eval.HostRef{ID: h.UID, Name: h.Name, Group: h.Group, Tags: h.Tags}
}

// seriesKey ist der Schluessel einer Messreihe im Verlauf.
func seriesKey(hostUID, svcKey, metric string) string { return hostUID + "|" + svcKey + "|" + metric }

func (m *Module) appendSeries(hostUID, svcKey, metric string, t time.Time, v float64) {
	if ser := m.seriesStore(); ser != nil {
		ser.Append(seriesKey(hostUID, svcKey, metric), t, v)
	}
}

// ruleKindOf: Art der Schwelle einer Messgroesse eines Dienstes (aus der letzten Runde, fuer fehlende Daten).
func (m *Module) ruleKindOf(r *ServiceRow, metric string) string {
	switch {
	case r.Kind == "cpu" && metric == "util":
		return model.RuleCPU
	case r.Kind == "load" && metric == "per_core":
		return model.RuleLoad
	case r.Kind == "mem" && metric == "used":
		return model.RuleMem
	case r.Kind == "swap" && metric == "used":
		return model.RuleSwap
	case r.Kind == "fs" && metric == "used":
		return model.RuleFS
	case (r.Kind == "zfs" || r.Kind == "store" || r.Kind == "ds") && metric == "used":
		return model.RuleStore
	case r.Kind == "if" && metric == "util":
		return model.RuleIfUtil
	case r.Kind == "if" && metric == "errrate":
		return model.RuleIfErrRate
	case r.Kind == "temp" && metric == "temp":
		return model.RuleTemp
	case r.Kind == "disk" && metric == "wear":
		return model.RuleWear
	case r.Kind == "disk" && metric == "temp":
		return model.RuleDiskTemp
	}
	return ""
}

// hostLevel liest die Einstellungen der Stufe "dieser Host" (Dienst und Art).
func (m *Module) hostLevel(r *ServiceRow) eval.HostLevel {
	var hl eval.HostLevel
	if r.HostRule != "" {
		var rule eval.Rule
		if json.Unmarshal([]byte(r.HostRule), &rule) == nil {
			hl.Service = &rule
		}
	}
	if kr := m.config().hostKind[r.HostUID+"|"+r.Kind]; kr != nil {
		hl.Kind = kr
	}
	return hl
}

// dispatch gibt eine gebuendelte Meldung an den Dispatcher der Node.
func (m *Module) dispatch(h *Host, msg eval.Message, unreachDetail string) {
	if m.dispatchFn == nil {
		return
	}
	var lines []notify.MonitorLine
	for _, l := range msg.Lines {
		ml := notify.MonitorLine{Kind: string(l.Kind), Key: l.Key, Name: l.Name, State: l.State.String(), Since: l.Since, Detail: l.Detail}
		if l.Kind == eval.LineUnreachable && ml.Detail == "" {
			ml.Detail = unreachDetail
		}
		lines = append(lines, ml)
	}
	b, _ := json.Marshal(lines)
	data := map[string]string{"host": h.Name, "path": "/monitor64/host/" + h.UID, "severity": msg.Severity.String(), "lines": string(b)}
	if len(msg.Lines) == 1 {
		data["key"] = msg.Lines[0].Key
	}
	if msg.AfterMaintenance {
		data["after_maint"] = "1"
	}
	info := notify.CheckInfo{Token: "m64:" + h.UID, Name: h.Name, Type: "monitor64", Target: h.Address, Local: true, NotifyDown: true, NotifyUp: true, Critical: msg.CritInQuiet}
	for _, id := range msg.Channels {
		if id == defaultChannels {
			info.Channels = nil // Standardkanaele der Node
			break
		}
		if n, err := strconv.ParseInt(id, 10, 64); err == nil {
			info.Channels = append(info.Channels, n)
		}
	}
	m.dispatchFn(notify.Alert{EventID: newUID(), Kind: notify.Kind(msg.Event), Time: msg.At, Check: info, Data: data})
}

// defaultChannels steht in der Benachrichtigung fuer "Standardkanaele der Node" (keine eigene Auswahl).
const defaultChannels = "default"
