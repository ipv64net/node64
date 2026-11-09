package monitor64

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/apis"
	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/monitor64/transport"
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
	case "pve", "pbs", "docker", "nut", "truenas", "unraid", "redfish":
		return 2
	case "snmp":
		return 3
	}
	return 4
}

// factKinds: welche Zustandsregeln eine Dienst-Art kennt (fehlt der Fact, ist die Bedingung nicht erfuellt).
var factKinds = map[string][]string{
	"disk":    {eval.KindSmartFailed, eval.KindSmartSectors, eval.KindSmartSectorsUp},
	"raid":    {eval.KindRAIDDegraded, eval.KindParityErrors},
	"ups":     {eval.KindUPSOnBattery, eval.KindUPSLowBattery, eval.KindUPSReplace, eval.KindUPSOverload, eval.KindUPSAlarm},
	"alerts":  {eval.KindDeviceWarn, eval.KindDeviceCrit},
	"system":  {eval.KindDeviceWarn, eval.KindDeviceCrit},
	"fan":     {eval.KindDeviceWarn, eval.KindDeviceCrit, eval.KindHWFailed},
	"psu":     {eval.KindDeviceWarn, eval.KindDeviceCrit, eval.KindHWFailed},
	"hw":      {eval.KindHWFailed},
	"if":      {eval.KindIfDown, eval.KindIfSpeedLow, eval.KindIfHalfDuplex},
	"uptime":  {eval.KindHostRestarted},
	"printer": {eval.KindPrinterError},
	"tray":    {eval.KindPaperEmpty},
	"poe":     {eval.KindPoEFault},
	"traps":   {eval.KindTrapReceived},
	"power":   {eval.KindDeviceWarn, eval.KindDeviceCrit},
	"ctrl":    {eval.KindDeviceWarn, eval.KindDeviceCrit},
	"temp":    {eval.KindDeviceWarn, eval.KindDeviceCrit},
	"zfs":     {eval.KindRAIDDegraded},
	"bond":    {eval.KindBondMemberDown, eval.KindBondLACP},
	"updates": {eval.KindUpdatesSecurity},
	"reboot":  {eval.KindRebootRequired},
	"systemd": {eval.KindSystemdFailed},
	"vm":      {eval.KindGuestDown},
	"winsvc":  {eval.KindWinSvcStopped},
	"ct":      {eval.KindGuestDown},
	"ctr":     {eval.KindGuestDown, eval.KindCtrUnhealthy},
	"backup":  {eval.KindBackupOld},
	"job":     {eval.KindJobFailed},
	"store":   {eval.KindStoreInactive, eval.KindRAIDDegraded},
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
	case "winsvc_stopped":
		return eval.KindWinSvcStopped
	case "ups_low_battery":
		return eval.KindUPSLowBattery
	case "ups_replace_battery":
		return eval.KindUPSReplace
	case "ups_overload":
		return eval.KindUPSOverload
	case "device_warn":
		return eval.KindDeviceWarn
	case "device_crit":
		return eval.KindDeviceCrit
	case "parity_errors":
		return eval.KindParityErrors
	case "disk_errors": // Geraet meldet Plattenfehler (TrueNAS/Unraid/Redfish) wie SMART-Sektoren
		return eval.KindSmartSectors
	case "restarted": // SNMP: Laufzeit zurueckgesprungen (Fact steht eine Weile)
		return eval.KindHostRestarted
	case "if_down":
		return eval.KindIfDown
	case "if_speed_low":
		return eval.KindIfSpeedLow
	case "if_half_duplex":
		return eval.KindIfHalfDuplex
	case "ups_alarm":
		return eval.KindUPSAlarm
	case "printer_error":
		return eval.KindPrinterError
	case "paper_empty":
		return eval.KindPaperEmpty
	case "hw_failed":
		return eval.KindHWFailed
	case "poe_fault":
		return eval.KindPoEFault
	case factTrapReceived:
		return eval.KindTrapReceived
	case "guest_down", "guest_fault": // guest_fault: gestartet, steht aber (io-error, Absturz)
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
	Cluster  *ClusterRef       `json:"cluster,omitempty"` // im Cluster: welche Node ueberwacht (cluster_state.go)
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
	removed  bool                     // aus dem Planer genommen: eine noch wartende Runde tut nichts mehr
	Trackers map[string]*eval.Tracker `json:"trackers"`
	Kinds    map[string]string        `json:"kinds,omitempty"`    // Tracker -> Regel-Art (fuer "Unbekannt" bei fehlenden Werten)
	Failures map[string]int           `json:"failures"`           // Zugang -> Runden in Folge ohne Antwort
	Missing  map[string]int           `json:"missing,omitempty"`  // Dienst -> Runden in Folge nicht geliefert
	Provider map[string]string        `json:"provider,omitempty"` // Dienst -> Zugang, der ihn zuletzt lieferte
	Rising   map[string]time.Time     `json:"rising,omitempty"`   // Platte -> "Sektoren steigen" gilt bis
	Local    map[string]localState    `json:"local,omitempty"`    // eigene Skripte: letzter Zustand
	Trend    map[string]trendState    `json:"trend,omitempty"`    // Fuellstand -> letzte Trendrechnung
	Traps    *hostTraps               `json:"traps,omitempty"`    // SNMP-Traps (Kopie fuer den Neustart)
	SeenUp   map[string][]string      `json:"seen_up,omitempty"`  // SNMP: Ports, die schon verbunden waren (je Zugang)
	LastDisc time.Time                `json:"last_disc,omitzero"`
	dirty    bool

	viewMu         sync.Mutex // eigene Sperre: die Oberflaeche wartet nicht auf eine laufende Abfrage
	view           *HostView
	lastSave       time.Time
	lastSavedState eval.State
	lastSavedView  eval.HostView
	lastMem        []byte // zuletzt gespeichertes Gedaechtnis der Meldungen (Wechsel = sofort speichern/veroeffentlichen)
}

type localState struct {
	State eval.State `json:"state"`
	At    time.Time  `json:"at"`
	Text  string     `json:"text,omitempty"`
}

type trendState struct {
	At   time.Time `json:"at"`
	Days float64   `json:"days"`
}

// initMaps legt fehlende Maps an (nach dem Laden aus m64_runtime).
func (rt *hostRT) initMaps() {
	if rt.Trackers == nil {
		rt.Trackers = map[string]*eval.Tracker{}
	}
	if rt.Kinds == nil {
		rt.Kinds = map[string]string{}
	}
	if rt.Failures == nil {
		rt.Failures = map[string]int{}
	}
	if rt.Missing == nil {
		rt.Missing = map[string]int{}
	}
	if rt.Provider == nil {
		rt.Provider = map[string]string{}
	}
	if rt.Rising == nil {
		rt.Rising = map[string]time.Time{}
	}
	if rt.Local == nil {
		rt.Local = map[string]localState{}
	}
	if rt.Trend == nil {
		rt.Trend = map[string]trendState{}
	}
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

const (
	discoverEvery  = time.Hour
	vanishRounds   = 3                  // so viele Runden in Folge ohne Dienst (bei vollstaendig antwortendem Zugang) = verschwunden
	risingHold     = 30 * time.Minute   // "ausstehende Sektoren steigen" gilt so lange (SMART wird nur alle 30 min gelesen)
	trendEvery     = time.Hour          // Trend "voll in N Tagen" hoechstens so oft neu rechnen
	dbTimeout      = 20 * time.Second   // Datenbank-Schritte einer Runde (eigenes Zeitlimit, unabhaengig von den Zugaengen)
	staleKindAfter = 7 * 24 * time.Hour // Messgroesse so lange nicht geliefert: Tracker vergessen
)

// i18nText baut einen uebersetzbaren Text ("i18n:<schluessel>?k=v"); Oberflaeche und Meldungen uebersetzen ihn.
func i18nText(key string, kv ...string) string {
	if len(kv) == 0 {
		return "i18n:" + key
	}
	q := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		q.Set(kv[i], kv[i+1])
	}
	return "i18n:" + key + "?" + q.Encode()
}

// finiteMetrics entfernt nicht endliche Werte (NaN, Inf) – Daten von Hosts sind nicht vertrauenswuerdig.
func finiteMetrics(in []model.Metric) []model.Metric {
	out := in[:0:0]
	for _, mt := range in {
		if math.IsNaN(mt.Value) || math.IsInf(mt.Value, 0) || math.IsNaN(mt.Max) || math.IsInf(mt.Max, 0) {
			continue
		}
		out = append(out, mt)
	}
	return out
}

// shortErr kuerzt Fehlertexte von Zugaengen (vom Host bestimmt) auf eine vertraegliche Laenge.
func shortErr(err error) string {
	s := strings.Map(func(r rune) rune {
		if r < 32 && r != '\t' {
			return ' '
		}
		return r
	}, err.Error())
	if len([]rune(s)) > 300 {
		s = string([]rune(s)[:300]) + "…"
	}
	return s
}

// poll ist eine Abfragerunde eines Hosts (vom Planer aufgerufen).
func (m *Module) poll(ctx context.Context, rt *hostRT) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.removed {
		return
	}
	rt.initMaps()
	now := time.Now()
	h := rt.host
	if h.Paused {
		return
	}
	// Datenbank-Schritte mit eigenem Zeitlimit: ein langsamer Zugang darf die Runde nicht abbrechen.
	dbctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	// Cluster: nur die zustaendige Node fragt ab und meldet (cluster_owner.go)
	role, owner := m.clusterRole(dbctx, rt)
	if role == roleIdle {
		m.idleView(rt, owner)
		return
	}

	// 1. Zugaenge abfragen
	type got struct {
		svc  model.Service
		via  string
		acc  string
		rank int
	}
	found := map[string]got{}
	failedAcc := map[string]bool{} // Zugang hat nicht geantwortet
	partial := map[string]error{}  // Zugang hat nur teilweise geantwortet
	var accViews []AccessView
	var accInputs []eval.Access
	for _, a := range rt.accs {
		name := accessName(a.row.Type)
		av := AccessView{UID: a.row.UID, Type: a.row.Type, Name: name}
		var svcs []model.Service
		var err error
		if a.col == nil {
			err = errors.New(a.err)
		} else {
			svcs, err = a.col.collect(ctx)
			if keys, ch := seenUpChanged(a.col, rt.SeenUp[a.row.UID]); ch {
				if rt.SeenUp == nil {
					rt.SeenUp = map[string][]string{}
				}
				rt.SeenUp[a.row.UID], rt.dirty = keys, true
			}
		}
		if err != nil && len(svcs) == 0 && errors.Is(err, transport.ErrNotConnected) && m.sinceStart() < pushStartGrace {
			// Push-Agent nach dem Start der Node noch nicht wieder verbunden (er wartet bis 5 min, bevor er es neu
			// versucht): nicht als Ausfall zaehlen, sonst meldet jeder Neustart alle Push-Hosts "nicht erreichbar"
			failedAcc[a.row.UID] = true
			av.Error = i18nText("monitor64.detail.push_waiting")
		} else if err != nil && len(svcs) == 0 {
			rt.Failures[a.row.UID]++
			failedAcc[a.row.UID] = true
			av.Error = shortErr(err)
		} else {
			rt.Failures[a.row.UID] = 0
			av.OK = true
			if err != nil { // Teilfehler (z. B. eine API-Abfrage): die fehlenden Dienste nicht "verschwunden" nennen
				partial[a.row.UID] = err
				av.Error = shortErr(err)
			}
		}
		av.Failures = rt.Failures[a.row.UID]
		accViews = append(accViews, av)
		accInputs = append(accInputs, eval.Access{Name: a.row.UID, Failures: av.Failures})
		rank := accessRank(a.row.Type)
		for _, s := range svcs {
			s.Metrics = finiteMetrics(s.Metrics)
			if g, ok := found[s.Key]; !ok || rank < g.rank {
				found[s.Key] = got{svc: s, via: name, acc: a.row.UID, rank: rank}
			}
		}
	}
	// SNMP-Traps: eigener Dienst des Hosts, solange ein SNMP-Zugang Traps nutzt
	if s, acc, ok := m.trapService(rt); ok {
		found[s.Key] = got{svc: s, via: accessName("snmp"), acc: acc, rank: accessRank("snmp")}
	}
	ref := hostRef(h)
	maint, win := m.inMaintenance(now, ref)
	hres0 := eval.HostState(eval.HostInput{Maintenance: maint, Accesses: accInputs})
	reachable := !hres0.Unreachable && len(found) > 0

	// 2. Dienste erkennen (beim ersten Mal und stuendlich); nie automatisch uebernehmen. Nicht vorgeschlagene (Default
	// false, z. B. einzelne Windows-Dienste, gestoppte Gaeste) kommen als "ignoriert" dazu, damit sie spaeter uebernommen
	// werden koennen, ohne die Liste der neuen Dienste zu fuellen (UpsertDiscovered).
	if reachable && role == roleReport && (rt.LastDisc.IsZero() || now.Sub(rt.LastDisc) >= discoverEvery) {
		offer := make([]model.Service, 0, len(found))
		for _, g := range found {
			offer = append(offer, g.svc)
		}
		sort.Slice(offer, func(i, j int) bool { return offer[i].Key < offer[j].Key })
		if _, err := m.store.UpsertDiscovered(dbctx, h.UID, offer, nil, SystemActor); err != nil {
			m.log.Warn("monitor64: discover", "host", h.Name, "err", err)
		}
		rt.LastDisc, rt.dirty = now, true
	}
	rows, err := m.store.Services(dbctx, h.UID)
	if err != nil {
		m.log.Warn("monitor64: services", "host", h.Name, "err", err)
		return
	}
	// verschwunden: erst nach vanishRounds Runden ohne den Dienst, und nur wenn sein Zugang vollstaendig
	// geantwortet hat; wieder geliefert = sofort zurueck.
	var gone []string
	for _, r := range rows {
		if r.Adopted != 1 || strings.HasPrefix(r.Key, "access:") {
			continue
		}
		if g, ok := found[r.Key]; ok {
			rt.Missing[r.Key], rt.Provider[r.Key] = 0, g.acc
			if !r.VanishedAt.IsZero() {
				if err := m.store.ClearVanished(dbctx, h.UID, r.Key); err == nil {
					r.VanishedAt = time.Time{}
				}
			}
			continue
		}
		if !reachable || !r.VanishedAt.IsZero() {
			continue
		}
		if prov := rt.Provider[r.Key]; prov != "" {
			if failedAcc[prov] || partialAffects(partial[prov], r.Key) {
				continue
			}
		} else if len(failedAcc) > 0 || len(partial) > 0 {
			continue
		}
		rt.Missing[r.Key]++
		if rt.Missing[r.Key] >= vanishRounds {
			gone = append(gone, r.Key)
			r.VanishedAt = now
		}
	}
	if len(gone) > 0 {
		_ = m.store.MarkVanished(dbctx, h.UID, gone, now)
	}

	// 3. bewerten und speichern
	cfg := m.config()
	iv := time.Duration(h.IntervalSec) * time.Second
	open := m.loadOpen(dbctx, h.UID)
	var views []SvcView
	var states []eval.State
	var inputs []eval.ServiceInput
	newCount := 0
	for _, r := range rows {
		if r.Adopted == 0 {
			newCount++
			continue
		}
		if r.Adopted < 0 || strings.HasPrefix(r.Key, "access:") {
			continue
		}
		g, ok := found[r.Key]
		acked := open[r.Key] != nil && open[r.Key].Acked
		sv := SvcView{Key: r.Key, Name: firstNonEmpty(r.Name, g.svc.Name, r.Key), Kind: r.Kind, Adopted: 1, Vanished: !r.VanishedAt.IsZero(), Via: g.via, Acked: acked}
		if ok {
			sv.Text = g.svc.Text
		}
		hostRules := parseHostRules(r.HostRule)
		var ms []eval.MetricStatus
		delivered := map[string]bool{}
		metrics := g.svc.Metrics
		if ok {
			metrics = append(metrics, m.trendMetric(dbctx, rt, h.UID, r.Key, g.svc, now)...)
		}
		freeOf := map[string]float64{}
		for _, mt := range metrics {
			if mt.Name == "free" && mt.Unit == "B" {
				freeOf[r.Key] = mt.Value
			}
		}
		onBattery := upsOnBattery(g.svc)
		// Zahlenwerte
		for _, mt := range metrics {
			if ok && mt.Name != "trend_days" {
				m.appendSeries(h.UID, r.Key, mt.Name, now, mt.Value)
			}
			mv := MetricView{Metric: mt}
			if mt.Rule != "" {
				delivered[mt.Name] = true
				e := eval.Resolve(cfg.std, cfg.overrides, ref, m.hostLevel(r.HostUID, hostRules, mt.Rule), mt.Rule)
				key := r.Key + "|" + mt.Name
				tr := rt.tracker(key, iv)
				rt.Kinds[key] = mt.Rule
				free := 0.0
				if f, has := freeOf[r.Key]; has && (mt.Name == "used") {
					free = f // exakt (beruecksichtigt reservierte Bloecke)
				} else if mt.Max > 0 && mt.Unit == "%" {
					free = mt.Max * (100 - mt.Value) / 100
				}
				if mt.Rule == model.RuleUPSRuntime && !onBattery {
					e = withoutLimits(e) // Restlaufzeit zaehlt nur auf Batterie; im Netzbetrieb OK beobachten (Tracker haengt nicht)
				}
				mv.Status = tr.Observe(e, eval.Sample{At: now, Value: mt.Value, Free: free})
				mv.RuleKind = mt.Rule
				ms = append(ms, eval.MetricStatus{Name: mt.Name, Status: mv.Status, Notify: e.Notify()})
			}
			sv.Metrics = append(sv.Metrics, mv)
		}
		// fehlende Messgroessen (Dienst oder einzelner Wert nicht geliefert): letzter Zustand, nach 3 Intervallen Unbekannt
		prefix := r.Key + "|"
		for key, kind := range rt.Kinds {
			if !strings.HasPrefix(key, prefix) || strings.HasPrefix(key[len(prefix):], "state:") {
				continue
			}
			name := key[len(prefix):]
			if delivered[name] {
				continue
			}
			tr := rt.Trackers[key]
			if tr == nil {
				delete(rt.Kinds, key)
				continue
			}
			if !tr.LastAt.IsZero() && now.Sub(tr.LastAt) > staleKindAfter { // lange nicht mehr geliefert: vergessen
				delete(rt.Kinds, key)
				delete(rt.Trackers, key)
				continue
			}
			if ok && tr.Level == eval.OK {
				continue // Dienst geliefert, Wert gewollt weggelassen (gestoppte VM, schlafende Platte, Port ohne Link)
			}
			e := eval.Resolve(cfg.std, cfg.overrides, ref, m.hostLevel(r.HostUID, hostRules, kind), kind)
			st := tr.Status(e, now)
			ms = append(ms, eval.MetricStatus{Name: name, Status: st, Notify: e.Notify()})
		}
		// Zustandsregeln (Facts)
		facts := map[string]string{}
		for _, f := range g.svc.Facts {
			facts[f.Code] = f.Text
		}
		if _, has := facts["smart_sectors_rising"]; has {
			rt.Rising[r.Key] = now.Add(risingHold)
		}
		_, smartUnreadable := facts["smart_unreadable"]
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
			switch k {
			case eval.KindServiceGone:
				cond, text = true, i18nText("monitor64.detail.vanished", "since", r.VanishedAt.UTC().Format(time.RFC3339))
			case eval.KindSmartSectorsUp:
				if until := rt.Rising[r.Key]; now.Before(until) {
					cond = true
				}
			case eval.KindGuestDown:
				if ok { // Soll-Zustand am Dienst geht vor dem Vorschlag (onboot/Neustart-Richtlinie)
					running, locked, hasRun := 1.0, 0.0, false
					for _, mt := range g.svc.Metrics {
						switch mt.Name {
						case "running":
							running, hasRun = mt.Value, true
						case "locked":
							locked = mt.Value
						}
					}
					switch r.Soll {
					case "off":
						_, cond = facts["guest_fault"] // darf aus sein, haengt aber nicht
					case "run":
						if hasRun {
							cond = running == 0 && locked == 0
							if cond && text == "" {
								text = i18nText("monitor64.detail.not_running")
							}
						}
					}
				}
			}
			e := eval.Resolve(cfg.std, cfg.overrides, ref, m.hostLevel(r.HostUID, hostRules, k), k)
			tr := rt.tracker(r.Key+"|state:"+k, iv)
			var st eval.Status
			isSmart := k == eval.KindSmartFailed || k == eval.KindSmartSectors || k == eval.KindSmartSectorsUp
			switch {
			case k == eval.KindServiceGone:
				st = tr.Observe(e, eval.Sample{At: now, Value: eval.Bool(cond)})
			case isSmart && smartUnreadable && !cond && tr.Level == eval.OK:
				continue // SMART nicht lesbar (z. B. virtuelle Platte) und vorher kein Problem: nicht bewerten
			case !ok || (isSmart && smartUnreadable && !cond):
				st = tr.Status(e, now) // keine (lesbaren) Daten: letzter Stand, dann Unbekannt
			default:
				st = tr.Observe(e, eval.Sample{At: now, Value: eval.Bool(cond)})
			}
			ms = append(ms, eval.MetricStatus{Name: k, Status: st, Notify: e.Notify()})
			if cond && st.State != eval.OK && text != "" {
				sv.Cause = text
			}
		}
		// eigene Skripte: Zustand direkt aus dem Skript; ohne Daten letzter Zustand, nach 3 Intervallen Unbekannt
		if r.Kind == "local" {
			ls, had := rt.Local[r.Key]
			if ok {
				ls = localState{State: eval.OK, At: now}
				for code, t := range facts {
					switch code {
					case "local_warn":
						ls.State, ls.Text = eval.Warn, t
					case "local_crit":
						ls.State, ls.Text = eval.Crit, t
					case "local_unknown":
						ls.State, ls.Text = eval.Unknown, t
					}
				}
				rt.Local[r.Key] = ls
			}
			st := ls.State
			if !ok && (!had || now.Sub(ls.At) > time.Duration(eval.UnknownAfter)*iv) {
				st = eval.Unknown
			}
			ms = append(ms, eval.MetricStatus{Name: "local", Status: eval.Status{State: st, Level: st, At: ls.At}, Notify: r.Report != "show"})
			if st != eval.OK && ls.Text != "" {
				sv.Cause = ls.Text
			}
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
		inputs = append(inputs, eval.ServiceInput{Key: r.Key, Name: sv.Name, State: notifyState, ShowOnly: sv.ShowOnly, Acked: acked, Detail: detail})
	}
	// Zugaenge als Dienst "Zugang X" (immer mitgeschickt, damit die Erholung eine Entwarnung bekommt)
	hres := eval.HostState(eval.HostInput{Maintenance: maint, Accesses: accInputs, Services: states})
	for i, a := range rt.accs {
		av := accViews[i]
		key := "access:" + a.row.UID
		failing := av.Failures >= eval.UnreachableRounds && !hres.Unreachable
		e := eval.Resolve(cfg.std, cfg.overrides, ref, eval.HostLevel{}, eval.KindAccessFailed)
		tr := rt.tracker(key+"|state:"+eval.KindAccessFailed, iv)
		st := tr.Observe(e, eval.Sample{At: now, Value: eval.Bool(failing)})
		name := i18nText("monitor64.detail.access", "name", av.Name)
		acked := open[key] != nil && open[key].Acked
		if st.State != eval.OK {
			views = append(views, SvcView{Key: key, Name: name, Kind: "access", State: st.State, Cause: av.Error, Adopted: 1, Acked: acked})
			states = append(states, st.State)
		}
		notifyState := st.State
		if !e.Notify() {
			notifyState = eval.OK
		}
		inputs = append(inputs, eval.ServiceInput{Key: key, Name: name, State: notifyState, ShowOnly: !e.Notify(), Acked: acked, Detail: av.Error})
	}
	hres = eval.HostState(eval.HostInput{Maintenance: maint, Accesses: accInputs, Services: states})

	// 4. Probleme und Benachrichtigung
	unreachDetail := ""
	if hres.Unreachable {
		var errs []string
		for _, av := range accViews {
			errs = append(errs, av.Name+": "+av.Error)
		}
		unreachDetail = strings.Join(errs, "; ")
	}
	var hostMem []byte
	if role == roleReport {
		m.syncProblems(dbctx, h, open, inputs, hres, unreachDetail, now)
		round := eval.Round{At: now, Host: ref, Unreachable: hres.Unreachable, Maintenance: maint, Quiet: m.quietNow(now), Services: inputs}
		m.notifyMu.Lock()
		if m.notifier == nil {
			m.notifyMu.Unlock()
			return
		}
		result := m.notifier.Round(round, eval.ResolveRouting(cfg.notify, cfg.notifyOverrides, ref))
		hostMem, _ = json.Marshal(m.notifier.Hosts[h.UID])
		m.notifyMu.Unlock()
		for _, k := range result.Unack {
			m.clearAck(dbctx, h.UID, k)
		}
		m.recordNotified(dbctx, h, result.Lines, now)
		for _, msg := range result.Messages {
			m.dispatch(dbctx, h, msg, unreachDetail)
		}
	} else { // ohne Mehrheit (Ersatz-Node vorhanden) bzw. kurz nach dem Start: messen, nicht melden
		m.notifyMu.Lock()
		if m.notifier != nil {
			hostMem, _ = json.Marshal(m.notifier.Hosts[h.UID])
		}
		m.notifyMu.Unlock()
	}

	// 5. Stand fuer die Oberflaeche und speichern
	sort.SliceStable(views, func(i, j int) bool { return kindOrder(views[i].Kind) < kindOrder(views[j].Kind) })
	rt.setView(&HostView{Host: h, View: hres.View, State: hres.State, Checked: now, Accesses: accViews, Services: views, New: newCount, Maint: win,
		Cluster: m.clusterSelfRef(role)})
	m.saveRuntime(dbctx, rt, hostMem)
}

// upsOnBattery: die USV meldet Batteriebetrieb (Messgroesse on_battery bzw. Fact ups_on_battery).
func upsOnBattery(s model.Service) bool {
	for _, mt := range s.Metrics {
		if mt.Name == "on_battery" && mt.Value > 0 {
			return true
		}
	}
	for _, f := range s.Facts {
		if f.Code == "ups_on_battery" {
			return true
		}
	}
	return false
}

// withoutLimits: dieselbe Regel ohne Schwellen (Messung wird als OK beobachtet).
func withoutLimits(e eval.Effective) eval.Effective {
	off := eval.Limit{Off: true}
	e.Warn, e.Crit, e.WarnFree, e.CritFree = off, off, off, off
	return e
}

// partialAffects: betrifft ein Teilfehler diesen Dienst? Ohne Angabe der betroffenen Dienste: ja (vorsichtig).
func partialAffects(err error, key string) bool {
	if err == nil {
		return false
	}
	var pe *apis.PartialError
	if errors.As(err, &pe) && len(pe.Prefixes) > 0 {
		return pe.Affects(key)
	}
	return true
}

// parseHostRules liest die Schwellen der Stufe "dieser Host, nur dieser Dienst" (Regel-Art -> Regel).
func parseHostRules(raw string) map[string]eval.Rule {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out map[string]eval.Rule
	if json.Unmarshal([]byte(raw), &out) != nil {
		return nil
	}
	return out
}

// hostLevel liefert die Stufe "dieser Host" fuer eine Regel-Art: Dienst (host_rule) und alle Dienste des Hosts
// mit dieser Art (m64_host_rules).
func (m *Module) hostLevel(hostUID string, svcRules map[string]eval.Rule, ruleKind string) eval.HostLevel {
	var hl eval.HostLevel
	if r, ok := svcRules[ruleKind]; ok {
		rr := r
		hl.Service = &rr
	}
	if kr := m.config().hostKind[hostUID+"|"+ruleKind]; kr != nil {
		hl.Kind = kr
	}
	return hl
}

// trendMetric rechnet hoechstens stuendlich den Trend "voll in N Tagen" fuer Fuellstaende (fs.used, store.used)
// aus dem Verlauf der letzten 7 Tage (Messgroesse trend_days, Regel fs.trend_days).
func (m *Module) trendMetric(ctx context.Context, rt *hostRT, hostUID, svcKey string, svc model.Service, now time.Time) []model.Metric {
	var used *model.Metric
	for i := range svc.Metrics {
		mt := &svc.Metrics[i]
		if mt.Name == "used" && (mt.Rule == model.RuleFS || mt.Rule == model.RuleStore) {
			used = mt
		}
	}
	if used == nil {
		return nil
	}
	ts, ok := rt.Trend[svcKey]
	if !ok || now.Sub(ts.At) >= trendEvery {
		days := eval.NoForecast
		if q, isQ := m.seriesStore().(seriesQuerier); isQ {
			s, err := q.Query(ctx, seriesKey(hostUID, svcKey, "used"), now.Add(-eval.TrendWindow), now, 400)
			if err == nil {
				pts := make([]eval.Point, 0, len(s.Points))
				for _, p := range s.Points {
					pts = append(pts, eval.Point{At: time.Unix(p.T, 0), V: p.Avg})
				}
				days = eval.Trend(pts, now, 100).Value()
			}
		}
		ts = trendState{At: now, Days: days}
		rt.Trend[svcKey] = ts
	}
	if ts.Days >= eval.NoForecast {
		return []model.Metric{{Name: "trend_days", Value: eval.NoForecast, Unit: "d", Rule: eval.KindFSTrendDays}}
	}
	return []model.Metric{{Name: "trend_days", Value: math.Round(ts.Days*10) / 10, Unit: "d", Rule: eval.KindFSTrendDays}}
}

// describe formuliert die ausloesende Messgroesse (uebersetzbar: "util 91 (Schwelle 90)").
func describe(ms eval.MetricStatus) string {
	st := ms.Status
	if st.Threshold.Off {
		return ms.Name
	}
	return i18nText("monitor64.detail.threshold", "metric", ms.Name, "value", fmtNum(st.Value), "limit", fmtNum(st.Threshold.V))
}

func fmtNum(v float64) string {
	s := strconv.FormatFloat(v, 'f', 2, 64)
	return strings.TrimRight(strings.TrimRight(s, "0"), ".") // sprachneutral (Punkt); Texte werden uebersetzt angezeigt
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

// dispatch gibt eine gebuendelte Meldung an den Dispatcher der Node. "default" (Standardkanaele der Node) und
// ausdruecklich gewaehlte Kanaele gehen als zwei Meldungen raus (eine mit leerer Auswahl = Standardkanaele, eine mit
// den uebrigen Kanaelen ohne die Standardkanaele, damit kein Kanal doppelt bekommt).
func (m *Module) dispatch(ctx context.Context, h *Host, msg eval.Message, unreachDetail string) {
	if m.dispatchFn == nil {
		return
	}
	var lines []notify.MonitorLine
	keys := map[string]bool{}
	for _, l := range msg.Lines {
		ml := notify.MonitorLine{Kind: string(l.Kind), Gone: l.Gone, Key: l.Key, Name: l.Name, State: l.State.String(), Since: l.Since, Detail: l.Detail}
		if l.Kind == eval.LineUnreachable && ml.Detail == "" {
			ml.Detail = unreachDetail
		}
		lines = append(lines, ml)
		keys[l.Key] = true
	}
	b, _ := json.Marshal(lines)
	data := map[string]string{"host": h.Name, "path": "/monitor64/host/" + h.UID, "severity": msg.Severity.String(), "lines": string(b)}
	if len(keys) == 1 {
		data["key"] = msg.Lines[0].Key
	}
	if msg.AfterMaintenance {
		data["after_maint"] = "1"
	}
	base := notify.CheckInfo{Token: "m64:" + h.UID, Name: h.Name, Type: "monitor64", Target: h.Address, Local: true, NotifyDown: true, NotifyUp: true, Critical: msg.CritInQuiet}
	// Ist "Standardkanaele" irgendwo im Routing dieses Hosts gewaehlt, folgen die Standardkanaele diesem Weg; ein
	// zusaetzlich ausdruecklich gewaehlter Standardkanal bekaeme sonst dieselbe Zeile doppelt (getrennte Meldungen).
	cfg := m.config()
	routeDefault := false
	for _, c := range eval.ResolveRouting(cfg.notify, cfg.notifyOverrides, hostRef(h)).Channels {
		if c.ID == defaultChannels && (c.Warn || c.Crit) {
			routeDefault = true
		}
	}
	var defaults map[int64]bool
	if routeDefault {
		defaults = m.defaultChannelIDs(ctx)
	}
	withDefault := false
	var explicit []int64
	for _, id := range msg.Channels {
		if id == defaultChannels {
			withDefault = true
			continue
		}
		if n, err := strconv.ParseInt(id, 10, 64); err == nil && !defaults[n] {
			explicit = append(explicit, n)
		}
	}
	send := func(chans []int64) {
		info := base
		info.Channels = chans
		m.dispatchFn(notify.Alert{EventID: newUID(), Kind: notify.Kind(msg.Event), Time: msg.At, Check: info, Data: data})
	}
	if withDefault {
		send(nil)
	}
	if len(explicit) > 0 {
		send(explicit)
	}
}

// defaultChannelIDs: lokale Standardkanaele der Node (damit ein Kanal nicht doppelt bekommt).
func (m *Module) defaultChannelIDs(ctx context.Context) map[int64]bool {
	out := map[int64]bool{}
	rows, err := m.st.Reader().QueryContext(ctx, `SELECT id FROM nf_channels WHERE is_default = 1 AND enabled = 1`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			out[id] = true
		}
	}
	return out
}

// defaultChannels steht in der Benachrichtigung fuer "Standardkanaele der Node" (keine eigene Auswahl).
const defaultChannels = "default"
