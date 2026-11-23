package monitor64

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"slices"
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

// accessName ist der Anzeigename eines Zugangs je Art ("SSH", "Proxmox VE", "Docker-API"); uebersetzbar, die Texte
// stehen unter monitor64.access.*.
func accessName(typ string) string {
	if validAccessType(typ) {
		return model.T("monitor64.access." + typ)
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
	case "pve", "pbs", "pmg", "mailcow", "fritzbox", "mikrotik", "unifi", "docker", "nut", "truenas", "unraid", "redfish":
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
	"btrfs":   {eval.KindRAIDDegraded, eval.KindDeviceWarn},
	"wan":     {eval.KindDeviceWarn, eval.KindDeviceCrit},
	"netdev":  {eval.KindDeviceWarn, eval.KindDeviceCrit},
	"dsl":     {eval.KindDeviceCrit},
	"routing": {eval.KindDeviceWarn},
	"bond":    {eval.KindBondMemberDown, eval.KindBondLACP},
	"updates": {eval.KindUpdatesSecurity, eval.KindFirmwareUpdate},
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
	case "firmware_update":
		return eval.KindFirmwareUpdate
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

// PendView ist eine laufende Wartezeit einer Zustandsregel.
type PendView struct {
	Kind  string     `json:"kind"`
	State eval.State `json:"state"` // Stufe, die nach der Dauer gilt
	Since time.Time  `json:"since"`
	At    time.Time  `json:"at"` // ab dann gilt sie
}

// MetricView ist eine bewertete Messgroesse fuer die Oberflaeche.
type MetricView struct {
	model.Metric
	Status   eval.Status `json:"status"`
	RuleKind string      `json:"rule_kind,omitempty"`
}

// SvcView ist ein Dienst fuer die Oberflaeche.
type SvcView struct {
	Key      string     `json:"key"`
	Name     string     `json:"name"`
	Kind     string     `json:"kind"`
	State    eval.State `json:"state"`
	Text     string     `json:"text,omitempty"`
	Cause    string     `json:"cause,omitempty"`
	Via      string     `json:"via,omitempty"`
	Adopted  int        `json:"adopted"`
	Vanished bool       `json:"vanished,omitempty"`
	ShowOnly bool       `json:"show_only,omitempty"`
	Acked    bool       `json:"acked,omitempty"`
	Detail   string     `json:"detail,omitempty"` // "smart": alle SMART-Werte abrufbar (smartdetail.go)
	// Pending: Zustandsregeln, deren Bedingung gilt, die aber erst nach ihrer Dauer melden (z. B. Sicherheitsupdates
	// nach 24 Std.) – damit sichtbar ist, warum der Dienst noch OK ist
	Pending []PendView   `json:"pending,omitempty"`
	Metrics []MetricView `json:"metrics,omitempty"`
	// Firing: Zustandsregeln, die gerade melden (Warnung/Kritisch); Accepted: Zustandsregeln, deren Bedingung gilt, die
	// aber als gewollt bestaetigt sind ("in Ordnung, bis sich der Zustand aendert") - beides fuer den Dienst-Dialog
	Firing   []string `json:"firing,omitempty"`
	Accepted []string `json:"accepted,omitempty"`
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

// foundSvc ist ein in der Runde gelieferter Dienst mit seinem Zugang (bei mehreren der mit dem besten Rang).
type foundSvc struct {
	svc  model.Service
	via  string
	acc  string
	rank int
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
	SeenUp   map[string][]string      `json:"seen_up,omitempty"`  // merkbarer Zustand der Sammler je Zugang (memo: SNMP-Ports mit Link, NUT TLS)
	Moved    map[string]string        `json:"moved,omitempty"`    // Proxmox-Gast -> Node, auf der er hier weitergefuehrt wird (#165)
	LastDisc time.Time                `json:"last_disc,omitzero"`
	Seen     time.Time                `json:"seen,omitzero"` // letzte Runde, in der der Host Daten lieferte
	Back     time.Time                `json:"back,omitzero"` // wieder da seit (erste Runde mit Daten nach einer Luecke, #275)
	Away     time.Time                `json:"away,omitzero"` // letzte Runde mit Daten vor dieser Luecke
	known    map[string]bool          // bei der Erkennung schon gesehene Dienste (nur im Speicher)
	follow   []string                 // uebernommene Proxmox-Gaeste fuer den Sammler (nil = noch aus der Datenbank lesen)
	dirty    bool

	viewMu         sync.Mutex // eigene Sperre: die Oberflaeche wartet nicht auf eine laufende Abfrage
	view           *HostView
	smart          map[string]*model.SmartDetail // Dienst -> zuletzt gelesene SMART-Werte (nur im Speicher)
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
	if rt.Moved == nil {
		rt.Moved = map[string]string{}
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
	// Anlaufzeit nach dem Wiederkommen eines Hosts (#275): so lange (mindestens aber die ueblichen 3 Intervalle)
	// bleiben Werte, die seit dem Wiederkommen noch nicht kamen, auf ihrem letzten Stand statt "unbekannt" - langsame
	// Abschnitte (Windows-Updates bis 10 min, SMART) liefert der Agent nach dem Start erst nach einer Weile
	startupGrace = 15 * time.Minute

	// Obergrenzen fuer Berichte, die vom ueberwachten Host kommen (nicht vertrauenswuerdig): sonst fuellte ein
	// manipulierter Agent mit immer neuen Namen je Runde Datenbank und Speicher
	maxServicesPerAccess = 5000
	maxLocalChecks       = 2000
)

// i18nText baut einen uebersetzbaren Text ("i18n:<schluessel>?k=v"); Oberflaeche und Meldungen uebersetzen ihn
// (model.T; Werte sind fertige Texte und werden nicht uebersetzt).
func i18nText(key string, kv ...string) string {
	args := make([]any, len(kv))
	for i, v := range kv {
		args[i] = v
	}
	return model.T(key, args...)
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

// accessErrText: Fehler eines Zugangs fuer die Anzeige. Wartet ein Passwort-Zugang auf die Bestaetigung des
// Hostschluessels, steht dort, was zu tun ist (statt des Textes aus dem Transport).
func accessErrText(err error) string {
	if errors.Is(err, transport.ErrHostKeyUnconfirmed) {
		return i18nText("monitor64.detail.hostkey_unconfirmed")
	}
	if errors.Is(err, transport.ErrNoKeyAuth) {
		return i18nText("monitor64.detail.ssh_no_pubkey")
	}
	return shortErr(err)
}

// hostAnswered: der Zugang ist am Host angekommen und wurde abgewiesen (Anmeldung, Hostschluessel, Zertifikat) - der
// Host laeuft also, auch wenn keine Werte kamen. Fuer "darf ausgeschaltet sein" (#229): nur echte
// Nichterreichbarkeit heisst "ausgeschaltet".
func hostAnswered(err error) bool {
	switch {
	case errors.Is(err, transport.ErrHostKeyChanged), errors.Is(err, transport.ErrHostKeyUnconfirmed), errors.Is(err, transport.ErrNoKeyAuth), errors.Is(err, transport.ErrPushAmbiguous), errors.Is(err, transport.ErrPushForeignKey):
		return true
	case apis.HostAnswered(err):
		return true
	}
	return strings.Contains(err.Error(), "ssh: unable to authenticate") // Anmeldung abgelehnt (golang.org/x/crypto/ssh)
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
	// Cluster: nur die zustaendige Node fragt ab und meldet (cluster_owner.go)
	rctx, rcancel := context.WithTimeout(context.Background(), dbTimeout)
	role, owner := m.clusterRole(rctx, rt)
	rcancel()
	if role == roleIdle {
		m.idleView(rt, owner)
		return
	}

	// 1. Zugaenge abfragen
	m.setFollow(rt) // Proxmox: uebernommene Gaeste auch auf anderen Nodes des Clusters suchen (#165)
	found := map[string]foundSvc{}
	failedAcc := map[string]bool{} // Zugang hat nicht geantwortet
	partial := map[string]error{}  // Zugang hat nur teilweise geantwortet
	var accViews []AccessView
	var accInputs []eval.Access
	pushWaiting := false
	answered := false             // ein Zugang wurde vom laufenden Host abgewiesen (Anmeldung, Schluessel, Zertifikat)
	smartOff := map[string]bool{} // Zugang fragt SMART gewollt nicht ab ("SMART-Werte abfragen" aus)
	for _, a := range rt.accs {
		name := accessName(a.row.Type)
		smartOff[a.row.UID] = accessSmartOff(a.row)
		av := AccessView{UID: a.row.UID, Type: a.row.Type, Name: name}
		var svcs []model.Service
		var err error
		if a.col == nil {
			err = errors.New(a.err)
		} else {
			svcs, err = a.col.collect(ctx)
			if keys, ch := memoChanged(a.col, rt.SeenUp[a.row.UID]); ch { // merkbarer Zustand des Sammlers (snmpaccess.go)
				if rt.SeenUp == nil {
					rt.SeenUp = map[string][]string{}
				}
				rt.SeenUp[a.row.UID], rt.dirty = keys, true
			}
		}
		if err != nil && len(svcs) == 0 && errors.Is(err, transport.ErrNotConnected) && m.sinceStart() < pushStartGrace {
			// Push-Agent nach dem Start der Node noch nicht wieder verbunden (er wartet bis 5 min, bevor er es neu
			// versucht): nicht als Ausfall zaehlen, sonst meldet jeder Neustart alle Push-Hosts "nicht erreichbar"
			failedAcc[a.row.UID], pushWaiting = true, true
			av.Error = i18nText("monitor64.detail.push_waiting")
		} else if err != nil && len(svcs) == 0 {
			rt.Failures[a.row.UID]++
			failedAcc[a.row.UID] = true
			av.Error = accessErrText(err)
			answered = answered || hostAnswered(err)
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
		if len(svcs) > maxServicesPerAccess { // Bericht eines (fremden) Agents bzw. Geraets: nicht beliebig viele Dienste
			m.log.Warn("monitor64: too many services, rest dropped", "host", h.Name, "access", a.row.UID, "count", len(svcs))
			svcs = svcs[:maxServicesPerAccess]
		}
		for _, s := range svcs {
			s.Metrics = finiteMetrics(s.Metrics)
			if g, ok := found[s.Key]; !ok || rank < g.rank {
				found[s.Key] = foundSvc{svc: s, via: name, acc: a.row.UID, rank: rank}
			}
		}
	}
	// Push-Agents nach dem Start der Node noch nicht wieder da und sonst nichts geliefert: die Runde auslassen statt
	// alle Werte nach 3 Intervallen "unbekannt" zu melden (der Agent wartet bis 5 min, bevor er neu verbindet)
	if pushWaiting && len(found) == 0 {
		return
	}
	// Datenbank-Schritte mit eigenem Zeitlimit, erst nach dem Abfragen: ein langsamer Zugang (bis zu 30 s) darf die
	// Runde nicht abbrechen - sonst bliebe ein haengender Zugang ohne Meldung und der Host auf dem letzten Stand
	dbctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	// SNMP-Traps: eigener Dienst des Hosts, solange ein SNMP-Zugang Traps nutzt
	if s, acc, ok := m.trapService(rt); ok {
		found[s.Key] = foundSvc{svc: s, via: accessName("snmp"), acc: acc, rank: accessRank("snmp")}
	}
	ref := hostRef(h)
	maint, win := m.inMaintenance(now, ref)
	hres0 := eval.HostState(eval.HostInput{Maintenance: maint, Accesses: accInputs})
	reachable := !hres0.Unreachable && len(found) > 0
	iv := time.Duration(h.IntervalSec) * time.Second
	if reachable {
		rt.markBack(now, iv)
	}
	startup := reachable && rt.inStartup(now, iv)

	// 2. Dienste erkennen (beim ersten Mal, stuendlich und sobald ein bisher nicht gesehener Dienst auftaucht, z. B.
	// "Updates", wenn der Agent die erste Suche erst nach der ersten Abfrage fertig hat); nie automatisch uebernehmen.
	// Nicht vorgeschlagene (Default false, z. B. einzelne Windows-Dienste, gestoppte Gaeste) kommen als "ignoriert" dazu,
	// damit sie spaeter uebernommen werden koennen, ohne die Liste der neuen Dienste zu fuellen (UpsertDiscovered).
	newKey := false
	for k, g := range found {
		if !rt.known[k] && g.svc.MovedTo == "" {
			newKey = true
			break
		}
	}
	if reachable && role == roleReport && (rt.LastDisc.IsZero() || now.Sub(rt.LastDisc) >= discoverEvery || newKey) {
		offer := make([]model.Service, 0, len(found))
		for _, g := range found {
			if g.svc.MovedTo == "" { // Gast auf einer anderen Node (#165): dort erkannt, hier nicht vorschlagen
				offer = append(offer, g.svc)
			}
		}
		sort.Slice(offer, func(i, j int) bool { return offer[i].Key < offer[j].Key })
		if _, err := m.store.UpsertDiscovered(dbctx, h.UID, offer, nil, SystemActor); err != nil {
			m.log.Warn("monitor64: discover", "host", h.Name, "err", err)
		}
		rt.LastDisc, rt.dirty = now, true
		if rt.known == nil {
			rt.known = make(map[string]bool, len(found))
		}
		for k := range found { // waechst nur: ein flackernder Dienst loest keine Erkennung je Runde aus
			rt.known[k] = true
		}
	}
	rows, err := m.store.Services(dbctx, h.UID)
	if err != nil {
		m.log.Warn("monitor64: services", "host", h.Name, "err", err)
		return
	}
	rows = m.migrated(dbctx, h, rt, rows, found, role, now) // Gaeste auf anderen Nodes: uebergeben bzw. hier weiter
	rt.follow = followKeys(rows)
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
	open := m.loadOpen(dbctx, h.UID)
	var views []SvcView
	var states []eval.State
	var inputs []eval.ServiceInput
	newCount := 0
	smartNew, smartKeep := map[string]*model.SmartDetail{}, map[string]bool{}
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
		smartKeep[r.Key] = true
		if ok && g.svc.Smart != nil {
			smartNew[r.Key] = g.svc.Smart
		}
		if smartNew[r.Key] != nil || rt.smartOf(r.Key) != nil {
			sv.Detail = "smart"
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
		var numDone []string // erledigte Ausnahmen "in Ordnung bis zu diesem Wert" (Zahlenwerte)
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
				// "in Ordnung bis zu diesem Wert" (Ausnahme am Dienst, z. B. SSD-Verschleiss 100 %): bis dahin keine Stufe;
				// wird der Wert schlechter oder faellt er unter die Warnschwelle, ist die Ausnahme erledigt
				if a := hostRules[mt.Rule].AcceptedAt; a != nil {
					if acceptWorse(e, *a, mt) || acceptRecovered(e, mt.Value) {
						numDone = append(numDone, mt.Rule)
					} else {
						e = withoutLimits(e)
						if !slices.Contains(sv.Accepted, mt.Rule) {
							sv.Accepted = append(sv.Accepted, mt.Rule)
						}
					}
				}
				mv.Status = tr.Observe(e, eval.Sample{At: now, Value: mt.Value, Free: free})
				mv.RuleKind = mt.Rule
				ms = append(ms, eval.MetricStatus{Name: mt.Name, Status: mv.Status, Notify: e.Notify()})
				if (mv.Status.State == eval.Warn || mv.Status.State == eval.Crit) && !slices.Contains(sv.Firing, mt.Rule) {
					sv.Firing = append(sv.Firing, mt.Rule) // meldet gerade: im Dialog als "in Ordnung" bestaetigbar
				}
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
			st := rt.missingStatus(tr, e, now, iv, startup)
			if ok && st.State == eval.Unknown && (svcStopped(g.svc) || smartOff[g.acc] && smartMetric(kind)) {
				// Dienst kommt weiter, ist aber aus (gestoppte VM mit Warnung zu CPU/RAM): Wert gewollt weggelassen - die
				// Warnung gilt nicht mehr, statt 7 Tage "unbekannt". Laeuft der Dienst, bleibt der fehlende Wert nach 3
				// Intervallen "unbekannt" (Teilfehler, Sammler liefert ihn nicht mehr) - keine Entwarnung ohne Erholung
				// (Review 7); kurz fehlend (erste Runde ohne Rate) bleibt der letzte Zustand. Ebenso gewollt weggelassen:
				// Werte aus SMART (Temperatur, Verschleiss), wenn der Zugang SMART nicht mehr abfragt
				delete(rt.Kinds, key)
				delete(rt.Trackers, key)
				rt.dirty = true
				continue
			}
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
		_, smartAsleep := facts["smart_standby"] // schlafende Platte ohne Vorstand (mapper.go): SMART nicht gelesen
		_, noData := facts[model.FactNoData]     // Dienst ohne Daten (Geraet offline): Zustand unbekannt, keine Aenderung
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
		// bestaetigte Zustaende, deren Bedingung entfallen ist (bzw. deren Regel-Art der Dienst nicht mehr hat): Ausnahme
		// entfernen, damit der naechste Eintritt wieder meldet
		accDone := numDone
		if (ok && !noData) || !r.VanishedAt.IsZero() {
			for k, hr := range hostRules {
				if hr.Accepted != nil && *hr.Accepted && !kinds[k] {
					accDone = append(accDone, k)
				}
			}
		}
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
			// "in Ordnung, bis sich der Zustand aendert": solange die Bedingung gilt, meldet sie nichts; entfaellt sie
			// (Dienst geliefert bzw. wieder da), ist die Ausnahme erledigt
			isSmart := k == eval.KindSmartFailed || k == eval.KindSmartSectors || k == eval.KindSmartSectorsUp
			if hr := hostRules[k]; hr.Accepted != nil && *hr.Accepted && (ok || k == eval.KindServiceGone) {
				switch {
				case cond:
					cond = false
					sv.Accepted = append(sv.Accepted, k)
				case isSmart && (smartUnreadable || smartAsleep), noData:
					sv.Accepted = append(sv.Accepted, k) // SMART bzw. Dienst in dieser Runde nicht gelesen: Bedingung unbekannt, bleibt
				default:
					accDone = append(accDone, k)
				}
			}
			e := eval.Resolve(cfg.std, cfg.overrides, ref, m.hostLevel(r.HostUID, hostRules, k), k)
			tr := rt.tracker(r.Key+"|state:"+k, iv)
			var st eval.Status
			switch {
			case k == eval.KindServiceGone:
				st = tr.Observe(e, eval.Sample{At: now, Value: eval.Bool(cond)})
			case isSmart && smartUnreadable && !cond && tr.Level == eval.OK:
				continue // SMART nicht lesbar (z. B. virtuelle Platte) und vorher kein Problem: nicht bewerten
			case !ok || (isSmart && smartUnreadable && !cond):
				st = rt.missingStatus(tr, e, now, iv, startup) // keine (lesbaren) Daten: letzter Stand, dann Unbekannt
			default:
				st = tr.Observe(e, eval.Sample{At: now, Value: eval.Bool(cond)})
			}
			ms = append(ms, eval.MetricStatus{Name: k, Status: st, Notify: e.Notify()})
			if cond && (st.State == eval.Warn || st.State == eval.Crit) {
				sv.Firing = append(sv.Firing, k)
			}
			if cond && st.State != eval.OK && text != "" {
				sv.Cause = text
			}
			if cond && st.State == eval.OK && (st.Pending == eval.Warn || st.Pending == eval.Crit) && !st.PendingAt.IsZero() {
				sv.Pending = append(sv.Pending, PendView{Kind: k, State: st.Pending, Since: st.PendingSince, At: st.PendingAt})
			}
		}
		if len(accDone) > 0 && role == roleReport {
			m.clearAccepted(dbctx, h.UID, r, hostRules, accDone)
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
			if !ok && (!had || now.Sub(ls.At) > time.Duration(eval.UnknownAfter)*iv) && !(startup && rt.lastBeforeBack(ls.At, iv)) {
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
			c := ms[res.Cause]
			kind := rt.Kinds[r.Key+"|"+c.Name] // Regel-Art der Messgroesse (leer bei Zustandsregeln: der Name ist die Art)
			free := kind != "" && eval.Resolve(cfg.std, cfg.overrides, ref, m.hostLevel(r.HostUID, hostRules, kind), kind).Mode == eval.ModeFree
			sv.Cause = describe(c, kind, free)
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
		name := model.T("monitor64.detail.access", "name", model.Sub(av.Name))
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

	// Host darf ausgeschaltet sein (#229): nicht erreichbar heisst "ausgeschaltet" - kein Problem, keine Meldung; die
	// letzten Werte bleiben, beim naechsten Einschalten gilt wieder alles wie sonst. Weist der Host einen Zugang ab
	// (Anmeldung, Hostschluessel, Zertifikat), laeuft er: das wird wie sonst gemeldet
	offline := h.OfflineOK && hres.Unreachable && !maint && !answered
	if offline {
		hres.View = eval.ViewOffline
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
	var hostMem []byte
	if offline {
		if role == roleReport {
			m.closeHostProblem(dbctx, h, open, now) // eben erst eingeschaltet, waehrend er schon nicht erreichbar war
		}
		m.notifyMu.Lock()
		if m.notifier != nil { // Gedaechtnis der Meldungen bleibt, wie es ist
			hostMem, _ = json.Marshal(m.notifier.Hosts[h.UID])
		}
		m.notifyMu.Unlock()
	} else if role == roleReport && len(rt.accs) > 0 {
		// ohne Zugang (letzter entfernt bzw. ausgeschaltet, Host wird gerade entfernt) liefert der Host nichts: weder
		// Probleme abgleichen noch melden - ohne Zugang hiesse er sonst erreichbar, mit "wieder erreichbar" und allen
		// Diensten "noch offen - Unbekannt" (#263)
		m.syncProblems(dbctx, h, open, inputs, hres, unreachDetail, now)
		round := eval.Round{At: now, Host: ref, Unreachable: hres.Unreachable, Maintenance: maint, Quiet: m.quietNow(now), Services: inputs}
		if op := open[""]; op != nil {
			round.HostAcked = op.Acked
		}
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
	rt.setSmart(smartNew, smartKeep, now)
	rt.setView(&HostView{Host: h, View: hres.View, State: hres.State, Checked: now, Accesses: accViews, Services: views, New: newCount, Maint: win,
		Cluster: m.clusterSelfRef(role)})
	m.saveRuntime(dbctx, rt, hostMem)
}

// svcStopped: der Dienst meldet sich als aus (Messgroesse running = 0: Gast, Container, Windows-Dienst) - seine
// Werte fehlen dann gewollt.
func svcStopped(s model.Service) bool {
	for _, mt := range s.Metrics {
		if mt.Name == "running" {
			return mt.Value == 0
		}
	}
	return false
}

// accessSmartOff: der Zugang fragt SMART gewollt nicht ab (Schalter "SMART-Werte abfragen" aus, #215; SSH ohne
// SMART per sudo smartctl).
func accessSmartOff(a *Access) bool {
	var cfg accessConfig
	if a == nil || json.Unmarshal(a.Config, &cfg) != nil {
		return false
	}
	switch {
	case smartSwitch(a.Type):
		return cfg.NoSmart
	case a.Type == "ssh":
		return !cfg.Smart
	}
	return false
}

// smartMetric: Regel-Art eines Werts, der aus SMART stammt (Temperatur, Verschleiss einer Platte).
func smartMetric(kind string) bool {
	return kind == model.RuleDiskTemp || kind == model.RuleNVMeTemp || kind == model.RuleWear
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

// acceptWorse: der Wert ist schlechter als der als gewollt bestaetigte at (Richtung der Regel, Hysterese als
// Spielraum, damit leichtes Schwanken die Ausnahme nicht beendet). Verglichen wird in der Einheit der Schwellen: im
// Modus "GB frei" die freien GB (at ist wie der Wert "belegt in %", umgerechnet ueber die Groesse), sonst der Wert
// selbst. Prozentwerte enden bei 100 % (bzw. 0 %): der Spielraum ist hoechstens die Haelfte des Rests bis dahin, sonst
// endete die Ausnahme nahe 100 % nie.
func acceptWorse(e eval.Effective, at float64, mt model.Metric) bool {
	v := mt.Value
	if e.Mode == eval.ModeFree && mt.Unit == "%" && mt.Max > 0 {
		l := e.WarnFree
		if l.Off {
			l = e.CritFree
		}
		h := e.Hyst
		if !l.Off {
			h = e.HystAt(l.V)
		}
		return mt.Max*(v-at)/100 > h*eval.GB // weniger frei als bei der Bestaetigung (ueber den Spielraum hinaus)
	}
	h := e.Hyst
	if e.Dir == eval.Down {
		if mt.Unit == "%" && at > 0 {
			h = math.Min(h, at/2)
		}
		return v < at-h
	}
	if mt.Unit == "%" && at < 100 {
		h = math.Min(h, (100-at)/2)
	}
	return v > at+h
}

// acceptRecovered: der Wert ist wieder unter der Warnschwelle (bzw. ohne Warnschwelle unter der kritischen) - die
// Ausnahme wird nicht mehr gebraucht. Im Modus "GB frei" endet sie nur, wenn der Wert schlechter wird.
func acceptRecovered(e eval.Effective, v float64) bool {
	if e.Mode == eval.ModeFree {
		return false
	}
	l := e.Warn
	if l.Off {
		l = e.Crit
	}
	if l.Off {
		return true
	}
	if e.Dir == eval.Down {
		return v > l.V
	}
	return v < l.V
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

// describe formuliert die ausloesende Messgroesse uebersetzbar mit Bezeichnung, Wert und Schwelle samt Einheit
// ("RAM belegt 92 % (Schwelle 90 %)"). kind ist die Regel-Art der Messgroesse (leer = der Name ist die Art, bei
// Zustandsregeln), free der Modus "GB frei" (Wert und Schwelle in GB frei).
func describe(ms eval.MetricStatus, kind string, free bool) string {
	st := ms.Status
	rk, known := ruleKindOf(firstNonEmpty(kind, ms.Name))
	label := model.Sub(model.Raw(ms.Name))
	if known {
		label = model.Sub(model.T("monitor64.kind." + kindKey(rk.Kind)))
	}
	if st.State == eval.Unknown && st.Level != eval.Unknown {
		// keine aktuellen Daten (nicht die Bezeichnung der Regel - "Unbekannt - Firmware-Update verfuegbar" klang wie ein
		// gefundenes Update, #275); Zustandsregeln ohne eigenen Namen, Messgroessen mit ihrer Bezeichnung
		if known && rk.State {
			return i18nText("monitor64.detail.no_data")
		}
		return model.T("monitor64.detail.no_data_of", "metric", label)
	}
	if st.Threshold.Off || (known && rk.State) {
		return string(label)
	}
	if free {
		return model.T("monitor64.detail.threshold_free", "value", shortNum(st.Value), "limit", shortNum(st.Threshold.V))
	}
	val := func(v float64) model.Sub {
		if rk.Factor > 0 {
			v /= rk.Factor
		}
		switch rk.Unit {
		case "":
			return model.Sub(shortNum(v))
		case "days", "min":
			return model.Sub(shortNum(v) + " " + model.T("monitor64.unit."+rk.Unit))
		}
		return model.Sub(shortNum(v) + " " + rk.Unit)
	}
	return model.T("monitor64.detail.threshold", "metric", label, "value", val(st.Value), "limit", val(st.Threshold.V))
}

// shortNum rundet fuer Texte: ab 10 ganze Zahlen, darunter eine, unter 1 zwei Nachkommastellen (sprachneutral).
func shortNum(v float64) string {
	d := 0
	switch a := math.Abs(v); {
	case a < 1:
		d = 2
	case a < 10:
		d = 1
	}
	s := strconv.FormatFloat(v, 'f', d, 64)
	if d > 0 {
		s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	}
	return s
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

// markBack merkt sich das Wiederkommen des Hosts (#275): eine Runde mit Daten nach mindestens einer Runde ohne Daten
// (ausgeschaltet, nicht erreichbar, Neustart, Node bzw. Monitor64 aus).
func (rt *hostRT) markBack(now time.Time, iv time.Duration) {
	if iv <= 0 {
		iv = eval.DefaultInterval
	}
	if rt.Seen.IsZero() || now.Before(rt.Seen) || now.Sub(rt.Seen) > iv+iv/2 {
		rt.Back, rt.Away, rt.dirty = now, rt.Seen, true
	}
	rt.Seen = now
}

// startupFor: Dauer der Anlaufzeit nach dem Wiederkommen - startupGrace, mindestens die Zeit, nach der fehlende Werte
// sonst "unbekannt" werden (3 Intervalle).
func startupFor(iv time.Duration) time.Duration {
	if iv <= 0 {
		iv = eval.DefaultInterval
	}
	return max(startupGrace, time.Duration(eval.UnknownAfter)*iv)
}

// inStartup: der Host ist erst seit kurzem wieder da (Anlaufzeit laeuft).
func (rt *hostRT) inStartup(now time.Time, iv time.Duration) bool {
	return !rt.Back.IsZero() && !rt.Away.IsZero() && !now.Before(rt.Back) && now.Sub(rt.Back) < startupFor(iv)
}

// lastBeforeBack: ein Wert mit letzter Messung last kam seit dem Wiederkommen noch nicht, war aber vor der Luecke
// aktuell. Werte, die schon vorher fehlten (bzw. "unbekannt" waren), bekommen keine Anlaufzeit.
func (rt *hostRT) lastBeforeBack(last time.Time, iv time.Duration) bool {
	if iv <= 0 {
		iv = eval.DefaultInterval
	}
	return !last.IsZero() && last.Before(rt.Back) && rt.Away.Sub(last) <= time.Duration(eval.UnknownAfter)*iv
}

// missingStatus: Zustand eines Werts ohne Messung in dieser Runde - letzter Stand, nach 3 Intervallen Unbekannt. In
// der Anlaufzeit nach dem Wiederkommen (startup) bleibt ein vor der Luecke aktueller Wert auf seinem letzten Stand,
// bis er wieder kommt (#275: sonst meldet jedes Einschalten "Updates: Unbekannt" und eine Runde spaeter "wieder OK").
func (rt *hostRT) missingStatus(tr *eval.Tracker, e eval.Effective, now time.Time, iv time.Duration, startup bool) eval.Status {
	st := tr.Status(e, now)
	if st.State == eval.Unknown && startup && rt.lastBeforeBack(tr.LastAt, iv) {
		st.State, st.Since = st.Level, tr.Changed
	}
	return st
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
	// Geht diese Meldung an "Standardkanaele", bekommen die Standardkanaele sie auf diesem Weg; ein zusaetzlich
	// ausdruecklich gewaehlter Standardkanal bekaeme sonst dieselbe Zeile doppelt (getrennte Meldungen). Geht sie nicht
	// an "Standardkanaele" (z. B. Warnung, wenn die Standardkanaele nur Kritisch bekommen), zaehlt der ausdruecklich
	// gewaehlte Kanal ganz normal - sonst ginge die Meldung verloren.
	withDefault := slices.Contains(msg.Channels, defaultChannels)
	var defaults map[int64]bool
	if withDefault {
		defaults = m.defaultChannelIDs(ctx)
	}
	var explicit []int64
	for _, id := range msg.Channels {
		if id == defaultChannels {
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
