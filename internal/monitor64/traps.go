package monitor64

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/monitor64/snmp"
	"github.com/ipv64net/node64/internal/monitor64/snmp/trap"
	"github.com/ipv64net/node64/internal/monitor64/transport"
)

// SNMP-Traps (Plan "SNMP – Traps" und "Sicherheit"): ein Empfaenger je Modul, offen nur, solange ein SNMP-Zugang
// Traps nutzt. Bekannte Traps (linkDown, onBattery ...) stossen eine sofortige Runde des Hosts an (entprellt; der
// Zustand kommt aus der Abfrage). Uebrige angenommene Traps landen im Dienst "traps" des Hosts (Warnung bis
// quittiert: Quittieren bzw. Loesen des Problems setzt den Dienst zurueck). Abgewiesene (Community, Benutzer,
// Engine-ID, Zeitfenster passt nicht) werden nur gezaehlt, unbekannte Absender in einer begrenzten Liste gemerkt –
// nie automatisch angelegt. Alles aus Traps ist nicht vertrauenswuerdig (bereinigt vom Empfaenger, escaped in der
// Oberflaeche). Im Cluster gehen Traps eines Hosts, den eine andere Node ueberwacht, an diese (traps_cluster.go).
//
// Bekannt ist ein Host, sobald seine Konfiguration Traps nutzt – unabhaengig davon, ob sein Name gerade aufgeloest
// werden kann (ein DNS-Fehler nimmt weder den Stand noch die zuletzt bekannte Adresse). Gescheiterte Aufloesung und
// ein belegter Port werden regelmaessig neu versucht.

const (
	setTrapPort        = "monitor64.trap_port"      // UDP-Port des Empfaengers (Standard 162)
	setTrapEngine      = "monitor64.trap_engine_id" // lokale Engine-ID (hex, einmal erzeugt) fuer v3-Informs
	defaultTrapPort    = 162
	trapKeep           = 20               // letzte Traps je Host
	trapKeepSaved      = 10               // davon im Laufzeitstand gespeichert (ohne Varbinds)
	trapDebounce       = 10 * time.Second // hoechstens eine sofortige Runde je Host
	maxUnknownSenders  = 100
	trapResolveTimeout = 3 * time.Second
	trapResolveWorkers = 8 // Namen gleichzeitig aufloesen
	maxTrapAddrs       = 16
	factTrapReceived   = "trap_received"
	trapSvcKey         = "traps"
)

var (
	trapRetryEvery   = time.Minute      // gescheiterte Aufloesung bzw. belegten Port so oft neu versuchen
	trapRefreshEvery = 10 * time.Minute // Namen so oft neu aufloesen (geaenderte Adressen)
)

// trapRunKinds: bekannte Traps, die nur eine sofortige Abfrage ausloesen (Zustand aus der Abfrage).
var trapRunKinds = map[string]bool{"link_down": true, "link_up": true, "restart": true, "shutdown": true, "ups_on_battery": true,
	"ups_on_line": true, "ups_battery_low": true, "ups_battery_ok": true, "ups_battery_replace": true, "ups_alarm": true,
	"ups_alarm_cleared": true, "printer_alert": true}

// trapEntry ist ein angenommener Trap im Dienst "traps".
type trapEntry struct {
	Time      time.Time      `json:"time"`
	Version   string         `json:"version"`
	Inform    bool           `json:"inform,omitempty"`
	User      string         `json:"user,omitempty"`
	TrapOID   string         `json:"trap_oid,omitempty"`
	TrapName  string         `json:"trap_name,omitempty"`
	Kind      string         `json:"kind,omitempty"`
	Handled   bool           `json:"handled,omitempty"` // bekannter Trap: nur sofortige Abfrage
	Varbinds  []trap.Varbind `json:"varbinds,omitempty"`
	Truncated bool           `json:"truncated,omitempty"`
}

// label ist der Name des Traps (bekannter Name, sonst OID).
func (e trapEntry) label() string { return firstNonEmpty(e.TrapName, e.TrapOID, "trap") }

// hostTraps ist der Trap-Stand eines Hosts.
type hostTraps struct {
	List         []trapEntry `json:"list,omitempty"` // neueste zuletzt
	Pending      int         `json:"pending,omitempty"`
	Total        uint64      `json:"total,omitempty"`
	Rejected     uint64      `json:"rejected,omitempty"`
	RejectReason string      `json:"reject_reason,omitempty"`
	RejectedAt   time.Time   `json:"rejected_at,omitzero"`
}

// unknownSender ist ein Absender, der keinem Host zugeordnet ist.
type unknownSender struct {
	Addr     string    `json:"addr"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
	Count    uint64    `json:"count"`
	Version  string    `json:"version"`
	TrapOID  string    `json:"trap_oid,omitempty"`
	TrapName string    `json:"trap_name,omitempty"`
	User     string    `json:"user,omitempty"`
}

// trapMgr haelt Empfaenger und Trap-Stand des Moduls.
type trapMgr struct {
	syncMu sync.Mutex // syncTraps nacheinander

	mu      sync.Mutex
	rcv     *trap.Receiver
	listen  string
	engine  string
	err     string // letzter Fehler beim Oeffnen des Ports
	active  int    // Hosts mit Traps
	stopped bool
	hosts   map[string]*hostTraps
	known   map[string]bool      // Hosts mit Traps laut Konfiguration (letzter Abgleich); nur deren Events zaehlen
	addrs   map[string]trapAddrs // letzte erfolgreiche Aufloesung je Host
	retry   bool                 // Abgleich bald wiederholen (Aufloesung, Port oder Datenbank gescheitert)
	names   bool                 // ein Host hat einen Namen statt einer IP (regelmaessig neu aufloesen)
	synced  time.Time            // letzter Abgleich
	unknown map[string]*unknownSender
	lastRun map[string]time.Time
	timers  map[string]*time.Timer

	now     func() time.Time
	after   func(time.Duration, func()) *time.Timer
	run     func(hostUID string)                // sofortige Runde (Planer)
	ownerOf func(hostUID string) (string, bool) // Cluster: zustaendige andere Node (traps_cluster.go); nil = immer hier
	kick    chan struct{}
	fwd     chan trapFwd // Eintraege an die zustaendige Node (traps_cluster.go)
}

// trapAddrs ist die zuletzt erfolgreiche Aufloesung einer Host-Adresse.
type trapAddrs struct {
	address string
	list    []netip.Addr
}

func newTrapMgr(run func(string)) *trapMgr {
	return &trapMgr{hosts: map[string]*hostTraps{}, known: map[string]bool{}, addrs: map[string]trapAddrs{}, unknown: map[string]*unknownSender{},
		lastRun: map[string]time.Time{}, timers: map[string]*time.Timer{}, now: time.Now, after: time.AfterFunc, run: run,
		kick: make(chan struct{}, 1), fwd: make(chan trapFwd, trapFwdQueue), stopped: true}
}

// host liefert den Stand eines Hosts (legt ihn an; nur fuer bekannte Hosts aufrufen). t.mu gehalten.
func (t *trapMgr) host(uid string) *hostTraps {
	h := t.hosts[uid]
	if h == nil {
		h = &hostTraps{}
		t.hosts[uid] = h
	}
	return h
}

// onEvent ist der Rueckruf des Empfaengers (eigene Goroutine, Events nacheinander). Events nach dem Stopp und von
// Hosts, die nicht (mehr) Traps nutzen (noch in der Warteschlange), legen keinen Stand an.
func (t *trapMgr) onEvent(ev trap.Event) {
	now := t.now()
	accepted := ev.Known && ev.HostID != "" && ev.Rejected == ""
	owner, remote := "", false
	if accepted { // Cluster: ueberwacht eine andere Node den Host? (ausserhalb t.mu)
		t.mu.Lock()
		of := t.ownerOf
		t.mu.Unlock()
		if of != nil {
			owner, remote = of(ev.HostID)
		}
	}
	t.mu.Lock()
	switch {
	case t.stopped:
		t.mu.Unlock()
		return
	case !ev.Known || ev.HostID == "":
		t.addUnknown(ev, now)
		t.mu.Unlock()
		return
	case !t.known[ev.HostID]:
		t.mu.Unlock()
		return
	case ev.Rejected != "":
		h := t.host(ev.HostID)
		h.Rejected++
		h.RejectReason, h.RejectedAt = ev.Rejected, now
		t.mu.Unlock()
		return
	}
	e := trapEntry{Time: now, Version: ev.Version, Inform: ev.Inform, User: ev.User, TrapOID: ev.TrapOID, TrapName: ev.TrapName, Kind: ev.Kind,
		Handled: trapRunKinds[ev.Kind], Varbinds: ev.Varbinds, Truncated: ev.Truncated}
	if remote {
		select {
		case t.fwd <- trapFwd{owner: owner, host: ev.HostID, entry: e}: // die zustaendige Node traegt ihn ein
			t.mu.Unlock()
			return
		default: // Warteschlange voll: hier eintragen
		}
	}
	runNow := t.add(ev.HostID, e, now)
	t.mu.Unlock()
	if runNow && t.run != nil {
		t.run(ev.HostID)
	}
}

// add traegt einen angenommenen Trap ein; true = sofortige Runde. t.mu gehalten.
func (t *trapMgr) add(uid string, e trapEntry, now time.Time) bool {
	h := t.host(uid)
	h.List = append(h.List, e)
	if len(h.List) > trapKeep {
		h.List = append([]trapEntry(nil), h.List[len(h.List)-trapKeep:]...)
	}
	h.Total++
	if !e.Handled {
		h.Pending++
	}
	return t.debounce(uid, now)
}

// addEntry traegt einen Trap ein, der nicht vom eigenen Empfaenger kommt (von einer anderen Node bzw. nicht
// weitergereicht); false = Host nutzt hier keine Traps bzw. Modul gestoppt.
func (t *trapMgr) addEntry(uid string, e trapEntry) bool {
	now := t.now()
	t.mu.Lock()
	if t.stopped || !t.known[uid] {
		t.mu.Unlock()
		return false
	}
	runNow := t.add(uid, e, now)
	t.mu.Unlock()
	if runNow && t.run != nil {
		t.run(uid)
	}
	return true
}

// debounce: sofortige Runde hoechstens alle trapDebounce je Host; kommt in der Sperrzeit ein weiterer Trap, folgt
// eine Runde am Ende der Sperrzeit (der Zustand kann sich inzwischen geaendert haben). t.mu gehalten.
func (t *trapMgr) debounce(uid string, now time.Time) bool {
	last, had := t.lastRun[uid]
	if !had || now.Sub(last) >= trapDebounce || now.Before(last) {
		t.lastRun[uid] = now
		return true
	}
	if t.timers[uid] == nil && t.after != nil {
		t.timers[uid] = t.after(trapDebounce-now.Sub(last), func() {
			t.mu.Lock()
			delete(t.timers, uid)
			t.lastRun[uid] = t.now()
			stopped := t.stopped
			t.mu.Unlock()
			if !stopped && t.run != nil {
				t.run(uid)
			}
		})
	}
	return false
}

// addUnknown merkt einen unbekannten Absender (hoechstens maxUnknownSenders, der am laengsten stille faellt raus).
func (t *trapMgr) addUnknown(ev trap.Event, now time.Time) {
	key := ev.From.String()
	u := t.unknown[key]
	if u == nil {
		if len(t.unknown) >= maxUnknownSenders {
			var oldest string
			for k, x := range t.unknown {
				if oldest == "" || x.Last.Before(t.unknown[oldest].Last) {
					oldest = k
				}
			}
			delete(t.unknown, oldest)
		}
		u = &unknownSender{Addr: key, First: now}
		t.unknown[key] = u
	}
	u.Last, u.Version, u.TrapOID, u.TrapName, u.User = now, ev.Version, ev.TrapOID, ev.TrapName, ev.User
	u.Count++
}

// reset setzt die offenen Traps eines Hosts zurueck (Quittieren, Loesen, Knopf).
func (t *trapMgr) reset(uid string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := t.hosts[uid]
	if h == nil || h.Pending == 0 {
		return false
	}
	h.Pending = 0
	return true
}

// restore uebernimmt den gespeicherten Stand eines Hosts nach einem Neustart (der Stand im Speicher geht vor).
func (t *trapMgr) restore(uid string, saved *hostTraps) {
	if saved == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.hosts[uid]; !ok {
		c := *saved
		c.List = append([]trapEntry(nil), saved.List...)
		t.hosts[uid] = &c
	}
}

// snapshot liefert eine Kopie des Stands eines Hosts (nil = keiner). full = mit allen Eintraegen und Varbinds.
func (t *trapMgr) snapshot(uid string, full bool) *hostTraps {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := t.hosts[uid]
	if h == nil {
		return nil
	}
	c := *h
	list := h.List
	if !full && len(list) > trapKeepSaved {
		list = list[len(list)-trapKeepSaved:]
	}
	c.List = make([]trapEntry, len(list))
	copy(c.List, list)
	if !full {
		for i := range c.List {
			c.List[i].Varbinds = nil
		}
	}
	return &c
}

// trapServiceIdle ist der Dienst "traps" ohne offene Traps.
func trapServiceIdle() model.Service {
	return model.Service{Key: trapSvcKey, Name: "Traps", Kind: "traps", Default: true, Metrics: []model.Metric{{Name: "pending", Value: 0}}}
}

// service baut den Dienst "traps" aus dem Stand eines Hosts: offene Traps sind ein Fact (Regel trap.received).
func (t *trapMgr) service(uid string) model.Service {
	s := trapServiceIdle()
	t.mu.Lock()
	defer t.mu.Unlock()
	h := t.hosts[uid]
	if h == nil {
		return s
	}
	s.Metrics[0].Value = float64(h.Pending)
	if n := len(h.List); n > 0 {
		last := h.List[n-1]
		s.Text = i18nText("monitor64.detail.trap_last", "name", last.label(), "at", last.Time.UTC().Format(time.RFC3339))
	}
	if h.Pending > 0 {
		var last trapEntry
		for i := len(h.List) - 1; i >= 0; i-- {
			if !h.List[i].Handled {
				last = h.List[i]
				break
			}
		}
		s.Facts = []model.Fact{{Code: factTrapReceived, Text: i18nText("monitor64.detail.traps", "n", strconv.Itoa(h.Pending), "name", last.label(),
			"at", last.Time.UTC().Format(time.RFC3339))}}
	}
	return s
}

// trapAccess: SNMP-Zugang eines Hosts, der Traps nutzt ("" = keiner).
func trapAccess(rt *hostRT) string {
	for _, a := range rt.accs {
		if a.row.Type != "snmp" || !a.row.Enabled {
			continue
		}
		var cfg accessConfig
		if json.Unmarshal(a.row.Config, &cfg) == nil && cfg.Traps {
			return a.row.UID
		}
	}
	return ""
}

// trapService liefert den Dienst "traps" fuer die Runde eines Hosts (ok=false: kein Zugang mit Traps) und merkt den
// Stand im Laufzeitstand (rt.mu gehalten).
func (m *Module) trapService(rt *hostRT) (model.Service, string, bool) {
	acc := trapAccess(rt)
	if acc == "" && rt.Traps != nil { // Traps aus: gemerkten Stand vergessen (beim Wiedereinschalten nichts Altes offen)
		rt.Traps, rt.dirty = nil, true
	}
	if acc == "" || m.traps == nil {
		return model.Service{}, "", false
	}
	uid := rt.host.UID
	snap := m.traps.snapshot(uid, false)
	if snap != nil && (rt.Traps == nil || rt.Traps.Pending != snap.Pending || rt.Traps.Total != snap.Total) {
		rt.dirty = true
	}
	rt.Traps = snap
	return m.traps.service(uid), acc, true
}

// kickTraps stoesst den Abgleich des Empfaengers an (nach jeder Aenderung an Hosts und Zugaengen).
func (m *Module) kickTraps() {
	if m.traps == nil {
		return
	}
	select {
	case m.traps.kick <- struct{}{}:
	default:
	}
}

// trapLoop gleicht den Empfaenger nach jedem Anstoss ab, wiederholt gescheiterte Abgleiche (Aufloesung, belegter
// Port) und loest Namen regelmaessig neu auf; dazu reicht er Traps im Cluster weiter (laeuft solange das Modul laeuft).
func (m *Module) trapLoop(ctx context.Context) {
	t := m.traps
	t.mu.Lock()
	t.ownerOf = m.trapOwner
	t.mu.Unlock()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); m.trapForwardLoop(ctx) }()
	defer wg.Wait()
	tick := time.NewTicker(trapRetryEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.kick:
			m.syncTraps(ctx)
		case <-tick.C:
			if t.syncDue() {
				m.syncTraps(ctx)
			}
		}
	}
}

// syncDue: Abgleich faellig (Fehler beim letzten Mal bzw. Namen lange nicht aufgeloest).
func (t *trapMgr) syncDue() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return !t.stopped && (t.retry || (t.names && t.now().Sub(t.synced) >= trapRefreshEvery))
}

// trapPort ist der eingestellte UDP-Port (Standard 162).
func (m *Module) trapPort(ctx context.Context) int {
	n, err := strconv.Atoi(m.st.SettingOr(ctx, setTrapPort, ""))
	if err != nil || n < 1 || n > 65535 {
		return defaultTrapPort
	}
	return n
}

// trapEngineID liefert die gespeicherte Engine-ID (beim ersten Mal erzeugt).
func (m *Module) trapEngineID(ctx context.Context) (string, error) {
	if v := m.st.SettingOr(ctx, setTrapEngine, ""); reEngineID.MatchString(v) {
		return v, nil
	}
	id := trap.GenerateEngineID()
	if err := m.st.SetSetting(ctx, setTrapEngine, id); err != nil {
		return "", err
	}
	return id, nil
}

// trapHostSet sind die Hosts mit Traps laut Konfiguration und der Stand ihrer Aufloesung.
type trapHostSet struct {
	hosts      []trap.Host // alle Hosts mit Traps (auch ohne aufgeloeste Adresse)
	unresolved int         // davon ohne Adresse (Aufloesung gescheitert, ohne fruehere Adresse)
	failed     int         // Aufloesung gescheitert (auch mit weiterverwendeter frueherer Adresse)
	names      bool        // ein Host hat einen Namen
}

// trapHosts liest die Hosts mit SNMP-Zugang und Traps (Geheimnisse entschluesselt, Adressen aufgeloest). Bekannt ist
// jeder Host mit Traps in der Konfiguration; scheitert die Aufloesung, gilt die zuletzt bekannte Adresse.
func (m *Module) trapHosts(ctx context.Context) (trapHostSet, error) {
	var set trapHostSet
	hosts, err := m.store.Hosts(ctx)
	if err != nil {
		return set, err
	}
	accs, err := m.store.Accesses(ctx, "")
	if err != nil {
		return set, err
	}
	byHost := map[string][]*Access{}
	for _, a := range accs {
		if a.Type == "snmp" && a.Enabled {
			byHost[a.HostUID] = append(byHost[a.HostUID], a)
		}
	}
	var out []trap.Host
	var addrOf, nameOf []string
	for _, h := range hosts {
		th := trap.Host{ID: h.UID}
		for _, a := range byHost[h.UID] {
			var cfg accessConfig
			if json.Unmarshal(a.Config, &cfg) != nil || !cfg.Traps {
				continue
			}
			sec := snmp.Secret{}
			if a.Secret != "" {
				s, err := m.box.Decrypt(a.Secret)
				if err != nil {
					m.log.Warn("monitor64: traps: secret unreadable", "host", h.Name)
					continue
				}
				sec = snmp.ParseSecret(s)
			}
			if sec.Community != "" && cfg.SNMPVersion != "3" { // Community nur bei v1/v2c (v3: nur der Benutzer)
				th.Communities = append(th.Communities, sec.Community)
			}
			if cfg.SNMPVersion == "3" && cfg.User != "" {
				if _, _, err := snmp.USM(cfg.User, cfg.Level, cfg.AuthProto, cfg.PrivProto, sec); err != nil {
					m.log.Warn("monitor64: traps: v3 user", "host", h.Name, "err", err)
				} else {
					th.Users = append(th.Users, trap.User{Name: cfg.User, Level: cfg.Level, AuthProto: cfg.AuthProto, PrivProto: cfg.PrivProto, Secret: sec, EngineID: cfg.TrapEngine})
				}
			}
		}
		if len(th.Communities) == 0 && len(th.Users) == 0 {
			continue
		}
		out = append(out, th)
		addrOf, nameOf = append(addrOf, h.Address), append(nameOf, h.Name)
	}
	// Adressen aufloesen (Namen gleichzeitig, mit Zeitlimit je Name)
	t := m.traps
	sem := make(chan struct{}, trapResolveWorkers)
	var wg sync.WaitGroup
	ok := make([]bool, len(out))
	for i := range out {
		if _, err := netip.ParseAddr(transport.SplitHost(addrOf[i])); err != nil {
			set.names = true
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i].Addrs = resolveAddrs(ctx, addrOf[i])
			ok[i] = len(out[i].Addrs) > 0
		}(i)
	}
	wg.Wait()
	t.mu.Lock()
	for i := range out {
		uid := out[i].ID
		switch prev, had := t.addrs[uid]; {
		case ok[i]:
			t.addrs[uid] = trapAddrs{address: addrOf[i], list: out[i].Addrs}
		case had && prev.address == addrOf[i]: // DNS-Fehler: zuletzt bekannte Adresse weiter verwenden
			set.failed++
			out[i].Addrs = prev.list
		default:
			set.failed++
			set.unresolved++
		}
	}
	t.mu.Unlock()
	for i := range out {
		if !ok[i] {
			m.log.Warn("monitor64: traps: address not resolvable", "host", nameOf[i], "using_previous", len(out[i].Addrs) > 0)
		}
	}
	set.hosts = out
	return set, nil
}

// resolveAddrs loest die Adresse eines Hosts auf (IP direkt, Name per DNS mit Zeitlimit).
func resolveAddrs(ctx context.Context, address string) []netip.Addr {
	host := transport.SplitHost(address)
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a.WithZone("").Unmap()}
	}
	if host == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, trapResolveTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, ip := range ips {
		if len(out) >= maxTrapAddrs {
			break
		}
		out = append(out, ip.WithZone("").Unmap())
	}
	return out
}

// syncTraps gleicht den Empfaenger mit der Konfiguration ab: ohne Host mit Traps ist der Port zu, sonst offen
// (neu bei geaendertem Port), mit den aktuellen Absendern.
func (m *Module) syncTraps(ctx context.Context) {
	t := m.traps
	t.syncMu.Lock()
	defer t.syncMu.Unlock()
	set, err := m.trapHosts(ctx)
	t.mu.Lock()
	t.synced, t.retry = t.now(), err != nil
	t.mu.Unlock()
	if err != nil {
		m.log.Warn("monitor64: traps: hosts", "err", err)
		return
	}
	hosts := set.hosts
	t.mu.Lock()
	stopped := t.stopped
	t.active, t.names, t.retry = len(hosts), set.names, set.failed > 0
	known := map[string]bool{}
	for _, h := range hosts {
		known[h.ID] = true
	}
	var gone []string
	for uid := range t.hosts { // Stand von Hosts ohne Traps (entfernt bzw. ausgeschaltet) vergessen
		if !known[uid] {
			delete(t.hosts, uid)
			delete(t.lastRun, uid)
			gone = append(gone, uid)
		}
	}
	for uid := range t.addrs {
		if !known[uid] {
			delete(t.addrs, uid)
		}
	}
	t.known = known
	t.mu.Unlock()
	m.forgetTraps(gone)
	if stopped || len(hosts) == 0 {
		t.closeReceiver()
		return
	}
	engine, err := m.trapEngineID(ctx)
	if err != nil {
		m.log.Warn("monitor64: traps: engine id", "err", err)
		t.setRetry()
		return
	}
	listen := ":" + strconv.Itoa(m.trapPort(ctx))
	t.mu.Lock()
	rcv := t.rcv
	if rcv != nil && (t.listen != listen || t.engine != engine) {
		t.mu.Unlock()
		t.closeReceiver()
		t.mu.Lock()
		rcv = nil
	}
	if rcv == nil {
		rcv, err = trap.New(trap.Config{Listen: listen, EngineID: engine}, t.onEvent)
		if err != nil {
			t.err, t.retry = err.Error(), true
			t.mu.Unlock()
			m.log.Warn("monitor64: traps: receiver", "err", err)
			return
		}
		t.rcv, t.listen, t.engine = rcv, listen, engine
	}
	t.mu.Unlock()
	if err := rcv.SetHosts(hosts); err != nil {
		m.log.Warn("monitor64: traps: hosts", "err", err)
		for i := range hosts { // v3-Benutzer fehlerhaft: wenigstens v1/v2c annehmen
			hosts[i].Users = nil
		}
		_ = rcv.SetHosts(hosts)
	}
	wasRunning := rcv.Running()
	err = rcv.Start()
	t.mu.Lock()
	t.err = ""
	if err != nil {
		t.err, t.retry = err.Error(), true // belegter Port: regelmaessig neu versuchen
	}
	t.mu.Unlock()
	switch {
	case err != nil:
		m.log.Warn("monitor64: traps: open port", "listen", listen, "err", err)
	case !wasRunning:
		m.log.Info("monitor64: traps: receiver started", "listen", listen, "hosts", len(hosts))
	}
}

func (t *trapMgr) setRetry() {
	t.mu.Lock()
	t.retry = true
	t.mu.Unlock()
}

// forgetTraps vergisst den gemerkten Trap-Stand im Laufzeitstand von Hosts, die keine Traps mehr nutzen (sonst kaeme
// er beim Wiedereinschalten samt Meldung zurueck). Wartet auf eine laufende Runde des Hosts.
func (m *Module) forgetTraps(uids []string) {
	for _, uid := range uids {
		m.rtMu.Lock()
		rt := m.rts[uid]
		m.rtMu.Unlock()
		if rt == nil {
			continue
		}
		rt.mu.Lock()
		if rt.Traps != nil {
			rt.Traps, rt.dirty = nil, true
		}
		rt.mu.Unlock()
	}
}

// closeReceiver schliesst den Port (der Stand der Hosts bleibt).
func (t *trapMgr) closeReceiver() {
	t.mu.Lock()
	rcv := t.rcv
	t.rcv, t.listen, t.engine = nil, "", ""
	t.mu.Unlock()
	if rcv != nil {
		rcv.Stop()
	}
}

// start erlaubt den Empfang (Modul gestartet).
func (t *trapMgr) start() {
	t.mu.Lock()
	t.stopped = false
	t.mu.Unlock()
}

// stop schliesst den Port und verwirft wartende Runden (Modul gestoppt).
func (t *trapMgr) stop() {
	t.syncMu.Lock()
	defer t.syncMu.Unlock()
	t.mu.Lock()
	t.stopped = true
	for k, tm := range t.timers {
		tm.Stop()
		delete(t.timers, k)
	}
	t.mu.Unlock()
	t.closeReceiver()
}

// trapStatus ist der Stand des Empfaengers (Einstellungen).
type trapStatus struct {
	Active   int             `json:"active"` // Hosts mit Traps
	Running  bool            `json:"running"`
	Port     int             `json:"port"`
	EngineID string          `json:"engine_id,omitempty"`
	Error    string          `json:"error,omitempty"`
	Stats    trap.Stats      `json:"stats"`
	Unknown  []unknownSender `json:"unknown"`
}

func (m *Module) trapStatus(ctx context.Context) trapStatus {
	s := trapStatus{Port: m.trapPort(ctx), EngineID: m.st.SettingOr(ctx, setTrapEngine, ""), Unknown: []unknownSender{}}
	if m.traps == nil {
		return s
	}
	t := m.traps
	t.mu.Lock()
	s.Active, s.Error = t.active, t.err
	if t.rcv != nil {
		s.Running, s.Stats = t.rcv.Running(), t.rcv.Stats()
	}
	for _, u := range t.unknown {
		s.Unknown = append(s.Unknown, *u)
	}
	t.mu.Unlock()
	sort.Slice(s.Unknown, func(i, j int) bool { return s.Unknown[i].Last.After(s.Unknown[j].Last) })
	return s
}

// apiTraps: GET Stand des Empfaengers mit der Liste unbekannter Absender.
func (m *Module) apiTraps(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, m.trapStatus(r.Context()))
}

// apiTrapsUnknownClear: DELETE Liste unbekannter Absender leeren.
func (m *Module) apiTrapsUnknownClear(w http.ResponseWriter, r *http.Request) {
	n := 0
	if m.traps != nil {
		m.traps.mu.Lock()
		n = len(m.traps.unknown)
		m.traps.unknown = map[string]*unknownSender{}
		m.traps.mu.Unlock()
	}
	m.audit(r, "traps.unknown_clear", "", fmt.Sprintf("entries=%d", n))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// hostTrapsOut ist der Trap-Stand eines Hosts fuer die Oberflaeche (neueste zuerst).
type hostTrapsOut struct {
	List         []trapEntry `json:"list"`
	Pending      int         `json:"pending"`
	Total        uint64      `json:"total"`
	Rejected     uint64      `json:"rejected"`
	RejectReason string      `json:"reject_reason,omitempty"`
	RejectedAt   time.Time   `json:"rejected_at,omitzero"`
}

// hostTrapsLocal ist der Trap-Stand eines Hosts auf dieser Node (neueste zuerst).
func (m *Module) hostTrapsLocal(uid string) hostTrapsOut {
	out := hostTrapsOut{List: []trapEntry{}}
	if m.traps != nil {
		if s := m.traps.snapshot(uid, true); s != nil {
			out.Pending, out.Total, out.Rejected, out.RejectReason, out.RejectedAt = s.Pending, s.Total, s.Rejected, s.RejectReason, s.RejectedAt
			for i := len(s.List) - 1; i >= 0; i-- {
				out.List = append(out.List, s.List[i])
			}
		}
	}
	return out
}

// apiHostTraps: GET letzte Traps eines Hosts (im Cluster mit dem Stand der zustaendigen Node).
func (m *Module) apiHostTraps(w http.ResponseWriter, r *http.Request) {
	h, err := m.store.Host(r.Context(), r.PathValue("uid"))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, m.hostTrapsView(r.Context(), h.UID))
}

// apiHostTrapsReset: POST offene Traps eines Hosts zuruecksetzen (wie Quittieren des Problems).
func (m *Module) apiHostTrapsReset(w http.ResponseWriter, r *http.Request) {
	h, err := m.store.Host(r.Context(), r.PathValue("uid"))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	m.resetTraps(r.Context(), h.UID)
	m.audit(r, "traps.reset", h.Name, "uid="+h.UID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// trapsAcked: Problem des Dienstes "traps" quittiert bzw. geloest -> offene Traps zuruecksetzen (hier und bei der
// zustaendigen Node, ohne auf sie zu warten).
func (m *Module) trapsAcked(hostUID, svcKey string) {
	if svcKey != trapSvcKey || m.traps == nil {
		return
	}
	if m.traps.reset(hostUID) {
		m.repoll(hostUID)
	}
	if owner, ok := m.trapOwner(hostUID); ok {
		go m.resetTrapsAt(context.Background(), owner, hostUID)
	}
}

// validTrapPort prueft den Port aus den Einstellungen.
func validTrapPort(p int) bool { return p >= 1 && p <= 65535 }
