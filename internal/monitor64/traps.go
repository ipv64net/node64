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
// Engine-ID passt nicht) werden nur gezaehlt, unbekannte Absender in einer begrenzten Liste gemerkt – nie
// automatisch angelegt. Alles aus Traps ist nicht vertrauenswuerdig (bereinigt vom Empfaenger, escaped in der
// Oberflaeche).

const (
	setTrapPort        = "monitor64.trap_port"      // UDP-Port des Empfaengers (Standard 162)
	setTrapEngine      = "monitor64.trap_engine_id" // lokale Engine-ID (hex, einmal erzeugt) fuer v3-Informs
	defaultTrapPort    = 162
	trapKeep           = 20               // letzte Traps je Host
	trapKeepSaved      = 10               // davon im Laufzeitstand gespeichert (ohne Varbinds)
	trapDebounce       = 10 * time.Second // hoechstens eine sofortige Runde je Host
	maxUnknownSenders  = 100
	trapResolveTimeout = 3 * time.Second
	maxTrapAddrs       = 16
	factTrapReceived   = "trap_received"
	trapSvcKey         = "traps"
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
	unknown map[string]*unknownSender
	lastRun map[string]time.Time
	timers  map[string]*time.Timer

	now   func() time.Time
	after func(time.Duration, func()) *time.Timer
	run   func(hostUID string) // sofortige Runde (Planer)
	kick  chan struct{}
}

func newTrapMgr(run func(string)) *trapMgr {
	return &trapMgr{hosts: map[string]*hostTraps{}, unknown: map[string]*unknownSender{}, lastRun: map[string]time.Time{},
		timers: map[string]*time.Timer{}, now: time.Now, after: time.AfterFunc, run: run, kick: make(chan struct{}, 1), stopped: true}
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

// onEvent ist der Rueckruf des Empfaengers (eigene Goroutine, Events nacheinander).
func (t *trapMgr) onEvent(ev trap.Event) {
	now := t.now()
	t.mu.Lock()
	switch {
	case !ev.Known || ev.HostID == "":
		t.addUnknown(ev, now)
		t.mu.Unlock()
		return
	case ev.Rejected != "":
		h := t.host(ev.HostID)
		h.Rejected++
		h.RejectReason, h.RejectedAt = ev.Rejected, now
		t.mu.Unlock()
		return
	}
	h := t.host(ev.HostID)
	e := trapEntry{Time: now, Version: ev.Version, Inform: ev.Inform, User: ev.User, TrapOID: ev.TrapOID, TrapName: ev.TrapName, Kind: ev.Kind,
		Handled: trapRunKinds[ev.Kind], Varbinds: ev.Varbinds, Truncated: ev.Truncated}
	h.List = append(h.List, e)
	if len(h.List) > trapKeep {
		h.List = append([]trapEntry(nil), h.List[len(h.List)-trapKeep:]...)
	}
	h.Total++
	if !e.Handled {
		h.Pending++
	}
	runNow := t.debounce(ev.HostID, now)
	t.mu.Unlock()
	if runNow && t.run != nil {
		t.run(ev.HostID)
	}
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

// trapLoop gleicht den Empfaenger nach jedem Anstoss ab (laeuft solange das Modul laeuft).
func (m *Module) trapLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.traps.kick:
			m.syncTraps(ctx)
		}
	}
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

// trapHosts liest die Hosts mit SNMP-Zugang und Traps (Adressen aufgeloest, Geheimnisse entschluesselt).
func (m *Module) trapHosts(ctx context.Context) ([]trap.Host, error) {
	hosts, err := m.store.Hosts(ctx)
	if err != nil {
		return nil, err
	}
	accs, err := m.store.Accesses(ctx, "")
	if err != nil {
		return nil, err
	}
	byHost := map[string][]*Access{}
	for _, a := range accs {
		if a.Type == "snmp" && a.Enabled {
			byHost[a.HostUID] = append(byHost[a.HostUID], a)
		}
	}
	var out []trap.Host
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
			if sec.Community != "" {
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
		th.Addrs = resolveAddrs(ctx, h.Address)
		if len(th.Addrs) == 0 {
			m.log.Warn("monitor64: traps: address not resolvable", "host", h.Name)
			continue
		}
		out = append(out, th)
	}
	return out, nil
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
	hosts, err := m.trapHosts(ctx)
	if err != nil {
		m.log.Warn("monitor64: traps: hosts", "err", err)
		return
	}
	t.mu.Lock()
	stopped := t.stopped
	t.active = len(hosts)
	known := map[string]bool{}
	for _, h := range hosts {
		known[h.ID] = true
	}
	for uid := range t.hosts { // Stand entfernter Hosts vergessen
		if !known[uid] {
			delete(t.hosts, uid)
			delete(t.lastRun, uid)
		}
	}
	t.mu.Unlock()
	if stopped || len(hosts) == 0 {
		t.closeReceiver()
		return
	}
	engine, err := m.trapEngineID(ctx)
	if err != nil {
		m.log.Warn("monitor64: traps: engine id", "err", err)
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
			t.err = err.Error()
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
		t.err = err.Error()
	}
	t.mu.Unlock()
	switch {
	case err != nil:
		m.log.Warn("monitor64: traps: open port", "listen", listen, "err", err)
	case !wasRunning:
		m.log.Info("monitor64: traps: receiver started", "listen", listen, "hosts", len(hosts))
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

// apiHostTraps: GET letzte Traps eines Hosts.
func (m *Module) apiHostTraps(w http.ResponseWriter, r *http.Request) {
	h, err := m.store.Host(r.Context(), r.PathValue("uid"))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	out := hostTrapsOut{List: []trapEntry{}}
	if m.traps != nil {
		if s := m.traps.snapshot(h.UID, true); s != nil {
			out.Pending, out.Total, out.Rejected, out.RejectReason, out.RejectedAt = s.Pending, s.Total, s.Rejected, s.RejectReason, s.RejectedAt
			for i := len(s.List) - 1; i >= 0; i-- {
				out.List = append(out.List, s.List[i])
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// apiHostTrapsReset: POST offene Traps eines Hosts zuruecksetzen (wie Quittieren des Problems).
func (m *Module) apiHostTrapsReset(w http.ResponseWriter, r *http.Request) {
	h, err := m.store.Host(r.Context(), r.PathValue("uid"))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	if m.traps != nil && m.traps.reset(h.UID) {
		m.repoll(h.UID)
	}
	m.audit(r, "traps.reset", h.Name, "uid="+h.UID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// trapsAcked: Problem des Dienstes "traps" quittiert bzw. geloest -> offene Traps zuruecksetzen.
func (m *Module) trapsAcked(hostUID, svcKey string) {
	if svcKey != trapSvcKey || m.traps == nil {
		return
	}
	if m.traps.reset(hostUID) {
		m.repoll(hostUID)
	}
}

// validTrapPort prueft den Port aus den Einstellungen.
func validTrapPort(p int) bool { return p >= 1 && p <= 65535 }
