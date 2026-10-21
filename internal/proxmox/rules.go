package proxmox

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

// Regeln: Engine vergleicht jeden Snapshot mit dem vorigen Stand je System und Key und liefert Ereignisse fuer die
// Benachrichtigung (Event.Kind down, up, threshold, threshold_ok, restarted). Die Engine haelt ihren Zustand im
// Speicher; gemeldete Stoerungen und Schwellen gibt Export heraus, damit die Einbindung sie speichern und nach einem
// Neustart von Node64 mit Import wiederherstellen kann (sonst kaemen sie doppelt bzw. ohne Entwarnung).

// Ereignisarten (Event.Kind).
const (
	KindDown        = "down"
	KindUp          = "up"
	KindThreshold   = "threshold"
	KindThresholdOK = "threshold_ok"
	KindRestarted   = "restarted"
)

// Ursachen (Event.What).
const (
	WhatCrashed     = "crashed"
	WhatStopped     = "stopped"
	WhatPaused      = "paused"
	WhatSuspended   = "suspended"
	WhatOffline     = "offline"
	WhatUnreachable = "unreachable"
	WhatCPU         = "cpu"
	WhatMem         = "mem"
	WhatDisk        = "disk"
)

// TagNoMonitor schliesst einen Gast aus (Proxmox-Tag).
const TagNoMonitor = "nomonitor"

type pveThrState struct {
	since        time.Time // seit wann ueber der Grenze (Null = nicht ueber)
	above, below int       // aufeinanderfolgende Abfragen ueber/unter der Grenze
	fired        bool      // gemeldet
}

type pveResState struct {
	bad       int       // aufeinanderfolgende Abfragen im Stoerungszustand
	down      bool      // Stoerung erkannt (Verzoegerung erreicht)
	notified  bool      // Stoerung gemeldet (dann folgt Entwarnung)
	what      string    // Ursache der Stoerung
	since     time.Time // erste Abfrage im Stoerungszustand
	ran       bool      // lief schon einmal (ExpectRunning automatisch)
	prevLock  bool      // vorige Abfrage mit Lock (Backup, Migration …)
	thr       [3]pveThrState
	thrLimits [3]float64
}

type pveSysState struct {
	bad      int
	down     bool
	notified bool
	since    time.Time
	res      map[string]*pveResState
}

// Engine wertet die Regeln aus (thread-sicher).
type Engine struct {
	mu  sync.Mutex
	sys map[int64]*pveSysState
}

// NewEngine erzeugt eine Engine ohne Vorwissen.
func NewEngine() *Engine { return &Engine{sys: map[int64]*pveSysState{}} }

// Forget verwirft den Stand eines Systems (geloescht oder abgeschaltet).
func (e *Engine) Forget(systemID int64) {
	e.mu.Lock()
	delete(e.sys, systemID)
	e.mu.Unlock()
}

func pveHasTag(r *Resource, tag string) bool {
	for _, t := range r.Tags {
		if strings.EqualFold(strings.TrimSpace(t), tag) {
			return true
		}
	}
	return false
}

// pveLabel liefert die Bezeichnung fuer Texte, z. B. VM 101 „web“.
func pveLabel(r *Resource) string {
	var s string
	switch r.Type {
	case TypeNode:
		return "Node „" + r.Node + "“"
	case TypeLXC:
		s = "Container " + itoa(r.VMID)
	default:
		s = "VM " + itoa(r.VMID)
	}
	if r.Name != "" {
		s += " „" + r.Name + "“"
	}
	return s
}

func pveDisplayName(r *Resource) string {
	if r.Name != "" {
		return r.Name
	}
	if r.Type == TypeNode {
		return r.Node
	}
	return r.Key()
}

func pvePct(v float64) string { return fmt.Sprintf("%.0f %%", v) }

var pveMetricLabel = [3]string{"CPU", "RAM", "Disk"}
var pveMetricWhat = [3]string{WhatCPU, WhatMem, WhatDisk}

// pveMeasurable: Werte sind aussagekraeftig (Node online, Gast laeuft – auch mit Lock).
func pveMeasurable(r *Resource) bool {
	if r.Type == TypeNode {
		return r.State == StateOnline
	}
	switch r.State {
	case StateRunning:
		return true
	case StateBackup, StateLocked:
		return r.Status == "running"
	}
	return false
}

// pveMetrics liefert CPU, RAM, Disk in Prozent; ok = Wert vorhanden.
func pveMetrics(r *Resource) (v [3]float64, ok [3]bool) {
	v[0], ok[0] = r.CPU*100, !math.IsNaN(r.CPU)
	if r.MaxMem > 0 {
		v[1], ok[1] = float64(r.Mem)*100/float64(r.MaxMem), true
	}
	if r.MaxDisk > 0 && (r.Disk > 0 || r.Type != TypeQEMU) {
		v[2], ok[2] = float64(r.Disk)*100/float64(r.MaxDisk), true
	}
	return
}

// Evaluate wertet einen Snapshot aus. set sind die Einstellungen des Systems (nil = Standardregeln).
//
//   - System nicht erreichbar (snap.OK = false) nach Verzoegerung → down/unreachable, wieder erreichbar → up.
//   - Node offline → down/offline; seine Gaeste melden nichts einzeln (Zustand unbekannt, Stand bleibt erhalten).
//   - Gast abgestuerzt (StateError) → down/crashed sofort; angehalten/suspendiert/gestoppt nach Verzoegerung.
//     Gestoppt nur, wenn erwartet (ExpectRunning bzw. automatisch: lief schon einmal); eine Abfrage direkt nach
//     einem Lock zaehlt nicht (Backup im Stopp-Modus, Migration). Lock ohne Stopp ist kein Ausfall.
//   - Neustart (Resource.Restarted) → restarted.
//   - Schwellen CPU/RAM/Disk: mindestens Delay Abfragen und Minutes Minuten ueber der Grenze → threshold,
//     Delay Abfragen darunter → threshold_ok.
//   - Template, Tag nomonitor, Muted (Ressource oder System) → nichts; AsCheck → keine Zustandsereignisse (down/up kommen ueber den Check), Neustart und Schwellen weiter
//     (down/up/restarted kommen dann ueber den Check), Schwellen weiter.
func (e *Engine) Evaluate(snap *Snapshot, set *SystemSettings) []Event {
	if snap == nil {
		return nil
	}
	now := snap.Time
	if now.IsZero() {
		now = time.Now()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if it := set.Item(""); it != nil && it.Muted {
		delete(e.sys, snap.SystemID)
		return nil
	}
	st := e.sys[snap.SystemID]
	if st == nil {
		st = &pveSysState{res: map[string]*pveResState{}}
		e.sys[snap.SystemID] = st
	}
	sysName := ""
	if set != nil {
		sysName = set.Name
	}
	if sysName == "" {
		sysName = "#" + itoa(int(snap.SystemID))
	}
	sysRule := set.Effective("", "")
	var evs []Event
	add := func(ev Event) {
		ev.SystemID = snap.SystemID
		evs = append(evs, ev)
	}

	// System erreichbar?
	if !snap.OK {
		st.bad++
		if st.bad == 1 {
			st.since = now
		}
		if !st.down && st.bad >= max(sysRule.Delay, 1) {
			st.down = true
			if sysRule.Unreachable {
				st.notified = true
				txt := "Proxmox „" + sysName + "“ nicht erreichbar"
				if snap.Error != "" {
					txt += ": " + snap.Error
				}
				add(Event{Name: sysName, Kind: KindDown, What: WhatUnreachable, Since: st.since, Text: txt})
			}
		}
		return evs // ohne Daten bleibt der Stand der Ressourcen unveraendert
	}
	if st.notified {
		add(Event{Name: sysName, Kind: KindUp, What: WhatUnreachable, Since: st.since, Text: "Proxmox „" + sysName + "“ wieder erreichbar"})
	}
	st.bad, st.down, st.notified = 0, false, false

	offline := map[string]bool{}
	for i := range snap.Resources {
		if r := &snap.Resources[i]; r.Type == TypeNode && r.State != StateOnline {
			offline[r.Node] = true
		}
	}
	present := map[string]bool{}
	for i := range snap.Resources {
		r := &snap.Resources[i]
		if r.Template || pveHasTag(r, TagNoMonitor) {
			continue
		}
		key := r.Key()
		it := set.Item(key)
		if it != nil && it.Muted {
			continue
		}
		present[key] = true
		guest := r.Type != TypeNode
		if guest && (offline[r.Node] || r.State == StateUnknown) {
			continue // Node offline bzw. keine Daten: nur der Node meldet, Stand des Gasts bleibt
		}
		rs := st.res[key]
		if rs == nil {
			rs = &pveResState{}
			st.res[key] = rs
		}
		rule := set.Effective(key, r.Node)
		asCheck := it != nil && it.AsCheck
		lbl := pveLabel(r)
		name := pveDisplayName(r)

		// Zustand: bad = Stoerung, good = in Ordnung, sonst neutral (zaehlt nicht, keine Entwarnung)
		what, bad, good := "", false, false
		delay := max(rule.Delay, 1)
		if !guest {
			switch r.State {
			case StateOnline:
				good = true
			default:
				what, bad = WhatOffline, rule.Offline
			}
		} else {
			switch r.State {
			case StateRunning:
				good = true
			case StateError:
				what, bad, delay = WhatCrashed, rule.Crashed, 1
			case StatePaused:
				what, bad = WhatPaused, rule.Paused
			case StateSuspended:
				what, bad = WhatSuspended, rule.Suspended
			case StateBackup, StateLocked:
				good = r.Status == "running"
			case StateStopped:
				expect := rs.ran || (it != nil && it.SeenRunning)
				if it != nil && it.ExpectRunning != nil {
					expect = *it.ExpectRunning
				}
				what, bad = WhatStopped, rule.Stopped && expect && !rs.prevLock
			}
		}
		upSent := false
		switch {
		case bad:
			rs.bad++
			if rs.bad == 1 {
				rs.since = now
			}
			if !rs.down && rs.bad >= delay {
				rs.down, rs.what = true, what
				if !asCheck {
					rs.notified = true
					ev := Event{Key: key, Name: name, Kind: KindDown, What: what, Since: rs.since, Text: pveDownText(r, lbl, what)}
					if what == WhatCrashed {
						ev.Detail = r.QMP // qmpstatus fuer den Text (internal-error, guest-panicked, io-error)
					}
					add(ev)
				}
			}
		case good:
			if rs.notified {
				txt := lbl + " läuft wieder"
				if !guest {
					txt = lbl + " ist wieder online"
				}
				add(Event{Key: key, Name: name, Kind: KindUp, What: rs.what, Since: rs.since, Text: txt})
				upSent = true
			}
			rs.bad, rs.down, rs.notified, rs.what = 0, false, false, ""
		default:
			if !rs.down {
				rs.bad = 0
			}
		}
		if guest && pveGuestRan(r) {
			rs.ran = true
		}
		rs.prevLock = guest && r.Lock != "" && r.State != StateSuspended
		if r.Restarted && rule.Restarted && !upSent { // auch als Check: der Check selbst meldet keinen Neustart
			add(Event{Key: key, Name: name, Kind: KindRestarted, Since: now.Add(-time.Duration(r.Uptime) * time.Second),
				Text: lbl + " wurde neu gestartet"})
		}

		// Schwellen
		vals, ok := pveMetrics(r)
		meas := pveMeasurable(r)
		lim := [3]Threshold{rule.CPU, rule.Mem, rule.Disk}
		for m := 0; m < 3; m++ {
			ts := &rs.thr[m]
			th := lim[m]
			if th.Percent <= 0 || (meas && !ok[m]) || (ts.fired && rs.thrLimits[m] != th.Percent) {
				*ts = pveThrState{} // aus bzw. Grenze geaendert: ohne Meldung zuruecksetzen
				continue
			}
			if !meas {
				ts.above, ts.since = 0, time.Time{} // gestoppt usw.: Dauer beginnt neu, Meldung bleibt offen
				continue
			}
			v := vals[m]
			if v >= th.Percent {
				ts.below = 0
				ts.above++
				if ts.since.IsZero() {
					ts.since = now
				}
				if !ts.fired && ts.above >= max(rule.Delay, 1) && now.Sub(ts.since) >= time.Duration(th.Minutes)*time.Minute {
					ts.fired = true
					rs.thrLimits[m] = th.Percent
					txt := fmt.Sprintf("%s: %s %s (Grenze %s", lbl, pveMetricLabel[m], pvePct(v), pvePct(th.Percent))
					if th.Minutes > 0 {
						txt += fmt.Sprintf(", seit %d min", int(now.Sub(ts.since).Minutes()))
					}
					add(Event{Key: key, Name: name, Kind: KindThreshold, What: pveMetricWhat[m], Value: pveRound1(v), Limit: th.Percent,
						Since: ts.since, Text: txt + ")"})
				}
				continue
			}
			if !ts.fired {
				*ts = pveThrState{}
				continue
			}
			ts.below++
			if ts.below >= max(rule.Delay, 1) {
				add(Event{Key: key, Name: name, Kind: KindThresholdOK, What: pveMetricWhat[m], Value: pveRound1(v), Limit: th.Percent,
					Since: ts.since, Text: fmt.Sprintf("%s: %s wieder unter %s (%s)", lbl, pveMetricLabel[m], pvePct(th.Percent), pvePct(v))})
				*ts = pveThrState{}
			}
		}
	}
	for k := range st.res {
		if !present[k] {
			delete(st.res, k) // geloescht, ausgeschlossen oder stumm: Stand verwerfen
		}
	}
	return evs
}

func pveRound1(v float64) float64 { return math.Round(v*10) / 10 }

func pveDownText(r *Resource, lbl, what string) string {
	switch what {
	case WhatCrashed:
		if r.QMP != "" {
			return lbl + " ist abgestürzt (" + r.QMP + ")"
		}
		return lbl + " ist abgestürzt"
	case WhatStopped:
		return lbl + " ist gestoppt"
	case WhatPaused:
		return lbl + " ist angehalten"
	case WhatSuspended:
		return lbl + " ist suspendiert"
	case WhatOffline:
		return lbl + " ist offline"
	}
	return lbl + ": " + what
}

// EngineState ist der gesicherte Stand eines Systems: nur gemeldete Stoerungen und Schwellen (alles andere beginnt
// nach einem Neustart neu zu zaehlen). Die Einbindung speichert ihn und stellt ihn beim Start mit Import wieder her.
type EngineState struct {
	Down  bool                      `json:"down,omitempty"` // „nicht erreichbar“ gemeldet
	Since time.Time                 `json:"since,omitempty"`
	Res   map[string]EngineResState `json:"res,omitempty"` // Key → gemeldeter Stand
}

// EngineResState ist der gemeldete Stand eines Nodes oder Gasts.
type EngineResState struct {
	What  string               `json:"what,omitempty"` // gemeldete Stoerung ('' = keine)
	Since time.Time            `json:"since,omitempty"`
	Thr   map[string]EngineThr `json:"thr,omitempty"` // cpu, mem, disk: gemeldete Schwellen
}

// EngineThr ist eine gemeldete Schwelle.
type EngineThr struct {
	Limit float64   `json:"limit"`
	Since time.Time `json:"since"`
}

// Export liefert die gemeldeten Stoerungen eines Systems (nil = nichts offen).
func (e *Engine) Export(systemID int64) *EngineState {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.sys[systemID]
	if st == nil {
		return nil
	}
	out := &EngineState{}
	if st.notified {
		out.Down, out.Since = true, st.since
	}
	for k, rs := range st.res {
		var x EngineResState
		if rs.notified {
			x.What, x.Since = rs.what, rs.since
		}
		for m := 0; m < 3; m++ {
			if rs.thr[m].fired {
				if x.Thr == nil {
					x.Thr = map[string]EngineThr{}
				}
				x.Thr[pveMetricWhat[m]] = EngineThr{Limit: rs.thrLimits[m], Since: rs.thr[m].since}
			}
		}
		if x.What != "" || x.Thr != nil {
			if out.Res == nil {
				out.Res = map[string]EngineResState{}
			}
			out.Res[k] = x
		}
	}
	if !out.Down && out.Res == nil {
		return nil
	}
	return out
}

// Import stellt den gesicherten Stand eines Systems wieder her (nach einem Neustart, vor der ersten Auswertung):
// die Stoerungen gelten als schon gemeldet, die naechste Auswertung meldet nur noch die Entwarnung.
func (e *Engine) Import(systemID int64, s *EngineState) {
	if s == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	st := &pveSysState{res: map[string]*pveResState{}}
	if s.Down {
		st.bad, st.down, st.notified, st.since = 1, true, true, s.Since
	}
	for k, x := range s.Res {
		rs := &pveResState{ran: true}
		if x.What != "" {
			rs.bad, rs.down, rs.notified, rs.what, rs.since = 1, true, true, x.What, x.Since
		}
		for m := 0; m < 3; m++ {
			if t, ok := x.Thr[pveMetricWhat[m]]; ok && t.Limit > 0 {
				rs.thr[m] = pveThrState{since: t.Since, above: 1, fired: true}
				rs.thrLimits[m] = t.Limit
			}
		}
		st.res[k] = rs
	}
	e.sys[systemID] = st
}
