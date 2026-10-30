package proxmox

import (
	"fmt"
	"math"
	"strconv"
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
	// Docker-Container (gleiche Werte wie Resource.Detail; Regel „Absturz“, ohne Verzoegerung)
	WhatUnhealthy  = DockerUnhealthy
	WhatRestarting = DockerRestarting
	WhatExited     = DockerExited
	WhatOOM        = DockerOOM
	WhatDead       = DockerDead
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

// pveLabel liefert die Bezeichnung fuer Texte, z. B. VM 101 „web“.
func pveLabel(r *Resource) string {
	var s string
	switch r.Type {
	case TypeNode:
		return "Node „" + r.Node + "“"
	case TypeLXC:
		s = "Container " + strconv.Itoa(r.VMID)
	case TypeDocker:
		return "Docker-Container „" + r.Name + "“"
	default:
		s = "VM " + strconv.Itoa(r.VMID)
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

// pveMetrics liefert CPU, RAM, Disk in Prozent; ok = Wert vorhanden.
func pveMetrics(r *Resource) (v [3]float64, ok [3]bool) {
	v[0], ok[0] = r.CPU*100, !math.IsNaN(r.CPU)
	v[1], ok[1] = r.MemPercent()
	v[2], ok[2] = r.DiskPercent()
	return
}

// Evaluate wertet einen Snapshot aus. set sind die Einstellungen des Systems (nil = Standardregeln).
//
//   - System nicht erreichbar (snap.OK = false) nach Verzoegerung → down/unreachable, wieder erreichbar → up.
//   - Node offline → down/offline; seine Gaeste melden nichts einzeln (Zustand unbekannt, Stand bleibt erhalten).
//   - Gast abgestuerzt (StateError) → down/crashed sofort; angehalten/suspendiert/gestoppt nach Verzoegerung.
//     Gestoppt nur, wenn erwartet (ExpectRunning bzw. automatisch: lief schon einmal, ohne Lock); eine Abfrage direkt
//     nach einem Lock zaehlt nicht (Backup im Stopp-Modus, Migration). Lock ohne Stopp ist kein Ausfall. Wird
//     ExpectRunning auf aus gesetzt („gestoppt ist richtig“), erledigt sich eine offene Stoerung still (ohne Entwarnung).
//   - Neustart (Resource.Restarted) → restarted.
//   - Schwellen CPU/RAM/Disk: mindestens Delay Abfragen und Minutes Minuten ueber der Grenze → threshold,
//     Delay Abfragen darunter → threshold_ok.
//   - Template, Tag nomonitor, Muted (Ressource oder System) → nichts; AsCheck → keine Zustandsereignisse (down/up
//     kommen ueber den Check), Neustart und Schwellen weiter. Eine Stoerung, die waehrend AsCheck bzw. bei
//     abgeschalteter Regel „nicht erreichbar“ erkannt wurde, wird gemeldet, sobald AsCheck aus bzw. die Regel an ist.
//   - Verzoegerung „nicht erreichbar“: Delay Abfragen und mindestens (Delay-1) × snap.Interval seit der ersten
//     fehlgeschlagenen (schnelle Wiederholungen nach Fehlern verkuerzen sie nicht).
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
		sysName = "#" + strconv.FormatInt(snap.SystemID, 10)
	}
	sysRule := set.Effective("", "")
	sysWord := "Proxmox"
	if set != nil && set.Kind == KindDocker {
		sysWord = "Docker"
	} else if set != nil && set.Kind == KindPBS {
		sysWord = "Proxmox Backup Server"
	}
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
		delay := max(sysRule.Delay, 1)
		if !st.down && st.bad >= delay && now.Sub(st.since) >= time.Duration(delay-1)*snap.Interval {
			st.down = true
		}
		if st.down && !st.notified && sysRule.Unreachable { // auch nachtraeglich, wenn die Regel wieder an ist
			st.notified = true
			txt := sysWord + " „" + sysName + "“ nicht erreichbar"
			if snap.Error != "" {
				txt += ": " + snap.Error
			}
			add(Event{Name: sysName, Kind: KindDown, What: WhatUnreachable, Since: st.since, Text: txt})
		}
		return evs // ohne Daten bleibt der Stand der Ressourcen unveraendert
	}
	if st.notified {
		add(Event{Name: sysName, Kind: KindUp, What: WhatUnreachable, Since: st.since, Text: sysWord + " „" + sysName + "“ wieder erreichbar"})
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
		if r.Excluded() {
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
		quiet := false // gestoppt bzw. beendet und soll fest nicht laufen: offene Stoerung still erledigen
		delay := max(rule.Delay, 1)
		if !guest {
			switch r.State {
			case StateOnline:
				good = true
			default:
				what, bad = WhatOffline, rule.Offline
			}
		} else {
			expect := rs.ran || (it != nil && it.SeenRunning)
			if it != nil && it.ExpectRunning != nil {
				expect = *it.ExpectRunning
				quiet = !expect && (r.State == StateStopped || r.Type == TypeDocker && r.DockerDown())
			}
			switch r.State {
			case StateRunning:
				good = true
			case StateError:
				what, bad, delay = WhatCrashed, rule.Crashed, 1
				if r.Type == TypeDocker {
					what = r.Detail
					if what == "" {
						what = WhatCrashed
					}
					if r.DockerDown() { // beendet bzw. tot: nur eine Stoerung, wenn der Container laufen soll
						bad = bad && expect
					}
				}
			case StatePaused:
				what, bad = WhatPaused, rule.Paused
			case StateSuspended:
				what, bad = WhatSuspended, rule.Suspended
			case StateBackup, StateLocked:
				good = r.Status == "running"
			case StateStopped:
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
			if !rs.down {
				rs.what = what
				rs.down = rs.bad >= delay
			}
			// auch nachtraeglich: waehrend AsCheck erkannt, Check inzwischen entfernt
			if rs.down && !rs.notified && !asCheck {
				rs.notified = true
				ev := Event{Key: key, Name: name, Kind: KindDown, What: rs.what, Since: rs.since, Text: pveDownText(r, lbl, rs.what)}
				if rs.what == WhatCrashed {
					ev.Detail = r.QMP // qmpstatus fuer den Text (internal-error, guest-panicked, io-error)
				}
				if r.Type == TypeDocker {
					ev.Detail = dockerEventDetail(r, rs.what)
				}
				add(ev)
			}
		case good:
			if rs.notified && !asCheck { // als Check: die Entwarnung kommt ueber den Check (sonst doppelt)
				txt := lbl + " läuft wieder"
				if !guest {
					txt = lbl + " ist wieder online"
				}
				add(Event{Key: key, Name: name, Kind: KindUp, What: rs.what, Since: rs.since, Text: txt})
				upSent = true
			}
			rs.bad, rs.down, rs.notified, rs.what = 0, false, false, ""
		default:
			if quiet { // „gestoppt ist richtig“ (ExpectRunning aus): ohne Entwarnung, es war keine Stoerung
				rs.bad, rs.down, rs.notified, rs.what = 0, false, false, ""
			} else if !rs.down {
				rs.bad = 0
			}
		}
		if guest && pveGuestRan(r) {
			rs.ran = true
		}
		rs.prevLock = guest && (r.State == StateBackup || r.State == StateLocked)
		if r.Restarted && rule.Restarted && !upSent { // auch als Check: der Check selbst meldet keinen Neustart
			add(Event{Key: key, Name: name, Kind: KindRestarted, Since: now.Add(-time.Duration(r.Uptime) * time.Second),
				Text: lbl + " wurde neu gestartet"})
		}

		// Schwellen
		vals, ok := pveMetrics(r)
		meas := r.Measurable()
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

// Outage liefert, ob fuer key eine Stoerung gemeldet ist (seit wann) – beim Einschalten von AsCheck uebernimmt der
// neue Check sie, statt sie noch einmal zu melden.
func (e *Engine) Outage(systemID int64, key string) (time.Time, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if st := e.sys[systemID]; st != nil {
		if rs := st.res[key]; rs != nil && rs.notified {
			return rs.since, true
		}
	}
	return time.Time{}, false
}

// Adopt uebernimmt eine Stoerung, die der Check gemeldet hat (AsCheck wird ausgeschaltet, Check war gestoert): sie
// gilt als gemeldet, die Engine meldet nur noch die Entwarnung. Ohne erkannte Stoerung aendert sich nichts.
func (e *Engine) Adopt(systemID int64, key string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if st := e.sys[systemID]; st != nil {
		if rs := st.res[key]; rs != nil && rs.bad > 0 {
			rs.down, rs.notified = true, true
		}
	}
}

func pveRound1(v float64) float64 { return math.Round(v*10) / 10 }

// dockerEventDetail: Zusatz fuer den Text ({detail}): Exit-Code bzw. Zahl der Neustarts.
func dockerEventDetail(r *Resource, what string) string {
	switch what {
	case WhatExited, WhatOOM:
		return strconv.Itoa(r.ExitCode)
	case WhatRestarting:
		return strconv.Itoa(r.Restarts)
	}
	return ""
}

func pveDownText(r *Resource, lbl, what string) string {
	switch what {
	case WhatUnhealthy:
		return lbl + " ist unhealthy"
	case WhatRestarting:
		return lbl + " startet ständig neu"
	case WhatExited:
		return lbl + " ist beendet (Exit-Code " + strconv.Itoa(r.ExitCode) + ")"
	case WhatOOM:
		return lbl + " wurde wegen Speichermangel beendet"
	case WhatDead:
		return lbl + " ist tot (dead)"
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
