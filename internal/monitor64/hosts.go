package monitor64

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/eval"
)

// Laufzeit der Hosts: Schluessel der Node, Sammler je Zugang, Auftraege im Planer, Laufzeitstand speichern.

const (
	setNodeKey   = "monitor64.node_key" // privater Schluessel der Node (verschluesselt, OpenSSH-PEM)
	saveEvery    = 5 * time.Minute      // Laufzeitstand je Host hoechstens so oft speichern (ausser bei Zustandswechsel)
	smartEvery   = 30 * time.Minute     // SSH ohne Agent: SMART lesen
	updatesEvery = time.Hour            // SSH ohne Agent: Paket-Updates pruefen
)

// startHosts laedt alle Hosts und plant ihre Abfragen ein.
func (m *Module) startHosts(ctx context.Context) error {
	hosts, err := m.store.Hosts(ctx)
	if err != nil {
		return err
	}
	for _, h := range hosts {
		m.scheduleHost(ctx, h, nil)
	}
	return nil
}

// ReloadHost plant einen Host nach einer Aenderung neu ein (bzw. entfernt ihn). Der Laufzeitstand im Speicher
// (Tracker, Gedaechtnis der Meldungen) bleibt erhalten, damit eine Aenderung nichts doppelt meldet.
func (m *Module) ReloadHost(ctx context.Context, uid string) {
	h, err := m.store.Host(ctx, uid)
	if errors.Is(err, ErrNotFound) {
		m.removeHost(uid)
		m.notifyMu.Lock()
		if m.notifier != nil {
			m.notifier.Forget(uid)
		}
		m.notifyMu.Unlock()
		return
	}
	if err != nil {
		m.log.Warn("monitor64: reload host", "host", uid, "err", err)
		return
	}
	old := m.removeHost(uid)
	m.scheduleHost(ctx, h, old)
}

// removeHost nimmt einen Host aus dem Planer; liefert den bisherigen Laufzeitstand (zum Weiterverwenden).
func (m *Module) removeHost(uid string) *hostRT {
	if s := m.scheduler(); s != nil {
		s.Remove("host:" + uid)
	}
	m.rtMu.Lock()
	rt := m.rts[uid]
	delete(m.rts, uid)
	m.rtMu.Unlock()
	if rt == nil {
		return nil
	}
	rt.mu.Lock() // wartet auf eine laufende Runde (die Zugaenge haben Zeitlimits)
	rt.removed = true
	for _, a := range rt.accs {
		if a.col != nil {
			a.col.close()
		}
	}
	rt.accs = nil
	rt.mu.Unlock()
	return rt
}

func (m *Module) scheduleHost(ctx context.Context, h *Host, old *hostRT) {
	sched := m.scheduler()
	if sched == nil {
		return
	}
	rt := &hostRT{host: h}
	if old != nil { // Stand im Speicher weiterverwenden (aktueller als m64_runtime)
		old.mu.Lock()
		rt.Trackers, rt.Kinds, rt.Failures, rt.Missing, rt.Provider = old.Trackers, old.Kinds, old.Failures, old.Missing, old.Provider
		rt.Rising, rt.Local, rt.Trend = old.Rising, old.Local, old.Trend
		old.mu.Unlock()
		rt.view = old.getView()
		rt.dirty = true
	} else if raw, _ := m.store.Runtime(ctx, h.UID); len(raw) > 0 {
		var saved struct {
			RT  json.RawMessage  `json:"rt"`
			Mem *eval.HostMemory `json:"mem"`
		}
		if json.Unmarshal(raw, &saved) == nil {
			_ = json.Unmarshal(saved.RT, rt)
			m.notifyMu.Lock()
			if m.notifier != nil && saved.Mem != nil {
				if _, inMem := m.notifier.Hosts[h.UID]; !inMem { // Gedaechtnis im Speicher geht vor
					m.notifier.Hosts[h.UID] = saved.Mem
				}
			}
			m.notifyMu.Unlock()
		}
	}
	rt.initMaps()
	rt.LastDisc = time.Time{} // nach dem (Neu-)Laden sofort erkennen (z. B. neuer Zugang)
	accs, err := m.store.Accesses(ctx, h.UID)
	if err != nil {
		m.log.Warn("monitor64: accesses", "host", h.Name, "err", err)
	}
	for _, a := range accs {
		if !a.Enabled {
			continue
		}
		col, err := m.newCollector(ctx, h, a)
		ar := &accRT{row: a, col: col}
		if err != nil {
			ar.err = err.Error()
		}
		rt.accs = append(rt.accs, ar)
	}
	m.rtMu.Lock()
	if m.rts == nil {
		m.rts = map[string]*hostRT{}
	}
	m.rts[h.UID] = rt
	m.rtMu.Unlock()
	sched.Set("host:"+h.UID, time.Duration(h.IntervalSec)*time.Second, func(ctx context.Context) { m.poll(ctx, rt) })
}

// saveRuntime speichert den Laufzeitstand eines Hosts (Tracker, Fehlerzaehler, Gedaechtnis der Meldungen).
func (m *Module) saveRuntime(ctx context.Context, rt *hostRT, mem []byte) {
	v := rt.getView()
	changed := v != nil && (rt.lastSavedState != v.State || rt.lastSavedView != v.View)
	if !rt.dirty && !changed && time.Since(rt.lastSave) < saveEvery {
		return
	}
	rtJSON, _ := json.Marshal(rt)
	b, _ := json.Marshal(map[string]json.RawMessage{"rt": rtJSON, "mem": mem})
	if err := m.store.SaveRuntime(ctx, rt.host.UID, b); err != nil {
		m.log.Warn("monitor64: save runtime", "host", rt.host.Name, "err", err)
		return
	}
	rt.dirty, rt.lastSave = false, time.Now()
	if v != nil {
		rt.lastSavedState, rt.lastSavedView = v.State, v.View
	}
}

// Views liefert den aktuellen Stand aller Hosts (fuer die Oberflaeche).
func (m *Module) Views() []*HostView {
	m.rtMu.Lock()
	rts := make([]*hostRT, 0, len(m.rts))
	for _, rt := range m.rts {
		rts = append(rts, rt)
	}
	m.rtMu.Unlock()
	out := make([]*HostView, 0, len(rts))
	for _, rt := range rts {
		v := rt.getView()
		if v == nil {
			v = &HostView{Host: rt.host, View: eval.ViewUnknown, State: eval.Unknown}
		}
		out = append(out, v)
	}
	return out
}

// repollAll stoesst alle Hosts sofort an (z. B. nach einer Aenderung an Schwellen, Benachrichtigung oder Wartung:
// "Neubewertung sofort").
func (m *Module) repollAll() {
	s := m.scheduler()
	if s == nil {
		return
	}
	for _, k := range s.Keys() {
		s.RunNow(k)
	}
}
