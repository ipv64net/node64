package monitor64

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ipv64net/node64/internal/monitor64/snmp/trap"
)

// Traps im Cluster (Plan "SNMP – Traps", docs/CLUSTER.md): ein Trap kommt bei der Node an, an die der Host ihn
// schickt – zustaendig ist aber womoeglich eine andere. Angenommene Traps eines Hosts, den eine andere, erreichbare
// Node ueberwacht, gehen als Eintrag an diese (Anfrage "trap", op "add") und stehen dort wie ein eigener Trap im
// Dienst "traps" (bekannte Arten stossen dort die sofortige Runde an). Anzeige ("list") und Zuruecksetzen ("reset")
// fragen die zustaendige Node. Ist sie nicht erreichbar oder lehnt ab (aeltere Version, nicht mehr zustaendig),
// bleibt der Trap hier wie ohne Cluster.
//
// Wechsel der zustaendigen Node: der Trap-Stand geht mit dem Laufzeitstand an die anderen Nodes (cluster_state.go);
// die uebernehmende macht damit weiter (adopt: offene Traps bleiben offen, das Problem laeuft weiter), bei der
// abgebenden gilt danach keiner mehr als offen (handedOver).

const (
	callTrap        = "trap"
	trapFwdQueue    = 64 // wartende Eintraege an andere Nodes (voll: hier eintragen)
	trapCallTimeout = 10 * time.Second
	trapViewTimeout = 5 * time.Second // Anzeige und Zuruecksetzen warten nicht laenger auf die zustaendige Node
)

// trapFwd ist ein Eintrag fuer die zustaendige Node.
type trapFwd struct {
	owner, host string
	entry       trapEntry
}

// trapCallReq ist die Anfrage "trap" zwischen den Nodes.
type trapCallReq struct {
	Op    string     `json:"op"` // add, list, reset
	Host  string     `json:"host"`
	Entry *trapEntry `json:"entry,omitempty"`
}

// trapOwner: zustaendige andere Node eines Hosts, sofern erreichbar (ok=false: hier behandeln).
func (m *Module) trapOwner(uid string) (string, bool) {
	if m.hooks().Call == nil {
		return "", false
	}
	m.rtMu.Lock()
	rt := m.rts[uid]
	m.rtMu.Unlock()
	if rt == nil {
		return "", false
	}
	role, owner := m.roleOf(rt.host)
	if role != roleIdle || owner == "" || owner == m.clusterSelf() || !m.clusterSnapshot().online(owner) {
		return "", false
	}
	return owner, true
}

// trapCall schickt eine Anfrage "trap" an eine andere Node.
func (m *Module) trapCall(ctx context.Context, node string, in trapCallReq, out any) error {
	call := m.hooks().Call
	if call == nil {
		return errors.New("no cluster")
	}
	return call(ctx, node, callTrap, in, out)
}

// trapForwardLoop reicht Eintraege an die zustaendige Node weiter (eine Goroutine neben trapLoop); scheitert das,
// wird der Trap hier eingetragen.
func (m *Module) trapForwardLoop(ctx context.Context) {
	t := m.traps
	for {
		select {
		case <-ctx.Done():
			return
		case f := <-t.fwd:
			cctx, cancel := context.WithTimeout(ctx, trapCallTimeout)
			err := m.trapCall(cctx, f.owner, trapCallReq{Op: "add", Host: f.host, Entry: &f.entry}, nil)
			cancel()
			if err != nil {
				m.log.Debug("monitor64: traps: forward to owner", "host", f.host, "node", f.owner, "err", err)
				t.addEntry(f.host, f.entry)
			}
		}
	}
}

// handleTrapCall beantwortet die Anfrage "trap" einer anderen Node (Aufruf aus HandleClusterCall).
func (m *Module) handleTrapCall(ctx context.Context, from string, body []byte) (any, error) {
	var in trapCallReq
	if err := json.Unmarshal(body, &in); err != nil || !reUID.MatchString(in.Host) {
		return nil, errBad("host")
	}
	h, err := m.store.Host(ctx, in.Host)
	if err != nil {
		return nil, err
	}
	switch in.Op {
	case "add":
		if in.Entry == nil {
			return nil, errBad("trap")
		}
		if role, _ := m.roleOf(h); role == roleIdle { // hier nicht (mehr) zustaendig: die Absenderin traegt ihn ein
			return nil, errBad("trap_owner")
		}
		if !m.traps.addEntry(h.UID, cleanTrapEntry(*in.Entry, m.traps.now())) {
			return nil, errBad("trap_host")
		}
		m.log.Debug("monitor64: traps: entry from node", "host", h.Name, "node", from)
		return map[string]bool{"ok": true}, nil
	case "list":
		return m.hostTrapsLocal(h.UID), nil
	case "reset":
		if m.traps.reset(h.UID) {
			m.repoll(h.UID)
		}
		return map[string]bool{"ok": true}, nil
	}
	return nil, errBad("trap")
}

// hostTrapsView: Trap-Stand fuer die Oberflaeche – im Cluster der der zustaendigen Node, ergaenzt um den hiesigen
// (Traps, die hier blieben, und hier abgewiesene).
func (m *Module) hostTrapsView(ctx context.Context, uid string) hostTrapsOut {
	local := m.hostTrapsLocal(uid)
	owner, ok := m.trapOwner(uid)
	if !ok {
		return local
	}
	ctx, cancel := context.WithTimeout(ctx, trapViewTimeout)
	defer cancel()
	var remote hostTrapsOut
	if err := m.trapCall(ctx, owner, trapCallReq{Op: "list", Host: uid}, &remote); err != nil {
		m.log.Debug("monitor64: traps: list at owner", "host", uid, "node", owner, "err", err)
		return local
	}
	return mergeTrapsOut(remote, local)
}

// sameTrap: derselbe Trap (ein uebernommener Eintrag steht nach einer Uebernahme auf beiden Nodes).
func sameTrap(a, b trapEntry) bool {
	return a.Time.Equal(b.Time) && a.TrapOID == b.TrapOID && a.Kind == b.Kind && a.Version == b.Version
}

func hasTrap(list []trapEntry, e trapEntry) bool {
	for _, x := range list {
		if sameTrap(x, e) {
			return true
		}
	}
	return false
}

// adopt: diese Node uebernimmt den Host und macht mit dem Trap-Stand der bisher zustaendigen Node weiter (from, Stand
// von at; nil = dort keine Traps) - sonst fehlten die offenen Traps nach einer Uebernahme. Ihr Stand gilt (offen,
// gesamt); dazu kommen nur Traps, die hier nach ihrem Stand eintrafen (z. B. waehrend sie nicht erreichbar war).
// Eintraege, die beide kennen, bleiben einmal (die hiesigen samt Varbinds); mehrfaches Uebernehmen zaehlt nichts doppelt.
func (t *trapMgr) adopt(uid string, from *hostTraps, at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var src hostTraps
	if from != nil {
		src = *from
	}
	h := t.hosts[uid]
	if h == nil {
		if from == nil {
			return
		}
		h = t.host(uid)
	}
	pending, total := src.Pending, src.Total
	list := append([]trapEntry(nil), h.List...)
	for _, e := range h.List {
		if e.Time.After(at) && !hasTrap(src.List, e) {
			total++
			if !e.Handled {
				pending++
			}
		}
	}
	for _, e := range src.List {
		if !hasTrap(h.List, e) {
			list = append(list, e)
		}
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].Time.Before(list[j].Time) })
	if len(list) > trapKeep {
		list = list[len(list)-trapKeep:]
	}
	h.List, h.Pending, h.Total = list, max(pending, 0), max(h.Total, total)
}

// handedOver: eine andere Node ueberwacht den Host jetzt und fuehrt die offenen Traps weiter (adopt dort). Hier gilt
// keiner mehr als offen - sonst zaehlte die Anzeige sie doppelt (hostTrapsView). true = es waren welche offen.
func (t *trapMgr) handedOver(uid string) bool {
	return t.reset(uid)
}

// mergeTrapsOut fasst zwei Staende zusammen (neueste zuerst, hoechstens trapKeep Eintraege; derselbe Trap nur einmal,
// bevorzugt mit Varbinds).
func mergeTrapsOut(a, b hostTrapsOut) hostTrapsOut {
	out := hostTrapsOut{Pending: a.Pending + b.Pending, Total: a.Total + b.Total, Rejected: a.Rejected + b.Rejected,
		RejectReason: a.RejectReason, RejectedAt: a.RejectedAt}
	if b.RejectedAt.After(a.RejectedAt) {
		out.RejectReason, out.RejectedAt = b.RejectReason, b.RejectedAt
	}
	out.List = append([]trapEntry{}, a.List...)
	for _, e := range b.List {
		dup := false
		for i := range out.List {
			if sameTrap(out.List[i], e) {
				dup = true
				if len(out.List[i].Varbinds) == 0 && len(e.Varbinds) > 0 {
					out.List[i] = e
				}
				break
			}
		}
		if !dup {
			out.List = append(out.List, e)
		}
	}
	sort.SliceStable(out.List, func(i, j int) bool { return out.List[i].Time.After(out.List[j].Time) })
	if len(out.List) > trapKeep {
		out.List = out.List[:trapKeep]
	}
	return out
}

// resetTraps setzt die offenen Traps eines Hosts zurueck: hier und bei der zustaendigen Node.
func (m *Module) resetTraps(ctx context.Context, uid string) {
	if m.traps == nil {
		return
	}
	if m.traps.reset(uid) {
		m.repoll(uid)
	}
	if owner, ok := m.trapOwner(uid); ok {
		m.resetTrapsAt(ctx, owner, uid)
	}
}

// resetTrapsAt setzt die offenen Traps eines Hosts bei einer anderen Node zurueck.
func (m *Module) resetTrapsAt(ctx context.Context, node, uid string) {
	ctx, cancel := context.WithTimeout(ctx, trapViewTimeout)
	defer cancel()
	if err := m.trapCall(ctx, node, trapCallReq{Op: "reset", Host: uid}, nil); err != nil {
		m.log.Debug("monitor64: traps: reset at owner", "host", uid, "node", node, "err", err)
	}
}

// cleanTrapEntry bereinigt einen Eintrag einer anderen Node (Groessen wie beim eigenen Empfaenger).
func cleanTrapEntry(e trapEntry, now time.Time) trapEntry {
	if e.Time.IsZero() || e.Time.After(now.Add(time.Minute)) || e.Time.Before(now.Add(-time.Hour)) {
		e.Time = now
	}
	switch e.Version {
	case "1", "2c", "3":
	default:
		e.Version = ""
	}
	e.User, e.TrapOID, e.TrapName, e.Kind = clipTrapText(e.User, 64), clipTrapText(e.TrapOID, 512), clipTrapText(e.TrapName, 64), clipTrapText(e.Kind, 32)
	e.Handled = trapRunKinds[e.Kind]
	if len(e.Varbinds) > trap.DefaultMaxVarbinds {
		e.Varbinds, e.Truncated = e.Varbinds[:trap.DefaultMaxVarbinds], true
	}
	vbs := make([]trap.Varbind, len(e.Varbinds))
	for i, v := range e.Varbinds {
		vbs[i] = trap.Varbind{OID: clipTrapText(v.OID, 512), Type: clipTrapText(v.Type, 32), Value: clipTrapText(v.Value, trap.DefaultMaxValueLen)}
	}
	e.Varbinds = vbs
	return e
}

// clipTrapText: gueltiges UTF-8 ohne Steuerzeichen, hoechstens n Zeichen.
func clipTrapText(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	if utf8.RuneCountInString(s) > n {
		s = string([]rune(s)[:n])
	}
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return ' '
		}
		return r
	}, s))
}
