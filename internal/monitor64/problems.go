package monitor64

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/eval"
)

// Problem-Historie (Plan "Probleme und Verlauf"): ein Problem je Host und Dienst, solange der Dienst nicht OK ist;
// der Ablauf steht in m64_events. Geloest wird automatisch (System), von Hand (Person/API-Key) oder in der Wartung.

// openProblem ist ein offenes Problem im Speicher.
type openProblem struct {
	UID   string
	State string
	Worst string
	Acked bool
}

var stateRank = map[string]int{"ok": 0, "warn": 1, "unknown": 2, "crit": 3, "unreachable": 4}

// loadOpen liest die offenen Probleme eines Hosts (Schluessel: Dienst, "" = Host).
func (m *Module) loadOpen(ctx context.Context, hostUID string) map[string]*openProblem {
	out := map[string]*openProblem{}
	rows, err := m.st.Reader().QueryContext(ctx, `SELECT uid, service_key, state, worst, ack FROM m64_problems WHERE host_uid = ? AND closed_at = '' AND deleted = 0`, hostUID)
	if err != nil {
		m.log.Warn("monitor64: load problems", "err", err)
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var p openProblem
		var key, ack string
		if rows.Scan(&p.UID, &key, &p.State, &p.Worst, &ack) == nil {
			p.Acked = ack != ""
			out[key] = &p
		}
	}
	if err := rows.Err(); err != nil {
		m.log.Warn("monitor64: load problems", "err", err)
	}
	return out
}

// openAcks: quittierte offene Probleme eines Hosts.
func (m *Module) openAcks(hostUID string) map[string]bool {
	out := map[string]bool{}
	for k, p := range m.loadOpen(context.Background(), hostUID) {
		if p.Acked {
			out[k] = true
		}
	}
	return out
}

// event schreibt einen Eintrag in den Ablauf eines Problems.
func (m *Module) event(ctx context.Context, problemUID, hostUID, svcKey, kind, text string, by Actor, at time.Time) {
	if _, err := m.st.Writer().ExecContext(ctx, `INSERT INTO m64_events (uid, node_id, problem_uid, host_uid, service_key, ts, kind, text, actor) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		newUID(), m.nodeID(), problemUID, hostUID, svcKey, ts(at), kind, text, by.json()); err != nil {
		m.log.Warn("monitor64: event", "err", err)
	}
}

// syncProblems gleicht die offenen Probleme mit dem Zustand der Runde ab (open: zu Beginn der Runde gelesen,
// wird hier fortgeschrieben).
func (m *Module) syncProblems(ctx context.Context, h *Host, open map[string]*openProblem, svcs []eval.ServiceInput, hres eval.HostResult, unreachDetail string, at time.Time) {
	cur := map[string]struct {
		state, detail string
	}{}
	if hres.Unreachable {
		cur[""] = struct{ state, detail string }{"unreachable", unreachDetail}
	} else {
		for _, s := range svcs {
			if s.State != eval.OK {
				cur[s.Key] = struct{ state, detail string }{s.State.String(), s.Detail}
			}
		}
	}
	how := "auto"
	if hres.Maintenance {
		how = "maint"
	}
	// neue bzw. geaenderte Probleme
	for key, c := range cur {
		p := open[key]
		if p == nil {
			uid := newUID()
			if _, err := m.st.Writer().ExecContext(ctx, `INSERT INTO m64_problems (uid, node_id, host_uid, service_key, state, worst, opened_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				uid, m.nodeID(), h.UID, key, c.state, c.state, ts(at), tsNow()); err != nil {
				m.log.Warn("monitor64: open problem", "err", err)
				continue
			}
			open[key] = &openProblem{UID: uid, State: c.state, Worst: c.state}
			m.event(ctx, uid, h.UID, key, c.state, c.detail, SystemActor, at)
			if hres.Maintenance {
				m.event(ctx, uid, h.UID, key, "maint", i18nText("monitor64.detail.maint_silent"), SystemActor, at)
			}
			continue
		}
		if p.State != c.state {
			worst := p.Worst
			if stateRank[c.state] > stateRank[worst] {
				worst = c.state
			}
			_, _ = m.st.Writer().ExecContext(ctx, `UPDATE m64_problems SET state = ?, worst = ?, updated_at = ? WHERE uid = ? AND closed_at = ''`, c.state, worst, tsNow(), p.UID)
			p.State, p.Worst = c.state, worst
			m.event(ctx, p.UID, h.UID, key, c.state, c.detail, SystemActor, at)
		}
	}
	// geloeste Probleme (Unreachable: Dienste bleiben offen, nur "" zaehlt)
	for key, p := range open {
		if _, still := cur[key]; still {
			continue
		}
		if hres.Unreachable && key != "" {
			continue
		}
		res, err := m.st.Writer().ExecContext(ctx, `UPDATE m64_problems SET state = 'ok', closed_at = ?, closed_how = ?, closed_by = ?, updated_at = ? WHERE uid = ? AND closed_at = ''`,
			ts(at), how, SystemActor.json(), tsNow(), p.UID)
		delete(open, key)
		if n, _ := res.RowsAffected(); err == nil && n > 0 {
			m.event(ctx, p.UID, h.UID, key, "ok", "", SystemActor, at)
		}
	}
}

// recordNotified merkt, an welche Kanaele ein Problem gemeldet wurde (Ablauf "gemeldet an ...").
func (m *Module) recordNotified(ctx context.Context, h *Host, lines []eval.Line, at time.Time) {
	if len(lines) == 0 {
		return
	}
	open := m.loadOpen(ctx, h.UID)
	for _, l := range lines {
		if len(l.Channels) == 0 {
			continue
		}
		key := l.Key
		p := open[key]
		if p == nil {
			continue
		}
		b, _ := json.Marshal(l.Channels)
		_, _ = m.st.Writer().ExecContext(ctx, `UPDATE m64_problems SET notified = ?, updated_at = ? WHERE uid = ?`, string(b), tsNow(), p.UID)
		m.event(ctx, p.UID, h.UID, key, "bell", string(l.Kind)+": "+strings.Join(l.Channels, ","), SystemActor, at)
	}
}

// clearAck hebt eine Quittierung auf (Verschlechterung).
func (m *Module) clearAck(ctx context.Context, hostUID, svcKey string) {
	p := m.loadOpen(ctx, hostUID)[svcKey]
	if p == nil || !p.Acked {
		return
	}
	_, _ = m.st.Writer().ExecContext(ctx, `UPDATE m64_problems SET ack = '', updated_at = ? WHERE uid = ?`, tsNow(), p.UID)
	m.event(ctx, p.UID, hostUID, svcKey, "unack", i18nText("monitor64.detail.unack"), SystemActor, time.Now())
}

// Ack quittiert ein offenes Problem (Kommentar optional).
func (m *Module) Ack(ctx context.Context, hostUID, svcKey, comment string, by Actor) error {
	p := m.loadOpen(ctx, hostUID)[svcKey]
	if p == nil {
		return ErrNotFound
	}
	b, _ := json.Marshal(map[string]any{"by": by, "at": tsNow(), "comment": comment})
	if _, err := m.st.Writer().ExecContext(ctx, `UPDATE m64_problems SET ack = ?, updated_at = ? WHERE uid = ?`, string(b), tsNow(), p.UID); err != nil {
		return err
	}
	m.event(ctx, p.UID, hostUID, svcKey, "ack", comment, by, time.Now())
	m.trapsAcked(hostUID, svcKey) // Dienst "traps": Warnung bis quittiert
	return nil
}

// Resolve markiert ein offenes Problem von Hand als geloest.
func (m *Module) Resolve(ctx context.Context, hostUID, svcKey, comment string, by Actor) error {
	p := m.loadOpen(ctx, hostUID)[svcKey]
	if p == nil {
		return ErrNotFound
	}
	how := "user"
	if by.Kind == "api" {
		how = "api"
	}
	if _, err := m.st.Writer().ExecContext(ctx, `UPDATE m64_problems SET closed_at = ?, closed_how = ?, closed_by = ?, updated_at = ? WHERE uid = ? AND closed_at = ''`,
		tsNow(), how, by.json(), tsNow(), p.UID); err != nil {
		return err
	}
	m.event(ctx, p.UID, hostUID, svcKey, "resolved", comment, by, time.Now())
	m.trapsAcked(hostUID, svcKey)
	return nil
}

// nodeID ist die Kennung dieser Node (Einstellung des Kerns).
func (m *Module) nodeID() string { return m.st.SettingOr(context.Background(), "node.id", "") }

// CloseHostProblems schliesst alle offenen Probleme eines Hosts (Host entfernt), mit Akteur.
func (m *Module) CloseHostProblems(ctx context.Context, hostUID string, by Actor) error {
	open := m.loadOpen(ctx, hostUID)
	for key, p := range open {
		if _, err := m.st.Writer().ExecContext(ctx, `UPDATE m64_problems SET closed_at = ?, closed_how = 'removed', closed_by = ?, updated_at = ? WHERE uid = ? AND closed_at = ''`,
			tsNow(), by.json(), tsNow(), p.UID); err != nil {
			return err
		}
		m.event(ctx, p.UID, hostUID, key, "resolved", i18nText("monitor64.detail.host_removed"), by, time.Now())
	}
	return nil
}

// purgeProblems loescht geschlossene Probleme und ihre Ereignisse nach der Aufbewahrung (wie die Stundenwerte).
func (m *Module) purgeProblems(ctx context.Context, now time.Time) {
	cut := ts(now.Add(-keepProblems))
	if _, err := m.st.Writer().ExecContext(ctx, `DELETE FROM m64_events WHERE ts < ? AND problem_uid IN (SELECT uid FROM m64_problems WHERE closed_at != '' AND closed_at < ?)`, cut, cut); err != nil {
		m.log.Warn("monitor64: purge events", "err", err)
	}
	if _, err := m.st.Writer().ExecContext(ctx, `DELETE FROM m64_problems WHERE closed_at != '' AND closed_at < ?`, cut); err != nil {
		m.log.Warn("monitor64: purge problems", "err", err)
	}
	if _, err := m.st.Writer().ExecContext(ctx, `DELETE FROM m64_runtime WHERE host_uid NOT IN (SELECT uid FROM m64_hosts WHERE deleted = 0)`); err != nil {
		m.log.Warn("monitor64: purge runtime", "err", err)
	}
}
