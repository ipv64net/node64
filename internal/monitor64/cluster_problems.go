package monitor64

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
)

// Probleme im Cluster (Bereich status, Eintraege "problem:<uid>"): das Problem mit seinem Ablauf (Ereignisse je mit
// Node-Kennung). Offene Probleme, Quittierungen, Kommentare und "gemeldet an" sind so ueberall gleich; die Node, die
// einen Host uebernimmt, macht mit dem Stand weiter. Ereignisse werden nie ueberschrieben, nur ergaenzt; ein
// geschlossenes Problem oeffnet keine Uebernahme wieder (die schliessende Node meldet ihren Stand dann neu).

type problemEntry struct {
	Node      string          `json:"node"`
	Host      string          `json:"host"`
	Key       string          `json:"key"`
	State     string          `json:"state"`
	Worst     string          `json:"worst"`
	Opened    string          `json:"opened_at"`
	Closed    string          `json:"closed_at,omitempty"`
	ClosedHow string          `json:"closed_how,omitempty"`
	ClosedBy  json.RawMessage `json:"closed_by,omitempty"`
	Ack       string          `json:"ack,omitempty"`
	Notified  []string        `json:"notified"` // Kanaele als "uid:<kennung>" bzw. "default"
	Updated   string          `json:"updated_at"`
	Events    []eventEntry    `json:"events,omitempty"`
}

const problemEventsMax = 500

func (m *Module) problemRow(ctx context.Context, uid string) (*problemEntry, error) {
	var p problemEntry
	var closedBy, notified string
	var del int
	err := m.st.Reader().QueryRowContext(ctx, `SELECT node_id, host_uid, service_key, state, worst, opened_at, closed_at, closed_how, closed_by, ack, notified, updated_at, deleted
		FROM m64_problems WHERE uid = ?`, uid).Scan(&p.Node, &p.Host, &p.Key, &p.State, &p.Worst, &p.Opened, &p.Closed, &p.ClosedHow, &closedBy, &p.Ack, &notified, &p.Updated, &del)
	if errors.Is(err, sql.ErrNoRows) || err == nil && del == 1 {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.ClosedBy = json.RawMessage(closedBy)
	if !json.Valid(p.ClosedBy) {
		p.ClosedBy = json.RawMessage(`{}`)
	}
	_ = json.Unmarshal([]byte(notified), &p.Notified)
	return &p, nil
}

func (m *Module) problemGet(ctx context.Context, uid string) (json.RawMessage, bool, error) {
	p, err := m.problemRow(ctx, uid)
	if err != nil || p == nil {
		return nil, false, err
	}
	p.Notified = m.channelListToCluster(ctx, p.Notified)
	p.Events = m.eventsWhere(ctx, `problem_uid = ? ORDER BY ts, id LIMIT `+strconv.Itoa(problemEventsMax), uid)
	b, err := json.Marshal(p)
	return b, err == nil, err
}

func (m *Module) problemApply(ctx context.Context, uid string, data json.RawMessage, deleted bool) error {
	db := m.st.Writer()
	if deleted { // Aufbewahrung abgelaufen (purgeProblems) bzw. entfernt
		if _, err := db.ExecContext(ctx, `DELETE FROM m64_events WHERE problem_uid = ?`, uid); err != nil {
			return err
		}
		_, err := db.ExecContext(ctx, `DELETE FROM m64_problems WHERE uid = ?`, uid)
		_, _ = db.ExecContext(ctx, `DELETE FROM m64_csync WHERE kind = 'problem' AND uid = ?`, uid)
		return err
	}
	var in problemEntry
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	if !reUID.MatchString(in.Host) || in.Node != "" && !reNodeID.MatchString(in.Node) || stateRankOK(in.State) || stateRankOK(in.Worst) ||
		parseTS(in.Opened).IsZero() || parseTS(in.Updated).IsZero() || len(in.Key) > 512 || len(in.Ack) > 8192 {
		return errClItem
	}
	if !json.Valid(in.ClosedBy) {
		in.ClosedBy = json.RawMessage(`{}`)
	}
	notified := m.channelListFromCluster(ctx, in.Notified)
	cur, err := m.problemRow(ctx, uid)
	if err != nil {
		return err
	}
	keepClosed := false
	if cur != nil {
		if stateRank[cur.Worst] > stateRank[in.Worst] {
			in.Worst = cur.Worst
		}
		for _, n := range cur.Notified { // "gemeldet an" ergaenzen, nie verlieren
			if !slices.Contains(notified, n) {
				notified = append(notified, n)
			}
		}
		if cur.Closed != "" && in.Closed == "" { // geschlossen bleibt geschlossen
			in.State, in.Closed, in.ClosedHow, in.ClosedBy = "ok", cur.Closed, cur.ClosedHow, cur.ClosedBy
			keepClosed = true
		}
	}
	nb, _ := json.Marshal(notified)
	_, err = db.ExecContext(ctx, `INSERT INTO m64_problems (uid, node_id, host_uid, service_key, state, worst, opened_at, closed_at, closed_how, closed_by, ack, notified, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (uid) DO UPDATE SET node_id = excluded.node_id, host_uid = excluded.host_uid, service_key = excluded.service_key, state = excluded.state,
			worst = excluded.worst, opened_at = excluded.opened_at, closed_at = excluded.closed_at, closed_how = excluded.closed_how, closed_by = excluded.closed_by,
			ack = excluded.ack, notified = excluded.notified, updated_at = excluded.updated_at, deleted = 0`,
		uid, in.Node, in.Host, in.Key, in.State, in.Worst, in.Opened, in.Closed, in.ClosedHow, string(in.ClosedBy), in.Ack, string(nb), in.Updated)
	if err != nil {
		return err // z. B. ein anderes offenes Problem derselben Node fuer denselben Dienst: spaeter erneut
	}
	for i, e := range in.Events {
		if i >= problemEventsMax {
			break
		}
		m.insertEvent(ctx, e, uid)
	}
	if keepClosed { // die andere Node erfaehrt, dass es geschlossen ist (sonst bliebe es dort offen)
		_, _ = db.ExecContext(ctx, `UPDATE m64_problems SET updated_at = ? WHERE uid = ?`, tsNow(), uid)
		m.csyncSet(ctx, "problem", uid, m.problemStamp(ctx, uid))
		m.clusterChange(context.Background(), ClusterItemStatus, "problem:"+uid, false)
		return supersededErr{"problem closed here"}
	}
	m.csyncSet(ctx, "problem", uid, m.problemStamp(ctx, uid))
	return nil
}

// stateRankOK: unbekannter Zustand (true = ungueltig).
func stateRankOK(s string) bool {
	_, ok := stateRank[s]
	return !ok
}

// purgeTombstones meldet entfernte Probleme an den Cluster (Aufbewahrung; die anderen Nodes raeumen ebenso auf, der
// Vermerk haelt nur das Protokoll klein).
func (m *Module) purgeTombstones(ctx context.Context, cut string) {
	if _, err := m.st.Writer().ExecContext(ctx, `DELETE FROM m64_cstate WHERE host_uid NOT IN (SELECT uid FROM m64_hosts WHERE deleted = 0)`); err != nil {
		m.log.Warn("monitor64: purge cluster state", "err", err)
	}
	if m.hooks().Change == nil {
		return
	}
	rows, err := m.st.Reader().QueryContext(ctx, `SELECT uid FROM m64_problems WHERE closed_at != '' AND closed_at < ?`, cut)
	if err != nil {
		return
	}
	var uids []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) == nil {
			uids = append(uids, u)
		}
	}
	rows.Close()
	for _, u := range uids {
		m.clusterChange(ctx, ClusterItemStatus, "problem:"+u, true)
		_, _ = m.st.Writer().ExecContext(ctx, `DELETE FROM m64_csync WHERE kind = 'problem' AND uid = ?`, u)
	}
}
