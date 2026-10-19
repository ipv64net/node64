package peer

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/ipv64net/node64/internal/healthchecks"
)

// Weiterreichen der hub-Daten: Eine Node ohne Healthchecks-Sync holt bei der weiterreichenden Node (verknuepft,
// erreichbar, kleinste Kennung) die Zustaende und Messpunkte vom hub – fuer Checks, die kein Mitglied der Gruppe
// misst, den Gesamtzustand, fuer alle die Messstellen ausserhalb der Gruppe. Erster Abruf: die letzten 24 h.

// Relay ist die Anbindung an das Healthchecks-Modul fuer hub-Daten (peerrelay.go).
type Relay interface {
	PeerRelayStates(ctx context.Context, keep func(source string) bool) []healthchecks.RelayState
	PeerRelayPoints(ctx context.Context, seq int64, from time.Time, limit int, keep func(source string) bool) ([]healthchecks.RelayPoint, int64, time.Time, bool, error)
	PeerRelayStart(ctx context.Context, from time.Time) int64
	ApplyPeerRelay(ctx context.Context, states []healthchecks.RelayState, pts []healthchecks.RelayPoint, overall func(nodes []string) bool) (int, error)
}

type relayOut struct {
	Linked   bool                      `json:"linked"`
	States   []healthchecks.RelayState `json:"states,omitempty"`
	Items    []healthchecks.RelayPoint `json:"items"`
	Last     int64                     `json:"last"`
	LastTime time.Time                 `json:"last_time"`
	More     bool                      `json:"more"`
}

func (m *Manager) relay() Relay {
	r, _ := m.checks().(Relay)
	return r
}

// groupSource: Messstelle einer Node der Gruppe (oder dieser Node) – die kommt von ihr selbst.
func (m *Manager) groupSource(ctx context.Context) func(source string) bool {
	ids := map[string]bool{"node:" + m.d.NodeID(): true}
	list := m.hcMembers(ctx)
	for _, x := range list {
		ids["node:"+x.NodeID] = true
	}
	return func(source string) bool { return ids[source] }
}

// involved: eine Node der Gruppe (oder diese) misst den Check.
func (m *Manager) involved(ctx context.Context, nodes []string) bool {
	in := m.groupSource(ctx)
	for _, id := range nodes {
		if in("node:" + id) {
			return true
		}
	}
	return false
}

// handleRelay liefert die hub-Daten dieser Node (nur verknuepft).
func (m *Manager) handleRelay(w http.ResponseWriter, r *http.Request, peer *Member, _ []byte) {
	rl := m.relay()
	if rl == nil || !m.linkedSelf() || !m.both(r.Context(), *peer, "healthchecks", "checks") {
		writeJSON(w, http.StatusOK, relayOut{Items: []healthchecks.RelayPoint{}})
		return
	}
	ctx := r.Context()
	in := m.groupSource(ctx)
	keep := func(source string) bool { return !in(source) }
	q := r.URL.Query()
	since, _ := strconv.ParseInt(q.Get("since"), 10, 64)
	from := parseTime(q.Get("from"))
	if since == startFresh {
		since = rl.PeerRelayStart(ctx, time.Now().Add(-firstSpan))
	}
	if from.IsZero() {
		from = time.Now().Add(-firstSpan)
	}
	out := relayOut{Linked: true}
	if q.Get("states") == "1" {
		out.States = rl.PeerRelayStates(ctx, keep)
	}
	var err error
	out.Items, out.Last, out.LastTime, out.More, err = rl.PeerRelayPoints(ctx, since, from, measPage, keep)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}
	if out.Items == nil {
		out.Items = []healthchecks.RelayPoint{}
	}
	writeJSON(w, http.StatusOK, out)
}

// pullRelay holt die hub-Daten bei der weiterreichenden Node (nur ohne eigenen Sync).
func (m *Manager) pullRelay(ctx context.Context, x Member) error {
	rl := m.relay()
	if rl == nil || m.linkedSelf() {
		return nil
	}
	if id, _, _ := m.Forwarder(ctx); id != x.NodeID {
		return nil
	}
	var cursor int64
	var rtime string
	_ = m.db.QueryRowContext(ctx, `SELECT rcursor, rtime FROM peer_members WHERE node_id = ?`, x.NodeID).Scan(&cursor, &rtime)
	if cursor == 0 {
		cursor = startFresh
	}
	overall := func(nodes []string) bool { return !m.involved(ctx, nodes) }
	total := 0
	for page := 0; page < measPages; page++ {
		q := "/peer/v1/relay?since=" + strconv.FormatInt(cursor, 10) + "&from=" + rtime
		if page == 0 {
			q += "&states=1"
		}
		var out relayOut
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := m.call(cctx, x, http.MethodGet, q, nil, &out)
		cancel()
		if err != nil {
			return err
		}
		if !out.Linked {
			return nil
		}
		n, err := rl.ApplyPeerRelay(ctx, out.States, out.Items, overall)
		if err != nil {
			return err
		}
		total += n
		if out.Last > 0 {
			cursor = out.Last
		}
		if !out.LastTime.IsZero() {
			rtime = fmtTime(out.LastTime)
		}
		_, _ = m.db.ExecContext(ctx, `UPDATE peer_members SET rcursor = ?, rtime = ? WHERE node_id = ?`, cursor, rtime, x.NodeID)
		if !out.More {
			break
		}
	}
	if total > 0 {
		m.d.Log.Debug("hub data via local group", "from", x.Name, "points", total)
	}
	return nil
}
