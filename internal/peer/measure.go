package peer

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/ipv64net/node64/internal/healthchecks"
	"github.com/ipv64net/node64/internal/wire"
)

// Messwerte und Zustaende (Schritt 3): jede Node holt bei den anderen deren eigene Messpunkte ab ihrem
// Stand und die aktuellen Zustaende ihrer Checks. Eine neue Node bekommt zuerst nur die letzten 24 h.

// Data ist die Anbindung an das Healthchecks-Modul fuer Messwerte.
type Data interface {
	PeerMeasurements(ctx context.Context, since int64, limit int) ([]wire.Measurement, int64, bool, error)
	PeerStartSeq(ctx context.Context, from time.Time) int64
	MaxMeasurementSeq(ctx context.Context) int64
	Snapshot(ctx context.Context) []wire.State
	ApplyPeerData(ctx context.Context, origin, label string, states []wire.State, ms []wire.Measurement) (int, error)
	PeerGroups(ctx context.Context) []healthchecks.GroupState
	ApplyPeerGroups(ctx context.Context, list []healthchecks.GroupState)
	PeerVerdicts(ctx context.Context, decide func(nodes []string) bool)
}

const (
	measPage   = 1000
	firstSpan  = 24 * time.Hour
	measPages  = 50
	startFresh = -1          // ?since=-1: ab den letzten 24 h
	measBytes  = maxBody / 2 // Antwort einer Seite; darueber schnitte der Empfaenger ab (Signatur passte nicht)
)

type measOut struct {
	States []wire.State              `json:"states,omitempty"`
	Groups []healthchecks.GroupState `json:"groups,omitempty"` // Gesamtzustand der Gruppe (Benachrichtigungen)
	Items  []wire.Measurement        `json:"items"`
	Last   int64                     `json:"last"`
	Head   int64                     `json:"head"`
	More   bool                      `json:"more"`
}

func (m *Manager) data() Data {
	d, _ := m.checks().(Data)
	return d
}

// handleMeasurements liefert eigene Messpunkte ab ?since (bei der ersten Seite auch die Zustaende).
func (m *Manager) handleMeasurements(w http.ResponseWriter, r *http.Request, from *Member, _ []byte) {
	d := m.data()
	if d == nil || !m.both(r.Context(), *from, "healthchecks", "checks") {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "healthchecks not running"})
		return
	}
	ctx := r.Context()
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	out := measOut{Head: d.MaxMeasurementSeq(ctx)}
	if since == startFresh {
		since = d.PeerStartSeq(ctx, time.Now().Add(-firstSpan))
	}
	if r.URL.Query().Get("states") == "1" {
		out.States, out.Groups = d.Snapshot(ctx), d.PeerGroups(ctx)
	}
	items, last, more, err := d.PeerMeasurements(ctx, since, measPage)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}
	out.Items, out.Last, out.More = items, last, more
	fitMeasPage(&out)
	writeJSON(w, http.StatusOK, out)
}

// fitMeasPage begrenzt eine Seite auf measBytes (mindestens ein Messpunkt); der letzte enthaltene Messpunkt wird
// dann zum Stand, der Rest folgt mit der naechsten Seite.
func fitMeasPage(out *measOut) {
	items := out.Items
	out.Items = nil
	b, _ := json.Marshal(out)
	out.Items = items
	size := len(b)
	for i, it := range items {
		ib, _ := json.Marshal(it)
		if i > 0 && size+len(ib)+1 > measBytes {
			out.Items, out.Last, out.More = items[:i], items[i-1].Seq, true
			return
		}
		size += len(ib) + 1
	}
}

// pullData holt Zustaende und neue Messpunkte einer Node.
func (m *Manager) pullData(ctx context.Context, x Member) error {
	d := m.data()
	if d == nil {
		return nil
	}
	var cursor int64
	_ = m.db.QueryRowContext(ctx, `SELECT mcursor FROM peer_members WHERE node_id = ?`, x.NodeID).Scan(&cursor)
	if cursor == 0 {
		cursor = startFresh
	}
	total := 0
	for page := 0; page < measPages; page++ {
		var out measOut
		q := "/peer/v1/measurements?since=" + strconv.FormatInt(cursor, 10)
		if page == 0 {
			q += "&states=1"
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := m.call(cctx, x, http.MethodGet, q, nil, &out)
		cancel()
		if err != nil {
			return err
		}
		if cursor > 0 && out.Head < cursor { // Datenbank der anderen Node neu: ab den letzten 24 h
			cursor = startFresh
			continue
		}
		d.ApplyPeerGroups(ctx, out.Groups)
		n, err := d.ApplyPeerData(ctx, x.NodeID, x.Name, out.States, out.Items)
		if err != nil {
			return err
		}
		total += n
		if out.Last > 0 && out.Last != cursor {
			cursor = out.Last
			_, _ = m.db.ExecContext(ctx, `UPDATE peer_members SET mcursor = ? WHERE node_id = ?`, cursor, x.NodeID)
		}
		if !out.More {
			break
		}
	}
	if total > 0 {
		m.d.Log.Debug("measurements from local group", "from", x.Name, "points", total)
	}
	return nil
}

// verdicts: Gesamtzustand der Checks, die diese Node nicht misst – ohne hub-Verknuepfung oder fuer Checks, die
// eine nicht verknuepfte Node mitmisst (auch als Stellvertreter-Node beim hub), entscheidet die Gruppe.
func (m *Manager) verdicts(ctx context.Context) {
	d := m.data()
	if d == nil {
		return
	}
	d.PeerVerdicts(ctx, func(nodes []string) bool { return m.GroupDecides(ctx, nodes) })
}

// GroupDecides: die Gruppe bewertet den Check, nicht der hub – eine Node der Gruppe misst ihn und diese Node ist
// nicht verknuepft oder eine messende Node ist es nicht (sonst kommt der Gesamtzustand vom hub bzw. weitergereicht).
func (m *Manager) GroupDecides(ctx context.Context, nodes []string) bool {
	return (!m.linkedSelf() || !m.hubDecides(ctx, nodes)) && m.involved(ctx, nodes)
}
