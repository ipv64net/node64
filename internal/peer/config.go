package peer

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/healthchecks"
	"github.com/ipv64net/node64/internal/wire"
)

// Abgleich der Konfiguration (Schritt 2, zunaechst Checks): jede Node fuehrt ein Protokoll, welche Eintraege
// sich geaendert haben – lokal, vom hub oder von einer anderen Node uebernommen. Die anderen holen ab ihrem
// letzten Stand ab (bei einer Aenderung sofort angestossen, sonst alle 15 s). Es gewinnt die juengere Aenderung;
// der Zeitpunkt bleibt beim Weiterreichen erhalten, daher pendelt nichts hin und her.

// Checks ist die Anbindung an das Healthchecks-Modul.
type Checks interface {
	PeerCheck(ctx context.Context, token, self string) (*wire.Check, time.Time, time.Time, error)
	ApplyPeerCheck(ctx context.Context, w wire.Check, changedAt time.Time, origin, self string) (bool, error)
	DeletePeerCheck(ctx context.Context, token string, deletedAt time.Time, origin string) (bool, error)
	PeerTokens(ctx context.Context) []string
}

const (
	pullEvery = 15 * time.Second
	pageSize  = 200
)

// change ist ein Eintrag beim Abholen.
type change struct {
	Seq       int64       `json:"seq"`
	Entity    string      `json:"entity"`
	ID        string      `json:"id"`
	Op        string      `json:"op"`
	Origin    string      `json:"origin"`
	ChangedAt time.Time   `json:"changed_at"`
	Check     *wire.Check `json:"check,omitempty"`
}

type changesOut struct {
	Items []change `json:"items"`
	Last  int64    `json:"last"` // hoechste gelieferte Nummer
	Head  int64    `json:"head"` // hoechste Nummer ueberhaupt (kleiner als der eigene Stand: Protokoll neu)
	More  bool     `json:"more"`
}

type pullState struct {
	mu    sync.Mutex
	kick  chan string // Node, bei der es Neues gibt ("" = alle)
	busy  map[string]*sync.Mutex
	timer *time.Timer
}

// LogChange haengt eine Aenderung an das Protokoll (Hook des Healthchecks-Stores, auch fuer Aenderungen vom hub
// und von anderen Nodes) und stoesst die Gruppe an.
func (m *Manager) LogChange(ctx context.Context, entity, id, op string) {
	if entity != "check" {
		return
	}
	origin, at, ok := healthchecks.PeerSource(ctx)
	if !ok {
		origin, at = m.d.NodeID(), time.Now()
		if healthchecks.IsRemote(ctx) {
			origin = "hub"
		}
	}
	tx, err := m.db.BeginTx(context.Background(), nil)
	if err != nil {
		return
	}
	_, _ = tx.Exec(`DELETE FROM peer_log WHERE entity = ? AND entity_id = ?`, entity, id)
	_, err = tx.Exec(`INSERT INTO peer_log (entity, entity_id, op, origin, changed_at) VALUES (?,?,?,?,?)`, entity, id, op, origin, fmtTime(at))
	if err != nil || tx.Commit() != nil {
		_ = tx.Rollback()
		return
	}
	m.pokeSoon()
}

// seed legt beim ersten Start alle vorhandenen Checks ins Protokoll (fuer den ersten Abgleich nach dem Beitritt).
func (m *Manager) seed(ctx context.Context) {
	hc := m.checks()
	if hc == nil {
		return
	}
	var n int
	_ = m.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM peer_log`).Scan(&n)
	if n > 0 {
		return
	}
	for _, tok := range hc.PeerTokens(ctx) {
		_, _ = m.db.ExecContext(ctx, `INSERT OR IGNORE INTO peer_log (entity, entity_id, op, origin, changed_at) VALUES ('check',?,'upsert',?,?)`, tok, m.d.NodeID(), fmtTime(time.Now()))
	}
}

func (m *Manager) checks() Checks {
	if m.d.Checks == nil {
		return nil
	}
	return m.d.Checks()
}

// pokeSoon stoesst die anderen Nodes an (gebuendelt: hoechstens einmal je halbe Sekunde).
func (m *Manager) pokeSoon() {
	p := &m.pull
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.timer != nil {
		return
	}
	p.timer = time.AfterFunc(500*time.Millisecond, func() {
		p.mu.Lock()
		p.timer = nil
		p.mu.Unlock()
		list, _ := m.Members(context.Background())
		for _, x := range list {
			go func(x Member) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = m.call(ctx, x, http.MethodPost, "/peer/v1/poke", map[string]string{}, nil)
			}(x)
		}
	})
}

// handleChanges liefert das Protokoll ab ?since (Checks im aktuellen Stand).
func (m *Manager) handleChanges(w http.ResponseWriter, r *http.Request, _ *Member, _ []byte) {
	hc := m.checks()
	if hc == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "healthchecks not running"})
		return
	}
	ctx := r.Context()
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	out := changesOut{Items: []change{}}
	_ = m.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), 0) FROM peer_log`).Scan(&out.Head)
	rows, err := m.db.QueryContext(ctx, `SELECT seq, entity, entity_id, op, origin, changed_at FROM peer_log WHERE seq > ? ORDER BY seq LIMIT ?`, since, pageSize+1)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}
	var list []change
	for rows.Next() {
		var c change
		var at string
		if rows.Scan(&c.Seq, &c.Entity, &c.ID, &c.Op, &c.Origin, &at) == nil {
			c.ChangedAt = parseTime(at)
			list = append(list, c)
		}
	}
	rows.Close()
	if len(list) > pageSize {
		list, out.More = list[:pageSize], true
	}
	self := m.d.NodeID()
	for _, c := range list {
		out.Last = c.Seq
		if c.Entity != "check" {
			continue
		}
		chk, upd, del, err := hc.PeerCheck(ctx, c.ID, self)
		switch {
		case err != nil:
			continue
		case chk != nil:
			c.Op, c.Check, c.ChangedAt = "upsert", chk, upd
		default:
			c.Op = "delete"
			if !del.IsZero() {
				c.ChangedAt = del
			}
		}
		out.Items = append(out.Items, c)
	}
	writeJSON(w, http.StatusOK, out)
}

func (m *Manager) handlePoke(w http.ResponseWriter, _ *http.Request, from *Member, _ []byte) {
	select {
	case m.pull.kick <- from.NodeID:
	default:
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// pullLoop holt regelmaessig und auf Anstoss die Aenderungen der anderen Nodes.
func (m *Manager) pullLoop(ctx context.Context) {
	t := time.NewTicker(pullEvery)
	defer t.Stop()
	m.pullAll(ctx, "")
	m.ready.Store(true)
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-m.pull.kick:
			m.pullAll(ctx, id)
		case <-t.C:
			m.pullAll(ctx, "")
		}
	}
}

func (m *Manager) pullAll(ctx context.Context, only string) {
	if m.checks() == nil {
		return
	}
	list, err := m.Members(ctx)
	if err != nil {
		return
	}
	for _, x := range list {
		if only != "" && x.NodeID != only {
			continue
		}
		if err := m.pullFrom(ctx, x); err != nil {
			m.d.Log.Debug("peer pull", "from", x.Name, "err", err)
			continue
		}
		if err := m.pullData(ctx, x); err != nil {
			m.d.Log.Debug("peer measurements", "from", x.Name, "err", err)
		}
	}
	m.verdicts(ctx)
}

// forwardFor: diese Node reicht die Aenderung an den hub weiter (Urheberin ist eine nicht verknuepfte Node).
func (m *Manager) forwardFor(ctx context.Context, origin string) bool {
	if m.d.Forward == nil || origin == "hub" || origin == m.d.NodeID() {
		return false
	}
	o, _ := m.member(ctx, origin)
	if o != nil && o.Linked {
		return false // die Urheberin meldet es selbst
	}
	return m.forwarder(ctx)
}

// hubKnows: keine der messenden Nodes ist ein nicht verknuepftes Mitglied der Gruppe (sonst lehnt der hub den
// Check ab; er bleibt dann in der lokalen Gruppe). Nodes ausserhalb der Gruppe kennt nur der hub.
func (m *Manager) hubKnows(ctx context.Context, nodes []string) bool {
	for _, id := range nodes {
		if id == m.d.NodeID() {
			continue
		}
		if x, _ := m.member(ctx, id); x != nil && !x.Linked {
			return false
		}
	}
	return true
}

// HubKnowsCheck: der hub kennt alle Nodes, die den Check messen (ohne Gruppe oder Healthchecks immer true).
func (m *Manager) HubKnowsCheck(ctx context.Context, token string) bool {
	hc := m.checks()
	if hc == nil {
		return true
	}
	w, _, _, err := hc.PeerCheck(ctx, token, m.d.NodeID())
	if err != nil || w == nil {
		return true
	}
	return m.hubKnows(ctx, w.Nodes)
}

// pullFrom holt die Aenderungen einer Node ab ihrem Stand und uebernimmt die juengeren.
func (m *Manager) pullFrom(ctx context.Context, x Member) error {
	hc := m.checks()
	if hc == nil {
		return nil
	}
	m.pull.mu.Lock()
	lock := m.pull.busy[x.NodeID]
	if lock == nil {
		lock = &sync.Mutex{}
		m.pull.busy[x.NodeID] = lock
	}
	m.pull.mu.Unlock()
	if !lock.TryLock() {
		return nil
	}
	defer lock.Unlock()
	var cursor int64
	_ = m.db.QueryRowContext(ctx, `SELECT cursor FROM peer_members WHERE node_id = ?`, x.NodeID).Scan(&cursor)
	self, applied := m.d.NodeID(), 0
	for page := 0; page < 100; page++ {
		var out changesOut
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		err := m.call(cctx, x, http.MethodGet, "/peer/v1/changes?since="+strconv.FormatInt(cursor, 10), nil, &out)
		cancel()
		if err != nil {
			return err
		}
		if out.Head < cursor { // Protokoll der anderen Node neu (z. B. zurueckgesetzt): von vorn
			cursor = 0
			continue
		}
		for _, c := range out.Items {
			var ok bool
			switch {
			case c.Op == "upsert" && c.Check != nil:
				ok, err = hc.ApplyPeerCheck(ctx, *c.Check, c.ChangedAt, c.Origin, self)
			case c.Op == "delete":
				ok, err = hc.DeletePeerCheck(ctx, c.ID, c.ChangedAt, c.Origin)
			}
			if err != nil {
				m.d.Log.Warn("peer change not applied", "from", x.Name, "id", c.ID, "err", err)
			}
			if ok {
				applied++
				if m.forwardFor(ctx, c.Origin) && (c.Op == "delete" || m.hubKnows(ctx, c.Check.Nodes)) {
					m.d.Forward(ctx, c.Entity, c.ID, c.Op)
				}
			}
		}
		if out.Last > cursor {
			cursor = out.Last
			_, _ = m.db.ExecContext(ctx, `UPDATE peer_members SET cursor = ? WHERE node_id = ?`, cursor, x.NodeID)
		}
		if !out.More {
			break
		}
	}
	if applied > 0 {
		m.d.Log.Info("checks updated from local group", "from", x.Name, "changes", applied)
	}
	return nil
}
