package peer

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Allgemeiner Abgleich der Module (alle ausser Healthchecks) ueber /peer/v2/sync: jede Node fuehrt im Protokoll
// cluster_log je Eintrag den letzten Stand (Urheberin, Zeitpunkt, geloescht). Die anderen holen ab ihrem Stand ab,
// nur die Bereiche, die auf beiden Seiten eingeschaltet sind (die abholende Node nennt sie, die liefernde prueft
// ihre eigenen). Es gewinnt die juengere Aenderung (bei Gleichstand die groessere Kennung der Urheberin); der
// Zeitpunkt bleibt beim Weiterreichen erhalten, daher pendelt nichts. Geloeschte bleiben 30 Tage als Vermerk.

const tombstoneTTL = 30 * 24 * time.Hour

// syncPageBytes: ab dieser Datenmenge endet eine Seite von /peer/v2/sync (die Antwort bleibt unter maxBody).
const syncPageBytes = maxBody / 2

type syncEntry struct {
	Seq       int64           `json:"seq"`
	Module    string          `json:"module"`
	Item      string          `json:"item"`
	ID        string          `json:"id"`
	Deleted   bool            `json:"deleted,omitempty"`
	Origin    string          `json:"origin"`
	ChangedAt time.Time       `json:"changed_at"`
	Data      json.RawMessage `json:"data,omitempty"`
}

type syncOut struct {
	Items []syncEntry `json:"items"`
	Last  int64       `json:"last"` // hoechste gelieferte Nummer
	Head  int64       `json:"head"` // hoechste Nummer ueberhaupt (kleiner als der eigene Stand: Protokoll neu)
	More  bool        `json:"more"`
}

type sync2State struct {
	mu     sync.Mutex
	busy   map[string]*sync.Mutex
	seeded map[string]bool // "modul/bereich": vorhandene Eintraege seit dem Start im Protokoll
	swept  time.Time
	due    map[string]time.Time // je Mitglied: naechste Wiederholung abgelehnter Eintraege (fehlt = sofort)
	tries  map[string]int       // je Mitglied: Wiederholungen ohne Erfolg (Abstand verdoppelt sich)
	warned map[string]bool      // Ablehnung schon gemeldet (Mitglied, Eintrag, Zeitpunkt): Wiederholungen nur Debug
}

// Abgelehnte Eintraege (z. B. Statusseite mit gleichem Slug, Benutzer zur Wahl, Key eines anderen Accounts) koennen
// sich hier aufloesen, ohne dass sich der Eintrag drueben aendert. peer_members.retry2 haelt die Nummer vor dem
// ersten abgelehnten Eintrag (-1 = keiner); ab dort wird erneut abgeholt, der Stand (cursor2) laeuft trotzdem weiter.

// sync2RetryEvery: erster Abstand der Wiederholungen abgelehnter Eintraege (Variable fuer Tests); er verdoppelt sich
// bis sync2RetryMax, solange die Ablehnung bleibt (z. B. Benutzer zur Wahl), und beginnt nach jeder Aenderung auf
// dieser Node von vorn (nur eine Aenderung hier oder drueben kann eine Ablehnung aufloesen).
var sync2RetryEvery = 5 * time.Minute

const sync2RetryMax = 6 * time.Hour

// registerSync2 haengt den Endpunkt an (aus Register).
func (m *Manager) registerSync2(mux *http.ServeMux) {
	mux.Handle("GET /peer/v2/sync", m.Handle(m.handleSync2))
}

// ClusterChange meldet eine Aenderung eines Eintrags (Hook des Moduls, auch bei Uebernahmen von anderen Nodes:
// die Herkunft steht dann in ctx, siehe ClusterOrigin).
func (m *Manager) ClusterChange(ctx context.Context, module, item, id string, deleted bool) {
	if id == "" || m.provider(module) == nil {
		return
	}
	origin, at, ok := ClusterOrigin(ctx)
	if !ok {
		origin, at = m.d.NodeID(), time.Now()
		m.pull.s2.mu.Lock() // Aenderung hier: abgelehnte Eintraege gleich wieder versuchen
		m.pull.s2.due, m.pull.s2.tries = nil, nil
		m.pull.s2.mu.Unlock()
	}
	if changed, err := m.logSync(module, item, id, deleted, origin, at); err != nil {
		m.d.Log.Warn("cluster change not logged", "module", module, "item", item, "err", err)
	} else if changed {
		m.pokeSoon()
	}
}

type syncLocal struct {
	origin  string
	at      time.Time
	deleted bool
}

func (m *Manager) syncLocal(module, item, id string) (*syncLocal, error) {
	var l syncLocal
	var at string
	err := m.db.QueryRow(`SELECT origin, changed_at, deleted FROM cluster_log WHERE module = ? AND item = ? AND entity_id = ?`, module, item, id).Scan(&l.origin, &at, &l.deleted)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	l.at = parseTime(at)
	return &l, nil
}

// logSync traegt einen Stand ein (neue Nummer, damit die anderen ihn abholen); unveraendert = nichts.
func (m *Manager) logSync(module, item, id string, deleted bool, origin string, at time.Time) (bool, error) {
	at = at.UTC().Truncate(time.Millisecond)
	if l, err := m.syncLocal(module, item, id); err == nil && l != nil && l.origin == origin && l.at.Equal(at) && l.deleted == deleted {
		return false, nil
	}
	tx, err := m.db.BeginTx(context.Background(), nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`DELETE FROM cluster_log WHERE module = ? AND item = ? AND entity_id = ?`, module, item, id); err != nil {
		return false, err
	}
	if _, err = tx.Exec(`INSERT INTO cluster_log (module, item, entity_id, deleted, origin, changed_at) VALUES (?,?,?,?,?,?)`,
		module, item, id, deleted, origin, fmtTime(at)); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// newer: der Stand (at, origin) schlaegt den lokalen.
func newer(at time.Time, origin string, local *syncLocal) bool {
	if local == nil {
		return true
	}
	at = at.UTC().Truncate(time.Millisecond)
	return at.After(local.at) || at.Equal(local.at) && origin > local.origin
}

// seedSync legt einmal je Prozess alle vorhandenen Eintraege ins Protokoll, die dort noch fehlen.
func (m *Manager) seedSync(ctx context.Context) {
	self, now := m.d.NodeID(), fmtTime(time.Now())
	for _, mi := range m.modules() {
		p := m.provider(mi.ID)
		if p == nil {
			continue
		}
		for _, it := range p.ClusterModule().Items {
			key := mi.ID + "/" + it.ID
			m.pull.s2.mu.Lock()
			done := m.pull.s2.seeded[key]
			m.pull.s2.mu.Unlock()
			if done {
				continue
			}
			ids, err := p.ClusterIDs(ctx, it.ID)
			if err != nil {
				continue
			}
			for _, id := range ids {
				_, _ = m.db.ExecContext(ctx, `INSERT OR IGNORE INTO cluster_log (module, item, entity_id, deleted, origin, changed_at) VALUES (?,?,?,0,?,?)`, mi.ID, it.ID, id, self, now)
			}
			m.pull.s2.mu.Lock()
			if m.pull.s2.seeded == nil {
				m.pull.s2.seeded = map[string]bool{}
			}
			m.pull.s2.seeded[key] = true
			m.pull.s2.mu.Unlock()
		}
	}
}

// handleSync2 liefert das Protokoll ab ?since fuer die Bereiche ?items ("modul/bereich,…"), soweit sie hier an sind.
func (m *Manager) handleSync2(w http.ResponseWriter, r *http.Request, _ *Member, _ []byte) {
	ctx := r.Context()
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	own := m.syncCaps(ctx)
	allowed := map[string]bool{}
	for _, c := range splitCaps(r.URL.Query().Get("items")) {
		if mod, item, _ := strings.Cut(c, "/"); m.v2Item(mod, item) && has(own, c) {
			allowed[c] = true
		}
	}
	out := syncOut{Items: []syncEntry{}}
	_ = m.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), 0) FROM cluster_log`).Scan(&out.Head)
	rows, err := m.db.QueryContext(ctx, `SELECT seq, module, item, entity_id, deleted, origin, changed_at FROM cluster_log WHERE seq > ? ORDER BY seq LIMIT ?`, since, pageSize+1)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}
	var list []syncEntry
	for rows.Next() {
		var e syncEntry
		var at string
		if rows.Scan(&e.Seq, &e.Module, &e.Item, &e.ID, &e.Deleted, &e.Origin, &at) == nil {
			e.ChangedAt = parseTime(at)
			list = append(list, e)
		}
	}
	rows.Close()
	if len(list) > pageSize {
		list, out.More = list[:pageSize], true
	}
	size := 0
	for _, e := range list {
		if size > syncPageBytes { // grosse Eintraege (z. B. Logos der Statusseiten): Rest auf der naechsten Seite
			out.More = true
			break
		}
		if allowed[e.Module+"/"+e.Item] {
			if !e.Deleted {
				data, found, err := m.provider(e.Module).ClusterGet(ctx, e.Item, e.ID)
				if err != nil { // die Seite endet hier, der Eintrag kommt beim naechsten Abholen
					out.More = true
					break
				}
				if found {
					e.Data = data
					size += len(data)
				} else {
					e.Deleted = true // ohne Hook geloescht: der Stand ist „weg“
				}
			}
			out.Items = append(out.Items, e)
		}
		out.Last = e.Seq
	}
	writeJSON(w, http.StatusOK, out)
}

// pullSync2 holt bei den Mitgliedern die Aenderungen der allgemein abgeglichenen Module.
func (m *Manager) pullSync2(ctx context.Context, list []Member, only string) {
	m.seedSync(ctx)
	if only == "" {
		m.pull.s2.mu.Lock()
		sweep := time.Since(m.pull.s2.swept) > time.Hour
		if sweep {
			m.pull.s2.swept = time.Now()
		}
		m.pull.s2.mu.Unlock()
		if sweep {
			_, _ = m.db.ExecContext(ctx, `DELETE FROM cluster_log WHERE deleted = 1 AND changed_at < ?`, fmtTime(time.Now().Add(-tombstoneTTL)))
		}
	}
	own := m.syncCaps(ctx)
	var wg sync.WaitGroup // je Mitglied nebenher: ein haengendes haelt die anderen nicht auf
	for _, x := range list {
		if x.Suspended() || only != "" && x.NodeID != only {
			continue
		}
		wants := m.wants(own, x, "")
		if len(wants) == 0 {
			continue
		}
		wg.Go(func() {
			if err := m.pullSync2From(ctx, x, wants); err != nil {
				m.d.Log.Debug("cluster pull", "from", x.Name, "err", err)
			}
		})
	}
	wg.Wait()
}

func (m *Manager) pullSync2From(ctx context.Context, x Member, wants []string) error {
	m.pull.s2.mu.Lock()
	if m.pull.s2.busy == nil {
		m.pull.s2.busy = map[string]*sync.Mutex{}
	}
	lock := m.pull.s2.busy[x.NodeID]
	if lock == nil {
		lock = &sync.Mutex{}
		m.pull.s2.busy[x.NodeID] = lock
	}
	m.pull.s2.mu.Unlock()
	if !lock.TryLock() {
		return nil
	}
	defer lock.Unlock()
	var cursor, retry int64
	var seen string
	_ = m.db.QueryRowContext(ctx, `SELECT cursor2, sync_seen2, retry2 FROM peer_members WHERE node_id = ?`, x.NodeID).Scan(&cursor, &seen, &retry)
	items := joinCaps(wants)
	if seen != items { // Bereiche geaendert: von vorn (die juengere Aenderung gewinnt, doppelt schadet nicht)
		cursor, retry = 0, -1
		_, _ = m.db.ExecContext(ctx, `UPDATE peer_members SET cursor2 = 0, retry2 = -1, sync_seen2 = ? WHERE node_id = ?`, items, x.NodeID)
	}
	self, applied := m.d.NodeID(), 0
	since, retried, failed, complete := cursor, false, int64(-1), false
	// seit wann diese Node mit der Urheberin einer Aenderung verbunden ist (ist sie kein Mitglied mehr: mit dem
	// liefernden Mitglied) - fuer Provider, die Aenderungen aus der Zeit davor anders behandeln (nodecfg, API-Key).
	// Nur fuer einen mitgebrachten Stand (hier eingetragen oder von einer Node ausserhalb des Clusters); stammt der
	// Stand hier schon aus dem Cluster, gilt die Aenderung normal (Null = keine Ausnahme).
	members, _ := m.Members(ctx)
	sinceOf := func(origin string, l *syncLocal) time.Time {
		if l != nil && l.origin != self {
			for _, y := range members {
				if y.NodeID == l.origin {
					return time.Time{} // der Stand hier kam schon aus diesem Cluster: keine Ausnahme
				}
			}
		}
		for _, y := range members {
			if y.NodeID == origin {
				return y.AddedAt
			}
		}
		return x.AddedAt
	}
	m.pull.s2.mu.Lock()
	if retry >= 0 && retry < cursor && !time.Now().Before(m.pull.s2.due[x.NodeID]) {
		since, retried = retry, true
	}
	m.pull.s2.mu.Unlock()
	for page := 0; page < 100; page++ {
		var out syncOut
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := m.call(cctx, x, http.MethodGet, "/peer/v2/sync?since="+strconv.FormatInt(since, 10)+"&items="+url.QueryEscape(items), nil, &out)
		cancel()
		if err != nil {
			m.setRetry(ctx, x.NodeID, retry, failed, false) // Ablehnungen der Seiten davor nicht verlieren (cursor2 steht schon dahinter)
			return err
		}
		if out.Head < cursor { // Protokoll der anderen Node neu: von vorn
			cursor, since = 0, 0
			continue
		}
		for _, e := range out.Items {
			if e.ID == "" || e.Origin == self || !has(wants, e.Module+"/"+e.Item) {
				continue // eigene Aenderungen kommen nicht zurueck
			}
			p := m.provider(e.Module)
			if p == nil {
				continue
			}
			l, err := m.syncLocal(e.Module, e.Item, e.ID)
			if err != nil || !newer(e.ChangedAt, e.Origin, l) {
				continue
			}
			if err := p.ClusterApply(WithMemberSince(WithClusterOrigin(ctx, e.Origin, e.ChangedAt), sinceOf(e.Origin, l)), e.Item, e.ID, e.Data, e.Deleted); err != nil {
				if superseded(err) {
					continue
				}
				if m.firstReject(x.NodeID + "|" + e.Module + "/" + e.Item + "/" + e.ID + "|" + fmtTime(e.ChangedAt)) {
					m.d.Log.Warn("cluster change not applied", "from", x.Name, "module", e.Module, "item", e.Item, "err", err)
				} else {
					m.d.Log.Debug("cluster change not applied", "from", x.Name, "module", e.Module, "item", e.Item, "err", err)
				}
				if failed < 0 || e.Seq-1 < failed {
					failed = e.Seq - 1
				}
				continue
			}
			if _, err := m.logSync(e.Module, e.Item, e.ID, e.Deleted, e.Origin, e.ChangedAt); err == nil {
				applied++
			}
		}
		if out.Last > since {
			since = out.Last
		}
		if since > cursor {
			cursor = since
			_, _ = m.db.ExecContext(ctx, `UPDATE peer_members SET cursor2 = ? WHERE node_id = ?`, cursor, x.NodeID)
		}
		if !out.More {
			complete = true
			break
		}
	}
	if !complete {
		retried = false // Wiederholung nicht bis zum Ende gelaufen: die alte Stelle bleibt
	}
	m.setRetry(ctx, x.NodeID, retry, failed, retried)
	if applied > 0 {
		m.d.Log.Info("cluster entries updated", "from", x.Name, "changes", applied)
		m.pokeSoon() // an die anderen weiterreichen
	}
	return nil
}

// setRetry merkt abgelehnte Eintraege eines Mitglieds zum erneuten Abholen (old = bisherige Nummer, failed = Nummer
// vor dem ersten abgelehnten Eintrag dieses Laufs, -1 = keine). Nach einer Wiederholung gilt nur ihr Ergebnis; sonst
// bleibt eine offene Wiederholung samt Termin.
func (m *Manager) setRetry(ctx context.Context, node string, old, failed int64, retried bool) {
	next := old
	switch {
	case failed < 0 && retried:
		next = -1
	case failed < 0:
	case retried || old < 0 || failed < old:
		next = failed
	}
	s := &m.pull.s2
	s.mu.Lock()
	switch {
	case failed >= 0 && (retried || old < 0):
		if s.due == nil {
			s.due, s.tries = map[string]time.Time{}, map[string]int{}
		}
		d := sync2RetryEvery << min(s.tries[node], 7)
		s.due[node], s.tries[node] = time.Now().Add(min(d, sync2RetryMax)), s.tries[node]+1
	case next < 0:
		delete(s.tries, node)
	}
	s.mu.Unlock()
	if next != old {
		_, _ = m.db.ExecContext(ctx, `UPDATE peer_members SET retry2 = ? WHERE node_id = ?`, next, node)
	}
}

// firstReject: diese Ablehnung (Mitglied, Eintrag, Zeitpunkt) zum ersten Mal - dann Warnung, sonst nur Debug.
func (m *Manager) firstReject(key string) bool {
	s := &m.pull.s2
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.warned == nil || len(s.warned) > 10000 {
		s.warned = map[string]bool{}
	}
	if s.warned[key] {
		return false
	}
	s.warned[key] = true
	return true
}
