package peer

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/checks"
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

// Maint ist die Anbindung an die Wartungsfenster des Healthchecks-Moduls (peermaint.go).
type Maint interface {
	MaintUID(ctx context.Context, localID string) string
	PeerMaintUIDs(ctx context.Context) []string
	PeerMaintenance(ctx context.Context, uid string) (*healthchecks.PeerMaint, time.Time, time.Time, int64, error)
	ApplyPeerMaintenance(ctx context.Context, p healthchecks.PeerMaint, at time.Time, origin string) (int64, bool, error)
	DeletePeerMaintenance(ctx context.Context, uid string, remote int64, at time.Time, origin string) (int64, bool, error)
}

const (
	pullEvery = 15 * time.Second
	pageSize  = 200
)

// change ist ein Eintrag beim Abholen.
type change struct {
	Seq       int64                   `json:"seq"`
	Entity    string                  `json:"entity"`
	ID        string                  `json:"id"`
	Op        string                  `json:"op"`
	Origin    string                  `json:"origin"`
	ChangedAt time.Time               `json:"changed_at"`
	Check     *wire.Check             `json:"check,omitempty"`
	Maint     *healthchecks.PeerMaint `json:"maintenance,omitempty"`
	Remote    int64                   `json:"remote,omitempty"`   // Server-ID eines geloeschten Wartungsfensters
	Settings  map[string]string       `json:"settings,omitempty"` // Benachrichtigungs-Einstellungen (settings.go)
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
	idle  map[string]time.Time // Node mit abgeschaltetem Healthchecks: bis dahin nicht abholen
	s2    sync2State           // allgemeiner Abgleich (sync2.go)
}

const idleBackoff = 5 * time.Minute // Healthchecks bei einer anderen Node aus: so lange Ruhe statt alle 15 s

// LogChange haengt eine Aenderung an das Protokoll (Hook des Healthchecks-Stores, auch fuer Aenderungen vom hub
// und von anderen Nodes) und stoesst die Gruppe an.
func (m *Manager) LogChange(ctx context.Context, entity, id, op string) {
	switch entity {
	case "check", "settings":
	case "maintenance": // Kennung statt lokaler Nummer
		if op == "delete" {
			id = healthchecks.DeletedMaintUID(ctx)
		} else if mc := m.maint(); mc != nil {
			id = mc.MaintUID(ctx, id)
		} else {
			id = ""
		}
		if id == "" {
			return
		}
	default:
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
	_ = m.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM peer_log WHERE entity = 'check'`).Scan(&n)
	if n == 0 {
		for _, tok := range hc.PeerTokens(ctx) {
			_, _ = m.db.ExecContext(ctx, `INSERT OR IGNORE INTO peer_log (entity, entity_id, op, origin, changed_at) VALUES ('check',?,'upsert',?,?)`, tok, m.d.NodeID(), fmtTime(time.Now()))
		}
	}
	mc := m.maint()
	_ = m.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM peer_log WHERE entity = 'maintenance'`).Scan(&n)
	if n == 0 && mc != nil {
		for _, uid := range mc.PeerMaintUIDs(ctx) {
			_, _ = m.db.ExecContext(ctx, `INSERT OR IGNORE INTO peer_log (entity, entity_id, op, origin, changed_at) VALUES ('maintenance',?,'upsert',?,?)`, uid, m.d.NodeID(), fmtTime(time.Now()))
		}
	}
}

func (m *Manager) maint() Maint {
	mc, _ := m.checks().(Maint)
	return mc
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
			if x.Suspended() {
				continue
			}
			go func(x Member) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = m.call(ctx, x, http.MethodPost, "/peer/v1/poke", map[string]string{}, nil)
			}(x)
		}
	})
}

// hcItem: Bereich im Cluster-Modul Healthchecks fuer eine Eintragsart des Protokolls.
func hcItem(entity string) string {
	if entity == "check" {
		return "checks"
	}
	return entity // maintenance, settings
}

// handleChanges liefert das Protokoll ab ?since (Checks im aktuellen Stand), nur Bereiche, die hier und bei der
// abholenden Node an sind (?items, ohne Angabe laut ihrem letzten Ping).
func (m *Manager) handleChanges(w http.ResponseWriter, r *http.Request, from *Member, _ []byte) {
	hc := m.checks()
	if hc == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "healthchecks not running"})
		return
	}
	ctx := r.Context()
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	want := m.v1Wants(m.syncCaps(ctx), *from)
	if q, ok := r.URL.Query()["items"]; ok {
		asked := splitCaps(strings.Join(q, ","))
		for i := 0; i < len(want); i++ {
			if !has(asked, want[i]) {
				want = append(want[:i], want[i+1:]...)
				i--
			}
		}
	}
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
		if !has(want, hcItem(c.Entity)) {
			continue
		}
		if c.Entity == "settings" {
			if c.ChangedAt = m.settingsAt(ctx); !c.ChangedAt.IsZero() {
				c.Settings = m.settingsBundle(ctx)
				out.Items = append(out.Items, c)
			}
			continue
		}
		if c.Entity == "maintenance" {
			mc := m.maint()
			if mc == nil {
				continue
			}
			p, upd, del, rid, err := mc.PeerMaintenance(ctx, c.ID)
			switch {
			case err != nil:
				continue
			case p != nil:
				c.Op, c.Maint, c.ChangedAt = "upsert", p, upd
			case !del.IsZero(): // nur mit echtem Loeschvermerk (sonst koennte eine Loeschung bis zum hub laufen)
				c.Op, c.ChangedAt, c.Remote = "delete", del, rid
			default:
				continue
			}
			out.Items = append(out.Items, c)
			continue
		}
		if c.Entity != "check" {
			continue
		}
		chk, upd, del, err := hc.PeerCheck(ctx, c.ID, self)
		switch {
		case err != nil:
			continue
		case chk != nil:
			if !has(want, "channels") {
				chk.ChannelUIDs = nil // Kanaele hier oder dort nicht im Cluster: Zuordnung bleibt je Node
			}
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
	// Die regelmaessige Runde laeuft nebenher: ein haengendes Mitglied (nimmt an, antwortet nicht) haelt sie bis
	// zum Timeout auf, Anstoesse der anderen werden trotzdem sofort abgeholt (je Mitglied sperrt ein eigenes Schloss).
	var round atomic.Bool
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-m.pull.kick:
			m.pullAll(ctx, id)
		case <-t.C:
			if round.CompareAndSwap(false, true) {
				go func() {
					defer round.Store(false)
					m.pullAll(ctx, "")
				}()
			}
		}
	}
}

func (m *Manager) pullAll(ctx context.Context, only string) {
	if all, err := m.Members(ctx); err == nil {
		m.pullSync2(ctx, all, only) // allgemein abgeglichene Module (sync2.go)
	}
	if m.checks() == nil {
		return
	}
	if !m.seeded.Load() { // Healthchecks erst nach dem Start eingeschaltet: vorhandene Checks nachtragen
		m.seed(ctx)
		m.seeded.Store(true)
	}
	m.checkSettings(ctx)
	hc := m.hcMembers(ctx) // Messwerte, hub-Daten, Stellvertreter: nur wo die Checks auf beiden Seiten an sind
	inHC := map[string]bool{}
	for _, x := range hc {
		inHC[x.NodeID] = true
	}
	for _, x := range m.v1Members(ctx) {
		if only != "" && x.NodeID != only {
			continue
		}
		m.pull.mu.Lock()
		until := m.pull.idle[x.NodeID]
		m.pull.mu.Unlock()
		if only == "" && time.Now().Before(until) {
			continue // dort ist Healthchecks aus (ein Anstoss von ihr holt trotzdem gleich ab)
		}
		if err := m.pullFrom(ctx, x); err != nil {
			if errors.Is(err, errPeerHCOff) {
				m.pull.mu.Lock()
				if m.pull.idle == nil {
					m.pull.idle = map[string]time.Time{}
				}
				m.pull.idle[x.NodeID] = time.Now().Add(idleBackoff)
				m.pull.mu.Unlock()
			}
			m.d.Log.Debug("peer pull", "from", x.Name, "err", err)
			continue
		}
		if !inHC[x.NodeID] {
			continue
		}
		if err := m.pullData(ctx, x); err != nil {
			m.d.Log.Debug("peer measurements", "from", x.Name, "err", err)
		}
		if err := m.pullRelay(ctx, x); err != nil {
			m.d.Log.Debug("peer relay", "from", x.Name, "err", err)
		}
	}
	if only == "" {
		m.pushProxies(ctx, hc)
	}
	m.verdicts(ctx)
}

// applyMaint uebernimmt ein Wartungsfenster. Verknuepfte Nodes bekommen Fenster vom hub; aus der Gruppe
// uebernimmt nur die weiterreichende Node die Fenster nicht verknuepfter Nodes (und meldet sie dem hub).
func (m *Manager) applyMaint(ctx context.Context, x Member, c change) int {
	mc := m.maint()
	if mc == nil {
		return 0
	}
	forward := false
	if m.linkedSelf() {
		if !m.forwardFor(ctx, c.Origin) {
			return 0
		}
		forward = true
	}
	var id int64
	var ok bool
	var err error
	switch {
	case c.Op == "upsert" && c.Maint != nil:
		id, ok, err = mc.ApplyPeerMaintenance(ctx, *c.Maint, c.ChangedAt, c.Origin)
		if ok && forward {
			m.d.Forward(ctx, "maintenance", strconv.FormatInt(id, 10), "upsert")
		}
	case c.Op == "delete":
		id, ok, err = mc.DeletePeerMaintenance(ctx, c.ID, c.Remote, c.ChangedAt, c.Origin)
		if ok && forward && c.Remote > 0 {
			m.d.Forward(healthchecks.WithDeletedRemote(ctx, c.Remote), "maintenance", strconv.FormatInt(id, 10), "delete")
		}
	}
	if err != nil {
		m.d.Log.Warn("peer maintenance not applied", "from", x.Name, "id", checks.TokenHint(c.ID), "err", err)
	}
	if ok {
		return 1
	}
	return 0
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

// hubKnows: der hub kennt alle messenden Nodes – verknuepfte und nicht verknuepfte Mitglieder, die die
// weiterreichende Node dort als Stellvertreter angemeldet hat (sonst lehnt der hub den Check ab; er bleibt dann in
// der lokalen Gruppe). Nodes ausserhalb der Gruppe kennt nur der hub.
func (m *Manager) hubKnows(ctx context.Context, nodes []string) bool {
	var known map[string]bool
	for _, id := range nodes {
		if id == m.d.NodeID() {
			if !m.linkedSelf() {
				return false // diese Node misst mit und ist nicht verknuepft
			}
			continue
		}
		if x, _ := m.member(ctx, id); x != nil && !x.Linked {
			if known == nil {
				known = m.hubNodes(ctx)
			}
			if !known[id] {
				return false
			}
		}
	}
	return true
}

// hubDecides: der hub bewertet und benachrichtigt – keine der messenden Nodes ist ein nicht verknuepftes Mitglied
// der Gruppe. Checks von Stellvertreter-Nodes zeigt der hub nur an; sie bewertet und meldet die Gruppe.
func (m *Manager) hubDecides(ctx context.Context, nodes []string) bool {
	for _, id := range nodes {
		if id == m.d.NodeID() {
			if !m.linkedSelf() {
				return false
			}
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
	var seen string
	_ = m.db.QueryRowContext(ctx, `SELECT cursor, sync_seen FROM peer_members WHERE node_id = ?`, x.NodeID).Scan(&cursor, &seen)
	want := m.v1Wants(m.syncCaps(ctx), x)
	if items := joinCaps(want); seen != items { // Bereiche geaendert: von vorn (die juengere Aenderung gewinnt)
		cursor = 0
		_, _ = m.db.ExecContext(ctx, `UPDATE peer_members SET cursor = 0, sync_seen = ? WHERE node_id = ?`, items, x.NodeID)
	}
	self, applied := m.d.NodeID(), 0
	for page := 0; page < 100; page++ {
		var out changesOut
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		err := m.call(cctx, x, http.MethodGet, "/peer/v1/changes?since="+strconv.FormatInt(cursor, 10)+"&items="+joinCaps(want), nil, &out)
		cancel()
		if err != nil {
			return err
		}
		if out.Head < cursor { // Protokoll der anderen Node neu (z. B. zurueckgesetzt): von vorn
			cursor = 0
			continue
		}
		for _, c := range out.Items {
			if !has(want, hcItem(c.Entity)) {
				continue // Bereich aus, oder eine Art, die diese Node nicht kennt (nie als Check behandeln)
			}
			if c.Entity == "maintenance" {
				applied += m.applyMaint(ctx, x, c)
				continue
			}
			if c.Entity == "settings" {
				applied += m.applySettings(ctx, c)
				continue
			}
			if c.Origin == "hub" && m.linkedSelf() {
				continue // Aenderung vom hub: kommt hier direkt vom hub (sonst pendelt sie zwischen den Nodes)
			}
			var ok bool
			switch {
			case c.Op == "upsert" && c.Check != nil:
				if !has(want, "channels") {
					c.Check.ChannelUIDs = nil
				}
				ok, err = hc.ApplyPeerCheck(ctx, *c.Check, c.ChangedAt, c.Origin, self)
			case c.Op == "delete":
				ok, err = hc.DeletePeerCheck(ctx, c.ID, c.ChangedAt, c.Origin)
			}
			if err != nil {
				m.d.Log.Warn("peer change not applied", "from", x.Name, "id", checks.TokenHint(c.ID), "err", err)
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
