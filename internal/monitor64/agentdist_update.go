package monitor64

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/monitor64/agentdist"
	"github.com/ipv64net/node64/internal/update"
)

// Automatische Updates des Monitor64-Agents (Plan "Monitor64-Agent" und "Sicherheit"): Die Node merkt sich je
// Agent-Zugang Version und Plattform (Anfrage "info"). Liegt eine neuere Version vor und sind automatische Updates
// fuer den Host an, schiebt sie die signierte Datei ueber die bestehende Verbindung (Anfrage "update", auch im
// Push-Betrieb) - hoechstens agentMaxUpdates Hosts gleichzeitig, nie waehrend einer Abfragerunde desselben Hosts
// (rt.mu) und im Cluster nur von der zustaendigen Node. Der Agent prueft Signatur, Plattform und Version selbst
// (kein Downgrade) und faellt bei einem Fehlstart auf die alte Datei zurueck. Erfolg steht als Ereignis
// "Agent 0.3 -> 0.4" im Verlauf, ein Fehler am Zugang; neuer Versuch fruehestens nach agentRetryAfter.

const (
	agentMaxUpdates  = 2                // gleichzeitige Updates
	agentRetryAfter  = 6 * time.Hour    // nach einem Fehlschlag derselben Version
	agentInfoEvery   = time.Hour        // Version der Agents so oft neu fragen
	agentInfoRetry   = 5 * time.Minute  // nach einer fehlgeschlagenen Anfrage
	agentFetchWait   = 6 * time.Minute  // Datei von der Quelle holen (erster Bedarf)
	agentPushTimeout = 3 * time.Minute  // Datei uebertragen und pruefen
	agentConfirmWait = 10 * time.Minute // so lange darf die neue Version auf sich warten lassen (Rueckfall des Agents)
	agentStateFile   = "hosts.json"     // Stand je Zugang in <data>/monitor64/agent/
)

// Zeiten als Variablen, damit Tests sie kuerzen koennen.
var (
	agentFirst       = 2 * time.Minute  // erster Lauf nach dem Start
	agentTick        = time.Minute      // danach
	agentRestartWait = 45 * time.Second // nach dem Uebertragen auf den Neustart des Agents warten (Runde bleibt gesperrt)
	agentRestartPoll = 2 * time.Second
)

// agentState ist der Stand des Agents eines Zugangs (je Node gemerkt).
type agentState struct {
	Host    string        `json:"host"`                  // Host-UID
	Version string        `json:"version,omitempty"`     // aus "info"
	OS      string        `json:"os,omitempty"`          // GOOS
	Arch    string        `json:"arch,omitempty"`        // GOARCH
	TryAt   time.Time     `json:"try_at,omitzero"`       // letzter Update-Versuch
	TryVer  string        `json:"try_version,omitempty"` // Version des letzten Versuchs
	Err     string        `json:"error,omitempty"`       // Fehler des letzten Versuchs
	Pending *agentPending `json:"pending,omitempty"`     // Datei uebertragen, neue Version noch nicht bestaetigt

	infoAt  time.Time // letzte Antwort auf "info"
	infoTry time.Time // letzter Versuch
	busy    bool      // Update laeuft bzw. wartet auf einen freien Platz
}

// agentPending: ein uebertragenes Update, dessen neue Version sich noch nicht gemeldet hat.
type agentPending struct {
	From string    `json:"from"`
	To   string    `json:"to"`
	By   Actor     `json:"by"`
	At   time.Time `json:"at"`
}

func loadAgentStates(path string) map[string]*agentState {
	out := map[string]*agentState{}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	for k, st := range out {
		if st == nil {
			delete(out, k)
		}
	}
	return out
}

// saveLocked schreibt den Stand atomar (ad.mu gehalten).
func (ad *agentRT) saveLocked(dir string) error {
	b, err := json.Marshal(ad.hosts)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp := filepath.Join(dir, agentStateFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, agentStateFile))
}

// state liefert eine Kopie des Stands eines Zugangs.
func (ad *agentRT) state(acc string) (agentState, bool) {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	st := ad.hosts[acc]
	if st == nil {
		return agentState{}, false
	}
	return *st, true
}

// agentSet aendert den Stand eines Zugangs und speichert ihn, wenn fn das verlangt.
func (m *Module) agentSet(acc, host string, fn func(st *agentState) (save bool)) {
	ad := m.agents()
	ad.mu.Lock()
	defer ad.mu.Unlock()
	st := ad.hosts[acc]
	if st == nil {
		st = &agentState{}
		ad.hosts[acc] = st
	}
	st.Host = host
	if fn(st) {
		if err := ad.saveLocked(filepath.Join(m.dir(), "agent")); err != nil {
			m.log.Warn("monitor64: save agent state", "err", err)
		}
	}
}

// agentPrune vergisst Zugaenge, die es nicht mehr gibt.
func (m *Module) agentPrune(accs []*Access) {
	ad := m.agents()
	keep := map[string]bool{}
	for _, a := range accs {
		keep[a.UID] = true
	}
	ad.mu.Lock()
	defer ad.mu.Unlock()
	changed := false
	for k, st := range ad.hosts {
		if !keep[k] && !st.busy {
			delete(ad.hosts, k)
			changed = true
		}
	}
	if changed {
		if err := ad.saveLocked(filepath.Join(m.dir(), "agent")); err != nil {
			m.log.Warn("monitor64: save agent state", "err", err)
		}
	}
}

// sameAgentVersion: gleiche Version unabhaengig von der Schreibweise ("v0.4.0" = "0.4.0").
func sameAgentVersion(a, b string) bool {
	return strings.TrimPrefix(strings.TrimSpace(a), "v") == strings.TrimPrefix(strings.TrimSpace(b), "v")
}

// rtOf liefert den Laufzeitstand eines Hosts (nil = nicht eingeplant).
func (m *Module) rtOf(uid string) *hostRT {
	m.rtMu.Lock()
	defer m.rtMu.Unlock()
	return m.rts[uid]
}

// agentCol liefert den Sammler eines Agent-Zugangs (rt.mu gehalten).
func (rt *hostRT) agentCol(acc string) *agentCollector {
	for _, a := range rt.accs {
		if a.row.UID == acc {
			c, _ := a.col.(*agentCollector)
			return c
		}
	}
	return nil
}

// agentInfo fragt Version und Plattform ab (rt.mu gehalten).
func agentInfo(ctx context.Context, ac *agentCollector) (*m64proto.Info, error) {
	c, err := ac.ref.agent(ac.cfg)
	if err != nil {
		return nil, err
	}
	return c.Info(ctx)
}

// agentLoop laeuft, solange das Modul laeuft: Verzeichnis regelmaessig holen, Versionen der Agents merken,
// automatische Updates anstossen. Ohne Agent-Zugang tut eine Runde nichts.
func (m *Module) agentLoop(ctx context.Context) {
	ad := &m.ad
	ad.mu.Lock()
	ad.life = ctx
	ad.mu.Unlock()
	defer func() {
		ad.mu.Lock()
		ad.life = nil
		ad.mu.Unlock()
		if ad.dist != nil {
			ad.dist.Abort() // laufende Abrufe beenden
		}
	}()
	t := time.NewTimer(agentFirst)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.agentRound(ctx)
			t.Reset(agentTick)
		}
	}
}

// agentLife ist der Kontext fuer Arbeit im Hintergrund (nil = Modul laeuft nicht).
func (m *Module) agentLife() context.Context {
	m.ad.mu.Lock()
	defer m.ad.mu.Unlock()
	return m.ad.life
}

// agentRound ist ein Durchgang ueber alle Agent-Zugaenge.
func (m *Module) agentRound(ctx context.Context) {
	all, err := m.agentAccesses(ctx)
	if err != nil {
		return
	}
	ad := m.agents()
	m.agentPrune(all)
	var accs []*Access
	for _, a := range all {
		if a.Enabled {
			accs = append(accs, a)
		}
	}
	if len(accs) == 0 {
		return // ohne Agent-Host keine Arbeit, auch kein Abruf des Verzeichnisses
	}
	if ad.dist.Due(agentIndexEvery, agentIndexRetry) {
		if err := ad.dist.Refresh(ctx); err != nil && ctx.Err() == nil {
			m.log.Warn("monitor64: agent index", "err", err)
		}
		m.agentPurgeEvents(ctx)
	}
	ix := ad.dist.Index()
	for _, a := range accs {
		if ctx.Err() != nil {
			return
		}
		rt := m.rtOf(a.HostUID)
		if rt == nil || !m.agentCheck(ctx, rt, a.UID, ix) {
			continue
		}
		select {
		case ad.slots <- struct{}{}: // hoechstens agentMaxUpdates gleichzeitig; sonst beim naechsten Durchgang
			if !m.agentBegin(a.UID, a.HostUID) {
				<-ad.slots
				continue
			}
			go func() {
				defer func() { <-ad.slots }()
				m.agentUpdate(ctx, rt, a.UID, SystemActor)
			}()
		default:
		}
	}
}

// agentPurgeEvents loescht alte Ereignisse "Agent a -> b" (hoechstens taeglich; so lange wie die Problem-Historie).
func (m *Module) agentPurgeEvents(ctx context.Context) {
	ad := m.agents()
	ad.mu.Lock()
	due := time.Since(ad.events) >= 24*time.Hour
	if due {
		ad.events = time.Now()
	}
	ad.mu.Unlock()
	if !due {
		return
	}
	if _, err := m.st.Writer().ExecContext(ctx, `DELETE FROM m64_events WHERE kind = ? AND problem_uid = '' AND ts < ?`, agentEventKind, ts(time.Now().Add(-keepProblems))); err != nil && ctx.Err() == nil {
		m.log.Warn("monitor64: purge agent events", "err", err)
	}
}

// agentReporting: diese Node ist fuer den Host zustaendig und meldet (im Cluster nicht kurz nach dem Start).
func (m *Module) agentReporting(h *Host) bool {
	if role, _ := m.roleOf(h); role != roleReport {
		return false
	}
	return !(m.clusterSnapshot().Active && m.clusterStarting())
}

// agentCheck merkt Version und Plattform eines Agents und sagt, ob jetzt ein automatisches Update faellig ist.
// Laeuft gerade eine Runde des Hosts, geschieht nichts (naechster Durchgang).
func (m *Module) agentCheck(ctx context.Context, rt *hostRT, acc string, ix *agentdist.Index) bool {
	if !rt.mu.TryLock() {
		return false
	}
	defer rt.mu.Unlock()
	h := rt.host
	if rt.removed || h.Paused || !m.agentReporting(h) {
		return false
	}
	ac := rt.agentCol(acc)
	if ac == nil || rt.getView() == nil || rt.Failures[acc] > 0 {
		return false // noch keine Runde bzw. der Zugang antwortet gerade nicht
	}
	now := time.Now()
	st, _ := m.agents().state(acc)
	if st.busy {
		return false
	}
	ask := st.infoAt.IsZero() && now.Sub(st.infoTry) >= agentInfoRetry || !st.infoAt.IsZero() && now.Sub(st.infoAt) >= agentInfoEvery ||
		st.Pending != nil // nach einem Update bei jedem Durchgang, bis die neue Version da ist
	if ask {
		info, err := agentInfo(ctx, ac)
		st = m.agentNoteInfo(ctx, h, acc, info, err, now)
		if err != nil {
			return false
		}
	}
	if st.Pending != nil || st.Version == "" || ix == nil || !update.Newer(ix.Version, st.Version) {
		return false
	}
	if _, ok := ix.Files[agentdist.Key(st.OS, st.Arch)]; !ok || !h.AgentAutoUpd {
		return false
	}
	return st.TryVer != ix.Version || now.Sub(st.TryAt) >= agentRetryAfter
}

// agentNoteInfo uebernimmt die Antwort auf "info" in den Stand und schliesst ein wartendes Update ab: neue Version
// da = Ereignis im Verlauf; meldet sich nach agentConfirmWait weiter die alte, ist der Agent zurueckgefallen.
func (m *Module) agentNoteInfo(ctx context.Context, h *Host, acc string, info *m64proto.Info, err error, now time.Time) agentState {
	var done *agentPending
	m.agentSet(acc, h.UID, func(st *agentState) bool {
		st.infoTry = now
		if err != nil || info == nil {
			return false
		}
		save := st.Version != info.Version || st.OS != info.OS || st.Arch != info.Arch
		st.infoAt, st.Version, st.OS, st.Arch = now, cleanAgentText(info.Version, 40), cleanAgentText(info.OS, 16), cleanAgentText(info.Arch, 16)
		if p := st.Pending; p != nil {
			switch {
			case sameAgentVersion(st.Version, p.To):
				done, st.Pending, st.Err, save = p, nil, "", true
			case now.Sub(p.At) >= agentConfirmWait:
				st.Pending, save = nil, true
				st.Err = i18nText("monitor64.agent.err_fallback", "to", p.To, "from", st.Version)
			}
		} else if st.Err != "" && st.TryVer != "" && !update.Newer(st.TryVer, st.Version) {
			st.Err, save = "", true // inzwischen aktuell (z. B. von Hand installiert)
		}
		return save
	})
	if done != nil {
		m.agentUpdated(ctx, h, done)
	}
	st, _ := m.agents().state(acc)
	return st
}

// cleanAgentText kuerzt Angaben des Agents (vom Host bestimmt) und entfernt Steuerzeichen.
func cleanAgentText(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > limit {
		s = string(r[:limit])
	}
	return s
}

// agentUpdated schreibt das Ereignis "Agent a -> b" in den Verlauf des Hosts.
func (m *Module) agentUpdated(ctx context.Context, h *Host, p *agentPending) {
	m.event(context.WithoutCancel(ctx), "", h.UID, "", agentEventKind, i18nText("monitor64.detail.agent_updated", "from", p.From, "to", p.To), p.By, time.Now())
	m.log.Info("monitor64: agent updated", "host", h.Name, "from", p.From, "to", p.To, "by", p.By.Kind)
}

// agentBegin merkt, dass fuer den Zugang ein Update laeuft (false = laeuft schon).
func (m *Module) agentBegin(acc, host string) bool {
	ok := false
	m.agentSet(acc, host, func(st *agentState) bool {
		ok = !st.busy
		st.busy = true
		return false
	})
	return ok
}

// agentUpdate schiebt die aktuelle Version auf einen Agent (agentBegin vorher, ein Platz in ad.slots belegt).
func (m *Module) agentUpdate(ctx context.Context, rt *hostRT, acc string, by Actor) {
	h := rt.host
	err := m.agentPush(ctx, rt, acc, by)
	failed := err != nil && !errors.Is(err, errAgentGone) && ctx.Err() == nil // Stopp des Moduls ist kein Fehler des Hosts
	m.agentSet(acc, h.UID, func(st *agentState) bool {
		st.busy = false
		if failed {
			st.Err = shortErr(err)
		}
		return true
	})
	if failed {
		m.log.Warn("monitor64: agent update", "host", h.Name, "err", err)
	}
}

// errAgentGone: der Host wurde waehrend des Updates geaendert oder entfernt (kein Fehler am Zugang).
var errAgentGone = errors.New("host changed during the update")

func (m *Module) agentPush(ctx context.Context, rt *hostRT, acc string, by Actor) error {
	ad := m.agents()
	h := rt.host
	st, _ := ad.state(acc)
	ix := ad.dist.Index()
	if ix == nil {
		return errors.New(i18nText("monitor64.agent.err_no_index"))
	}
	if st.Version == "" { // "jetzt aktualisieren" vor der ersten Auskunft
		rt.mu.Lock()
		ac := rt.agentCol(acc)
		if rt.removed || ac == nil {
			rt.mu.Unlock()
			return errAgentGone
		}
		info, err := agentInfo(ctx, ac)
		rt.mu.Unlock()
		st = m.agentNoteInfo(ctx, h, acc, info, err, time.Now())
		if err != nil {
			return err
		}
	}
	if !update.Newer(ix.Version, st.Version) {
		return nil // schon aktuell
	}
	if _, ok := ix.Files[agentdist.Key(st.OS, st.Arch)]; !ok {
		return errors.New(i18nText("monitor64.agent.err_no_file", "platform", agentdist.Key(st.OS, st.Arch)))
	}
	// Versuch merken (auch wenn schon das Holen der Datei scheitert: neuer Versuch erst nach agentRetryAfter)
	from := st.Version
	m.agentSet(acc, h.UID, func(s *agentState) bool {
		s.TryAt, s.TryVer, s.Err, s.Pending = time.Now(), ix.Version, "", nil
		return true
	})
	// Datei bereitlegen (erster Bedarf: von der Quelle holen), bevor die Runde des Hosts gesperrt wird
	fctx, cancel := context.WithTimeout(ctx, agentFetchWait)
	path, hdr, err := ad.dist.Program(fctx, agentdist.FileName(st.OS, st.Arch))
	cancel()
	if err != nil {
		return err
	}

	rt.mu.Lock() // wartet auf eine laufende Runde; bis der Agent wieder da ist, laeuft keine neue
	defer rt.mu.Unlock()
	ac := rt.agentCol(acc)
	if rt.removed || ac == nil {
		return errAgentGone
	}
	c, err := ac.ref.agent(ac.cfg)
	if err != nil {
		return err
	}
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	pctx, cancel := context.WithTimeout(ctx, agentPushTimeout)
	_, err = c.Update(pctx, hdr, in)
	cancel()
	_ = in.Close()
	if err != nil {
		return err
	}
	// Uebertragen und vom Agent angenommen: er startet neu. Kurz warten, bis sich die neue Version meldet - so faellt
	// die naechste Runde nicht in den Neustart, und der Erfolg steht gleich im Verlauf.
	pending := &agentPending{From: from, To: hdr.Version, By: by, At: time.Now()}
	m.agentSet(acc, h.UID, func(s *agentState) bool {
		s.Pending = pending
		return true
	})
	deadline := time.Now().Add(agentRestartWait)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(agentRestartPoll):
		}
		ictx, cancel := context.WithTimeout(ctx, 10*time.Second)
		info, err := agentInfo(ictx, ac)
		cancel()
		if err == nil && sameAgentVersion(info.Version, hdr.Version) {
			m.agentNoteInfo(ctx, h, acc, info, nil, time.Now())
			return nil
		}
	}
	return nil // noch nicht bestaetigt: agentCheck fragt weiter (bis agentConfirmWait)
}

// apiAgentUpdate: POST "jetzt aktualisieren" fuer einen Host (auch bei abgeschalteten automatischen Updates). Das
// Update laeuft im Hintergrund; der Stand steht danach unter /api/monitor64/agent bzw. am Zugang.
func (m *Module) apiAgentUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	h, err := m.store.Host(ctx, r.PathValue("uid"))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	life, rt := m.agentLife(), m.rtOf(h.UID)
	if life == nil || rt == nil {
		m.fail(w, r, errNotRunning)
		return
	}
	if !m.agentReporting(h) { // Cluster: nur die zustaendige Node hat die Verbindung
		m.fail(w, r, errBad("agent_elsewhere"))
		return
	}
	accs, err := m.store.Accesses(ctx, h.UID)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	ad := m.agents()
	if ad.dist.Index() == nil { // erster Bedarf: Verzeichnis holen
		rctx, cancel := context.WithTimeout(ctx, agentRefreshWait)
		if err := ad.dist.Refresh(rctx); err != nil {
			m.log.Warn("monitor64: agent index", "err", err)
		}
		cancel()
	}
	ix := ad.dist.Index()
	if ix == nil {
		m.fail(w, r, errBad("agent_no_index"))
		return
	}
	var todo []string
	found := false
	for _, a := range accs {
		if a.Type != "agent" || !a.Enabled {
			continue
		}
		found = true
		st, _ := ad.state(a.UID)
		if st.busy {
			m.fail(w, r, errBad("agent_busy"))
			return
		}
		if st.Version != "" && !update.Newer(ix.Version, st.Version) {
			continue
		}
		if _, ok := ix.Files[agentdist.Key(st.OS, st.Arch)]; st.Version != "" && !ok {
			m.fail(w, r, errBad("agent_no_file", "platform", agentdist.Key(st.OS, st.Arch)))
			return
		}
		todo = append(todo, a.UID)
	}
	switch {
	case !found:
		m.fail(w, r, errBad("agent_none"))
		return
	case len(todo) == 0:
		m.fail(w, r, errBad("agent_current", "version", ix.Version))
		return
	}
	by := m.actor(r)
	for _, acc := range todo {
		if !m.agentBegin(acc, h.UID) {
			continue
		}
		go func() {
			select {
			case ad.slots <- struct{}{}: // wartet auf einen freien Platz
				defer func() { <-ad.slots }()
				m.agentUpdate(life, rt, acc, by)
			case <-life.Done():
				m.agentSet(acc, h.UID, func(st *agentState) bool { st.busy = false; return false })
			}
		}()
	}
	m.audit(r, "agent.update", h.Name, "uid="+h.UID+" to="+ix.Version)
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "version": ix.Version})
}
