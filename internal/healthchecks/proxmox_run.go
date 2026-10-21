package healthchecks

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/proxmox"
	"github.com/ipv64net/node64/internal/scheduler"
	"github.com/ipv64net/node64/internal/secrets"
)

// Proxmox VE (Plan docs/PLAN-NODE64-PROXMOX.md): Laufzeit der Ueberwachung im Modul Healthchecks. Je eingeschaltetem
// System laeuft ein proxmox.Poller; jeder Snapshot geht durch die Regeln (Engine → Benachrichtigung) und in den
// Verlauf. Gemeldete Stoerungen ueberstehen einen Neustart (Einstellung pve.engine.<id>). Gaeste bzw. Nodes „als
// Check“ sind normale Checks vom Typ proxmox, die den letzten Snapshot lesen (pveLookup).

const (
	pveSettingEngine = "pve.engine."       // + System-ID: gemeldete Stoerungen (JSON, leer = keine)
	pveSettingLast   = "pve.last_incident" // letzte Stoerung (Startseite)
	pveCheckGroup    = "Proxmox VE"        // Gruppe der Checks „als Check“
	pveRetentionRead = time.Minute         // Aufbewahrung (hc.raw_days/hc.hourly_days) so oft neu lesen
)

// pveRuntime ist der Laufzeitzustand der Proxmox-Ueberwachung.
type pveRuntime struct {
	mu        sync.Mutex
	st        *proxmox.Store
	box       *secrets.Box
	engine    *proxmox.Engine
	ctx       context.Context // Kontext von Start (nil = gestoppt)
	polls     map[int64]*pvePoll
	errs      map[int64]string // System wird nicht abgefragt: Grund (z. B. Secret nicht lesbar)
	saved     map[int64]string // zuletzt gespeicherter Stand der Engine (JSON)
	fails     map[int64]int64  // fehlgeschlagene Abfragen seit dem Start (Prometheus)
	retention time.Time        // letztes Lesen der Aufbewahrung
	wg        sync.WaitGroup
	// Tests: noRun startet keine Abfrage-Schleife (Abfragen nur per Poll), alert faengt Meldungen ab
	noRun bool
	alert func(notify.Alert)
}

type pvePoll struct {
	sys    proxmox.System
	p      *proxmox.Poller
	cancel context.CancelFunc
	done   chan struct{}
}

// pveIncident ist die letzte Stoerung (Startseite).
type pveIncident struct {
	SystemID int64     `json:"system_id"`
	Key      string    `json:"key"`
	Name     string    `json:"name"`
	What     string    `json:"what"`
	Time     time.Time `json:"time"`
}

func newPVERuntime(m *Module, box *secrets.Box) *pveRuntime {
	return &pveRuntime{st: proxmox.NewStore(m.core, box), box: box, engine: proxmox.NewEngine(), polls: map[int64]*pvePoll{},
		errs: map[int64]string{}, saved: map[int64]string{}, fails: map[int64]int64{}}
}

// SetSecrets setzt den Schluessel fuer die Token-Secrets der Proxmox-Systeme (vor Start aufrufen).
func (m *Module) SetSecrets(box *secrets.Box) {
	m.box = box
	m.pve = newPVERuntime(m, box)
}

// PVEStore gibt die Datenhaltung der Proxmox-Ueberwachung frei (Tests, Einbindung).
func (m *Module) PVEStore() *proxmox.Store { return m.pve.st }

// pveStart startet die Abfrage aller eingeschalteten Systeme und stellt gemeldete Stoerungen wieder her.
func (m *Module) pveStart(ctx context.Context) {
	rt := m.pve
	rt.mu.Lock()
	rt.ctx = ctx
	rt.engine = proxmox.NewEngine()
	rt.errs, rt.saved = map[int64]string{}, map[int64]string{}
	rt.mu.Unlock()
	rt.st.SetRetention(RawDays(m.core), HourlyDays(m.core))
	list, err := rt.st.Systems(ctx)
	if err != nil {
		m.log.Error("proxmox systems", "err", err)
		return
	}
	for _, sys := range list {
		if raw := m.core.SettingOr(ctx, pveSettingEngine+strconv.FormatInt(sys.ID, 10), ""); raw != "" && sys.Enabled {
			var es proxmox.EngineState
			if json.Unmarshal([]byte(raw), &es) == nil {
				rt.engine.Import(sys.ID, &es)
				rt.mu.Lock()
				rt.saved[sys.ID] = raw
				rt.mu.Unlock()
			}
		}
		if sys.Enabled {
			m.pveRun(ctx, sys)
		}
	}
	if len(list) > 0 {
		m.log.Info("proxmox monitoring started", "systems", len(list))
	}
}

// pveStop beendet alle Abfragen (Stop des Moduls).
func (m *Module) pveStop() {
	rt := m.pve
	rt.mu.Lock()
	rt.ctx = nil
	polls := rt.polls
	rt.polls = map[int64]*pvePoll{}
	rt.mu.Unlock()
	for _, p := range polls {
		p.cancel()
	}
	rt.wg.Wait()
}

// pveRun startet die Abfrage eines Systems (vorher laufende wird beendet).
func (m *Module) pveRun(ctx context.Context, sys *proxmox.System) {
	rt := m.pve
	m.pveHalt(sys.ID)
	if sys.Secret == "" {
		reason := m.pveSecretProblem(ctx, sys.ID)
		rt.mu.Lock()
		rt.errs[sys.ID] = reason
		rt.mu.Unlock()
		m.log.Error("proxmox system not polled", "system", sys.Name, "reason", reason)
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.ctx == nil {
		return // Modul gestoppt
	}
	delete(rt.errs, sys.ID)
	pctx, cancel := context.WithCancel(rt.ctx)
	p := proxmox.NewPoller(m.log, *sys, m.pveSnapshot)
	pp := &pvePoll{sys: *sys, p: p, cancel: cancel, done: make(chan struct{})}
	rt.polls[sys.ID] = pp
	if rt.noRun {
		close(pp.done)
		return
	}
	rt.wg.Add(1)
	go func() {
		defer rt.wg.Done()
		defer close(pp.done)
		p.Run(pctx)
	}()
}

// pveHalt beendet die Abfrage eines Systems und wartet darauf.
func (m *Module) pveHalt(id int64) {
	rt := m.pve
	rt.mu.Lock()
	pp := rt.polls[id]
	delete(rt.polls, id)
	delete(rt.errs, id)
	rt.mu.Unlock()
	if pp != nil {
		pp.cancel()
		<-pp.done
	}
}

// pveReload liest ein System neu und startet bzw. beendet seine Abfrage (nach Anlegen, Aendern, Ein-/Ausschalten).
func (m *Module) pveReload(ctx context.Context, id int64) {
	sys, err := m.pve.st.System(ctx, id)
	if err != nil || !sys.Enabled {
		m.pveHalt(id)
		m.pveForget(ctx, id)
		return
	}
	m.pveRun(ctx, sys)
}

// pveForget verwirft den Stand der Regeln eines Systems (geloescht oder abgeschaltet).
func (m *Module) pveForget(ctx context.Context, id int64) {
	rt := m.pve
	rt.engine.Forget(id)
	rt.mu.Lock()
	had := rt.saved[id] != ""
	delete(rt.saved, id)
	rt.mu.Unlock()
	if had || m.core.SettingOr(ctx, pveSettingEngine+strconv.FormatInt(id, 10), "") != "" {
		_ = m.core.SetSetting(ctx, pveSettingEngine+strconv.FormatInt(id, 10), "")
	}
}

// pveSecretProblem erklaert, warum ein System kein Secret hat: fehlt (z. B. Import ohne Passwort) oder laesst
// sich nicht entschluesseln (secret.key fehlt bzw. ersetzt).
func (m *Module) pveSecretProblem(ctx context.Context, id int64) string {
	var raw string
	_ = m.core.Reader().QueryRowContext(ctx, `SELECT secret FROM pve_systems WHERE id = ?`, id).Scan(&raw)
	switch {
	case raw == "":
		return "token secret missing – enter the secret again (edit the system)"
	case secrets.IsEncrypted(raw) && m.box == nil:
		return "no secret key loaded – the token secret cannot be decrypted"
	case secrets.IsEncrypted(raw):
		if _, err := m.box.Decrypt(raw); err != nil {
			return "token secret cannot be decrypted (secret.key missing or replaced) – enter the secret again"
		}
	}
	return "token secret missing – enter the secret again (edit the system)"
}

// pvePollOf liefert die laufende Abfrage eines Systems (nil = keine) und ggf. den Grund.
func (m *Module) pvePollOf(id int64) (*pvePoll, string) {
	rt := m.pve
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.polls[id], rt.errs[id]
}

// pveLast liefert den letzten Snapshot eines Systems (nil = keiner).
func (m *Module) pveLast(id int64) *proxmox.Snapshot {
	if pp, _ := m.pvePollOf(id); pp != nil {
		return pp.p.Last()
	}
	return nil
}

// pveSnapshot verarbeitet einen Snapshot (Callback des Pollers): Regeln → Benachrichtigung, Stand sichern, Verlauf.
func (m *Module) pveSnapshot(ctx context.Context, s *proxmox.Snapshot) {
	rt := m.pve
	if !s.OK {
		rt.mu.Lock()
		rt.fails[s.SystemID]++
		rt.mu.Unlock()
	}
	now := time.Now()
	rt.mu.Lock()
	due := now.Sub(rt.retention) >= pveRetentionRead
	if due {
		rt.retention = now
	}
	rt.mu.Unlock()
	if due { // Aufbewahrung wie in den lokalen Einstellungen der Healthchecks (Aenderung greift spaetestens hier)
		rt.st.SetRetention(RawDays(m.core), HourlyDays(m.core))
	}
	set, err := rt.st.Settings(ctx, s.SystemID)
	if err != nil {
		return // System inzwischen geloescht
	}
	m.pveCheckLinks(ctx, set)
	evs := rt.engine.Evaluate(s, set)
	m.pvePersist(ctx, s.SystemID)
	for _, ev := range evs {
		m.pveNotify(ctx, set, s, ev)
	}
	if err := rt.st.Record(ctx, s); err != nil && ctx.Err() == nil {
		m.log.Error("proxmox history", "system", set.Name, "err", err)
	}
}

// pveCheckLinks: wurde ein Check „als Check“ in der Liste der Healthchecks geloescht, gilt der Gast wieder als normal
// ueberwacht (sonst meldete niemand seinen Zustand).
func (m *Module) pveCheckLinks(ctx context.Context, set *proxmox.SystemSettings) {
	for _, it := range set.Items {
		if !it.AsCheck {
			continue
		}
		if c, err := m.st.Check(ctx, it.CheckToken); err == nil && c != nil {
			continue
		} else if err != nil {
			continue
		}
		it.AsCheck, it.CheckToken = false, ""
		if err := m.pve.st.SaveSettings(ctx, it); err != nil {
			m.log.Error("proxmox settings", "err", err)
		}
	}
}

// pvePersist speichert den Stand der Regeln, wenn er sich geaendert hat.
func (m *Module) pvePersist(ctx context.Context, id int64) {
	rt := m.pve
	raw := ""
	if es := rt.engine.Export(id); es != nil {
		b, _ := json.Marshal(es)
		raw = string(b)
	}
	rt.mu.Lock()
	same := rt.saved[id] == raw
	rt.saved[id] = raw
	rt.mu.Unlock()
	if same {
		return
	}
	if err := m.core.SetSetting(context.WithoutCancel(ctx), pveSettingEngine+strconv.FormatInt(id, 10), raw); err != nil {
		m.log.Error("proxmox engine state", "err", err)
	}
}

// pveKindOf ordnet die Ereignisart der Regeln der Benachrichtigungsart zu.
func pveKindOf(kind string) (notify.Kind, bool) {
	switch kind {
	case proxmox.KindDown:
		return notify.KindProxmoxDown, true
	case proxmox.KindUp:
		return notify.KindProxmoxUp, true
	case proxmox.KindThreshold:
		return notify.KindProxmoxThreshold, true
	case proxmox.KindThresholdOK:
		return notify.KindProxmoxThresholdOK, true
	case proxmox.KindRestarted:
		return notify.KindProxmoxRestarted, true
	}
	return "", false
}

// pveKeyType: Typ aus dem Key (node, qemu, lxc; leer = System).
func pveKeyType(key string) string {
	t, _, _ := strings.Cut(key, "/")
	return t
}

// pveResPath: Seite eines Systems bzw. einer Ressource.
func pveResPath(id int64, key string) string {
	p := pvePath + "/system/" + strconv.FormatInt(id, 10)
	if key != "" {
		p += "/res/" + key
	}
	return p
}

// pveNotify verschickt ein Ereignis der Regeln (Text in der Sprache des Kanals ueber pve.ev.<Kind>.<What>).
func (m *Module) pveNotify(ctx context.Context, set *proxmox.SystemSettings, s *proxmox.Snapshot, ev proxmox.Event) {
	kind, ok := pveKindOf(ev.Kind)
	if !ok {
		return
	}
	name := set.Name
	if ev.Key != "" {
		name += " – " + ev.Name
	}
	data := map[string]string{"what": ev.What, "type": pveKeyType(ev.Key), "name": ev.Name, "system": set.Name, "detail": ev.Detail,
		"path": pveResPath(set.SystemID, ev.Key)}
	if ev.Key == "" {
		data["name"] = set.Name
	}
	if ev.Kind == proxmox.KindThreshold || ev.Kind == proxmox.KindThresholdOK {
		data["value"] = strconv.FormatFloat(ev.Value, 'f', -1, 64)
		data["limit"] = strconv.FormatFloat(ev.Limit, 'f', -1, 64)
	}
	at := s.Time
	if at.IsZero() {
		at = time.Now()
	}
	node := ""
	for i := range s.Resources {
		if s.Resources[i].Key() == ev.Key {
			node = s.Resources[i].Node
			break
		}
	}
	a := notify.Alert{EventID: "pve-" + strconv.FormatInt(set.SystemID, 10) + "-" + ev.Key + "-" + ev.Kind + "-" + strconv.FormatInt(at.UnixNano(), 36),
		Kind: kind, Time: at.UTC(), Reason: ev.What, Data: data,
		Check: notify.CheckInfo{Name: name, Type: string(checks.TypeProxmox), Target: ev.Key, NotifyDown: true, NotifyUp: true, Local: true,
			Channels: m.pveChannels(ctx, set.Effective(ev.Key, node).Channels)}}
	// Ruhezeit ist Ruhezeit, auch beim Absturz (Dennis 2026-10-21): der Dispatcher merkt die Meldung und schickt sie
	// danach in der Sammelmeldung wie bei Checks. Wartungsfenster unterdruecken die Meldung: Fenster fuer alle Checks
	// immer, Fenster fuer bestimmte Checks, wenn der Gast als Check gefuehrt wird.
	tok := ""
	if it := set.Items[ev.Key]; it != nil {
		tok = it.CheckToken
	}
	if m.st != nil && m.st.InMaintenance(ctx, tok, at) {
		m.log.Info("proxmox event suppressed (maintenance)", "system", set.Name, "key", ev.Key, "kind", ev.Kind, "what", ev.What)
		return
	}
	if ev.Kind == proxmox.KindUp && !ev.Since.IsZero() {
		a.Duration = at.Sub(ev.Since)
	}
	if ev.Kind == proxmox.KindDown {
		inc := pveIncident{SystemID: set.SystemID, Key: ev.Key, Name: name, What: ev.What, Time: at.UTC()}
		if b, err := json.Marshal(inc); err == nil {
			_ = m.core.SetSetting(context.WithoutCancel(ctx), pveSettingLast, string(b))
		}
	}
	m.log.Info("proxmox event", "system", set.Name, "key", ev.Key, "kind", ev.Kind, "what", ev.What)
	if m.pve.alert != nil {
		m.pve.alert(a)
	} else if m.dispatcher != nil {
		m.dispatcher.Dispatch(a)
	}
}

// pveChannels liefert die Kanaele einer Meldung aus der wirksamen Regel ohne geloeschte Kanaele (nil = Standardkanaele,
// auch wenn keiner der gewaehlten mehr existiert).
func (m *Module) pveChannels(ctx context.Context, ids []int64) []int64 {
	if len(ids) == 0 {
		return nil
	}
	all, err := m.channels(ctx)
	if err != nil || m.notifyStore == nil {
		return ids // Kanaele nicht lesbar bzw. kein Kanalspeicher: der Dispatcher ignoriert unbekannte ohnehin
	}
	have := map[int64]bool{}
	for _, ch := range all {
		have[ch.ID] = true
	}
	var out []int64
	for _, id := range ids {
		if have[id] {
			out = append(out, id)
		}
	}
	return out
}

// pveLastIncident liefert die letzte Stoerung (nil = keine).
func (m *Module) pveLastIncident(ctx context.Context) *pveIncident {
	raw := m.core.SettingOr(ctx, pveSettingLast, "")
	if raw == "" {
		return nil
	}
	var inc pveIncident
	if json.Unmarshal([]byte(raw), &inc) != nil || inc.Time.IsZero() {
		return nil
	}
	return &inc
}

// pveLookup liefert dem Check-Typ proxmox den letzten Stand eines Gasts bzw. Nodes.
func (m *Module) pveLookup(systemID int64, key string) checks.ProxmoxState {
	var st checks.ProxmoxState
	pp, reason := m.pvePollOf(systemID)
	if pp == nil {
		st.Error = reason
		if sys, err := m.pve.st.System(context.Background(), systemID); err == nil {
			st.System = sys.Name
			if !sys.Enabled && reason == "" {
				st.Error = "proxmox system " + sys.Name + " is switched off"
			}
		} else if reason == "" {
			st.Error = "proxmox system not found"
		}
		return st
	}
	st.System, st.Polling, st.Interval = pp.sys.Name, true, proxmox.ClampInterval(pp.sys.Interval)
	s := pp.p.Last()
	if s == nil {
		return st
	}
	st.Time, st.Reachable, st.Error = s.Time, s.OK, s.Error
	for i := range s.Resources {
		r := &s.Resources[i]
		if r.Key() != key {
			continue
		}
		st.Found, st.Name, st.Node, st.State, st.Status, st.QMP, st.Lock, st.Uptime = true, r.Name, r.Node, string(r.State), r.Status, r.QMP, r.Lock, r.Uptime
		break
	}
	return st
}

// ---------------------------------------------------------------- „auch als Check fuehren“

// pveCheckInterval: Intervall des Checks wie das System (mindestens das kleinste Check-Intervall).
func pveCheckInterval(sys *proxmox.System) time.Duration {
	return max(proxmox.ClampInterval(sys.Interval), checks.MinInterval)
}

// pveResName liefert den Anzeigenamen eines Keys aus dem letzten Snapshot (sonst den Key).
func (m *Module) pveResName(id int64, key string) string {
	if s := m.pveLast(id); s != nil {
		for i := range s.Resources {
			if r := &s.Resources[i]; r.Key() == key {
				if r.Name != "" {
					return r.Name
				}
				break
			}
		}
	}
	return key
}

// pveSetAsCheck schaltet „auch als Check fuehren“ fuer einen Gast bzw. Node: legt den Check an bzw. loescht ihn.
func (m *Module) pveSetAsCheck(r *http.Request, sys *proxmox.System, key string, on bool) error {
	ctx := r.Context()
	if key == "" || !proxmox.ValidKey(key) {
		return &proxmox.FieldError{Field: "key", Key: "pve.err.key"}
	}
	set, err := m.pve.st.Settings(ctx, sys.ID)
	if err != nil {
		return err
	}
	it := set.Item(key)
	if it == nil {
		it = &proxmox.Settings{SystemID: sys.ID, Key: key}
	}
	var existing *Check
	if it.CheckToken != "" {
		existing, _ = m.st.Check(ctx, it.CheckToken)
	}
	if on {
		if existing != nil {
			it.AsCheck = true
			return m.pve.st.SaveSettings(ctx, it)
		}
		params, _ := json.Marshal(checks.ProxmoxParams{SystemID: sys.ID, Key: key})
		iv := int(pveCheckInterval(sys).Seconds())
		riv := min(20, iv)
		group := pveCheckGroup
		in := checkJSON{Name: sys.Name + " – " + m.pveResName(sys.ID, key), Type: string(checks.TypeProxmox), Target: key, Params: params,
			IntervalSeconds: &iv, RetryIntervalSeconds: &riv, Group: &group, Tags: []string{"proxmox"}, Execution: "local"}
		c := &Check{Token: NewToken(), UpdatedBy: m.actor(r)}
		if err := m.apply(c, in, true); err != nil {
			return err
		}
		if err := m.st.Insert(ctx, c); err != nil {
			return err
		}
		c, _ = m.st.Check(ctx, c.Token)
		if s := m.scheduler(); s != nil && c != nil {
			upsertSched(s, c, nil)
		}
		if c != nil {
			m.audit(r, "check.create", c)
			it.CheckToken = c.Token
		}
		it.AsCheck = true
		return m.pve.st.SaveSettings(ctx, it)
	}
	if existing != nil {
		if s := m.scheduler(); s != nil {
			s.Remove(existing.Token)
		}
		if err := m.st.Delete(ctx, existing.Token); err != nil {
			return err
		}
		m.audit(r, "check.delete", existing)
	}
	it.AsCheck, it.CheckToken = false, ""
	return m.pve.st.SaveSettings(ctx, it)
}

// pveSystemChecks liefert die Checks „als Check“ eines Systems.
func (m *Module) pveSystemChecks(ctx context.Context, id int64) []*Check {
	set, err := m.pve.st.Settings(ctx, id)
	if err != nil {
		return nil
	}
	var out []*Check
	for _, it := range set.Items {
		if it.AsCheck && it.CheckToken != "" {
			if c, _ := m.st.Check(ctx, it.CheckToken); c != nil {
				out = append(out, c)
			}
		}
	}
	return out
}

// pveSyncChecks gleicht die Checks eines Systems an: Intervall wie das System, pausiert, solange es abgeschaltet ist.
func (m *Module) pveSyncChecks(ctx context.Context, sys *proxmox.System, by string, pauseChanged bool) {
	iv := pveCheckInterval(sys)
	for _, c := range m.pveSystemChecks(ctx, sys.ID) {
		changed := false
		if c.Interval != iv {
			c.Interval, changed = iv, true
			if c.RetryInterval > iv {
				c.RetryInterval = iv
			}
		}
		if changed {
			c.UpdatedBy = by
			if err := m.st.Update(ctx, c); err != nil {
				m.log.Error("proxmox check update", "err", err)
				continue
			}
		}
		if pauseChanged && c.Paused == sys.Enabled {
			if err := m.st.SetPaused(ctx, c.Token, !sys.Enabled, by); err != nil {
				m.log.Error("proxmox check pause", "err", err)
				continue
			}
			changed = true
		}
		if changed {
			if s := m.scheduler(); s != nil {
				if nc, _ := m.st.Check(ctx, c.Token); nc != nil {
					var rt *scheduler.Runtime
					if live, ok := s.Runtime(c.Token); ok && !pauseChanged {
						rt = &live
					}
					upsertSched(s, nc, rt)
				}
			}
		}
	}
}

// pveDeleteSystem loescht ein System mit seinen Checks, Einstellungen und dem Verlauf.
func (m *Module) pveDeleteSystem(r *http.Request, id int64) error {
	ctx := r.Context()
	cs := m.pveSystemChecks(ctx, id)
	if _, err := m.pve.st.System(ctx, id); err != nil {
		return err
	}
	m.pveHalt(id)
	m.pveForget(ctx, id)
	for _, c := range cs {
		if s := m.scheduler(); s != nil {
			s.Remove(c.Token)
		}
		if err := m.st.Delete(ctx, c.Token); err == nil {
			m.audit(r, "check.delete", c)
		}
	}
	if err := m.pve.st.DeleteSystem(ctx, id); err != nil {
		return err
	}
	if inc := m.pveLastIncident(ctx); inc != nil && inc.SystemID == id {
		_ = m.core.SetSetting(ctx, pveSettingLast, "")
	}
	return nil
}

// pveSaveSystem legt ein System an bzw. aendert es und startet die Abfrage neu.
func (m *Module) pveSaveSystem(r *http.Request, sys *proxmox.System) error {
	ctx := r.Context()
	wasEnabled := true
	if sys.ID != 0 {
		old, err := m.pve.st.System(ctx, sys.ID)
		if err != nil {
			return err
		}
		wasEnabled = old.Enabled
	}
	if m.pve.box == nil {
		return proxmox.ErrNoBox
	}
	if err := m.pve.st.SaveSystem(ctx, sys); err != nil {
		return err
	}
	if !sys.Enabled {
		m.pveHalt(sys.ID)
		m.pveForget(ctx, sys.ID)
	} else {
		m.pveReload(ctx, sys.ID)
	}
	m.pveSyncChecks(ctx, sys, m.actor(r), wasEnabled != sys.Enabled)
	return nil
}
