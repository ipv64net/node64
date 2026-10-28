package healthchecks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
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
	pveSettingEngine  = "pve.engine."       // + System-ID: gemeldete Stoerungen (JSON, leer = keine)
	pveSettingLast    = "pve.last_incident" // letzte Stoerung (Startseite)
	pveCheckGroup     = "Proxmox VE"        // Gruppe der Checks „als Check“
	pveRetentionRead  = time.Minute         // Aufbewahrung (hc.raw_days/hc.hourly_days) so oft neu lesen
	dockerCheckGroup  = "Docker"            // Gruppe der Container „als Check“
	dockerSettingLast = "docker.last_incident"
)

// pveNewSource baut die Abfrage eines Systems (Tests: Docker-API austauschen).
var pveNewSource = proxmox.NewSource

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
	dockerMu  sync.Mutex       // Docker-Host automatisch einrichten (nur einmal)
	wg        sync.WaitGroup
	// Tests: noRun startet keine Abfrage-Schleife (Abfragen nur per Poll), alert faengt Meldungen ab
	noRun bool
	alert func(notify.Alert)
}

type pvePoll struct {
	sys     proxmox.System
	p       proxmox.Source
	cancel  context.CancelFunc
	done    chan struct{}
	started time.Time
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

// pveRun startet die Abfrage eines Systems (vorher laufende wird beendet). Austausch unter der Sperre: bei
// gleichzeitigem Speichern bleibt keine Abfrage verwaist; die neue beginnt erst, wenn die alte beendet ist.
func (m *Module) pveRun(ctx context.Context, sys *proxmox.System) {
	rt := m.pve
	reason := ""
	if sys.Secret == "" && !sys.IsDocker() {
		reason = m.pveSecretProblem(ctx, sys.ID)
	}
	rt.mu.Lock()
	old := rt.polls[sys.ID]
	delete(rt.polls, sys.ID)
	delete(rt.errs, sys.ID)
	if old != nil {
		old.cancel()
	}
	switch {
	case reason != "":
		rt.errs[sys.ID] = reason
	case rt.ctx != nil: // sonst Modul gestoppt
		pctx, cancel := context.WithCancel(rt.ctx)
		p := pveNewSource(m.log, *sys, m.pveSnapshot)
		pp := &pvePoll{sys: *sys, p: p, cancel: cancel, done: make(chan struct{}), started: time.Now()}
		rt.polls[sys.ID] = pp
		if rt.noRun {
			close(pp.done)
			break
		}
		rt.wg.Add(1)
		go func() {
			defer rt.wg.Done()
			defer close(pp.done)
			if old != nil {
				<-old.done
			}
			p.Run(pctx)
		}()
	}
	rt.mu.Unlock()
	if old != nil {
		<-old.done
	}
	if reason != "" {
		m.log.Error("proxmox system not polled", "system", sys.Name, "reason", reason)
	}
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
	if set.Kind == proxmox.KindDocker {
		m.dockerLinkChecks(ctx, set, s)
	}
	m.pveCheckLabels(ctx, set, s)
	evs := rt.engine.Evaluate(s, set)
	m.pvePersist(ctx, s.SystemID)
	for _, ev := range evs {
		m.pveNotify(ctx, set, s, ev)
	}
	if err := rt.st.Record(ctx, s); err != nil && ctx.Err() == nil {
		m.log.Error("proxmox history", "system", set.Name, "err", err)
	}
}

// pveSystemLabel: Name eines Systems fuer die Gruppierung der Checks (Proxmox: Clustername aus dem letzten Abruf,
// sonst Name des Systems; Docker: Name des Hosts).
func (m *Module) pveSystemLabel(sys *proxmox.System) string {
	if !sys.IsDocker() {
		if s := m.pveLast(sys.ID); s != nil && s.OK && s.Cluster != "" {
			return s.Cluster
		}
	}
	return sys.Name
}

// pveCheckLabels haelt den Namen des Systems in den Parametern der Checks „als Check“ aktuell (Umbenennen, Cluster).
// Er geht per Sync zu ipv64 und gruppiert die Checks dort wie in der Liste der Node.
func (m *Module) pveCheckLabels(ctx context.Context, set *proxmox.SystemSettings, s *proxmox.Snapshot) {
	if !s.OK {
		return
	}
	label := set.Name
	if set.Kind != proxmox.KindDocker && s.Cluster != "" {
		label = s.Cluster
	}
	for _, it := range set.Items {
		if !it.AsCheck || it.CheckToken == "" {
			continue
		}
		c, err := m.st.Check(ctx, it.CheckToken)
		if err != nil || c == nil || c.Foreign() {
			continue
		}
		var raw []byte
		switch c.Type {
		case checks.TypeProxmox:
			var p checks.ProxmoxParams
			if json.Unmarshal(c.Params, &p) != nil || p.System == label {
				continue
			}
			p.System = label
			raw, _ = json.Marshal(p)
		case checks.TypeDocker:
			var p checks.DockerParams
			if len(c.Params) > 0 && json.Unmarshal(c.Params, &p) != nil || p.System == label {
				continue
			}
			p.System = label
			raw, _ = json.Marshal(p)
		default:
			continue
		}
		c.Params = raw
		if err := m.st.Update(ctx, c); err != nil {
			m.log.Warn("proxmox check label", "token", c.Token, "err", err)
			continue
		}
		if sch := m.scheduler(); sch != nil {
			var rt *scheduler.Runtime
			if live, ok := sch.Runtime(c.Token); ok {
				rt = &live
			}
			upsertSched(sch, c, rt)
		}
	}
}

// pveCheckLinks: wurde ein Check „als Check“ in der Liste der Healthchecks geloescht, gilt der Gast wieder als normal
// ueberwacht (sonst meldete niemand seinen Zustand). Eine Abfrage fuer alle Checks vom Typ proxmox bzw. docker (nicht je Gast).
func (m *Module) pveCheckLinks(ctx context.Context, set *proxmox.SystemSettings) {
	var have map[string]bool
	for _, it := range set.Items {
		if !it.AsCheck {
			continue
		}
		if have == nil {
			var err error
			if have, err = m.pveCheckTokens(ctx, pveCheckType(set.Kind)); err != nil {
				return
			}
		}
		if have[it.CheckToken] {
			continue
		}
		it.AsCheck, it.CheckToken = false, ""
		if err := m.pve.st.SaveSettings(ctx, it); err != nil {
			m.log.Error("proxmox settings", "err", err)
		}
	}
}

// pveCheckType: Check-Typ „als Check“ je Art des Systems (Docker: der vorhandene Typ docker).
func pveCheckType(kind string) checks.Type {
	if kind == proxmox.KindDocker {
		return checks.TypeDocker
	}
	return checks.TypeProxmox
}

// pveCheckTokens liefert die Tokens aller Checks des Typs.
func (m *Module) pveCheckTokens(ctx context.Context, typ checks.Type) (map[string]bool, error) {
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT token FROM hc_checks WHERE type = ?`, string(typ))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	have := map[string]bool{}
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		have[t] = true
	}
	return have, rows.Err()
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

// pveResPath: Seite eines Systems bzw. einer Ressource (Docker-Container: Seite unter /healthchecks/docker).
func pveResPath(id int64, key string) string {
	if name, ok := strings.CutPrefix(key, proxmox.TypeDocker+"/"); ok {
		return dockerSysPath(id) + "/c/" + name
	}
	p := pvePath + "/system/" + strconv.FormatInt(id, 10)
	if key != "" {
		p += "/res/" + key
	}
	return p
}

// dockerSysPath: Seite eines Docker-Hosts.
func dockerSysPath(id int64) string { return dockerPath + "/system/" + strconv.FormatInt(id, 10) }

// pveKeyPath: Seite eines Keys nach Art des Systems ("" = System).
func pveKeyPath(kind string, id int64, key string) string {
	if kind == proxmox.KindDocker && key == "" {
		return dockerSysPath(id)
	}
	return pveResPath(id, key)
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
	docker := set.Kind == proxmox.KindDocker
	data := map[string]string{"what": ev.What, "type": pveKeyType(ev.Key), "name": ev.Name, "system": set.Name, "detail": ev.Detail,
		"path": pveKeyPath(set.Kind, set.SystemID, ev.Key)}
	if docker {
		data["source"] = "docker" // Betreff „Docker: …“ statt „Proxmox: …“
		if ev.Key == "" {
			data["what"] = "docker_" + ev.What // Text „Docker-Host … nicht erreichbar“
		}
	}
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
		Check: notify.CheckInfo{Name: name, Type: string(pveCheckType(set.Kind)), Target: ev.Key, NotifyDown: true, NotifyUp: true, Local: true,
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
			key := pveSettingLast
			if docker { // eigene letzte Stoerung (Docker-Seite), die Proxmox-Karte bleibt bei Proxmox
				key = dockerSettingLast
			}
			_ = m.core.SetSetting(context.WithoutCancel(ctx), key, string(b))
		}
	}
	if sys, err := m.pve.st.System(ctx, set.SystemID); err == nil && !m.pveNotifiesHere(ctx, sys) {
		m.log.Info("proxmox event (home node notifies)", "system", set.Name, "key", ev.Key, "kind", ev.Kind, "what", ev.What)
		return // System aus dem Cluster: meldet die Heim-Node (pvecluster.go)
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
	return m.lastIncident(ctx, pveSettingLast)
}

// lastIncident liest die letzte Stoerung aus einer Einstellung (Proxmox bzw. Docker).
func (m *Module) lastIncident(ctx context.Context, setting string) *pveIncident {
	raw := m.core.SettingOr(ctx, setting, "")
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
	st.System, st.Polling, st.Interval, st.Started = pp.sys.Name, true, proxmox.ClampInterval(pp.sys.Interval), pp.started
	if w, ok := pp.p.(interface{ WantIP(key string) }); ok {
		w.WantIP(key) // Adresse des Gasts fuer den Ping der Latenz holen lassen
	}
	s := pp.p.Last()
	if s == nil {
		st.Last = m.pveCheckLast(systemID, key) // noch kein Stand: voriges Ergebnis des Checks bleibt
		return st
	}
	st.Time, st.Reachable, st.Error, st.APILatency = s.Time, s.OK, s.Error, s.APILatency
	for i := range s.Resources {
		r := &s.Resources[i]
		if r.Key() != key {
			continue
		}
		st.Found, st.Name, st.Node, st.State, st.Status, st.QMP, st.Lock, st.Uptime = true, r.Name, r.Node, string(r.State), r.Status, r.QMP, r.Lock, r.Uptime
		st.IP = r.IP
		break
	}
	return st
}

// pveCheckLast liefert das letzte Ergebnis des Checks „als Check“ eines Keys (leer = keins).
func (m *Module) pveCheckLast(systemID int64, key string) checks.Status {
	s := m.scheduler()
	if s == nil {
		return ""
	}
	set, err := m.pve.st.Settings(context.Background(), systemID)
	if err != nil {
		return ""
	}
	if it := set.Item(key); it != nil && it.CheckToken != "" {
		if rt, ok := s.Runtime(it.CheckToken); ok {
			return rt.LastStatus
		}
	}
	return ""
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
// Der neue Check bekommt die Kanaele der Proxmox-Regeln und ist pausiert, solange das System abgeschaltet ist. Eine
// schon gemeldete Stoerung uebernimmt er (beginnt gestoert, meldet nur die Entwarnung); umgekehrt uebernimmt die
// Engine die Stoerung eines gestoerten Checks, der entfernt wird (keine doppelte Meldung).
func (m *Module) pveSetAsCheck(r *http.Request, sys *proxmox.System, key string, on bool) error {
	return m.pveSetAsCheckNamed(r, sys, key, on, "")
}

// pveSetAsCheckNamed: wie pveSetAsCheck, mit eigenem Namen fuer einen neuen Check (leer = "System – Eintrag").
func (m *Module) pveSetAsCheckNamed(r *http.Request, sys *proxmox.System, key string, on bool, name string) error {
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
		params, _ := json.Marshal(checks.ProxmoxParams{SystemID: sys.ID, Key: key, System: m.pveSystemLabel(sys), SystemUID: sys.UID})
		iv := int(pveCheckInterval(sys).Seconds())
		riv := min(20, iv)
		group := pveCheckGroup
		paused := !sys.Enabled
		in := checkJSON{Name: sys.Name + " – " + m.pveResName(sys.ID, key), Type: string(checks.TypeProxmox), Target: key, Params: params,
			IntervalSeconds: &iv, RetryIntervalSeconds: &riv, Group: &group, Tags: []string{"proxmox"}, Execution: "local", Paused: &paused,
			Channels: m.pveChannels(ctx, set.Effective(key, m.pveNodeOf(sys.ID, key)).Channels)}
		if sys.IsDocker() { // Docker: der vorhandene Check-Typ docker fragt den Container selbst (laeuft auch ohne Abfrage)
			name, _ := strings.CutPrefix(key, proxmox.TypeDocker+"/")
			dp := checks.DockerParams{System: sys.Name}
			if h := dockerSysHost(sys); h != checks.DefaultDockerHost() {
				dp.Host = h
			}
			params, _ = json.Marshal(dp)
			group = dockerCheckGroup
			in.Name, in.Type, in.Target, in.Params, in.Tags = sys.Name+" – "+name, string(checks.TypeDocker), name, params, []string{"docker"}
		}
		if name != "" {
			in.Name = name
		}
		c := &Check{Token: NewToken(), UpdatedBy: m.actor(r)}
		if err := m.apply(c, in, true); err != nil {
			return err
		}
		if err := m.st.Insert(ctx, c); err != nil {
			return err
		}
		c, _ = m.st.Check(ctx, c.Token)
		var start *scheduler.Runtime
		if since, ok := m.pve.engine.Outage(sys.ID, key); ok && c != nil && sys.Enabled {
			// schon gemeldet: der Check beginnt gestoert (keine zweite Meldung), die Entwarnung kommt vom Check
			start = &scheduler.Runtime{State: scheduler.StateDown, Since: since, DownSince: since, LastStatus: checks.Down, ConsecutiveFail: 1}
			if err := m.st.SaveRuntime(ctx, c.Token, *start); err != nil {
				m.log.Error("proxmox check runtime", "err", err)
			}
		}
		if s := m.scheduler(); s != nil && c != nil {
			upsertSched(s, c, start)
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
			if live, ok := s.Runtime(existing.Token); ok && pveRuntimeDown(live.State) {
				m.pve.engine.Adopt(sys.ID, key) // vom Check gemeldet: Engine meldet nur noch die Entwarnung
			}
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

// pveRuntimeDown: Check gilt als gestoert (Meldung ist raus).
func pveRuntimeDown(st scheduler.State) bool {
	return st == scheduler.StateDown || st == scheduler.StateDependent || st == scheduler.StateStabilizing
}

// pveSyncCheckChannels gibt den Checks „als Check“ eines Systems die Kanaele der Proxmox-Regeln (nach Aenderung
// der Regeln; wirksame Regel je Gast bzw. Node wie bei den Meldungen der Engine).
func (m *Module) pveSyncCheckChannels(ctx context.Context, id int64, by string) {
	set, err := m.pve.st.Settings(ctx, id)
	if err != nil {
		return
	}
	for key, it := range set.Items {
		if !it.AsCheck || it.CheckToken == "" {
			continue
		}
		c, _ := m.st.Check(ctx, it.CheckToken)
		if c == nil {
			continue
		}
		ch := m.pveChannels(ctx, set.Effective(key, m.pveNodeOf(id, key)).Channels)
		if slices.Equal(ch, c.Channels) {
			continue
		}
		c.Channels, c.UpdatedBy = ch, by
		if err := m.st.Update(ctx, c); err != nil {
			m.log.Error("proxmox check channels", "err", err)
		}
	}
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
		// Checks „als Check“ folgen dem System: Ueberwachung aus = pausiert (auch Docker, wie Proxmox VE)
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
	return m.pveDeleteSystemBy(r.Context(), id, r)
}

// pveDeleteSystemBy: wie pveDeleteSystem; r nil = aus dem Cluster (ohne Eintrag im Audit-Log).
func (m *Module) pveDeleteSystemBy(ctx context.Context, id int64, r *http.Request) error {
	cs := m.pveSystemChecks(ctx, id)
	sys, err := m.pve.st.System(ctx, id)
	if err != nil {
		return err
	}
	if sys.IsDocker() && !dockerNeedsPoll(sys) {
		cs = nil // Docker-Checks bleiben (sie fragen den Container selbst, auch selbst angelegte und nur verknuepfte)
	}
	if sys.IsDocker() && dockerIsLocal(sys) {
		_ = m.core.SetSetting(ctx, dockerSettingMonitor, "off") // lokalen Host nicht automatisch neu anlegen
	}
	m.pveHalt(id)
	m.pveForget(ctx, id)
	for _, c := range cs {
		if s := m.scheduler(); s != nil {
			s.Remove(c.Token)
		}
		if err := m.st.Delete(ctx, c.Token); err == nil && r != nil {
			m.audit(r, "check.delete", c)
		}
	}
	if err := m.pve.st.DeleteSystem(ctx, id); err != nil {
		return err
	}
	m.pveClusterChanged(ctx, sys, sys, true)
	for _, k := range []string{pveSettingLast, dockerSettingLast} {
		if inc := m.lastIncident(ctx, k); inc != nil && inc.SystemID == id {
			_ = m.core.SetSetting(ctx, k, "")
		}
	}
	return nil
}

// pveSaveSystem legt ein System an bzw. aendert es und startet die Abfrage neu.
func (m *Module) pveSaveSystem(r *http.Request, sys *proxmox.System) error {
	return m.pveSaveSystemBy(r.Context(), sys, m.actor(r))
}

// pveSaveSystemBy: wie pveSaveSystem mit Urheber by (Aenderungen an den Checks; "cluster" aus dem Cluster).
func (m *Module) pveSaveSystemBy(ctx context.Context, sys *proxmox.System, by string) error {
	wasEnabled := true
	var old *proxmox.System
	if sys.ID != 0 {
		var err error
		if old, err = m.pve.st.System(ctx, sys.ID); err != nil {
			return err
		}
		wasEnabled = old.Enabled
		sys.Kind = old.Kind // die Art bleibt
	}
	if m.pve.box == nil && !sys.IsDocker() {
		return proxmox.ErrNoBox
	}
	if err := m.pve.st.SaveSystem(ctx, sys); err != nil {
		return err
	}
	pauseChanged := wasEnabled != sys.Enabled
	if old != nil && sys.IsDocker() && dockerSysHost(old) != dockerSysHost(sys) {
		pauseChanged = m.dockerRetarget(ctx, old, sys, by) || pauseChanged
	}
	if !sys.Enabled {
		m.pveHalt(sys.ID)
		m.pveForget(ctx, sys.ID)
	} else {
		m.pveReload(ctx, sys.ID)
	}
	m.pveSyncChecks(ctx, sys, by, pauseChanged)
	if sys.UID == "" { // neu angelegt: Kennung aus der Datenbank
		if s, err := m.pve.st.System(ctx, sys.ID); err == nil {
			sys.UID, sys.Home = s.UID, s.Home
		}
	}
	m.pveClusterChanged(ctx, old, sys, false)
	return nil
}

// dockerRetarget: neue Adresse eines Docker-Hosts. Die Checks „als Check“ fragen ab jetzt die neue Adresse; zeigt sie
// auf eine andere Maschine, gelten Verlauf, „laufend gesehen“ und gemeldete Stoerungen des alten Hosts nicht mehr.
// true: die Pause der Checks ist neu abzugleichen (ssh/https brauchen die Abfrage, die anderen nicht).
func (m *Module) dockerRetarget(ctx context.Context, old, sys *proxmox.System, by string) bool {
	oldHost, newHost := dockerSysHost(old), dockerSysHost(sys)
	for _, c := range m.pveSystemChecks(ctx, sys.ID) {
		if c.Type != checks.TypeDocker || dockerCheckHost(c) != oldHost {
			continue
		}
		dp := checks.DockerParams{System: m.pveSystemLabel(sys)} // Systemname behalten (Gruppierung), auch ohne erfolgreiche Abfrage
		if newHost != checks.DefaultDockerHost() {
			dp.Host = newHost
		}
		c.Params, _ = json.Marshal(dp)
		c.UpdatedBy = by
		if err := m.st.Update(ctx, c); err != nil {
			m.log.Error("docker check host", "err", err)
			continue
		}
		if s := m.scheduler(); s != nil {
			if nc, _ := m.st.Check(ctx, c.Token); nc != nil {
				upsertSched(s, nc, nil)
			}
		}
	}
	if dockerMachine(oldHost) != dockerMachine(newHost) {
		m.pveHalt(sys.ID)
		m.pveForget(ctx, sys.ID)
		if err := m.pve.st.ResetHistory(ctx, sys.ID); err != nil {
			m.log.Error("docker reset history", "err", err)
		}
	}
	return dockerNeedsPoll(old) != dockerNeedsPoll(sys)
}

// dockerMachine: Rechner hinter einer Docker-Adresse (Hostname bzw. lokal), ohne Port, Benutzer, Pfad und Art.
func dockerMachine(host string) string {
	if proxmox.DockerLocal(host) {
		return "local"
	}
	u, err := url.Parse(strings.Replace(host, "tcp://", "http://", 1))
	if err != nil {
		return host
	}
	return strings.ToLower(u.Hostname())
}
