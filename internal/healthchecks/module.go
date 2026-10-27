// Package healthchecks ist das Modul Healthchecks: Datenhaltung, Scheduler-
// Anbindung, lokale JSON-API und (ab Phase 3) die Oberflaeche.
package healthchecks

import (
	"context"
	"embed"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/scheduler"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
	"github.com/ipv64net/node64/internal/wire"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

//go:embed CHANGELOG.md
var changelog string

//go:embed CHANGELOG.en.md
var changelogEN string

const Name = "healthchecks"

// Module implementiert module.Module.
type Module struct {
	publicIP    func(ctx context.Context, family string) (string, error) // DNS-Check "public_ip"
	core        *store.Store
	st          *Store
	log         *slog.Logger
	notifier    scheduler.Notifier
	dispatcher  *notify.Dispatcher
	notifyStore *notify.Store
	version     string
	reminders   map[string]time.Time // Token -> letzte Erinnerung

	g module.Guards

	mu         sync.Mutex
	sched      *scheduler.Scheduler
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	push       *pushLimiter
	linked     func() bool                      // ipv64-Verknuepfung aktiv (Sync-Phase), nil = standalone
	quota      func() (today, limit, locs int)  // Tageskontingent der Online-Checks, nil = standalone
	api        *ipv64api.Key                    // zentraler API-Key: Online-Checks ohne Sync (online_api.go)
	groupRole  GroupRole                        // lokale Gruppe: wer benachrichtigt (groupnotify.go), nil = keine Gruppe
	groupPeers func(ctx context.Context) []Peer // Nodes der lokalen Gruppe (Auswahl der Messstellen)
	// Account-Klasse und Online-Messstellen-Limit, nil = standalone
	account func() (plan string, onlineLimit int)
	// Testlauf von ipv64 vor dem Umhaengen, nil = standalone
	onlineTest func(ctx context.Context, def wire.Check, locations []string) (*OnlineTest, error)
	// Ereignisse von ipv64 (Detailseite), nil = standalone
	hubEvents func(ctx context.Context, token string) ([]Event, error)
	// wer in der lokalen Gruppe benachrichtigt (Anzeige, groupnotify.go)
	groupNotifier func(ctx context.Context, nodes []string) (key, name string)
	onl           onlineCache
	// pushFwd meldet einen lokal empfangenen Push an den hub (der ihn an andere Messstellen weitergibt)
	pushFwd func(token string, down bool, msg, from string) bool
	// runRemote bittet den hub, den Check bei den anderen messenden Nodes sofort zu messen
	runRemote func(token string) bool
	// lokale Gruppe: sie bewertet den Gesamtzustand statt des hub (Stellvertreter-Nodes), nil = keine Gruppe
	groupDecides func(ctx context.Context, nodes []string) bool
	// Proxmox VE (proxmox_*.go): Schluessel fuer die Token-Secrets und Laufzeit der Abfragen
	box *secrets.Box
	pve *pveRuntime
	// Proxmox VE und Docker ueber den Cluster (pvecluster.go)
	cluster ClusterHooks
}

// New erzeugt das Modul. dispatcher und notifyStore duerfen nil sein (dann nur Log).
func New(core *store.Store, log *slog.Logger, dispatcher *notify.Dispatcher, notifyStore *notify.Store, version string) *Module {
	m := &Module{core: core, st: NewStore(core), log: log.With("module", Name), dispatcher: dispatcher, notifyStore: notifyStore, version: version, push: newPushLimiter(), reminders: map[string]time.Time{}}
	m.notifier = m
	m.st.OnStatusChange = m.statusFlush // Statusseiten: zwischengespeicherte Sichten verwerfen (statusview.go)
	m.publicIP = newPublicIP()
	m.pve = newPVERuntime(m, nil) // ohne SetSecrets lassen sich keine Systeme speichern
	setSelfStore(core)
	return m
}

// Notify (scheduler.Notifier): Ereignis in einen Alert fuer den Dispatcher umsetzen.
func (m *Module) Notify(ctx context.Context, e scheduler.Event, c scheduler.Check) {
	full, err := m.st.Check(ctx, c.Token)
	if err != nil || full == nil {
		return
	}
	if group, _, _ := m.role(ctx, full); group {
		m.groupVerdict(ctx, full) // mehrere Nodes der Gruppe messen: Gesamtzustand, genau eine meldet
		return
	}
	if e.Silent {
		return
	}
	if full.Foreign() {
		return // misst nur mit: benachrichtigt der hub bzw. die Besitzer-Node (sonst doppelt)
	}
	var kind notify.Kind
	switch e.Kind {
	case scheduler.EventDown:
		kind = notify.KindDown
	case scheduler.EventUp:
		kind = notify.KindUp
		m.mu.Lock()
		delete(m.reminders, c.Token)
		m.mu.Unlock()
	case scheduler.EventFlappingStart:
		kind = notify.KindFlappingStart
	case scheduler.EventFlappingEnd:
		kind = notify.KindFlappingEnd
	default:
		return
	}
	if m.dispatcher == nil {
		m.log.Info("notification", "check", c.Name, "kind", kind, "reason", e.Reason, "message", e.Message)
		return
	}
	m.dispatcher.Dispatch(notify.Alert{EventID: e.ID, Kind: kind, Time: e.Time, Check: alertInfo(full), Reason: string(e.Reason), Message: e.Message, Duration: e.Duration, Flaps: e.Flaps})
}

func alertInfo(c *Check) notify.CheckInfo {
	return notify.CheckInfo{Token: c.Token, Name: c.Name, Type: string(c.Type), Target: c.Target, Critical: c.Critical, Channels: c.Channels, NotifyDown: c.NotifyDown, NotifyUp: c.NotifyUp}
}

// remind schickt Erinnerungen fuer Checks, die laenger gestoert sind
// (repeat_minutes je Check, 0 = aus).
func (m *Module) remind(ctx context.Context) {
	if m.dispatcher == nil {
		return
	}
	list, err := m.st.Checks(ctx)
	if err != nil {
		return
	}
	now := time.Now()
	for _, c := range list {
		if c.RepeatMinutes <= 0 {
			continue
		}
		rt := m.liveRuntime(c)
		if group, me, ready := m.role(ctx, c); group { // Gruppe: nur die Node, die an der Reihe ist, nach dem Gesamtzustand
			if !me || !ready {
				continue
			}
			rt.State, rt.DownSince = m.groupState(ctx, c.Token)
		} else if !c.MeasuredHere() || c.Foreign() {
			continue // misst hier nicht oder gehoert einer anderen Node: meldet der hub bzw. die Besitzer-Node
		}
		if rt.State != scheduler.StateDown && rt.State != scheduler.StateFlapping {
			continue
		}
		every := time.Duration(c.RepeatMinutes) * time.Minute
		m.mu.Lock()
		last, ok := m.reminders[c.Token]
		if !ok {
			last = rt.DownSince
		}
		due := !last.IsZero() && now.Sub(last) >= every
		if due {
			m.reminders[c.Token] = now
		}
		m.mu.Unlock()
		if !due {
			continue
		}
		m.dispatcher.Dispatch(notify.Alert{EventID: scheduler.NewID(), Kind: notify.KindReminder, Time: now, Check: alertInfo(c), Reason: string(rt.LastReason), Message: rt.LastMessage, Duration: now.Sub(rt.DownSince)})
	}
}

// Store gibt die Datenhaltung frei (Dashboard, Tests).
func (m *Module) Store() *Store { return m.st }

// SetLinked meldet, ob die Node mit ipv64 verknuepft ist (schaltet Online/Hybrid im Formular frei).
func (m *Module) SetLinked(fn func() bool) { m.linked = fn }

// SetQuota liefert das Tageskontingent der Online-Checks (Hinweis in der Uebersicht).
func (m *Module) SetQuota(fn func() (today, limit, locs int)) { m.quota = fn }

// SetAccount: Account-Klasse und Limit der Online-Messstellen (Check x Standort) aus dem Sync.
func (m *Module) SetAccount(fn func() (plan string, onlineLimit int)) { m.account = fn }

// SetRunRemote installiert "Jetzt pruefen" ueber den hub (andere messende Nodes).
func (m *Module) SetRunRemote(fn func(token string) bool) { m.runRemote = fn }

// SetHubEvents: Ereignisse, die ipv64 selbst bewertet hat (Detailseite, nur Anzeige).
func (m *Module) SetHubEvents(fn func(ctx context.Context, token string) ([]Event, error)) {
	m.hubEvents = fn
}

// SetPushForward installiert die Weitergabe lokal empfangener Pushes an den hub.
func (m *Module) SetPushForward(fn func(token string, down bool, msg, from string) bool) {
	m.pushFwd = fn
}

func (m *Module) Info() module.Info {
	return module.Info{Name: Name, TitleKey: "nav.healthchecks", Icon: "bi-heart-pulse", Path: "/healthchecks", Available: true, Order: 10, Version: "2.38.1", Changelog: changelog, ChangelogEN: changelogEN}
}

func (m *Module) Migrations() []store.Migration {
	ms, err := store.ReadMigrations(migrationFS, "migrations")
	if err != nil {
		panic(err)
	}
	return ms
}

// Start laedt alle Checks in den Scheduler und startet Verdichtung.
func (m *Module) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ctx, m.cancel = context.WithCancel(ctx)
	m.st.reloadMaintenance(ctx)
	runner := checks.NewRunner()
	runner.PublicIP = m.publicIP
	runner.Proxmox = m.pveLookup   // Check-Typ proxmox liest den letzten Stand der Proxmox-Abfrage
	runner.ProxmoxUID = m.pveUIDOf // System ueber die Kennung im Cluster
	runner.Docker = m.dockerRemote // Check-Typ docker: Hosts mit Zugangsdaten ueber die Verbindung der Docker-Abfrage
	m.sched = scheduler.New(m.st, m.notifier, runner, m.log, scheduler.Options{})
	list, err := m.st.Checks(ctx)
	if err != nil {
		return err
	}
	for _, c := range list {
		if !c.MeasuredHere() { // fremde oder reine Online-Checks nur zur Anzeige
			continue
		}
		rt := c.Runtime
		m.sched.Upsert(c.SchedulerCheck(), &rt)
	}
	m.pveStart(ctx)        // Proxmox VE: Abfrage der eingeschalteten Systeme (vor den Checks: Docker-Checks auf ssh/https nutzen sie)
	m.pveBackfillUIDs(ctx) // Kennung der Systeme in aeltere Proxmox-Checks (Cluster)
	m.sched.Start(ctx)
	m.wg.Add(1)
	go m.housekeeping(ctx)
	m.log.Info("healthchecks loaded", "count", len(list))
	return nil
}

// Stop haelt Scheduler und Hintergrundjobs an.
func (m *Module) Stop(ctx context.Context) error {
	m.mu.Lock()
	cancel, sched := m.cancel, m.sched
	m.cancel, m.sched = nil, nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.pveStop()
	if sched != nil {
		sched.Stop()
	}
	done := make(chan struct{})
	go func() { m.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func (m *Module) scheduler() *scheduler.Scheduler {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sched
}

// housekeeping verdichtet stuendlich, laedt Wartungsfenster neu und
// verschickt minuetlich faellige Erinnerungen.
func (m *Module) housekeeping(ctx context.Context) {
	defer m.wg.Done()
	hourly := time.NewTicker(time.Hour)
	defer hourly.Stop()
	minutely := time.NewTicker(time.Minute)
	defer minutely.Stop()
	m.aggregate(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-hourly.C:
			m.aggregate(ctx)
			m.st.reloadMaintenance(ctx)
		case <-minutely.C:
			m.remind(ctx)
		}
	}
}

func (m *Module) aggregate(ctx context.Context) {
	start := time.Now()
	m.st.SetRetention(m.retention())
	m.pve.st.SetRetention(RawDays(m.core), HourlyDays(m.core)) // Proxmox-Verlauf wie die Healthchecks
	if err := m.st.Aggregate(ctx, time.Now()); err != nil {
		m.log.Error("aggregation failed", "err", err)
		return
	}
	m.log.Debug("aggregation done", "took_ms", time.Since(start).Milliseconds())
}

// Routes registriert API und Seiten. Die Push-URL ist oeffentlich.
func (m *Module) Routes(mux *http.ServeMux, g module.Guards) {
	api := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /api/checks", api(m.apiList))
	mux.Handle("POST /api/checks", api(m.apiCreate))
	mux.Handle("GET /api/checks/{token}", api(m.apiGet))
	mux.Handle("PUT /api/checks/{token}", api(m.apiUpdate))
	mux.Handle("DELETE /api/checks/{token}", api(m.apiDelete))
	mux.Handle("POST /api/checks/{token}/pause", api(m.apiPause))
	mux.Handle("POST /api/checks/{token}/resume", api(m.apiResume))
	mux.Handle("POST /api/checks/{token}/run", api(m.apiRun))
	mux.Handle("POST /api/checks/{token}/clone", api(m.apiClone))
	mux.Handle("POST /api/checks/bulk", api(m.apiBulk))
	mux.Handle("POST /api/checks/online-test", api(m.apiOnlineTest))
	mux.Handle("GET /api/checks/{token}/measurements", api(m.apiMeasurements))
	mux.Handle("GET /api/checks/{token}/events", api(m.apiEvents))
	mux.Handle("GET /api/checks/{token}/incidents", api(m.apiIncidents))
	mux.Handle("GET /api/checks/{token}/stats", api(m.apiStats))
	mux.Handle("GET /api/checks/{token}/chart", api(m.apiChart))
	mux.Handle("GET /api/events", api(m.apiAllEvents))
	mux.Handle("GET /api/incidents", api(m.apiAllIncidents))
	mux.Handle("GET /api/maintenance", api(m.apiMaintenanceList))
	mux.Handle("POST /api/maintenance", api(m.apiMaintenanceCreate))
	mux.Handle("PUT /api/maintenance/{id}", api(m.apiMaintenanceUpdate))
	mux.Handle("DELETE /api/maintenance/{id}", api(m.apiMaintenanceDelete))
	mux.Handle("GET /api/check-types", api(m.apiTypes))
	// Heartbeat: ohne Anmeldung, Antwort verraet nichts ueber den Token
	mux.Handle("GET /api/push/{token}", g.Enabled(http.HandlerFunc(m.apiPush)))
	mux.Handle("POST /api/push/{token}", g.Enabled(http.HandlerFunc(m.apiPush)))
	m.uiRoutes(mux, g)
	m.statusRoutes(mux, g) // oeffentliche Statusseiten /status/{slug} (statuspublic.go)
	m.onlineRoutes(mux, g)
	m.onlineAPIRoutes(mux, api)
	m.statusPagesAPIRoutes(mux, api)
	m.pveAPIRoutes(mux, api)
}

// upsertSched plant einen Check ein, wenn diese Node ihn misst; Online-Checks und Checks
// anderer Nodes kommen aus dem Scheduler raus (sonst misst die Node sie bis zum Neustart mit).
func upsertSched(s *scheduler.Scheduler, c *Check, rt *scheduler.Runtime) {
	if c == nil {
		return
	}
	if c.MeasuredHere() {
		s.Upsert(c.SchedulerCheck(), rt)
	} else {
		s.Remove(c.Token)
	}
}
