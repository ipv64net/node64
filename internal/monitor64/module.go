// Package monitor64 ist das Node64-Modul Monitor64: Systeme ueberwachen mit Schwellen und Verlauf (Plan
// docs/PLAN-NODE64-MONITOR64.md). Zugaenge: Monitor64-Agent, SSH ohne Agent, SNMP, APIs (Proxmox VE, PBS, Docker).
//
// Standard aus: ausgeschaltet gibt es keinen Menuepunkt, keinen Port, keine Goroutine und keine Abfrage; die
// Tabellen entstehen erst beim ersten Einschalten (Migrationen des Moduls).
package monitor64

import (
	"context"
	"embed"
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/monitor64/apis"
	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/transport"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

// changelog wird unter Einstellungen > Module angezeigt (Version siehe Info).
//
//go:embed CHANGELOG.md
var changelog string

//go:embed CHANGELOG.en.md
var changelogEN string

//go:embed migrations/*.sql
var migrationFS embed.FS

// Name ist der technische Schluessel des Moduls.
const Name = "monitor64"

const (
	version = "0.1.8"

	// EnvLoadGen startet den Lastgenerator mit N Schein-Hosts (nur Entwicklung, nie in der Oberflaeche).
	EnvLoadGen = "NODE64_MONITOR64_LOADGEN"

	dbFile       = "monitor64.db"
	flushEvery   = 5 * time.Minute      // laufende Bloecke sichern (tsdb)
	purgeEvery   = 6 * time.Hour        // Aufbewahrung durchsetzen
	purgeFirst   = 5 * time.Minute      // erster Lauf nach dem Start
	keepProblems = 365 * 24 * time.Hour // Problem-Historie so lange wie die Stundenwerte
	stopWait     = 15 * time.Second
)

// Migrations liefert die Tabellen des Moduls.
func Migrations() []store.Migration {
	ms, err := store.ReadMigrations(migrationFS, "migrations")
	if err != nil {
		panic(err)
	}
	return ms
}

// Module ist Monitor64.
type Module struct {
	nodeIDCache atomic.Pointer[string] // node.id, einmal gelesen (nodeID)
	st          *store.Store
	log         *slog.Logger
	box         *secrets.Box
	dataDir     string
	nodeVersion string
	dispatchFn  func(notify.Alert)
	quietFn     func(time.Time) bool
	g           module.Guards
	store       *Store

	notifyMu sync.Mutex
	notifier *eval.Notifier // Gedaechtnis der Meldungen (je Host in m64_runtime gespeichert)
	cfg      atomic.Pointer[cfgCache]
	rtMu     sync.Mutex
	reloadMu sync.Mutex
	pveSeen  *apis.ClusterSeen // Proxmox: welche Nodes hier erfolgreich abgefragt werden (Zustaendigkeit Cluster)
	rts      map[string]*hostRT
	pool     *transport.Pool
	traps    *trapMgr                // SNMP-Trap-Empfaenger
	push     *transport.PushListener // Agents im Push-Betrieb (Port nur offen, wenn ein Zugang ihn nutzt)
	pushMu   sync.Mutex
	pushAddr string
	locMu    sync.Mutex
	loc      *time.Location
	locAt    time.Time

	ctl    sync.Mutex // Start/Stop
	mu     sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup
	sched  *Scheduler
	series Series
	load   *loadGen
	start  time.Time

	cl clusterRT // Cluster (cluster*.go)
	ad agentRT   // Agent-Verteilung und automatische Updates (agentdist*.go)
}

// New legt das Modul an (laeuft erst nach Start).
func New(core *store.Store, log *slog.Logger, box *secrets.Box, dataDir, nodeVersion string) *Module {
	m := &Module{st: core, log: log.With("module", Name), box: box, dataDir: dataDir, nodeVersion: nodeVersion, store: newStore(core),
		pveSeen: &apis.ClusterSeen{}}
	m.traps = newTrapMgr(m.repoll)
	return m
}

// SetQuiet verbindet die Ruhezeit-Pruefung der Benachrichtigung (fuer Erinnerungen).
func (m *Module) SetQuiet(fn func(time.Time) bool) { m.quietFn = fn }

// SetNotifier verbindet den Dispatcher der Benachrichtigungen.
func (m *Module) SetNotifier(fn func(notify.Alert)) { m.dispatchFn = fn }

// Info beschreibt das Modul.
func (m *Module) Info() module.Info {
	return module.Info{Name: Name, TitleKey: "nav.monitor64", Icon: "bi-activity", Image: "monitor64.svg", Path: "/monitor64", Available: true, Order: 15,
		Version: version, Changelog: changelog, ChangelogEN: changelogEN}
}

// Migrations: Tabellen m64_* (entstehen beim ersten Einschalten).
func (m *Module) Migrations() []store.Migration { return Migrations() }

// Routes registriert Oberflaeche und API.
func (m *Module) Routes(mux *http.ServeMux, g module.Guards) {
	m.g = g
	m.uiRoutes(mux, g)
}

func (m *Module) dir() string { return filepath.Join(m.dataDir, Name) }

// Start oeffnet den Verlauf und startet den Planer.
func (m *Module) Start(ctx context.Context) error {
	m.ctl.Lock()
	defer m.ctl.Unlock()
	m.mu.Lock()
	running := m.cancel != nil
	m.mu.Unlock()
	if running {
		return nil
	}
	if err := os.MkdirAll(m.dir(), 0o700); err != nil {
		return err
	}
	ser, err := openSeries(filepath.Join(m.dir(), dbFile), m.log)
	if err != nil {
		return fmt.Errorf("monitor64: open history: %w", err)
	}
	life, cancel := context.WithCancel(context.Background())
	sched := NewScheduler(m.workers(ctx))
	sched.OnPanic = func(key string, v any) { m.log.Error("monitor64: job panic", "job", key, "panic", fmt.Sprint(v)) }
	m.mu.Lock()
	m.cancel, m.sched, m.series, m.start = cancel, sched, ser, time.Now()
	m.mu.Unlock()

	m.notifyMu.Lock()
	m.notifier = &eval.Notifier{Hosts: map[string]*eval.HostMemory{}}
	m.notifyMu.Unlock()
	m.pool = transport.NewPool(0)
	m.mu.Lock()
	m.push = transport.NewPushListener(transport.PushConfig{Logger: m.log})
	m.mu.Unlock()
	m.cfg.Store(nil)
	m.reloadConfig(ctx)
	if line, err := m.PublicKeyLine(ctx); err == nil { // oeffentlich, fuer Installationsbefehle (kein Geheimnis)
		m.log.Info("monitor64: node public key", "authorized_key", line)
	} else {
		m.log.Warn("monitor64: node key", "err", err)
	}
	if err := m.startHosts(ctx); err != nil {
		m.log.Warn("monitor64: load hosts", "err", err)
	}
	m.syncPush(ctx)
	m.traps.start()
	m.cl.mu.Lock()
	m.cl.started, m.cl.roles = m.cl.clock(), nil // nach dem Start: Stand der anderen abholen, Rollen neu bestimmen
	m.cl.mu.Unlock()
	m.uptimeMark(ctx, time.Now()) // Laufzeit: lief das Modul laenger nicht, steht die Zeit als Luecke (Statusseiten, uptime.go)
	m.wg.Add(5)
	go func() { defer m.wg.Done(); m.uptimeLoop(life) }()
	go func() { defer m.wg.Done(); sched.Run(life) }()
	go func() { defer m.wg.Done(); m.housekeeping(life) }()
	go func() { defer m.wg.Done(); m.trapLoop(life) }()
	go func() { defer m.wg.Done(); m.clusterLoop(life) }()
	m.kickTraps() // Trap-Empfaenger nur, wenn ein SNMP-Zugang Traps nutzt
	m.wg.Add(1)
	go func() { defer m.wg.Done(); m.agentLoop(life) }() // Agent-Dateien und automatische Updates (agentdist_update.go)

	if n, _ := strconv.Atoi(os.Getenv(EnvLoadGen)); n > 0 {
		lg := newLoadGen(n, sched, ser)
		m.mu.Lock()
		m.load = lg
		m.mu.Unlock()
		lg.start()
		m.log.Warn("monitor64: load generator active", "hosts", n)
	}
	m.log.Info("monitor64 started")
	return nil
}

// Stop beendet Planer und Hintergrundarbeit, sichert den Verlauf und schliesst ihn.
func (m *Module) Stop(ctx context.Context) error {
	m.ctl.Lock()
	defer m.ctl.Unlock()
	m.mu.Lock()
	cancel, ser := m.cancel, m.series
	m.cancel = nil
	m.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	done := make(chan struct{})
	go func() { m.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(stopWait):
		m.log.Warn("monitor64: stop timeout, jobs still running")
	}
	m.traps.stop()
	m.mu.Lock()
	pl := m.push
	m.push = nil
	m.mu.Unlock()
	if pl != nil {
		_ = pl.Close()
	}
	m.rtMu.Lock()
	rts := m.rts
	m.rts = nil
	m.rtMu.Unlock()
	for _, rt := range rts { // Laufzeitstand sichern (Tracker, Gedaechtnis der Meldungen)
		if !rt.mu.TryLock() { // Runde laeuft noch (Stop-Zeitlimit ueberschritten): nicht gleichzeitig lesen
			continue
		}
		m.notifyMu.Lock()
		mem, _ := json.Marshal(m.notifier.Hosts[rt.host.UID])
		m.notifyMu.Unlock()
		rt.dirty = true
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		m.saveRuntime(sctx, rt, mem)
		cancel()
		rt.removed = true
		for _, a := range rt.accs { // Sammler schliessen (z. B. Redfish-Sitzung abmelden, Verbindungen)
			if a.col != nil {
				a.col.close()
			}
		}
		rt.accs = nil
		rt.mu.Unlock()
	}
	if m.pool != nil {
		m.pool.Close()
	}
	var err error
	if ser != nil {
		err = ser.Close()
	}
	m.mu.Lock()
	m.sched, m.series, m.load = nil, nil, nil
	m.mu.Unlock()
	m.log.Info("monitor64 stopped")
	return err
}

// workers: gleichzeitige Abfragen (Einstellung, Standard 16).
func (m *Module) workers(ctx context.Context) int {
	n, _ := strconv.Atoi(m.st.SettingOr(ctx, setWorkers, ""))
	if n <= 0 || n > 512 {
		return defaultWorkers
	}
	return n
}

// housekeeping sichert alle 5 Minuten den Verlauf und setzt die Aufbewahrung durch.
func (m *Module) housekeeping(ctx context.Context) {
	flush := time.NewTicker(flushEvery)
	defer flush.Stop()
	purge := time.NewTimer(purgeFirst) // erster Lauf kurz nach dem Start (sonst nie bei haeufigen Neustarts)
	defer purge.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-flush.C:
			if ser := m.seriesStore(); ser != nil {
				if err := ser.Flush(ctx); err != nil && ctx.Err() == nil {
					m.log.Warn("monitor64: flush history", "err", err)
				}
			}
		case <-purge.C:
			if ser := m.seriesStore(); ser != nil {
				if _, err := ser.Purge(ctx, time.Now()); err != nil && ctx.Err() == nil {
					m.log.Warn("monitor64: purge history", "err", err)
				}
			}
			m.purgeProblems(ctx, time.Now())
			purge.Reset(purgeEvery)
		}
	}
}

func (m *Module) seriesStore() Series {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.series
}

func (m *Module) scheduler() *Scheduler {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sched
}

// Einstellungs-Schluessel (Kern-Einstellungen, Praefix monitor64.).
const (
	setWorkers = "monitor64.workers"
)
