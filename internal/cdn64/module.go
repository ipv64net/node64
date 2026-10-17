// Package cdn64 ist das Modul CDN64: ein Reverse-Proxy-Manager im Funktionsumfang des Nginx Proxy Manager, ohne
// nginx (Go selbst, HTTP/2 und HTTP/3). Hosts melden sich beim gemeinsamen Eingang des Kerns (edge) an,
// Zertifikate kommen aus der Zertifikatsverwaltung des Kerns (certs). Plan: docs/PLAN-NODE64-CDN64.md.
//
// Ausgeschaltet laeuft nichts: keine Routen beim Eingang (der schliesst dann seine Ports), keine Pruefung der
// Ziele, keine Erneuerung der Zertifikate fuer CDN64, Cache freigegeben.
package cdn64

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/ports"
	"github.com/ipv64net/node64/internal/store"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

//go:embed templates
var templateFS embed.FS

// changelog wird unter Einstellungen > Module angezeigt (Version siehe Info).
//
//go:embed CHANGELOG.md
var changelog string

const (
	Name    = "cdn64"
	Version = "1.6.0"
)

const cacheLimit = 64 << 20 // Asset-Cache aller Hosts zusammen

// Module implementiert module.Module.
type Module struct {
	core    *store.Store
	log     *slog.Logger
	edge    *edge.Edge
	certs   *certs.Manager
	version string
	g       module.Guards

	applyMu    sync.Mutex
	mu         sync.Mutex
	running    bool
	startedAt  time.Time
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	stats      map[int64]*hostStats
	routeErr   map[int64]string
	loopToken  string
	trVerify   *http.Transport
	trInsecure *http.Transport
	cache      *assetCache
	reach      *reacher
	ports      *ports.Registry         // Pruefung der Stream-Ports (nil = keine)
	dataDir    string                  // fuer cdn64.db ("" = keine Statistik)
	stats2     atomic.Pointer[statsDB] // Statistik und Zugriffs-Log (nur bei laufendem Modul)
	acl        map[int64]*guard
	authFail   *failLimiter
	hostTr     map[int64]*http.Transport
	checks     CheckCreator // Healthcheck anlegen (nil = nicht verfuegbar)
	findChecks CheckFinder  // Healthchecks lesen ("ueberwacht" in der Liste; nil = nicht verfuegbar)
	bl         *blocklists  // ipv64-Blocklisten
	lim        *limiter     // Schutz vor Ueberlastung
	dnsrec     DNSRecords   // DNS-Records bei ipv64 (nil = nicht verfuegbar)

	sapply sync.Mutex // ein Abgleich der Streams gleichzeitig
	smu    sync.Mutex // Streams (nur kurz halten)
	runs   map[int64]*streamRun
	sstats map[int64]*streamStats
	sreach *reacher
}

// New erzeugt das Modul. edge und certs kommen aus dem Kern (nil nur in Tests ohne Eingang).
func New(core *store.Store, log *slog.Logger, e *edge.Edge, c *certs.Manager, version string) *Module {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	m := &Module{core: core, log: log.With("module", Name), edge: e, certs: c, version: version, stats: map[int64]*hostStats{},
		routeErr: map[int64]string{}, loopToken: hex.EncodeToString(b), trVerify: newTransport(true), trInsecure: newTransport(false),
		cache: newAssetCache(cacheLimit), reach: newReacher(), runs: map[int64]*streamRun{}, sstats: map[int64]*streamStats{}, sreach: newReacher(),
		acl: map[int64]*guard{}, authFail: newFailLimiter(), hostTr: map[int64]*http.Transport{}, bl: newBlocklists(), lim: newLimiter()}
	m.lim.onBan = func(ip netip.Addr, until time.Time) {
		m.log.Warn("cdn64 limits: address banned", "ip", limShow(ip), "until", until.Format(time.RFC3339))
	}
	return m
}

// SetDataDir legt fest, wo cdn64.db liegt (Statistik, Zugriffs-Log).
func (m *Module) SetDataDir(dir string) { m.dataDir = dir }

// CheckCreator legt einen Healthchecks-Check an (JSON wie POST /api/checks) und liefert seinen Token.
type CheckCreator func(r *http.Request, body []byte) (token string, err error)

// SetCheckCreator haengt das Anlegen von Healthchecks an ("Healthcheck fuer dieses Ziel").
func (m *Module) SetCheckCreator(f CheckCreator) { m.checks = f }

// SetPorts haengt die Port-Verwaltung an (Streams pruefen ihre Ports vor dem Oeffnen).
func (m *Module) SetPorts(r *ports.Registry) { m.ports = r }

func (m *Module) Info() module.Info {
	return module.Info{Name: Name, TitleKey: "nav.proxy", Icon: "bi-diagram-3", Image: "cdn64.webp", Path: "/cdn64", Available: true, Order: 30,
		Version: Version, Changelog: changelog}
}

func (m *Module) Migrations() []store.Migration {
	ms, err := store.ReadMigrations(migrationFS, "migrations")
	if err != nil {
		panic(err)
	}
	return ms
}

// Templates liefert die Seiten des Moduls (module.Templater).
func (m *Module) Templates() fs.FS {
	sub, _ := fs.Sub(templateFS, "templates")
	return sub
}

func (m *Module) Routes(mux *http.ServeMux, g module.Guards) {
	m.g = g
	m.uiRoutes(mux, g)
	m.apiRoutes(mux, g)
}

// Start meldet die Hosts beim Eingang an und startet die Pruefung der Ziele.
func (m *Module) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return nil
	}
	ctx, m.cancel = context.WithCancel(ctx)
	m.running, m.startedAt = true, time.Now()
	m.wg.Add(1)
	m.mu.Unlock()
	if m.dataDir != "" {
		st, err := openStats(filepath.Join(m.dataDir, Name), m.log, func() int { return m.logDays(context.Background()) },
			func() bool { return m.core.SettingOr(context.Background(), setAnonymize, "off") == "mask" })
		if err != nil {
			m.log.Warn("cdn64 statistics not available", "err", err)
		} else {
			m.stats2.Store(st)
		}
	}
	if m.certs != nil {
		m.certs.SetUsers(Name, m.certUsers)
		m.certs.Acquire(Name)
	}
	m.limLoad(ctx)
	m.apply(ctx)
	m.applyStreams(ctx)
	go func() { defer m.wg.Done(); m.reachLoop(ctx) }()
	m.wg.Add(1)
	go func() { defer m.wg.Done(); m.blLoop(ctx) }()
	m.wg.Add(1)
	go func() { defer m.wg.Done(); m.limLoop(ctx) }()
	if m.edge != nil {
		m.edge.SetBlocker(m.blockedAny)
		m.edge.SetGate(m.gateOpen)
	}
	m.log.Info("cdn64 started")
	return nil
}

// Stop meldet alles beim Eingang ab und beendet die Pruefung.
func (m *Module) Stop(ctx context.Context) error {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return nil
	}
	m.running = false
	cancel := m.cancel
	m.cancel = nil
	m.mu.Unlock()
	m.applyMu.Lock() // laufendes apply abwarten, danach meldet keins mehr an
	if m.edge != nil {
		m.edge.Remove(Name)
		m.edge.SetBlocker(nil)
		m.edge.SetGate(nil)
	}
	m.applyMu.Unlock()
	m.stopStreams()
	if m.certs != nil {
		m.certs.Release(Name)
		m.certs.SetUsers(Name, nil)
	}
	cancel()
	done := make(chan struct{})
	go func() { m.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
	m.cache.clear()
	st := m.stats2.Swap(nil)
	m.mu.Lock()
	for id, tr := range m.hostTr {
		tr.CloseIdleConnections()
		delete(m.hostTr, id)
	}
	m.mu.Unlock()
	if st != nil {
		st.close()
	}
	m.trVerify.CloseIdleConnections()
	m.trInsecure.CloseIdleConnections()
	m.log.Info("cdn64 stopped")
	return nil
}

// Card liefert die Dashboard-Karte (module.CardProvider).
func (m *Module) Card(ctx context.Context) (*module.Card, error) {
	c := &module.Card{TitleKey: "nav.proxy", Image: "cdn64.webp", Path: "/cdn64"}
	list, err := m.hosts(ctx)
	if err != nil {
		return nil, err
	}
	var on, down int64
	var req int64
	for _, h := range list {
		if !h.Enabled {
			continue
		}
		on++
		if m.reach.get(h.ID).State == ReachDown {
			down++
		}
		req += m.statsOf(h.ID).requests.Load()
	}
	c.Stats = []module.CardStat{{LabelKey: "cdn64.card.hosts", Value: on}}
	if down > 0 {
		c.Stats = append(c.Stats, module.CardStat{LabelKey: "cdn64.card.down", Value: down, Class: "text-danger"})
	} else {
		c.Stats = append(c.Stats, module.CardStat{LabelKey: "cdn64.card.down", Value: 0})
	}
	c.Stats = append(c.Stats, module.CardStat{LabelKey: "cdn64.card.requests", Value: req})
	if m.certs != nil {
		var soon int64
		if cl, err := m.certs.List(ctx); err == nil {
			for _, x := range cl {
				if len(x.UsedBy) > 0 && !x.NotAfter.IsZero() && x.DaysLeft() < 14 {
					soon++
				}
			}
		}
		st := module.CardStat{LabelKey: "cdn64.card.certs_soon", Value: soon}
		if soon > 0 {
			st.Class = "text-warning-emphasis"
		}
		c.Stats = append(c.Stats, st)
	}
	if e := m.edgeError(); e != "" {
		c.Err = e
	}
	return c, nil
}

// edgeError: ein Port des Eingangs, den CDN64 braucht, ist nicht offen.
func (m *Module) edgeError() string {
	if m.edge == nil {
		return ""
	}
	for _, l := range m.edge.Status().Listeners {
		if l.Needed && !l.Running && l.Error != "" {
			return l.Name + " (" + string(l.Proto) + " " + itoa(l.Port) + "): " + l.Error
		}
	}
	return ""
}

// ---------------------------------------------------------------- Export / Import (module.Exporter)

type exportFile struct {
	Hosts   []*Host   `json:"hosts"`
	Streams []*Stream `json:"streams,omitempty"`
}

func (m *Module) Export(ctx context.Context) (any, error) {
	list, err := m.hosts(ctx)
	if err != nil {
		return nil, err
	}
	for _, h := range list {
		if h.CertID > 0 { // Kennungen gelten nur auf dieser Node: beim Import passendes nach Namen
			h.CertID = CertAuto
		}
	}
	streams, err := m.streams(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range streams {
		s.TLSCertID = 0 // Zertifikate gehoeren nicht zum Export
	}
	return exportFile{Hosts: list, Streams: streams}, nil
}

// Import legt Hosts und Streams an, deren Namen bzw. Ports es hier noch nicht gibt (nichts wird geaendert oder
// geloescht).
func (m *Module) Import(ctx context.Context, raw json.RawMessage) (int, error) {
	var f exportFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return 0, err
	}
	n := 0
	var firstErr error
	for _, h := range f.Hosts {
		h.ID = 0
		if err := m.saveHost(ctx, h); err != nil {
			var fe *FieldError
			if errors.As(err, &fe) && fe.Key == "cdn64.err.name_taken" {
				continue // gibt es schon
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		n++
	}
	for _, s := range f.Streams {
		s.ID = 0
		if err := m.saveStream(ctx, s); err != nil {
			var fe *FieldError
			if errors.As(err, &fe) && fe.Key == "cdn64.err.stream_port_taken" {
				continue // gibt es schon
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		n++
	}
	return n, firstErr
}

// logDays: Aufbewahrung des Zugriffs-Logs in Tagen (1-90, Standard 7).
func (m *Module) logDays(ctx context.Context) int {
	n, err := strconv.Atoi(m.core.SettingOr(ctx, setLogDays, "7"))
	if err != nil || n < 1 || n > 90 {
		return 7
	}
	return n
}
