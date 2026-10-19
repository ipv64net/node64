// Package dns64 ist das Modul DNS64: ein lokaler, cachender DNS-Resolver fuers Heimnetz, der Werbung,
// Tracker und Malware ueber Blocklisten filtert und verschluesselt (DNS-over-HTTPS) ins Internet fragt.
// Uebernommen aus dem eigenstaendigen DNS64-Container; Plan: docs/PLAN-NODE64-DNS64.md.
//
// Aus = keine Sockets, keine Goroutinen, kein Speicher fuer Listen und Cache. Die Daten liegen unter
// <DATA_DIR>/dns64/ (Abfrage-Log dns64.db, Freigaben allowlist.txt, Blocklisten lists/).
package dns64

import (
	"context"
	"crypto/tls"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/dns64/cache"
	"github.com/ipv64net/node64/internal/dns64/dnsserver"
	"github.com/ipv64net/node64/internal/dns64/filter"
	"github.com/ipv64net/node64/internal/dns64/localnet"
	"github.com/ipv64net/node64/internal/dns64/querylog"
	"github.com/ipv64net/node64/internal/dns64/upstream"
	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/notify"
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

const (
	Name      = "dns64"
	version   = "1.15.0"
	cacheSize = 20000

	setPort      = "dns64.port"      // Port fuer DNS (UDP/TCP), Standard 53
	setBind      = "dns64.bind"      // Adresse, leer = alle
	setRouter    = "dns64.router"    // DNS des Routers fuer lokale Namen, leer = automatisch (Default-Gateway)
	setRetention = "dns64.retention" // Tage im Abfrage-Log
)

// Module implementiert module.Module.
type Module struct {
	core    *store.Store
	log     *slog.Logger
	dataDir string
	version string

	g module.Guards

	ctl     sync.Mutex // serialisiert Start, Stop und Neustart
	mu      sync.Mutex
	life    context.CancelFunc // nil = Modul aus
	retryWG sync.WaitGroup
	eng     *engine        // nil = DNS-Dienst laeuft nicht
	ingress *edge.Edge     // gemeinsamer Eingang des Kerns (DoH auf dem HTTPS-Port), nil = keiner
	certs   *certs.Manager // zentrale Zertifikatsverwaltung, nil = keine (Tests)
	lastErr string         // letzter Fehler beim Start (z. B. Port belegt)

	recs atomic.Pointer[recordTable] // eigene DNS-Eintraege (records.go)

	webCert, webKey string // Zertifikat der Weboberflaeche (cert_mode node64)

	notifier func(notify.Alert) // Meldungen (nil = keine)
	splitFn  func(string) bool  // Namen, die im Heimnetz die Node meinen (CDN64 online), nil = keine

	cur atomic.Pointer[tls.Certificate] // aktuelles Zertifikat fuer DoH/DoT/DoQ (wechselt ohne Neustart)
	// certInUse: Kennung des Zertifikats aus der Verwaltung, das DNS64 gerade nutzt (0 = keins)
	certInUse atomic.Int64
	migErr    string // Umzug in die Verwaltung noch nicht erledigt: letzter Fehler (m.mu)

	pauseUntil atomic.Int64 // Blockieren aus bis (UnixNano), -1 = bis zum Wiedereinschalten, 0 = aktiv (pause.go)
}

const retryEvery = time.Minute

// engine ist der laufende Resolver mit allem, was dazu gehoert.
type engine struct {
	addr    string
	started time.Time
	store   *querylog.Store
	lists   *filter.Manager
	cache   *cache.Cache
	up      *upstream.Resolver
	local   *localnet.Resolver
	srv     *dnsserver.Server
	enc     *encrypted // DoH/DoT/DoQ fuer Geraete
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// New erzeugt das Modul. dataDir ist das Datenverzeichnis von Node64.
func New(core *store.Store, log *slog.Logger, dataDir, nodeVersion string) *Module {
	return &Module{core: core, log: log.With("module", Name), dataDir: dataDir, version: nodeVersion}
}

func (m *Module) Info() module.Info {
	return module.Info{Name: Name, TitleKey: "nav.dns64", Icon: "bi-shield-check", Image: "dns64.webp", Path: "/dns64", Available: true, Order: 40,
		Version: version, Changelog: changelog, ChangelogEN: changelogEN}
}

// Migrations: eigene DNS-Eintraege in node64.db (Abfrage-Log in eigener Datei, Einstellungen im Kern).
func (m *Module) Migrations() []store.Migration {
	ms, err := store.ReadMigrations(migrationFS, "migrations")
	if err != nil {
		panic(err)
	}
	return ms
}

func (m *Module) Routes(mux *http.ServeMux, g module.Guards) {
	m.uiRoutes(mux, g)
	m.apiRoutes(mux, g)
	m.apiMoreRoutes(mux, g)
}

func (m *Module) dir() string { return filepath.Join(m.dataDir, "dns64") }

// listenAddr ist die Adresse des DNS-Dienstes aus den Einstellungen.
func (m *Module) listenAddr(ctx context.Context) string {
	return net.JoinHostPort(m.core.SettingOr(ctx, setBind, ""), strconv.Itoa(m.port(ctx)))
}

// selfAddr ist die Adresse, unter der die Node den eigenen DNS-Dienst erreicht.
func (m *Module) selfAddr(ctx context.Context) string {
	host := m.core.SettingOr(ctx, setBind, "")
	if ip := net.ParseIP(host); ip == nil || ip.IsUnspecified() {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, strconv.Itoa(m.port(ctx)))
}

func (m *Module) port(ctx context.Context) int {
	p, err := strconv.Atoi(m.core.SettingOr(ctx, setPort, "53"))
	if err != nil || p < 1 || p > 65535 {
		return 53
	}
	return p
}

func (m *Module) retention(ctx context.Context) int {
	d, err := strconv.Atoi(m.core.SettingOr(ctx, setRetention, "7"))
	if err != nil || d < 1 || d > 90 {
		return 7
	}
	return d
}

// routerAddr ist der fest eingestellte Router (ip oder ip:port), leer = automatisch.
func (m *Module) routerAddr(ctx context.Context) string {
	r := strings.TrimSpace(m.core.SettingOr(ctx, setRouter, ""))
	if r == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(r); err != nil {
		r = net.JoinHostPort(strings.Trim(r, "[]"), "53")
	}
	return r
}

// Start oeffnet das Abfrage-Log, laedt Freigaben und Blocklisten und lauscht auf dem DNS-Port. Klappt das nicht
// (z. B. Port belegt), bleibt das Modul an, damit Seiten und Einstellungen erreichbar sind; der Fehler steht auf
// den Seiten und der Start wird jede Minute wiederholt.
func (m *Module) Start(ctx context.Context) error {
	m.ctl.Lock()
	defer m.ctl.Unlock()
	return m.startLocked()
}

// startLocked: Start ohne m.ctl (Aufrufer haelt ihn).
func (m *Module) startLocked() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.life != nil {
		return nil
	}
	lctx, cancel := context.WithCancel(context.Background())
	m.life = cancel
	if m.tryStart(lctx) != nil {
		m.retryWG.Add(1)
		go m.retry(lctx)
	}
	return nil
}

// tryStart startet den DNS-Dienst und merkt sich den Fehler (m.mu gehalten).
func (m *Module) tryStart(ctx context.Context) error {
	err := m.start(ctx)
	m.lastErr = ""
	if err != nil {
		m.lastErr = err.Error()
		m.log.Warn("dns64 could not start", "err", err)
	}
	return err
}

func (m *Module) retry(ctx context.Context) {
	defer m.retryWG.Done()
	t := time.NewTicker(retryEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		m.mu.Lock()
		if ctx.Err() != nil || m.eng != nil {
			m.mu.Unlock()
			return
		}
		err := m.tryStart(ctx)
		m.mu.Unlock()
		if err == nil {
			return
		}
	}
}

func (m *Module) start(ctx context.Context) error {
	if err := os.MkdirAll(m.dir(), 0o750); err != nil {
		return err
	}
	if err := m.loadRecords(ctx); err != nil {
		return fmt.Errorf("load records: %w", err)
	}
	cfg := m.loadConfig(ctx)
	m.migrateCentral(ctx, &cfg)
	m.loadPause(ctx)
	e := &engine{addr: m.listenAddr(ctx), started: time.Now()}
	st, err := querylog.Open(filepath.Join(m.dir(), "dns64.db"), time.Duration(cfg.Retention)*24*time.Hour, m.log)
	if err != nil {
		return fmt.Errorf("open query log: %w", err)
	}
	e.store = st
	allow, err := filter.LoadAllowlist(filepath.Join(m.dir(), "allowlist.txt"))
	if err != nil {
		st.CloseNow()
		return fmt.Errorf("load allowlist: %w", err)
	}
	lists := filepath.Join(m.dir(), "lists")
	if e.lists, err = filter.NewManager(lists, cfg.activeLists(), time.Duration(cfg.ListHours)*time.Hour, allow, listClient(m.selfAddr(ctx)), m.log); err != nil {
		st.CloseNow()
		return err
	}
	e.cache = cache.New(cfg.CacheSize)
	e.up = upstream.New(cfg.activeUpstreams(), cfg.UpMode)
	e.up.SetTop(cfg.UpCount)
	e.local = localnet.New(m.routerAddr(ctx), m.log)
	e.srv = &dnsserver.Server{Addr: e.addr, Local: e.local, Filter: e.lists, Upstream: e.up, Cache: e.cache, Log: st, Logger: m.log,
		Records: m, Split: m.split, BlockNX: cfg.BlockMode == blockNX, ExtraNets: cfg.allowPrefixes(), Anonymize: cfg.anonymizer(), Paused: m.paused}
	if err := e.srv.Start(); err != nil {
		st.CloseNow()
		e.up.Close()
		return fmt.Errorf("dns %s: %w", e.addr, err)
	}
	e.enc = m.startEncrypted(cfg, e.srv)
	ectx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	for _, run := range []func(context.Context){st.Run, e.lists.Run, e.local.Run, e.up.RunProbes, func(ctx context.Context) { m.runMonitor(ctx, e) }} {
		e.wg.Add(1)
		go func() { defer e.wg.Done(); run(ectx) }()
	}
	m.eng = e
	m.log.Info("dns64 started", "dns", e.addr, "router", m.routerAddr(ctx))
	return nil
}

// Stop schliesst die Sockets, schreibt das Abfrage-Log zu Ende und gibt Listen und Cache frei.
func (m *Module) Stop(ctx context.Context) error {
	m.ctl.Lock()
	defer m.ctl.Unlock()
	return m.stopLocked(ctx)
}

// stopLocked: Stop ohne m.ctl (Aufrufer haelt ihn).
func (m *Module) stopLocked(ctx context.Context) error {
	m.mu.Lock()
	if m.life != nil {
		m.life() // unter m.mu, damit ein laufender Wiederholversuch danach nichts mehr startet
	}
	e := m.eng
	m.life, m.eng, m.lastErr = nil, nil, ""
	m.mu.Unlock()
	m.retryWG.Wait()
	if e == nil {
		return nil
	}
	e.enc.stop(ctx)
	e.srv.Shutdown(ctx)
	e.cancel()
	done := make(chan struct{})
	go func() { e.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		// Hintergrundjobs haengen: Verbindungen trotzdem schliessen, das Abfrage-Log, sobald sie fertig sind
		e.up.Close()
		go func() { e.wg.Wait(); _ = e.store.Close() }()
		return ctx.Err()
	}
	err := e.store.Close()
	e.up.Close()
	debug.FreeOSMemory() // Blocklisten und Cache sind gross
	return err
}

// running liefert den laufenden Resolver (nil = aus).
func (m *Module) running() *engine {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.eng
}

// startError ist der letzte Fehler beim Start ("" = keiner).
func (m *Module) startError() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastErr
}

// restart startet den Resolver mit neuen Einstellungen neu (nur wenn das Modul an ist).
// Unter m.ctl: ein gleichzeitiges Abschalten (Registry.Disable -> Stop) wartet, bis der Neustart fertig ist, und
// stoppt danach; kommt es zuerst, ist das Modul aus und es wird nicht neu gestartet.
func (m *Module) restart(ctx context.Context) error {
	m.ctl.Lock()
	defer m.ctl.Unlock()
	m.mu.Lock()
	on := m.life != nil
	m.mu.Unlock()
	if !on {
		return nil // aus: neue Einstellungen gelten beim naechsten Start
	}
	sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := m.stopLocked(sctx); err != nil {
		return err
	}
	_ = m.startLocked()
	if e := m.startError(); e != "" {
		return errors.New(e)
	}
	return nil
}

var errNotRunning = errors.New("dns64 is not running")

// listClient laedt die Blocklisten und loest ihre Hostnamen ueber den eigenen DNS-Dienst auf, damit es auch
// geht, wenn der Host selbst diesen Resolver benutzt.
func listClient(self string) *http.Client {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, self)
		},
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, Resolver: resolver}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = dialer.DialContext
	tr.Proxy = nil
	return &http.Client{Transport: tr}
}

// Card liefert die Dashboard-Karte (module.CardProvider): Zahlen der letzten 24 Stunden.
func (m *Module) Card(ctx context.Context) (*module.Card, error) {
	c := &module.Card{TitleKey: "nav.dns64", Image: "dns64.webp", Path: "/dns64"}
	e := m.running()
	if e == nil {
		c.Err = m.startError()
		return c, nil
	}
	sum, err := e.store.Summary(ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		return nil, err
	}
	var pct float64
	if sum.Total > 0 {
		pct = 100 * float64(sum.Blocked) / float64(sum.Total)
	}
	c.Stats = []module.CardStat{
		{LabelKey: "dns64.card.listen", Text: e.addr},
		{LabelKey: "dns64.card.total", Value: sum.Total},
		{LabelKey: "dns64.card.blocked", Value: sum.Blocked, Pct: pct, Class: "text-danger"},
		{LabelKey: "dns64.card.cached", Value: sum.Cached},
		{LabelKey: "dns64.card.clients", Value: sum.Clients},
		{LabelKey: "dns64.card.lists", Value: int64(e.lists.Matcher().Size())},
	}
	if p := m.pauseState(); p.Active { // Blockieren pausiert: oben und gelb
		until := "∞"
		if !p.Forever {
			until = p.Until.Format("15:04")
		}
		c.Stats = append([]module.CardStat{{LabelKey: "dns64.card.paused", Text: until, Class: "text-warning-emphasis"}}, c.Stats...)
	}
	return c, nil
}
