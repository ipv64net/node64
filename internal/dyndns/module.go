// Package dyndns ist das Modul DynDNS: ein lokaler Updater, der ausgewaehlte
// Domains/Records bei ipv64 mit der oeffentlichen Adresse des Anschlusses
// aktuell haelt. Plan: docs/PLAN-NODE64-DYNDNS.md.
package dyndns

import (
	"context"
	"embed"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// changelog wird unter Einstellungen > Module angezeigt (Version siehe Info).
//
//go:embed CHANGELOG.md
var changelog string

//go:embed CHANGELOG.en.md
var changelogEN string

const Name = "dyndns"

// Module implementiert module.Module.
type Module struct {
	core       *store.Store
	log        *slog.Logger
	box        *secrets.Box // Tokens und API-Key verschluesselt
	dispatcher *notify.Dispatcher
	version    string

	g module.Guards

	mu     sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup

	notifier func(notify.Alert) // Meldungen (nil = keine)
	fetch    fetchFunc          // Abruf einer IP-Quelle (Tests ersetzen ihn)
	probe    func(fam int) bool // Route fuer die Familie vorhanden?
	trace    func(ctx context.Context, dst netip.Addr, maxHops int) ([]netip.Addr, error)
	trigger  chan chan struct{} // "Jetzt pruefen"
	key      *ipv64api.Key      // zentraler ipv64-API-Key des Containers (Auswahl, Tokens, Limit)

	upd       *updState                                    // Abstand, Backoff, Tageslimit der Update-Aufrufe
	updateURL string                                       // update.php (Tests ersetzen ihn)
	httpc     *http.Client                                 // fuer update.php
	local     func() []ifAddr                              // globale IPv6-Adressen der Interfaces
	dnsLookup func(ctx context.Context, t *Target) dnsView // nil = Nameserver von ipv64 direkt fragen

	startedAt time.Time // Start des Moduls (Anschluss-Analyse danach neu, z. B. nach Wechsel des Netzwerkmodus)

	stMu      sync.Mutex
	fam       [2]famState // [0] IPv4, [1] IPv6
	lim       limitInfo   // Update-Limit des Accounts (mit API-Key)
	ipFail    [2]int      // Fehlversuche der IP-Ermittlung in Folge je Familie (Meldung ab ipFailAlert)
	ipAlerted [2]bool
}

// New erzeugt das Modul. dispatcher darf nil sein.
func New(core *store.Store, log *slog.Logger, box *secrets.Box, dispatcher *notify.Dispatcher, version string) *Module {
	m := &Module{core: core, log: log.With("module", Name), box: box, dispatcher: dispatcher, version: version,
		fetch: newFetcher("node64/" + version), probe: defaultProbe, trace: traceUDP, trigger: make(chan chan struct{}),
		upd: &updState{flaps: map[int64][]time.Time{}, nsCache: map[string]nsEntry{}, external: map[int64]bool{}, tback: map[int64]tBackoff{}, alerted: map[int64]bool{}}, updateURL: defaultUpdateURL,
		httpc: &http.Client{Timeout: 20 * time.Second}, local: localIPv6}
	if dispatcher != nil {
		m.notifier = dispatcher.Dispatch
	}
	return m
}

// SetKey installiert den zentralen API-Key des Containers.
func (m *Module) SetKey(k *ipv64api.Key) { m.key = k }

// keyOf liefert den zentralen API-Key (leer = keiner eingetragen).
func (m *Module) keyOf(ctx context.Context) string {
	if m.key == nil {
		return ""
	}
	return m.key.Get(ctx)
}

// adoptOldKey zieht einen frueher im Modul gespeicherten Key in die zentrale Ablage um.
func (m *Module) adoptOldKey(ctx context.Context) {
	old := m.core.SettingOr(ctx, "dyndns.apikey", "")
	if old == "" || m.key == nil {
		return
	}
	if m.key.Adopt(ctx, old, m.core.SettingOr(ctx, "dyndns.account", "")) {
		m.log.Info("api key moved to the central ipv64 settings")
	}
	_ = m.core.SetSetting(ctx, "dyndns.apikey", "")
	_ = m.core.SetSetting(ctx, "dyndns.account", "")
}

func (m *Module) Info() module.Info {
	return module.Info{Name: Name, TitleKey: "nav.dyndns", Icon: "bi-globe", Image: "dyndns64.webp", Path: "/dyndns", Available: true, Order: 20,
		Version: "1.4.0", Changelog: changelog, ChangelogEN: changelogEN}
}

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
}

// Start laedt den letzten Stand und startet die Pruefrunden.
func (m *Module) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ctx, m.cancel = context.WithCancel(ctx)
	m.startedAt = time.Now()
	m.adoptOldKey(ctx)
	m.loadState(ctx)
	m.wg.Add(1)
	go m.loop(ctx)
	m.log.Info("dyndns started", "interval", m.interval().String())
	return nil
}

// Stop beendet alle Goroutinen des Moduls.
func (m *Module) Stop(ctx context.Context) error {
	m.mu.Lock()
	cancel := m.cancel
	m.cancel = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
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
