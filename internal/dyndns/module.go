// Package dyndns ist das Modul DynDNS: ein lokaler Updater, der ausgewaehlte
// Domains/Records bei ipv64 mit der oeffentlichen Adresse des Anschlusses
// aktuell haelt. Plan: docs/PLAN-NODE64-DYNDNS.md.
package dyndns

import (
	"context"
	"embed"
	"log/slog"
	"net/http"
	"sync"

	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

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

	fetch   fetchFunc          // Abruf einer IP-Quelle (Tests ersetzen ihn)
	probe   func(fam int) bool // Route fuer die Familie vorhanden?
	trigger chan chan struct{} // "Jetzt pruefen"

	stMu sync.Mutex
	fam  [2]famState // [0] IPv4, [1] IPv6
}

// New erzeugt das Modul. dispatcher darf nil sein.
func New(core *store.Store, log *slog.Logger, box *secrets.Box, dispatcher *notify.Dispatcher, version string) *Module {
	return &Module{core: core, log: log.With("module", Name), box: box, dispatcher: dispatcher, version: version,
		fetch: newFetcher("node64/" + version), probe: defaultProbe, trigger: make(chan chan struct{})}
}

func (m *Module) Info() module.Info {
	return module.Info{Name: Name, TitleKey: "nav.dyndns", Icon: "bi-globe", Image: "dyndns64.webp", Path: "/dyndns", Available: true, Order: 20}
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
}

// Start laedt den letzten Stand und startet die Pruefrunden.
func (m *Module) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ctx, m.cancel = context.WithCancel(ctx)
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
