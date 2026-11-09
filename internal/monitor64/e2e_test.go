package monitor64

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/m64agent"
	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

// fakeHost liefert Berichte eines Linux-Hosts; fsUsed steuert den Fuellstand von "/".
type fakeHost struct {
	mu     sync.Mutex
	fsUsed uint64 // Prozent
	t      int64
}

func (f *fakeHost) Collect(_ context.Context, _ []string) *m64proto.Report {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t += 60_000
	return &m64proto.Report{V: 1, Time: f.t,
		CPU: &m64proto.CPU{Cores: 2, User: uint64(f.t / 100), Idle: uint64(f.t / 50)},
		Mem: &m64proto.Mem{Total: 1000, Available: 500},
		FS:  []m64proto.FS{{Mount: "/", Total: 100, Used: f.fsUsed, Avail: 100 - f.fsUsed}},
	}
}

func (f *fakeHost) set(used uint64) { f.mu.Lock(); f.fsUsed = used; f.mu.Unlock() }

func newTestModule(t *testing.T) (*Module, *[]notify.Alert, *sync.Mutex) {
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(context.Background(), filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cm, _ := store.CoreMigrations()
	if err := st.Migrate(context.Background(), "core", cm); err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(context.Background(), Name, Migrations()); err != nil {
		t.Fatal(err)
	}
	box, err := secrets.New([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	m := New(st, log, box, dir, "test")
	var mu sync.Mutex
	var alerts []notify.Alert
	m.SetNotifier(func(a notify.Alert) { mu.Lock(); alerts = append(alerts, a); mu.Unlock() })
	return m, &alerts, &mu
}

func TestEndToEndAgent(t *testing.T) {
	ctx := context.Background()
	m, alerts, amu := newTestModule(t)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })

	// Agent im Prozess mit dem Schluessel der Node
	line, err := m.PublicKeyLine(ctx)
	if err != nil {
		t.Fatal(err)
	}
	adir := t.TempDir()
	keys := filepath.Join(adir, "keys")
	if err := os.WriteFile(keys, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hk, err := m64agent.LoadOrCreateHostKey(filepath.Join(adir, "hostkey"))
	if err != nil {
		t.Fatal(err)
	}
	fh := &fakeHost{fsUsed: 50}
	srv, err := m64agent.New(m64agent.Config{HostKey: hk, KeysFile: keys, Collector: fh, Version: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	// Host mit Agent-Zugang anlegen
	by := Actor{Kind: "user", Name: "dennis", Method: "local"}
	h := &Host{Name: "test01", Address: "127.0.0.1", Kind: "linux-agent", Group: "Keller", IntervalSec: 60}
	if err := m.store.SaveHost(ctx, h, by); err != nil {
		t.Fatal(err)
	}
	if err := m.store.SaveAccess(ctx, &Access{HostUID: h.UID, Type: "agent", Config: []byte(`{"port":` + port + `}`), Enabled: true}, false, by); err != nil {
		t.Fatal(err)
	}
	m.ReloadHost(ctx, h.UID)
	rt := m.rts[h.UID]

	// 1. Runde: Dienste erkannt, nichts uebernommen, Hostschluessel gemerkt (TOFU)
	m.poll(ctx, rt)
	rows, _ := m.store.Services(ctx, h.UID)
	if len(rows) < 3 {
		t.Fatalf("discovered %d services", len(rows))
	}
	for _, r := range rows {
		if r.Adopted != 0 {
			t.Fatalf("service %s adopted automatically", r.Key)
		}
	}
	if v := rt.getView(); v == nil || v.New != len(rows) || v.View != eval.ViewOK {
		t.Fatalf("view after first round: %+v", v)
	}
	accs, _ := m.store.Accesses(ctx, h.UID)
	if accs[0].HostKey == "" {
		t.Fatal("host key not remembered (TOFU)")
	}
	// alle uebernehmen
	for _, r := range rows {
		if err := m.store.SetAdopted(ctx, h.UID, r.Key, 1, by); err != nil {
			t.Fatal(err)
		}
	}
	// 2. Runde: OK
	m.poll(ctx, rt)
	if v := rt.getView(); v.State != eval.OK || len(v.Services) < 3 {
		t.Fatalf("view OK round: state %s, %d services", v.State, len(v.Services))
	}
	// 3. Runde: Dateisystem 95 % -> Kritisch, Problem offen, Meldung
	fh.set(95)
	m.poll(ctx, rt)
	v := rt.getView()
	if v.State != eval.Crit {
		t.Fatalf("expected crit, got %s", v.State)
	}
	open := m.loadOpen(ctx, h.UID)
	if open["fs:/"] == nil || open["fs:/"].State != "crit" {
		t.Fatalf("no open problem for fs:/: %+v", open["fs:/"])
	}
	amu.Lock()
	n := len(*alerts)
	var last notify.Alert
	if n > 0 {
		last = (*alerts)[n-1]
	}
	amu.Unlock()
	if n == 0 || last.Kind != notify.KindMonitorProblem || !strings.Contains(last.Data["lines"], "fs:/") || last.Check.Channels != nil {
		t.Fatalf("expected problem alert to default channels, got %d alerts, last %+v", n, last)
	}
	// Quittieren mit Akteur
	if err := m.Ack(ctx, h.UID, "fs:/", "räume auf", by); err != nil {
		t.Fatal(err)
	}
	// 4. Runde: wieder OK -> Problem automatisch geloest, Entwarnung
	fh.set(40)
	m.poll(ctx, rt)
	if len(m.loadOpen(ctx, h.UID)) != 0 {
		t.Fatal("problem not closed automatically")
	}
	amu.Lock()
	last = (*alerts)[len(*alerts)-1]
	amu.Unlock()
	if last.Kind != notify.KindMonitorOK {
		t.Fatalf("expected ok alert, got %s", last.Kind)
	}
	var how, closedBy string
	if err := m.st.Reader().QueryRow(`SELECT closed_how, closed_by FROM m64_problems WHERE host_uid = ?`, h.UID).Scan(&how, &closedBy); err != nil || how != "auto" || !strings.Contains(closedBy, "system") {
		t.Fatalf("closed how=%q by=%q err=%v", how, closedBy, err)
	}
	var evs int
	_ = m.st.Reader().QueryRow(`SELECT COUNT(*) FROM m64_events WHERE host_uid = ? AND kind = 'ack' AND actor LIKE '%dennis%'`, h.UID).Scan(&evs)
	if evs != 1 {
		t.Fatal("ack event with actor missing")
	}
	// 5. Agent weg: nach 2 Runden nicht erreichbar, eine Meldung
	_ = srv.Close()
	m.poll(ctx, rt)
	m.poll(ctx, rt)
	if v := rt.getView(); v.View != eval.ViewUnreachable {
		t.Fatalf("expected unreachable, got %s", v.View)
	}
	amu.Lock()
	last = (*alerts)[len(*alerts)-1]
	amu.Unlock()
	if last.Kind != notify.KindMonitorUnreachable {
		t.Fatalf("expected unreachable alert, got %s", last.Kind)
	}
	// Verlauf hat Werte
	if err := m.seriesStore().Flush(ctx); err != nil {
		t.Fatal(err)
	}
	_ = time.Second
}
