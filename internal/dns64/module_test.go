package dns64

import (
	"context"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ipv64net/node64/internal/dns64/querylog"
	"github.com/ipv64net/node64/internal/store"
)

func testModule(t *testing.T) (*Module, int) {
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	core, err := store.Open(context.Background(), filepath.Join(dir, "node64.db"), filepath.Join(dir, "backup"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Close() })
	ms, _ := store.CoreMigrations()
	if err := core.Migrate(context.Background(), "core", ms); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	ctx := context.Background()
	_ = core.SetSetting(ctx, setPort, strconv.Itoa(port))
	_ = core.SetSetting(ctx, setBind, "127.0.0.1")
	_ = core.SetSetting(ctx, setRouter, fakeRouter(t)) // lokale Namen gehen nur an den (Test-)Router
	m := New(core, log, dir, "test")
	if err := core.Migrate(ctx, Name, m.Migrations()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(context.Background()) })
	return m, port
}

// fakeRouter beantwortet "nas" mit 192.168.1.10 und alles andere mit NXDOMAIN.
func fakeRouter(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Name == "nas." {
			m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "nas.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.168.1.10")}}
		} else {
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// freePort sucht einen Port, der fuer UDP und TCP frei ist.
func freePort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 20; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p := l.Addr().(*net.TCPAddr).Port
		l.Close()
		if pc, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p))); err == nil {
			pc.Close()
			return p
		}
	}
	t.Fatal("no free port")
	return 0
}

func query(addr, name string) (*dns.Msg, error) {
	c := &dns.Client{Timeout: 2 * time.Second}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	r, _, err := c.Exchange(q, addr)
	return r, err
}

func TestStartStopFreesEverything(t *testing.T) {
	m, port := testModule(t)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	before := runtime.NumGoroutine()

	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m.running() == nil {
		t.Fatalf("not running: %s", m.startError())
	}
	// lokaler Name: Antwort vom Router
	r, err := query(addr, "nas")
	if err != nil || len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "192.168.1.10" {
		t.Fatalf("local name: %v %v", r, err)
	}
	if r, err := query(addr, "drucker.fritz.box"); err != nil || r.Rcode != dns.RcodeNameError {
		t.Fatalf("unknown local name: %v %v", r, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := m.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	// Port ist wieder frei (UDP und TCP)
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("udp still bound: %v", err)
	}
	pc.Close()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("tcp still bound: %v", err)
	}
	l.Close()
	// keine Goroutinen uebrig (kurz warten, bis Leser-Goroutinen der Sockets beendet sind)
	for i := 0; i < 50 && runtime.NumGoroutine() > before; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before {
		buf := make([]byte, 1<<16)
		t.Fatalf("goroutines: %d before, %d after stop\n%s", before, n, buf[:runtime.Stack(buf, true)])
	}
	// Nachfragen nach dem Stopp laufen ins Leere
	if _, err := query(addr, "nas"); err == nil {
		t.Fatal("dns still answers after stop")
	}
}

func TestBusyPortKeepsModuleReachable(t *testing.T) {
	m, port := testModule(t)
	l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("start must not fail (pages stay reachable): %v", err)
	}
	if m.running() != nil || m.startError() == "" {
		t.Fatalf("busy port: running=%v err=%q", m.running() != nil, m.startError())
	}
	// Port wird frei, neuer Start mit denselben Einstellungen klappt
	l.Close()
	if err := m.restart(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m.running() == nil {
		t.Fatal("restart did not start the dns service")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := m.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestExportImport(t *testing.T) {
	a, _ := testModule(t)
	ctx := context.Background()
	al, err := a.allowlist()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := al.Add("Example.COM"); err != nil {
		t.Fatal(err)
	}
	out, err := a.Export(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ex := out.(exportData)
	if len(ex.Allowlist) != 1 || ex.Allowlist[0] != "example.com" || ex.Settings[setBind] != "127.0.0.1" {
		t.Fatalf("export = %+v", ex)
	}
	b, _ := testModule(t)
	raw := []byte(`{"settings":{"dns64.retention":"14"},"allowlist":["example.com","bad domain"]}`)
	n, err := b.Import(ctx, raw)
	if err != nil || n != 2 {
		t.Fatalf("import n=%d err=%v", n, err)
	}
	if b.retention(ctx) != 14 {
		t.Fatal("retention not imported")
	}
	bl, _ := b.allowlist()
	if !bl.Contains("www.example.com") {
		t.Fatal("allowlist not imported")
	}
}

// Eigene Sperrliste wirkt sofort (samt Subdomains); eine angehaengte Suchdomain steht im Log mit Hinweis.
func TestDenylistAndSearchSuffix(t *testing.T) {
	m, port := testModule(t)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	e := m.running()
	if e == nil || e.lists.Deny == nil {
		t.Fatalf("not running or no denylist: %s", m.startError())
	}
	if _, err := e.lists.Deny.Add("tracker.test"); err != nil {
		t.Fatal(err)
	}
	r, err := query(addr, "ads.tracker.test")
	if err != nil || len(r.Answer) != 1 || !r.Answer[0].(*dns.A).A.IsUnspecified() {
		t.Fatalf("own block: %v %v", r, err)
	}
	if r, err := query(addr, "example.com.home.local"); err != nil || r.Rcode != dns.RcodeNameError {
		t.Fatalf("search suffix: %v %v", r, err)
	}
	var rows []querylog.LogRow
	for i := 0; i < 50; i++ { // das Log schreibt gebuendelt
		rows, _, _ = e.store.Recent(context.Background(), querylog.LogFilter{Limit: 10})
		if len(rows) >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	got := map[string]string{}
	for _, row := range rows {
		got[row.Domain] = row.Reason
	}
	if got["ads.tracker.test"] != "own:tracker.test" || got["example.com.home.local"] != "search:example.com" {
		t.Fatalf("log reasons: %v", got)
	}
}

// Neustart mit abgebrochenem Kontext der Anfrage (Client weg): DNS64 muss danach wieder laufen.
func TestRestartWithCanceledContextKeepsDNS(t *testing.T) {
	m, port := testModule(t)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m.running() == nil {
		t.Fatalf("not started: %s", m.startError())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = m.restart(ctx)
	if m.running() == nil {
		t.Fatalf("dns stays off after restart with canceled context: %s", m.startError())
	}
	c := &dns.Client{Timeout: 2 * time.Second}
	q := new(dns.Msg)
	q.SetQuestion("nas.", dns.TypeA)
	if _, _, err := c.Exchange(q, net.JoinHostPort("127.0.0.1", strconv.Itoa(port))); err != nil {
		t.Fatalf("dns does not answer after restart: %v", err)
	}
}
