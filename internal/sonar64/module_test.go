package sonar64

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/config"
	"github.com/ipv64net/node64/internal/i18n"
	"github.com/ipv64net/node64/internal/logging"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/ports"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/sonar"
	"github.com/ipv64net/node64/internal/store"
	nodesync "github.com/ipv64net/node64/internal/sync"
	"github.com/ipv64net/node64/internal/web"
)

const testToken = "s64_abcdefghijABCDEFGHIJ0123456789abcdefghij"

// fakeRunner ersetzt den Kern (kein Netz); dasselbe Objekt ueber Neustarts.
type fakeRunner struct {
	mu       sync.Mutex
	cfg      sonar.Config
	starts   int
	running  int
	status   sonar.Status
	me       sonar.Me
	updates  []sonar.Me
	results  []sonar.Result
	inbound  []sonar.Inbound
	rows     []sonar.InboundRow
	newErr   error
	inSince  time.Time
	inCalled int
	updErr   error
	leaves   int
	forgets  int
	leaveErr error
}

func (f *fakeRunner) Leave(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.leaves++
	return f.leaveErr
}

func (f *fakeRunner) Forget() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forgets++
	return nil
}

func (f *fakeRunner) leaveCounts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.leaves, f.forgets
}

func (f *fakeRunner) Run(ctx context.Context) error {
	f.mu.Lock()
	f.running++
	f.mu.Unlock()
	<-ctx.Done()
	f.mu.Lock()
	f.running--
	f.mu.Unlock()
	return ctx.Err()
}

func (f *fakeRunner) Status() sonar.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

func (f *fakeRunner) Recent(n int) ([]sonar.Result, []sonar.Inbound) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sonar.Result(nil), f.results...), append([]sonar.Inbound(nil), f.inbound...)
}

func (f *fakeRunner) Me(context.Context) (*sonar.Me, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.me
	return &c, nil
}

func (f *fakeRunner) UpdateMe(_ context.Context, m sonar.Me) (*sonar.Me, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updates = append(f.updates, m)
	if f.updErr != nil {
		return nil, f.updErr
	}
	f.me = m
	c := m
	return &c, nil
}

func (f *fakeRunner) Inbound(_ context.Context, since time.Time) ([]sonar.InboundRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inSince, f.inCalled = since, f.inCalled+1
	return append([]sonar.InboundRow(nil), f.rows...), nil
}

func (f *fakeRunner) snapshot() (sonar.Config, int, int, []sonar.Me) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cfg, f.starts, f.running, append([]sonar.Me(nil), f.updates...)
}

func modCore(t *testing.T) (*store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	core, err := store.Open(context.Background(), filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Close() })
	cm, _ := store.CoreMigrations()
	if err := core.Migrate(context.Background(), "core", cm); err != nil {
		t.Fatal(err)
	}
	return core, dir
}

// modTest legt das Modul mit Ersatz-Kern, Schluesselbox und festem API-Key an.
func modTest(t *testing.T) (*Module, *fakeRunner, *int) {
	t.Helper()
	syncFirst = 20 * time.Millisecond
	core, dir := modCore(t)
	box, err := secrets.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	m := New(core, slog.New(slog.NewTextHandler(io.Discard, nil)), box, dir, "test")
	f := &fakeRunner{status: sonar.Status{NodeID: "nabcdefghijk", Registered: true, Mode: "module"},
		me: sonar.Me{NodeID: "nabcdefghijk", Name: "Sonar-Falke-42", Slug: "sonar-falke-42", Trust: TrustNew, Budget: sonar.BudgetLow, Device: "node64"}}
	m.newRunner = func(c sonar.Config) (runnerAPI, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.newErr != nil {
			return nil, f.newErr
		}
		f.cfg, f.starts = c, f.starts+1
		f.status.Measured, f.status.Responder, f.status.Budget = c.Measured, c.Measured, c.Budget
		return f, nil
	}
	tokens := 0
	m.createToken = func(_ context.Context, _, apiKey, name string) (string, error) {
		if apiKey != "k0123456789abcdef" || !strings.HasPrefix(name, "Node64") {
			return "", errors.New("bad call")
		}
		tokens++
		return testToken, nil
	}
	m.keyOf = func(context.Context) string { return "k0123456789abcdef" }
	t.Cleanup(func() { _ = m.Stop(context.Background()) })
	return m, f, &tokens
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout: %s", what)
}

// Eingeschaltet ohne Teilnahme: kein Knoten, kein Port.
func TestModuleOnWithoutParticipationRunsNothing(t *testing.T) {
	m, f, tokens := modTest(t)
	ctx := context.Background()
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, starts, _, _ := f.snapshot(); starts != 0 || m.runner() != nil || len(m.Claims(ctx)) != 0 || *tokens != 0 {
		t.Fatalf("nothing may run: starts=%d claims=%v", starts, m.Claims(ctx))
	}
}

// Teilnahme braucht den API-Key, legt das Token einmal an (verschluesselt) und startet den Kern im Modus module.
func TestParticipate(t *testing.T) {
	m, f, tokens := modTest(t)
	ctx := context.Background()
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	m.keyOf = func(context.Context) string { return "" }
	if err := m.SetParticipate(ctx, true); !errors.Is(err, ErrNoKey) {
		t.Fatalf("without key: %v", err)
	}
	if m.LoadSettings(ctx).Participate {
		t.Fatal("must not participate without key")
	}
	m.keyOf = func(context.Context) string { return "k0123456789abcdef" }
	if err := m.SetParticipate(ctx, true); err != nil {
		t.Fatal(err)
	}
	if raw := m.core.SettingOr(ctx, setToken, ""); raw == "" || strings.Contains(raw, testToken) || !secrets.IsEncrypted(raw) {
		t.Fatalf("token must be stored encrypted: %q", raw)
	}
	waitFor(t, "runner", func() bool { _, _, running, _ := f.snapshot(); return running == 1 })
	cfg, _, _, _ := f.snapshot()
	if cfg.Mode != "module" || cfg.Token != testToken || cfg.Measured || cfg.Budget != sonar.BudgetLow || cfg.DataDir != filepath.Join(m.dataDir, Name) ||
		cfg.Version != "0.1.0/node64-test" {
		t.Fatalf("config: %+v", cfg)
	}
	if fi, err := os.Stat(cfg.DataDir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("data dir: %v %v", fi, err)
	}
	if len(m.Claims(ctx)) != 0 {
		t.Fatal("outbound only: no port")
	}
	waitFor(t, "me", func() bool { return m.cachedMe() != nil })
	// wieder an (laeuft schon): kein zweites Token
	if err := m.SetParticipate(ctx, true); err != nil {
		t.Fatal(err)
	}
	if *tokens != 1 {
		t.Fatalf("token created %d times", *tokens)
	}
	// austreten: bei ipv64 abmelden (Leave), Token weg; wieder teilnehmen = neues Token
	if err := m.SetParticipate(ctx, false); err != nil {
		t.Fatal(err)
	}
	if _, _, running, _ := f.snapshot(); running != 0 || m.runner() != nil || m.cachedMe() != nil {
		t.Fatal("runner must stop")
	}
	if l, fg := f.leaveCounts(); l != 1 || fg != 0 || m.core.SettingOr(ctx, setToken, "") != "" {
		t.Fatalf("leave %d forget %d token %q", l, fg, m.core.SettingOr(ctx, setToken, ""))
	}
	if err := m.SetParticipate(ctx, true); err != nil {
		t.Fatal(err)
	}
	if *tokens != 2 {
		t.Fatalf("token created %d times, want a new one after leaving", *tokens)
	}
	// Modul aus: Knoten aus
	if err := m.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, running, _ := f.snapshot(); running != 0 {
		t.Fatal("module stop must stop the runner")
	}
}

// Austreten ohne Verbindung: lokal trotzdem (Forget), Hinweis ErrLeftLocally; Node-Reset tritt aus; Neu teilnehmen.
func TestLeaveOfflineResetRejoin(t *testing.T) {
	m, f, tokens := modTest(t)
	ctx := context.Background()
	_ = m.Start(ctx)
	if err := m.BeforeReset(ctx); err != nil { // nie teilgenommen: nichts zu tun
		t.Fatal(err)
	}
	if l, _ := f.leaveCounts(); l != 0 {
		t.Fatal("leave without token")
	}
	if err := m.SetParticipate(ctx, true); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.leaveErr = errors.New("ipv64 not reachable")
	f.mu.Unlock()
	err := m.SetParticipate(ctx, false)
	if !errors.Is(err, ErrLeftLocally) || !strings.Contains(err.Error(), "not reachable") {
		t.Fatalf("offline leave: %v", err)
	}
	if l, fg := f.leaveCounts(); l != 1 || fg != 1 || m.LoadSettings(ctx).Participate || m.core.SettingOr(ctx, setToken, "") != "" {
		t.Fatalf("offline leave: leave %d forget %d", l, fg)
	}
	// Node-Reset: tritt aus, Fehler als Hinweis
	if err := m.SetParticipate(ctx, true); err != nil {
		t.Fatal(err)
	}
	if err := m.BeforeReset(ctx); err == nil || !strings.Contains(err.Error(), "30 days") {
		t.Fatalf("reset offline: %v", err)
	}
	f.mu.Lock()
	f.leaveErr = nil
	f.mu.Unlock()
	if err := m.SetParticipate(ctx, true); err != nil {
		t.Fatal(err)
	}
	if err := m.BeforeReset(ctx); err != nil || m.LoadSettings(ctx).Participate || m.core.SettingOr(ctx, setToken, "") != "" {
		t.Fatalf("reset: %v", err)
	}
	// von ipv64 abgemeldet: Neu teilnehmen legt ein neues Token an
	if err := m.SetParticipate(ctx, true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "runner", func() bool { return m.runner() != nil })
	f.mu.Lock()
	f.status.Paused = "revoked"
	f.mu.Unlock()
	before := *tokens
	leaves, _ := f.leaveCounts()
	if err := m.Rejoin(ctx); err != nil {
		t.Fatal(err)
	}
	if l, _ := f.leaveCounts(); *tokens != before+1 || l != leaves+1 || !m.LoadSettings(ctx).Participate {
		t.Fatalf("rejoin: tokens %d leaves %d", *tokens, l)
	}
	waitFor(t, "runner after rejoin", func() bool { return m.runner() != nil })
}

// Ungueltiges Token von ipv64 wird nicht gespeichert.
func TestParticipateRejectsBadToken(t *testing.T) {
	m, _, _ := modTest(t)
	ctx := context.Background()
	_ = m.Start(ctx)
	m.createToken = func(context.Context, string, string, string) (string, error) { return "s64_kurz", nil }
	if err := m.SetParticipate(ctx, true); !errors.Is(err, ErrToken) {
		t.Fatalf("bad token: %v", err)
	}
	if m.core.SettingOr(ctx, setToken, "") != "" || m.LoadSettings(ctx).Participate {
		t.Fatal("nothing may be saved")
	}
}

// Auch gemessen: UDP 6464 ueber die Port-Verwaltung, Konflikt am Feld; Rolle und Budget gehen an ipv64.
func TestMeasuredPortAndSync(t *testing.T) {
	m, f, _ := modTest(t)
	ctx := context.Background()
	reg := ports.New()
	other := false
	reg.Provide("dns64", func(context.Context) []ports.Claim {
		if !other {
			return nil
		}
		return []ports.Claim{{Purpose: "X", Proto: ports.UDP, Port: sonar.Port, Active: true}}
	})
	reg.Provide(Name, m.Claims)
	m.SetPorts(reg)
	_ = m.Start(ctx)
	if err := m.SetParticipate(ctx, true); err != nil {
		t.Fatal(err)
	}
	other = true
	var fe FieldErrors
	if _, err := m.SaveSettings(ctx, Settings{Measured: true, Budget: sonar.BudgetNormal}); !errors.As(err, &fe) || fe["measured"] == "" {
		t.Fatalf("conflict expected: %v", err)
	}
	other = false
	if _, err := m.SaveSettings(ctx, Settings{Measured: true, Budget: sonar.BudgetNormal, Quiet: "23-6"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "restart", func() bool { c, _, r, _ := f.snapshot(); return c.Measured && r == 1 })
	cfg, _, _, _ := f.snapshot()
	if cfg.Quiet != [2]int{23, 6} || cfg.Budget != sonar.BudgetNormal {
		t.Fatalf("config: %+v", cfg)
	}
	waitFor(t, "claim", func() bool { c := m.Claims(ctx); return len(c) == 1 && c[0].Active })
	if c := reg.Overview(ctx); len(c) != 1 || c[0].Owner != Name || c[0].Proto != ports.UDP || c[0].Port != 6464 {
		t.Fatalf("overview: %+v", c)
	}
	waitFor(t, "update me", func() bool { _, _, _, u := f.snapshot(); return len(u) > 0 })
	_, _, _, u := f.snapshot()
	if !u[len(u)-1].Measured || u[len(u)-1].Budget != sonar.BudgetNormal || u[len(u)-1].Name != "Sonar-Falke-42" {
		t.Fatalf("update: %+v", u)
	}
	// ungueltig
	for _, s := range []Settings{{Budget: "viel"}, {Budget: sonar.BudgetLow, Quiet: "25-3"}, {Budget: sonar.BudgetLow, Quiet: "5-5"}} {
		if _, err := m.SaveSettings(ctx, s); !errors.As(err, &fe) {
			t.Fatalf("%+v: %v", s, err)
		}
	}
	// beim Start belegt: nur ausgehend, Claim mit Fehler
	other = true
	if err := m.SetParticipate(ctx, true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "outbound", func() bool { c, _, r, _ := f.snapshot(); return !c.Measured && r == 1 })
	if c := m.Claims(ctx); len(c) != 1 || c[0].Active || c[0].Error == "" {
		t.Fatalf("busy claim: %+v", c)
	}
}

// Profil: pruefen, zusammenfuehren, Rolle/Budget lokal.
func TestSaveProfile(t *testing.T) {
	m, f, _ := modTest(t)
	ctx := context.Background()
	if _, err := m.SaveProfile(ctx, Profile{Name: "Sonar-1"}); !errors.Is(err, ErrNotJoined) {
		t.Fatalf("not joined: %v", err)
	}
	_ = m.Start(ctx)
	_ = m.SetParticipate(ctx, true)
	waitFor(t, "runner", func() bool { return m.runner() != nil })
	lat, lon, bad := 50.1109123456, 8.6821, 91.0
	for _, p := range []Profile{{Name: "ab"}, {Name: "<script>"}, {Name: "Mein  Pi"}, {Name: "admin-1"}, {Name: "Anker Pi"}, {Lat: &lat}, {Lat: &bad, Lon: &lon}, {Access: "isdn"}, {Device: "toaster"}} {
		if _, err := m.SaveProfile(ctx, p); !errors.As(err, new(FieldErrors)) {
			t.Fatalf("%+v: %v", p, err)
		}
	}
	me, err := m.SaveProfile(ctx, Profile{Name: " Mein Knoten ", Lat: &lat, Lon: &lon, Access: "fiber"})
	if err != nil {
		t.Fatal(err)
	}
	if me.Name != "Mein Knoten" || *me.Lat != 50.11091 || me.Access != "fiber" || me.Device != "node64" || me.Measured || me.Budget != sonar.BudgetLow {
		t.Fatalf("me: %+v", me)
	}
	if me, err = m.SaveProfile(ctx, Profile{ClearLoc: true}); err != nil || me.Lat != nil || me.Name != "Mein Knoten" {
		t.Fatalf("clear: %+v %v", me, err)
	}
	// Namensfehler von ipv64 am Feld
	f.mu.Lock()
	f.updErr = &sonar.APIError{Status: 409, Code: "name_taken", Detail: "This name is already taken."}
	f.mu.Unlock()
	if _, err := m.SaveProfile(ctx, Profile{Name: "Sonar-2"}); !errors.As(err, new(FieldErrors)) || err.(FieldErrors)["name"] != "sonar64.err.name_taken" {
		t.Fatalf("name taken: %v", err)
	}
	f.mu.Lock()
	f.updErr = &sonar.APIError{Status: 502, Detail: "down"}
	f.mu.Unlock()
	if _, err := m.SaveProfile(ctx, Profile{Name: "Sonar-2"}); err == nil || errors.As(err, new(FieldErrors)) {
		t.Fatalf("api error: %v", err)
	}
	f.mu.Lock()
	f.updErr = nil
	f.status.Registered = false
	f.mu.Unlock()
	if _, err := m.SaveProfile(ctx, Profile{Name: "Sonar-1"}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("not ready: %v", err)
	}
}

// Abgleich Rolle/Budget scheitert: geholter Knoten bleibt sichtbar, Fehler dazu.
func TestSyncKeepsMeOnUpdateError(t *testing.T) {
	m, f, _ := modTest(t)
	ctx := context.Background()
	f.me.Budget = sonar.BudgetHigh // weicht von der lokalen Einstellung ab
	f.updErr = errors.New("ipv64: HTTP 502")
	_ = m.Start(ctx)
	if err := m.SetParticipate(ctx, true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "me", func() bool { return m.cachedMe() != nil })
	m.mu.Lock()
	meErr := m.meErr
	m.mu.Unlock()
	if me := m.cachedMe(); me.Name != "Sonar-Falke-42" || meErr == "" {
		t.Fatalf("me %+v err %q", me, meErr)
	}
	// Austreten leert den Knoten auch nach einem spaeten Abgleich
	if err := m.SetParticipate(ctx, false); err != nil {
		t.Fatal(err)
	}
	if m.cachedMe() != nil {
		t.Fatal("me kept after leaving")
	}
}

// Fehler beim Anlegen des Kerns (z. B. noch nicht fertig): Fehler sichtbar, kein Absturz.
func TestRunnerErrorShown(t *testing.T) {
	m, f, _ := modTest(t)
	ctx := context.Background()
	f.newErr = sonar.ErrNotImplemented
	_ = m.Start(ctx)
	if err := m.SetParticipate(ctx, true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "error", func() bool { m.mu.Lock(); defer m.mu.Unlock(); return strings.Contains(m.runErr, "not implemented") })
	if m.runner() != nil {
		t.Fatal("no runner expected")
	}
}

func TestHelpers(t *testing.T) {
	for in, want := range map[string][3]int{"": {0, 0, 1}, "23-6": {23, 6, 1}, "0-7": {0, 7, 1}, "7-7": {0, 0, 0}, "24-1": {0, 0, 0}, "1-": {0, 0, 0}, " 1-2": {0, 0, 0}} {
		f, to, ok := parseQuiet(in)
		if f != want[0] || to != want[1] || ok != (want[2] == 1) {
			t.Errorf("%q: %d %d %v", in, f, to, ok)
		}
	}
	if got := publicURL("sonar-falke-42"); got != "https://ipv64.net/sonar/node.php?slug=sonar-falke-42" {
		t.Fatal(got)
	}
	if publicURL("a/b") != "" || publicURL("") != "" || publicURL("x\"onclick") != "" {
		t.Fatal("slug must be checked")
	}
	if id := shortID("nabcdefghijk"); len(id) != 8 {
		t.Fatal(id)
	}
	m, _, _ := modTest(t)
	_ = m.core.SetSetting(context.Background(), setNodeName, "Küche <Pi> & mehr Text, der viel zu lang ist")
	if n := m.tokenName(context.Background()); !nameRe.MatchString(n) || !strings.HasPrefix(n, "Node64 Kche Pi") {
		t.Fatalf("token name %q", n)
	}
	if p, ok := parseCoord("50,25"); !ok || *p != 50.25 {
		t.Fatal("comma")
	}
	if _, ok := parseCoord("NaN"); ok {
		// NaN ist parsebar, validate lehnt es ab
		lat, lon := *mustCoord("NaN"), 1.0
		if fe := (&Profile{Lat: &lat, Lon: &lon}).validate(); fe["lat"] == "" {
			t.Fatal("NaN must be rejected")
		}
	}
}

func mustCoord(s string) *float64 { p, _ := parseCoord(s); return p }

func TestTrust(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	if v := trustOf(nil, false, now); v.Level != TrustNew || v.Pct != 0 || v.Next != TrustStable || v.Class != "text-bg-secondary" {
		t.Fatalf("nil: %+v", v)
	}
	v := trustOf(&sonar.Me{Trust: TrustNew, Since: now.Add(-3 * 24 * time.Hour), Uptime30: 1}, false, now)
	if v.Days != 3 || v.Pct != 42 || v.NeedDays != 7 {
		t.Fatalf("new: %+v", v)
	}
	v = trustOf(&sonar.Me{Trust: TrustTrusted, Since: now.Add(-400 * 24 * time.Hour), Uptime30: 0.99}, false, now)
	if v.Next != TrustPillar || !v.NeedMeasured || v.Pct != 99 {
		t.Fatalf("trusted: %+v", v)
	}
	for level, class := range map[string]string{TrustStable: "text-bg-primary", TrustTrusted: "text-bg-success", TrustPillar: "s64-gold", TrustAnchor: "s64-violet", TrustQuarantine: "text-bg-danger", "bogus": "text-bg-secondary"} {
		if TrustClass(level) != class {
			t.Errorf("%s: %s", level, TrustClass(level))
		}
	}
	if v := trustOf(&sonar.Me{Trust: TrustQuarantine}, true, now); v.Next != "" || v.Pct != 0 {
		t.Fatalf("quarantine: %+v", v)
	}
	if v := trustOf(&sonar.Me{Trust: TrustAnchor}, true, now); v.Pct != 100 || v.Next != "" {
		t.Fatalf("anchor: %+v", v)
	}
}

var (
	csrfRe    = regexp.MustCompile(`name="_csrf" value="([^"]+)"`)
	tplKeyRe  = regexp.MustCompile(`\.T "([a-z0-9_.]+)"`)
	codeKeyRe = regexp.MustCompile(`"(sonar64\.[a-z0-9_.]+)"`)
)

// TestPagesRender rendert die Seite im echten Layout (aus = 404), prueft Formulare, API und dass jeder benutzte
// i18n-Schluessel in beiden Sprachdateien steht.
func TestPagesRender(t *testing.T) {
	m, f, _ := modTest(t)
	st := m.core
	logger := logging.New("error", "text", io.Discard)
	bundle, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	reg := module.NewRegistry(st, logger.Slog())
	reg.Register(m)
	t.Cleanup(reg.StopAll)
	s, err := web.New(web.Deps{Cfg: &config.Config{DataDir: m.dataDir, HTTPPort: 8080, LogLevel: "error"}, Store: st, Log: logger, I18n: bundle, Modules: reg,
		Sync: nodesync.NoOp{}, Version: "test", StartedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	do := func(method, path, body string, hdr map[string]string) (int, string) {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	get := func(path string) (int, string) { return do("GET", path, "", nil) }
	post := func(path string, form url.Values) (int, string) {
		return do("POST", path, form.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	}
	_, body := get("/setup")
	csrf := csrfRe.FindStringSubmatch(body)
	if csrf == nil {
		t.Fatal("no csrf")
	}
	if code, _ := post("/setup", url.Values{"_csrf": {csrf[1]}, "lang": {"de"}, "username": {"admin"}, "password": {"sehr geheimes passwort"},
		"password2": {"sehr geheimes passwort"}, "timezone": {"Europe/Berlin"}, "node_name": {"pi"}}); code != http.StatusSeeOther {
		t.Fatalf("setup: %d", code)
	}
	// aus: 404, kein Menuepunkt
	for _, p := range []string{"/sonar64", "/api/sonar64/status", "/sonar64/sonar64.js"} {
		if code, _ := get(p); code != http.StatusNotFound {
			t.Fatalf("module off %s: %d", p, code)
		}
	}
	if _, body := get("/"); strings.Contains(body, `href="/sonar64"`) {
		t.Fatal("menu entry while off")
	}
	if err := reg.Enable(context.Background(), Name); err != nil {
		t.Fatal(err)
	}
	code, body := get("/sonar64")
	if code != 200 || !strings.Contains(body, `action="/sonar64/participate"`) || strings.Contains(body, `id="s64-settings"`) || strings.Contains(body, "sonar64.js") {
		t.Fatalf("not participating: %d\n%s", code, body)
	}
	csrf = csrfRe.FindStringSubmatch(body)
	if code, _ := post("/sonar64/participate", url.Values{"_csrf": {csrf[1]}, "participate": {"1"}}); code != http.StatusSeeOther {
		t.Fatalf("participate: %d", code)
	}
	waitFor(t, "me", func() bool { return m.cachedMe() != nil })
	f.mu.Lock()
	f.results = []sonar.Result{{Round: time.Now(), Target: "a_fsn", Family: 4, Method: "udp", Sent: 4, Recv: 3, MinMs: 9.1, AvgMs: 10.2, MaxMs: 12, At: time.Now()},
		{Target: "n<b>x</b>", Family: 6, Method: "icmp", Sent: 2, Recv: 0, Error: "no_route", At: time.Now()}}
	f.inbound = []sonar.Inbound{{From: shortID("nzzzzzzzzzzz"), Family: 4, At: time.Now(), Count: 3}}
	f.rows = []sonar.InboundRow{{From: "nzzzzzzzzzzz", Name: "Nachbar", ASName: "Telekom", Trust: TrustStable, Family: 4, Method: "icmp", AvgMs: 11, At: time.Now()}}
	f.me.Trust = TrustStable
	f.mu.Unlock()
	code, body = get("/sonar64")
	if code != 200 || !strings.Contains(body, `id="s64-settings"`) || !strings.Contains(body, `id="s64-profile"`) || !strings.Contains(body, "a_fsn") ||
		!strings.Contains(body, "n&lt;b&gt;x&lt;/b&gt;") || !strings.Contains(body, `/sonar64/sonar64.js?v=`) ||
		!strings.Contains(body, `href="https://ipv64.net/sonar/node.php?slug=sonar-falke-42"`) || !strings.Contains(body, `value="Sonar-Falke-42"`) ||
		!strings.Contains(body, `class="badge text-bg-secondary"`) {
		t.Fatalf("participating: %d\n%s", code, body)
	}
	// Formular: Fehler am Feld, dann gueltig
	if code, body := post("/sonar64/settings", url.Values{"_csrf": {csrf[1]}, "measured": {"0"}, "budget": {"sparsam"}, "quiet": {"9-9"}}); code != http.StatusUnprocessableEntity ||
		!strings.Contains(body, "is-invalid") || !strings.Contains(body, `value="9-9"`) {
		t.Fatalf("invalid settings: %d", code)
	}
	if code, _ := post("/sonar64/settings", url.Values{"_csrf": {csrf[1]}, "measured": {"1"}, "budget": {"normal"}, "quiet": {""}}); code != http.StatusSeeOther {
		t.Fatalf("save settings: %d", code)
	}
	if s := m.LoadSettings(context.Background()); !s.Measured || s.Budget != "normal" || !s.Participate {
		t.Fatalf("saved: %+v", s)
	}
	waitFor(t, "runner", func() bool { return m.runner() != nil })
	if code, body := post("/sonar64/profile", url.Values{"_csrf": {csrf[1]}, "name": {"x"}, "lat": {"50,1"}, "lon": {""}}); code != http.StatusUnprocessableEntity ||
		!strings.Contains(body, `value="50,1"`) || !strings.Contains(body, "is-invalid") {
		t.Fatalf("invalid profile: %d", code)
	}
	waitFor(t, "registered", func() bool { return m.runner() != nil && m.runner().Status().Registered })
	if code, _ := post("/sonar64/profile", url.Values{"_csrf": {csrf[1]}, "name": {"Mein Pi"}, "lat": {"50,1"}, "lon": {"8.6"}, "access": {"dsl"}, "device": {"pi"}}); code != http.StatusSeeOther {
		t.Fatalf("save profile: %d", code)
	}
	if me := m.cachedMe(); me == nil || me.Name != "Mein Pi" || me.Access != "dsl" || *me.Lon != 8.6 {
		t.Fatalf("profile: %+v", me)
	}
	if _, body := get("/sonar64"); !strings.Contains(body, `name="had_loc" value="1"`) {
		t.Fatal("had_loc missing")
	}
	// leere Felder ohne gezeigten Standort: Standort bleibt
	if code, _ := post("/sonar64/profile", url.Values{"_csrf": {csrf[1]}, "name": {"Mein Pi"}, "lat": {""}, "lon": {""}}); code != http.StatusSeeOther {
		t.Fatalf("save profile 2: %d", code)
	}
	if me := m.cachedMe(); me == nil || me.Lat == nil {
		t.Fatalf("location lost: %+v", me)
	}
	if code, _ := post("/sonar64/profile", url.Values{"_csrf": {csrf[1]}, "name": {"Mein Pi"}, "lat": {""}, "lon": {""}, "had_loc": {"1"}}); code != http.StatusSeeOther {
		t.Fatalf("save profile 3: %d", code)
	}
	if me := m.cachedMe(); me == nil || me.Lat != nil {
		t.Fatalf("location kept: %+v", me)
	}
	if code, body := get("/sonar64"); code != 200 || !strings.Contains(body, `data-s64-in-live`) || !strings.Contains(body, `class="badge text-bg-primary"`) {
		t.Fatalf("measured page: %d", code)
	}

	// API
	code, body = get("/api/sonar64/status")
	var stat StatusInfo
	if code != 200 || json.Unmarshal([]byte(body), &stat) != nil || !stat.Participate || !stat.KeySet || stat.Version != version || stat.Me == nil ||
		stat.PublicURL == "" || stat.Node.NodeID != "nabcdefghijk" || strings.Contains(body, testToken) {
		t.Fatalf("status: %d %s", code, body)
	}
	code, body = get("/api/sonar64/inbound")
	if code != 200 || !strings.Contains(body, `"Nachbar"`) || !strings.Contains(body, `"ready":true`) {
		t.Fatalf("inbound: %d %s", code, body)
	}
	get("/api/sonar64/inbound") // aus dem Zwischenspeicher
	f.mu.Lock()
	calls, since := f.inCalled, f.inSince
	f.mu.Unlock()
	if calls != 1 || time.Since(since) > inboundBack+2*time.Minute {
		t.Fatalf("inbound calls %d since %v", calls, since)
	}
	if code, _ := get("/api/sonar64/inbound?since=gestern"); code != 400 {
		t.Fatalf("bad since: %d", code)
	}
	code, body = get("/api/sonar64/recent?n=5")
	var rec recentInfo
	if code != 200 || json.Unmarshal([]byte(body), &rec) != nil || len(rec.Results) != 2 || rec.Results[0].Loss != 25 || len(rec.Inbound) != 1 ||
		rec.Inbound[0].Name != "Nachbar" || !rec.Responder || strings.Contains(body, "addr") {
		t.Fatalf("recent: %d %s", code, body)
	}
	if code, _ := get("/api/sonar64/recent?n=-1"); code != 400 {
		t.Fatalf("bad n: %d", code)
	}
	hdr := map[string]string{"Content-Type": "application/json", "X-CSRF-Token": csrf[1]}
	if code, _ := do("PUT", "/api/sonar64/settings", `{"budget":"grosszuegig","foo":1}`, hdr); code != 400 {
		t.Fatalf("unknown field: %d", code)
	}
	if code, body := do("PUT", "/api/sonar64/settings", `{"name":"x"}`, hdr); code != 422 || !strings.Contains(body, `"name"`) {
		t.Fatalf("invalid name: %d %s", code, body)
	}
	code, body = do("PUT", "/api/sonar64/settings", `{"budget":"grosszuegig","quiet":"22-7","access":"cable"}`, hdr)
	var sv SettingsView
	if code != 200 || json.Unmarshal([]byte(body), &sv) != nil || sv.Budget != "grosszuegig" || sv.Quiet != "22-7" || sv.Access != "cable" || !sv.Participate {
		t.Fatalf("put: %d %s", code, body)
	}
	if code, body := get("/api/sonar64/settings"); code != 200 || !strings.Contains(body, `"budget":"grosszuegig"`) {
		t.Fatalf("get settings: %d %s", code, body)
	}
	// von ipv64 abgemeldet: Hinweis und „Neu teilnehmen“
	f.mu.Lock()
	f.status.Paused = "revoked"
	f.mu.Unlock()
	if code, body := get("/sonar64"); code != 200 || !strings.Contains(body, `id="s64-revoked"`) || !strings.Contains(body, `action="/sonar64/rejoin"`) {
		t.Fatalf("revoked page: %d", code)
	}
	if code, _ := post("/sonar64/rejoin", url.Values{"_csrf": {csrf[1]}}); code != http.StatusSeeOther || !m.LoadSettings(context.Background()).Participate {
		t.Fatalf("rejoin: %d", code)
	}
	f.mu.Lock()
	f.status.Paused = ""
	f.mu.Unlock()
	waitFor(t, "runner after rejoin", func() bool { return m.runner() != nil })
	if code, _ := do("PUT", "/api/sonar64/settings", `{"participate":false}`, hdr); code != 200 || m.LoadSettings(context.Background()).Participate {
		t.Fatalf("leave: %d", code)
	}
	if code, body := get("/sonar64/sonar64.js"); code != 200 || !strings.Contains(body, "/api/sonar64/recent") || strings.Contains(body, "innerHTML") {
		t.Fatalf("js: %d", code)
	}

	// i18n-Schluessel: Templates und Go-Dateien des Moduls
	keys := map[string]bool{"nav.sonar64": true}
	files, _ := filepath.Glob("templates/pages/*.html")
	gofiles, _ := filepath.Glob("*.go")
	skip := map[string]bool{setConfig: true, setToken: true, "sonar64.participate": true, "sonar64.settings": true, "sonar64.profile": true,
		"sonar64.rejoin": true, "sonar64.json": true, "sonar64.key": true}
	for _, fn := range append(files, gofiles...) {
		if strings.HasSuffix(fn, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(fn)
		re := codeKeyRe
		if strings.HasSuffix(fn, ".html") {
			re = tplKeyRe
		}
		for _, mm := range re.FindAllStringSubmatch(string(b), -1) {
			if !strings.HasSuffix(mm[1], ".") && !strings.HasSuffix(mm[1], "_") && !skip[mm[1]] {
				keys[mm[1]] = true
			}
		}
	}
	for _, l := range []string{TrustNew, TrustStable, TrustTrusted, TrustPillar, TrustAnchor, TrustQuarantine} {
		keys["sonar64.trust."+l], keys["sonar64.trust_hint."+l] = true, true
	}
	for _, x := range Budgets {
		keys["sonar64.budget."+x] = true
	}
	for _, x := range Accesses {
		keys["sonar64.access."+x] = true
	}
	for _, x := range Devices {
		keys["sonar64.device."+x] = true
	}
	for _, x := range []string{"uplink", "quiet", "no_plan", "budget", "revoked"} {
		keys["sonar64.paused."+x] = true
	}
	for _, x := range []string{"none", "icmp", "udp"} {
		keys["sonar64.reach."+x] = true
	}
	for _, x := range []string{"on", "off"} {
		keys["sonar64.flash.participate_"+x] = true
	}
	for k := range keys {
		for _, lang := range []string{"de", "en"} {
			if bundle.T(lang, k) == k {
				t.Errorf("%s: missing i18n key %s", lang, k)
			}
		}
	}
}
