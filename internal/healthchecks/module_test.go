package healthchecks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/scheduler"
	"github.com/ipv64net/node64/internal/store"
)

func newTestModule(t *testing.T) (*Module, *httptest.Server) {
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
	m := New(core, log, nil, nil, "test")
	if err := core.Migrate(context.Background(), Name, m.Migrations()); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Stop(context.Background()) })
	mux := http.NewServeMux()
	pass := func(h http.Handler) http.Handler { return h }
	m.Routes(mux, module.Guards{Enabled: pass, Auth: pass})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return m, srv
}

func call(t *testing.T, srv *httptest.Server, method, path string, body any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, srv.URL+path, rd)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func TestCheckLifecycleViaAPI(t *testing.T) {
	// Lokaler HTTP-Server als Ziel
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("fine")) }))
	defer target.Close()
	m, srv := newTestModule(t)

	// Validierung
	code, b := call(t, srv, "POST", "/api/checks", map[string]any{"name": "x", "type": "http", "target": "ftp://nope"})
	if code != 422 {
		t.Fatalf("expected 422, got %d %s", code, b)
	}
	iv := 4
	code, b = call(t, srv, "POST", "/api/checks", map[string]any{"name": "x", "type": "http", "target": target.URL, "interval_seconds": iv})
	if code != 422 || !strings.Contains(string(b), "interval_seconds") {
		t.Fatalf("min interval: %d %s", code, b)
	}
	// Anlegen
	code, b = call(t, srv, "POST", "/api/checks", map[string]any{"name": "Web", "type": "http", "target": target.URL, "tags": []string{"prod", "web"},
		"interval_seconds": 20, "retry_interval_seconds": 5, "retries": 0, "stabilize": 1})
	if code != 201 {
		t.Fatalf("create: %d %s", code, b)
	}
	var c checkJSON
	_ = json.Unmarshal(b, &c)
	// "up" ist auch richtig: die erste Messung kann schon vor der Antwort gelaufen sein (z. B. mit -race)
	if len(c.Token) != 32 || (c.State.State != "pending" && c.State.State != "up") || *c.IntervalSeconds != 20 || c.Revision != 1 {
		t.Fatalf("created: %+v", c)
	}
	// Erste Messung abwarten
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, b = call(t, srv, "GET", "/api/checks/"+c.Token, nil)
		_ = json.Unmarshal(b, &c)
		if c.State.State == "up" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if c.State.State != "up" {
		t.Fatalf("expected up, got %+v", c.State)
	}
	_, mb := call(t, srv, "GET", "/api/checks/"+c.Token+"/measurements", nil)
	t.Logf("state latency %.3f ms, measurements: %s", c.State.LastLatencyMS, mb)
	// Messpunkte und Stats
	code, b = call(t, srv, "GET", "/api/checks/"+c.Token+"/measurements", nil)
	var ms []Measurement
	_ = json.Unmarshal(b, &ms)
	if code != 200 || len(ms) == 0 || ms[0].Status != "up" || ms[0].Details["status"] != float64(200) {
		t.Fatalf("measurements: %d %s", code, b)
	}
	code, b = call(t, srv, "GET", "/api/checks/"+c.Token+"/stats?range=24h", nil)
	var st Stats
	_ = json.Unmarshal(b, &st)
	if code != 200 || st.Count == 0 || st.UpPercent != 100 || len(st.Series) == 0 {
		t.Fatalf("stats: %d %s", code, b)
	}
	// Aendern: Revision steigt, Zustand bleibt
	code, b = call(t, srv, "PUT", "/api/checks/"+c.Token, map[string]any{"name": "Web 2", "type": "http", "target": target.URL, "interval_seconds": 30, "retry_interval_seconds": 10})
	_ = json.Unmarshal(b, &c)
	if code != 200 || c.Name != "Web 2" || c.Revision != 2 || c.State.State != "up" {
		t.Fatalf("update: %d %s", code, b)
	}
	// Pausieren und fortsetzen
	code, b = call(t, srv, "POST", "/api/checks/"+c.Token+"/pause", nil)
	_ = json.Unmarshal(b, &c)
	if code != 200 || c.State.State != "paused" || !*c.Paused {
		t.Fatalf("pause: %d %s", code, b)
	}
	code, b = call(t, srv, "POST", "/api/checks/"+c.Token+"/resume", nil)
	_ = json.Unmarshal(b, &c)
	if code != 200 || *c.Paused {
		t.Fatalf("resume: %d %s", code, b)
	}
	// Klonen
	code, b = call(t, srv, "POST", "/api/checks/"+c.Token+"/clone", nil)
	var clone checkJSON
	_ = json.Unmarshal(b, &clone)
	if code != 201 || clone.Token == c.Token || !*clone.Paused || !strings.HasSuffix(clone.Name, "(copy)") {
		t.Fatalf("clone: %d %s", code, b)
	}
	// Zyklus bei Abhaengigkeit verhindern
	code, _ = call(t, srv, "PUT", "/api/checks/"+c.Token, map[string]any{"name": "Web 2", "type": "http", "target": target.URL, "parent": clone.Token})
	if code != 200 {
		t.Fatalf("set parent: %d", code)
	}
	code, b = call(t, srv, "PUT", "/api/checks/"+clone.Token, map[string]any{"name": "c", "type": "http", "target": target.URL, "parent": c.Token})
	if code != 422 || !strings.Contains(string(b), "cycle") {
		t.Fatalf("cycle: %d %s", code, b)
	}
	// Liste mit Filter
	code, b = call(t, srv, "GET", "/api/checks?tag=prod", nil)
	var list []checkJSON
	_ = json.Unmarshal(b, &list)
	if code != 200 || len(list) != 2 {
		t.Fatalf("list by tag: %d %s", code, b)
	}
	// Loeschen
	code, _ = call(t, srv, "DELETE", "/api/checks/"+clone.Token, nil)
	if code != 204 {
		t.Fatalf("delete: %d", code)
	}
	code, _ = call(t, srv, "GET", "/api/checks/"+clone.Token, nil)
	if code != 404 {
		t.Fatalf("deleted check still there: %d", code)
	}
	if _, ok := m.scheduler().Runtime(clone.Token); ok {
		t.Fatal("deleted check still scheduled")
	}
	_, b = call(t, srv, "GET", "/api/checks/"+c.Token, nil)
	_ = json.Unmarshal(b, &c)
	if *c.Parent != "" {
		t.Fatal("parent reference should be cleared after deleting the parent")
	}
}

func TestPushViaAPI(t *testing.T) {
	m, srv := newTestModule(t)
	code, b := call(t, srv, "POST", "/api/checks", map[string]any{"name": "Backup", "type": "push", "params": map[string]int{"period_seconds": 1, "grace_seconds": 0}, "stabilize": 1})
	if code != 201 {
		t.Fatalf("create push: %d %s", code, b)
	}
	var c checkJSON
	_ = json.Unmarshal(b, &c)
	if !strings.HasSuffix(c.PushURL, "/api/push/"+c.Token) {
		t.Fatalf("push url: %s", c.PushURL)
	}
	code, b = call(t, srv, "GET", "/api/push/"+c.Token+"?msg=backup+done", nil)
	if code != 200 || !strings.Contains(string(b), "ok") {
		t.Fatalf("push: %d %s", code, b)
	}
	// Mindestabstand: zweite Meldung sofort danach wird gedrosselt
	if code, _ = call(t, srv, "GET", "/api/push/"+c.Token, nil); code != 429 {
		t.Fatalf("expected 429 on rapid push, got %d", code)
	}
	// Unbekannter Token: gleiche Antwort wie bekannt
	if code, b = call(t, srv, "GET", "/api/push/"+strings.Repeat("Z", 32), nil); code != 200 || !strings.Contains(string(b), "ok") {
		t.Fatalf("unknown token must look the same: %d %s", code, b)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if rt, _ := m.scheduler().Runtime(c.Token); rt.State == scheduler.StateUp {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if rt, _ := m.scheduler().Runtime(c.Token); rt.State != scheduler.StateUp || rt.LastMessage != "backup done" {
		t.Fatalf("push state: %+v", rt)
	}
	if code, _ = call(t, srv, "POST", "/api/checks/"+c.Token+"/run", nil); code != 409 {
		t.Fatalf("run on push check: %d", code)
	}
}

func TestMaintenanceWindows(t *testing.T) {
	m, srv := newTestModule(t)
	code, b := call(t, srv, "POST", "/api/maintenance", map[string]any{"name": "Nachts", "start_at": "2026-01-01T01:00:00Z", "end_at": "2026-01-01T03:00:00Z", "repeat": "daily"})
	if code != 201 {
		t.Fatalf("create: %d %s", code, b)
	}
	var mw Maintenance
	_ = json.Unmarshal(b, &mw)
	in := time.Date(2026, 5, 10, 2, 30, 0, 0, time.UTC)
	out := time.Date(2026, 5, 10, 4, 0, 0, 0, time.UTC)
	if !m.st.InMaintenance(context.Background(), "any", in) || m.st.InMaintenance(context.Background(), "any", out) {
		t.Fatal("daily window evaluation wrong")
	}
	if !mw.Covers("x", time.Date(2025, 12, 31, 2, 0, 0, 0, time.UTC)) == false {
		t.Fatal("before start must not match")
	}
	weekly := Maintenance{StartAt: time.Date(2026, 1, 5, 22, 0, 0, 0, time.UTC), EndAt: time.Date(2026, 1, 5, 23, 0, 0, 0, time.UTC), Repeat: "weekly", Active: true}
	if !weekly.Covers("x", time.Date(2026, 1, 12, 22, 30, 0, 0, time.UTC)) || weekly.Covers("x", time.Date(2026, 1, 13, 22, 30, 0, 0, time.UTC)) {
		t.Fatal("weekly window evaluation wrong")
	}
	monthly := Maintenance{StartAt: time.Date(2026, 1, 31, 10, 0, 0, 0, time.UTC), EndAt: time.Date(2026, 1, 31, 11, 0, 0, 0, time.UTC), Repeat: "monthly", Active: true, RepeatUntil: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)}
	if !monthly.Covers("x", time.Date(2026, 3, 31, 10, 30, 0, 0, time.UTC)) || monthly.Covers("x", time.Date(2026, 7, 31, 10, 30, 0, 0, time.UTC)) {
		t.Fatal("monthly window evaluation wrong")
	}
	scoped := Maintenance{StartAt: time.Now().Add(-time.Hour), EndAt: time.Now().Add(time.Hour), Repeat: "none", Active: true, Tokens: []string{"abc"}}
	if !scoped.Covers("abc", time.Now()) || scoped.Covers("def", time.Now()) {
		t.Fatal("token scope wrong")
	}
	// nach der Zeitumstellung bleibt das Fenster bei derselben Ortszeit (03:00 Berlin: erst 01:00, dann 02:00 UTC)
	if berlin, err := time.LoadLocation("Europe/Berlin"); err == nil {
		dst := Maintenance{StartAt: time.Date(2026, 10, 20, 1, 0, 0, 0, time.UTC), EndAt: time.Date(2026, 10, 20, 2, 0, 0, 0, time.UTC), Repeat: "daily", Active: true}
		if !dst.CoversIn("x", time.Date(2026, 10, 24, 1, 30, 0, 0, time.UTC), berlin) || !dst.CoversIn("x", time.Date(2026, 10, 28, 2, 30, 0, 0, time.UTC), berlin) ||
			dst.CoversIn("x", time.Date(2026, 10, 28, 1, 30, 0, 0, time.UTC), berlin) {
			t.Fatal("daily window must follow local time after DST")
		}
		dst.Repeat = "weekly"
		if !dst.CoversIn("x", time.Date(2026, 10, 27, 2, 30, 0, 0, time.UTC), berlin) || dst.CoversIn("x", time.Date(2026, 10, 27, 1, 30, 0, 0, time.UTC), berlin) {
			t.Fatal("weekly window must follow local time after DST")
		}
		occ := statusMaintOccurrences(dst, time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC), berlin)
		if len(occ) != 1 || !occ[0].from.Equal(time.Date(2026, 10, 27, 2, 0, 0, 0, time.UTC)) {
			t.Fatalf("occurrences after DST: %+v", occ)
		}
	}
	code, _ = call(t, srv, "DELETE", fmt.Sprintf("/api/maintenance/%d", mw.ID), nil)
	if code != 204 || m.st.InMaintenance(context.Background(), "any", in) {
		t.Fatal("delete did not clear the window")
	}
}

func TestAggregation(t *testing.T) {
	// Eigener Store ohne gestartetes Modul, sonst laeuft die Start-Verdichtung parallel
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	core, err := store.Open(context.Background(), filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Close() })
	if err := core.Migrate(context.Background(), Name, New(core, log, nil, nil, "test").Migrations()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st := NewStore(core)
	c := &Check{Token: NewToken(), Type: checks.TypeHTTP, Name: "a", Target: "http://x/", Params: json.RawMessage("{}"), Interval: time.Minute, RetryInterval: 20 * time.Second,
		ConnectTimeout: time.Second, TotalTimeout: 2 * time.Second, Stabilize: 1, IPMode: checks.IPAuto}
	if err := st.Insert(ctx, c); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	// Feste Minute, damit die zehn Punkte nie eine Stunden- oder Tagesgrenze kreuzen
	old := now.Add(-40 * 24 * time.Hour).Truncate(time.Hour).Add(10 * time.Minute)
	for i := 0; i < 10; i++ {
		status := checks.Up
		if i%5 == 0 {
			status = checks.Down
		}
		if err := st.SaveMeasurement(ctx, scheduler.Measurement{Token: c.Token, Time: old.Add(time.Duration(i) * time.Minute), Status: status, Latency: time.Duration(10+i) * time.Millisecond}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SaveMeasurement(ctx, scheduler.Measurement{Token: c.Token, Time: now, Status: checks.Up, Latency: 7 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	if err := st.Aggregate(ctx, now); err != nil {
		t.Fatal(err)
	}
	var raw, hourly, daily int
	st.r.QueryRow(`SELECT count(*) FROM hc_measurements`).Scan(&raw)
	st.r.QueryRow(`SELECT count(*) FROM hc_hourly`).Scan(&hourly)
	st.r.QueryRow(`SELECT count(*) FROM hc_daily`).Scan(&daily)
	if raw != 1 || hourly != 1 || daily != 1 {
		t.Fatalf("raw=%d hourly=%d daily=%d", raw, hourly, daily)
	}
	var cnt, up int
	st.r.QueryRow(`SELECT count, up_count FROM hc_daily`).Scan(&cnt, &up)
	if cnt != 10 || up != 8 {
		t.Fatalf("daily count=%d up=%d", cnt, up)
	}
	s, err := st.Stats(ctx, c.Token, "1y", now)
	if err != nil || s.Count != 11 || s.UpCount != 9 {
		t.Fatalf("1y stats: %v %+v", err, s)
	}
	_ = net.IPv4zero
}

// Der Tag an der Grenze der Rohdaten-Aufbewahrung darf beim naechsten Lauf nicht aus einem Rest neu berechnet werden.
func TestAggregationBoundaryDay(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	core, err := store.Open(context.Background(), filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Close() })
	if err := core.Migrate(context.Background(), Name, New(core, log, nil, nil, "test").Migrations()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st := NewStore(core)
	tok := NewToken()
	now := time.Date(2026, 10, 28, 12, 30, 0, 0, time.UTC)
	day := now.Add(-RawRetention).Truncate(24 * time.Hour)
	for i := 0; i < 24; i++ {
		if err := st.SaveMeasurement(ctx, scheduler.Measurement{Token: tok, Time: day.Add(time.Duration(i)*time.Hour + time.Minute), Status: checks.Up}); err != nil {
			t.Fatal(err)
		}
	}
	dayCount := func() int {
		var n int
		st.r.QueryRow(`SELECT count FROM hc_daily WHERE token = ?`, tok).Scan(&n)
		return n
	}
	for _, at := range []time.Time{now, now.Add(time.Hour), now.Add(5 * time.Hour)} {
		if err := st.Aggregate(ctx, at); err != nil {
			t.Fatal(err)
		}
		if n := dayCount(); n != 24 {
			t.Fatalf("%s: daily count=%d", at, n)
		}
	}
	if err := st.Aggregate(ctx, now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	var raw, hours, sum int
	st.r.QueryRow(`SELECT count(*) FROM hc_measurements WHERE token = ?`, tok).Scan(&raw)
	st.r.QueryRow(`SELECT count(*), sum(count) FROM hc_hourly WHERE token = ?`, tok).Scan(&hours, &sum)
	if raw != 0 || hours != 24 || sum != 24 || dayCount() != 24 {
		t.Fatalf("raw=%d hours=%d sum=%d daily=%d", raw, hours, sum, dayCount())
	}
}
