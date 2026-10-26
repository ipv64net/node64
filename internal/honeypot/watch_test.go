package honeypot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/notify"
)

const watchTestKey = "WATCHKEY0123456789abcdef"

// fakeWatchAPI spielt /api/v2/threat/watch nach (Vertrag H5): Seiten zu 100, aelteste zuerst, next = created_at des
// letzten Treffers. inclusive: since schliesst den Treffer mit genau diesem Zeitpunkt ein (dann muss die Node
// doppelte IDs selbst verwerfen).
type fakeWatchAPI struct {
	mu        sync.Mutex
	srv       *httptest.Server
	networks  []ipv64api.ThreatWatchNetwork
	dyndns    []ipv64api.ThreatWatchDynDNS
	alerts    []ipv64api.ThreatWatchAlert
	inclusive bool
	key       string
	status    int    // != 0: jede Anfrage antwortet so
	retry     string // Retry-After bei status
	failPage  int    // > 0: die n-te Abfrage der Treffer scheitert mit 500
	lists     int    // Aufrufe der Liste
	alertReqs int    // Aufrufe der Treffer
	sinces    []string
	added     []string // eingetragene cidr|label
	deleted   []int64
	addStatus int    // != 0: POST antwortet so
	addCode   string // Fehlercode bei addStatus
}

func newFakeWatchAPI(t *testing.T) *fakeWatchAPI {
	f := &fakeWatchAPI{key: watchTestKey}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeWatchAPI) addAlerts(n int, start time.Time, firstID int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	nid := int64(1)
	for i := 0; i < n; i++ {
		f.alerts = append(f.alerts, ipv64api.ThreatWatchAlert{ID: firstID + int64(i), IP: "203.0.113." + strconv.Itoa(i%250+1), CIDR: "203.0.113.0/24",
			NetworkID: &nid, Source: "network", Listed: i%2 == 0, Score: 50 + i%50, Kinds: []string{"ssh:bruteforce"}, FirstSeen: "2026-10-19", LastSeen: "2026-10-20",
			CreatedAt: start.Add(time.Duration(i) * time.Second).UTC().Format(time.RFC3339)})
	}
}

func (f *fakeWatchAPI) counts() (lists, alerts int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lists, f.alertReqs
}

func watchWriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func watchAPIErr(w http.ResponseWriter, status int, code string) {
	watchWriteJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": code + " message"}})
}

func (f *fakeWatchAPI) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+f.key {
		watchAPIErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if f.status != 0 {
		if f.retry != "" {
			w.Header().Set("Retry-After", f.retry)
		}
		watchAPIErr(w, f.status, "fake_status")
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v2/threat/watch":
		f.lists++
		nets := f.networks
		if nets == nil {
			nets = []ipv64api.ThreatWatchNetwork{}
		}
		dyn := f.dyndns
		if dyn == nil {
			dyn = []ipv64api.ThreatWatchDynDNS{}
		}
		watchWriteJSON(w, 200, map[string]any{"data": map[string]any{"limits": ipv64api.ThreatWatchLimits{Max: 3, MinPrefixV4: 16, MinPrefixV6: 32},
			"networks": nets, "dyndns": dyn}})
	case r.Method == http.MethodGet && r.URL.Path == "/api/v2/threat/watch/alerts":
		f.alertReqs++
		since := r.URL.Query().Get("since")
		f.sinces = append(f.sinces, since)
		if f.failPage > 0 && f.alertReqs == f.failPage {
			watchAPIErr(w, http.StatusInternalServerError, "boom")
			return
		}
		out := []ipv64api.ThreatWatchAlert{}
		for _, a := range f.alerts {
			if since == "" || a.CreatedAt > since || (f.inclusive && a.CreatedAt == since) {
				out = append(out, a)
			}
			if len(out) == ipv64api.ThreatWatchPage {
				break
			}
		}
		next := since
		if len(out) > 0 {
			next = out[len(out)-1].CreatedAt
		}
		watchWriteJSON(w, 200, map[string]any{"data": map[string]any{"alerts": out, "next": next}})
	case r.Method == http.MethodPost && r.URL.Path == "/api/v2/threat/watch":
		if f.addStatus != 0 {
			watchAPIErr(w, f.addStatus, f.addCode)
			return
		}
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.added = append(f.added, in["cidr"]+"|"+in["label"])
		n := ipv64api.ThreatWatchNetwork{ID: int64(10 + len(f.added)), CIDR: in["cidr"], Label: in["label"], CreatedAt: "2026-10-20T12:00:00Z"}
		f.networks = append(f.networks, n)
		watchWriteJSON(w, http.StatusCreated, map[string]any{"data": n})
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v2/threat/watch/"):
		id, _ := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/api/v2/threat/watch/"), 10, 64)
		for i, n := range f.networks {
			if n.ID == id {
				f.networks = append(f.networks[:i], f.networks[i+1:]...)
				f.deleted = append(f.deleted, id)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		watchAPIErr(w, http.StatusNotFound, "not_found")
	default:
		http.NotFound(w, r)
	}
}

// watchNotes sammelt Benachrichtigungen.
type watchNotes struct {
	mu   sync.Mutex
	list []notify.Alert
	ch   chan struct{}
}

func (n *watchNotes) add(a notify.Alert) {
	n.mu.Lock()
	n.list = append(n.list, a)
	n.mu.Unlock()
	select {
	case n.ch <- struct{}{}:
	default:
	}
}

func (n *watchNotes) all() []notify.Alert {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]notify.Alert(nil), n.list...)
}

// watchRendered haelt fest, was Render bekommen hat.
type watchRendered struct {
	status int
	page   string
	data   any
}

type watchFlash struct{ kind, text string }

type watchEnv struct {
	m       *Module
	api     *fakeWatchAPI
	notes   *watchNotes
	audit   []auditEntry
	render  []watchRendered
	flashes []watchFlash
}

// watchTest legt das Modul (ohne Sensor) mit Key und Fake-API an. withKey = false: kein Key eingetragen.
func watchTest(t *testing.T, withKey bool) *watchEnv {
	t.Helper()
	core, dir := modCore(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := New(core, log, dir, "test")
	if err := core.Migrate(context.Background(), Name, m.Migrations()); err != nil {
		t.Fatal(err)
	}
	e := &watchEnv{m: m, api: newFakeWatchAPI(t), notes: &watchNotes{ch: make(chan struct{}, 16)}}
	if withKey {
		if err := core.SetSetting(context.Background(), ipv64api.SetKey, watchTestKey); err != nil {
			t.Fatal(err)
		}
	}
	m.SetKey(ipv64api.NewKey(core, nil, ipv64api.NewClient(e.api.srv.URL+"/api/v2", "node64/test"), log))
	m.SetNotifier(e.notes.add)
	g := testGuards(&e.audit)
	g.T = func(_ *http.Request, key string, args ...any) string { // erkennbar uebersetzt (watchErrText prueft t != key)
		if len(args) == 0 {
			return "[" + key + "]"
		}
		return "[" + key + fmt.Sprint(args...) + "]"
	}
	g.Render = func(w http.ResponseWriter, _ *http.Request, status int, page, _ string, data any) {
		e.render = append(e.render, watchRendered{status, page, data})
		w.WriteHeader(status)
	}
	g.Flash = func(_ http.ResponseWriter, _ *http.Request, kind, text string) {
		e.flashes = append(e.flashes, watchFlash{kind, text})
	}
	m.g = g
	return e
}

func (e *watchEnv) state(t *testing.T) watchState {
	t.Helper()
	return e.m.watchLoad(context.Background())
}

func withWatchTiming(t *testing.T, tm watchTimingT) {
	old := watchTimes()
	setWatchTiming(tm)
	t.Cleanup(func() { setWatchTiming(old) })
}

func TestWatchCheckBundlesAndAdvances(t *testing.T) {
	e := watchTest(t, true)
	ctx := context.Background()
	e.api.networks = []ipv64api.ThreatWatchNetwork{{ID: 1, CIDR: "203.0.113.0/24", Label: "Buero"}}
	e.api.dyndns = []ipv64api.ThreatWatchDynDNS{{IP: "198.51.100.7", Domain: "x.ipv64.net"}}
	start := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	e.api.addAlerts(3, start, 100)
	e.api.alerts = append(e.api.alerts, ipv64api.ThreatWatchAlert{ID: 103, IP: "198.51.100.7", CIDR: "198.51.100.7/32", Source: "dyndns", Score: 20,
		CreatedAt: start.Add(10 * time.Second).Format(time.RFC3339)})

	n, wait, err := e.m.watchCheck(ctx, false)
	if err != nil || n != 4 || wait <= 0 {
		t.Fatalf("check: n=%d wait=%v err=%v", n, wait, err)
	}
	notes := e.notes.all()
	if len(notes) != 1 {
		t.Fatalf("want one bundled notification, got %d", len(notes))
	}
	a := notes[0]
	lines := strings.Split(a.Message, "\n")
	if a.Kind != notify.KindHoneypotWatch || len(lines) != 4 || a.Check.Name != "203.0.113.1 +3" || !a.Check.Local || !a.Check.NotifyDown ||
		!strings.Contains(lines[0], "Buero (203.0.113.0/24)") || !strings.Contains(lines[0], "v64 Blocklist") || !strings.Contains(lines[3], "x.ipv64.net (DynDNS)") ||
		a.EventID != "honeypot-watch-100-103" {
		t.Fatalf("notification: %+v", a)
	}
	st := e.state(t)
	if len(st.Hits) != 4 || st.Hits[0].ID != 103 || st.Hits[3].ID != 100 || st.Hits[3].Label != "Buero" || st.Hits[0].Label != "x.ipv64.net" ||
		st.Next != start.Add(10*time.Second).Format(time.RFC3339) || st.Total != 4 || st.Networks != 1 || st.DynDNS != 1 || st.LastSuccess.IsZero() ||
		st.NextAttempt.IsZero() || st.LastError != "" {
		t.Fatalf("state: %+v", st)
	}

	// nichts Neues: keine Meldung, since = gespeichertes next
	if n, _, err := e.m.watchCheck(ctx, false); err != nil || n != 0 || len(e.notes.all()) != 1 {
		t.Fatalf("second check: %d %v", n, err)
	}
	if got := e.api.sinces[len(e.api.sinces)-1]; got != st.Next {
		t.Fatalf("since %q, want %q", got, st.Next)
	}
	// zwei neue: eine weitere Meldung, Treffer vorn
	e.api.addAlerts(2, start.Add(time.Minute), 200)
	if n, _, err := e.m.watchCheck(ctx, false); err != nil || n != 2 || len(e.notes.all()) != 2 {
		t.Fatalf("third check: %d %v", n, err)
	}
	if st := e.state(t); st.Hits[0].ID != 201 || len(st.Hits) != 6 || st.Total != 6 {
		t.Fatalf("state after third: %+v", st.Hits[:2])
	}
}

// since schliesst den letzten Treffer ein: bekannte IDs kommen nicht noch einmal.
func TestWatchInclusiveSinceDedup(t *testing.T) {
	e := watchTest(t, true)
	e.api.inclusive = true
	e.api.networks = []ipv64api.ThreatWatchNetwork{{ID: 1, CIDR: "203.0.113.0/24"}}
	e.api.addAlerts(2, time.Now().Add(-time.Hour), 1)
	ctx := context.Background()
	if n, _, err := e.m.watchCheck(ctx, false); n != 2 || err != nil {
		t.Fatalf("first: %d %v", n, err)
	}
	if n, _, err := e.m.watchCheck(ctx, false); n != 0 || err != nil || len(e.notes.all()) != 1 {
		t.Fatalf("second: %d %v (%d notes)", n, err, len(e.notes.all()))
	}
}

// Mehr als eine Seite: alles in einem Abruf, eine Meldung (gekuerzt), lokal hoechstens watchKeep.
func TestWatchPagingAndKeep(t *testing.T) {
	e := watchTest(t, true)
	e.api.networks = []ipv64api.ThreatWatchNetwork{{ID: 1, CIDR: "203.0.113.0/24"}}
	e.api.addAlerts(250, time.Now().Add(-time.Hour), 1)
	n, _, err := e.m.watchCheck(context.Background(), false)
	if err != nil || n != 250 {
		t.Fatalf("check: %d %v", n, err)
	}
	if _, reqs := e.api.counts(); reqs != 3 {
		t.Fatalf("alert requests: %d", reqs)
	}
	notes := e.notes.all()
	lines := strings.Split(notes[0].Message, "\n")
	if len(notes) != 1 || len(lines) != watchNotifyMax+1 || lines[watchNotifyMax] != "+ 240 …" {
		t.Fatalf("notification: %d %q", len(notes), lines[len(lines)-1])
	}
	st := e.state(t)
	if len(st.Hits) != watchKeep || st.Hits[0].ID != 250 || st.Total != 250 {
		t.Fatalf("hits: %d first %d total %d", len(st.Hits), st.Hits[0].ID, st.Total)
	}
}

// Ohne Netz und DynDNS-IP keine Abfrage der Treffer; ohne Key gar keine Anfrage.
func TestWatchNothingToWatch(t *testing.T) {
	e := watchTest(t, true)
	e.api.addAlerts(1, time.Now(), 1)
	if n, _, err := e.m.watchCheck(context.Background(), false); n != 0 || err != nil {
		t.Fatalf("check: %d %v", n, err)
	}
	if lists, alerts := e.api.counts(); lists != 1 || alerts != 0 {
		t.Fatalf("requests: lists %d alerts %d", lists, alerts)
	}
	e2 := watchTest(t, false)
	if _, _, err := e2.m.watchCheck(context.Background(), false); !errors.Is(err, errWatchNoKey) {
		t.Fatalf("no key: %v", err)
	}
	if lists, alerts := e2.api.counts(); lists+alerts != 0 {
		t.Fatal("request without key")
	}
}

// 401/403: Zustand zeigt es, derselbe Key wird erst nach AuthBackoff wieder versucht; neuer Key oder Knopf sofort.
func TestWatchAuthBackoff(t *testing.T) {
	withWatchTiming(t, watchTimingT{First: time.Millisecond, Every: time.Minute, AuthBackoff: time.Hour, MinRetry: time.Second})
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		e := watchTest(t, true)
		ctx := context.Background()
		e.api.status = status
		_, wait, err := e.m.watchCheck(ctx, false)
		var ae *ipv64api.APIError
		if !errors.As(err, &ae) || ae.Status != status || wait != time.Minute {
			t.Fatalf("%d: wait %v err %v", status, wait, err)
		}
		st := e.state(t)
		if !st.AuthFailed() || st.LastError == "" || time.Until(st.NextAttempt) < 59*time.Minute || st.KeyFP == "" || strings.Contains(st.KeyFP, watchTestKey) {
			t.Fatalf("%d: state %+v", status, st)
		}
		e.api.status = 0
		if _, _, err := e.m.watchCheck(ctx, false); err != nil {
			t.Fatal(err)
		}
		if lists, _ := e.api.counts(); lists != 0 { // die erste Anfrage zaehlt der Fake bei status nicht
			t.Fatalf("%d: asked again with the same key", status)
		}
		// Knopf: sofort, Erfolg loescht den Fehler
		if _, _, err := e.m.watchCheck(ctx, true); err != nil {
			t.Fatal(err)
		}
		if lists, _ := e.api.counts(); lists != 1 || e.state(t).AuthFailed() {
			t.Fatalf("%d: force did not retry", status)
		}
		// neuer Key nach Ablehnung: sofort
		e.api.status = status
		_, _, _ = e.m.watchCheck(ctx, true)
		e.api.status = 0
		e.api.key = "OTHERKEY0123456789abcdef"
		_ = e.m.core.SetSetting(ctx, ipv64api.SetKey, e.api.key)
		if _, _, err := e.m.watchCheck(ctx, false); err != nil {
			t.Fatalf("%d: new key: %v", status, err)
		}
		if lists, _ := e.api.counts(); lists != 2 {
			t.Fatalf("%d: new key not tried (%d)", status, lists)
		}
	}
}

// 429: Retry-After (mindestens MinRetry) bestimmt die Wartezeit.
func TestWatchRetryAfter(t *testing.T) {
	withWatchTiming(t, watchTimingT{First: time.Millisecond, Every: time.Minute, AuthBackoff: time.Hour, MinRetry: 30 * time.Second})
	e := watchTest(t, true)
	e.api.status, e.api.retry = http.StatusTooManyRequests, "120"
	if _, wait, err := e.m.watchCheck(context.Background(), false); err == nil || wait != 120*time.Second {
		t.Fatalf("wait %v err %v", wait, err)
	}
	if st := e.state(t); st.ErrorStatus != 429 || st.AuthFailed() || time.Until(st.NextAttempt) < 110*time.Second {
		t.Fatalf("state: %+v", st)
	}
	e.api.retry = "2"
	if _, wait, _ := e.m.watchCheck(context.Background(), false); wait != 30*time.Second {
		t.Fatalf("min retry: %v", wait)
	}
	e.api.status, e.api.retry = http.StatusBadGateway, ""
	if _, wait, _ := e.m.watchCheck(context.Background(), false); wait != time.Minute {
		t.Fatalf("other error: %v", wait)
	}
}

// Fehler mitten im Abruf: schon geholte Treffer bleiben (gemeldet, gespeichert, next weiter).
func TestWatchErrorMidPaging(t *testing.T) {
	e := watchTest(t, true)
	e.api.networks = []ipv64api.ThreatWatchNetwork{{ID: 1, CIDR: "203.0.113.0/24"}}
	e.api.addAlerts(150, time.Now().Add(-time.Hour), 1)
	e.api.failPage = 2
	n, _, err := e.m.watchCheck(context.Background(), false)
	if err == nil || n != 100 || len(e.notes.all()) != 1 {
		t.Fatalf("check: %d %v", n, err)
	}
	st := e.state(t)
	if len(st.Hits) != 100 || st.Next != e.api.alerts[99].CreatedAt || st.LastError == "" || st.ErrorStatus != 500 {
		t.Fatalf("state: hits %d next %q err %q", len(st.Hits), st.Next, st.LastError)
	}
	e.api.failPage = 0
	if n, _, err := e.m.watchCheck(context.Background(), false); err != nil || n != 50 || len(e.notes.all()) != 2 {
		t.Fatalf("rest: %d %v", n, err)
	}
}

// Die Schleife: erster Abruf nach First, dann im Takt; endet mit ctx.
func TestWatchLoop(t *testing.T) {
	withWatchTiming(t, watchTimingT{First: 5 * time.Millisecond, Every: 20 * time.Millisecond, AuthBackoff: time.Hour, MinRetry: time.Millisecond})
	e := watchTest(t, true)
	e.api.networks = []ipv64api.ThreatWatchNetwork{{ID: 1, CIDR: "203.0.113.0/24"}}
	e.api.addAlerts(2, time.Now().Add(-time.Hour), 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.m.watchLoop(ctx); close(done) }()
	waitNote := func(want int) {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for len(e.notes.all()) < want {
			select {
			case <-e.notes.ch:
			case <-deadline:
				t.Fatalf("waiting for notification %d", want)
			}
		}
	}
	waitNote(1)
	e.api.addAlerts(1, time.Now(), 50)
	waitNote(2)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("loop did not stop")
	}
	if notes := e.notes.all(); len(notes) != 2 || !strings.HasPrefix(notes[1].Message, "203.0.113.1 ") {
		t.Fatalf("notes: %+v", notes)
	}
}

func TestNormalizeCIDR(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.77/24": "203.0.113.0/24", " 198.51.100.5 ": "198.51.100.5/32", "2001:db8:1::5/48": "2001:db8:1::/48",
		"2a01:4f8::1": "2a01:4f8::1/128", "::ffff:203.0.113.9/120": "203.0.113.0/24",
		"10.1.0.0/16": "!not_public", "127.0.0.1": "!not_public", "fe80::1/64": "!not_public", "0.0.0.0/0": "!not_public",
		"x": "!invalid_cidr", "1.2.3.4/33": "!invalid_cidr", "": "!invalid_cidr", "fe80::1%eth0": "!invalid_cidr",
	} {
		got, code := normalizeCIDR(in)
		if code != "" {
			got = "!" + code
		}
		if got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	if s, ok := cleanLabel(" Bu\x00ero\n "); s != "Bu ero" || !ok {
		t.Fatalf("label: %q %v", s, ok)
	}
	if _, ok := cleanLabel(strings.Repeat("ä", watchLabelMax+1)); ok {
		t.Fatal("long label accepted")
	}
}

func TestWatchTab(t *testing.T) {
	n := 0
	for _, tab := range tabsFor("watch") {
		if tab.Key == "watch" {
			n++
			if !tab.Active || tab.Path != "/honeypot/watch" {
				t.Fatalf("tab: %+v", tab)
			}
		}
	}
	if n != 1 {
		t.Fatalf("watch tab %d times", n)
	}
}

// watchMux: die Routen mit Guards, die ohne Kopfzeile X-Test-Auth 401 liefern.
func (e *watchEnv) mux() *http.ServeMux {
	g := e.m.g
	g.Enabled = func(h http.Handler) http.Handler { return h }
	g.Auth = func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Test-Auth") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			h.ServeHTTP(w, r)
		})
	}
	mux := http.NewServeMux()
	e.m.watchRoutes(mux, g)
	return mux
}

func (e *watchEnv) do(mux *http.ServeMux, method, path string, form url.Values) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, path, body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	r.Header.Set("X-Test-Auth", "1")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestWatchPages(t *testing.T) {
	e := watchTest(t, true)
	mux := e.mux()
	e.api.networks = []ipv64api.ThreatWatchNetwork{{ID: 1, CIDR: "203.0.113.0/24", Label: "Buero", Verified: true, CreatedAt: "2026-10-20T12:00:00Z"}}
	e.api.dyndns = []ipv64api.ThreatWatchDynDNS{{IP: "198.51.100.7", Domain: "x.ipv64.net"}}

	// Guard: ohne Anmeldung nichts
	for _, p := range []string{"/honeypot/watch"} {
		r := httptest.NewRequest(http.MethodGet, p, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized || len(e.render) != 0 {
			t.Fatalf("guard: %d", w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/honeypot/watch", strings.NewReader("cidr=203.0.113.0/24"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized || len(e.api.added) != 0 {
		t.Fatalf("guard post: %d", w.Code)
	}

	// GET: Liste live, Grenzen, DynDNS
	if w := e.do(mux, http.MethodGet, "/honeypot/watch", nil); w.Code != 200 {
		t.Fatalf("get: %d", w.Code)
	}
	d := e.render[len(e.render)-1].data.(watchData)
	if e.render[len(e.render)-1].page != "honeypot/watch" || !d.KeySet || !d.Loaded || len(d.Networks) != 1 || d.Networks[0].Created.IsZero() ||
		len(d.DynDNS) != 1 || d.Limits.Max != 3 || d.Full || d.Err != "" {
		t.Fatalf("view: %+v", d)
	}

	// POST: normalisiert, Audit, Weiterleitung
	w = e.do(mux, http.MethodPost, "/honeypot/watch", url.Values{"cidr": {"198.51.100.77/24"}, "label": {"Lager"}})
	if w.Code != http.StatusSeeOther || len(e.api.added) != 1 || e.api.added[0] != "198.51.100.0/24|Lager" {
		t.Fatalf("add: %d %v", w.Code, e.api.added)
	}
	if len(e.audit) != 1 || e.audit[0].action != "honeypot.watch.add" || e.audit[0].target != "198.51.100.0/24" {
		t.Fatalf("audit: %+v", e.audit)
	}
	// ungueltig bzw. privat: Seite mit Fehler, keine Anfrage
	for _, c := range []struct{ in, code string }{{"nonsense", "invalid_cidr"}, {"192.168.1.0/24", "not_public"}} {
		w = e.do(mux, http.MethodPost, "/honeypot/watch", url.Values{"cidr": {c.in}, "label": {"x"}})
		d := e.render[len(e.render)-1].data.(watchData)
		if w.Code != http.StatusUnprocessableEntity || !strings.Contains(d.FormErr, "honeypot.watch.err."+c.code) || d.CIDR != c.in || d.Label != "x" || len(e.api.added) != 1 {
			t.Fatalf("%s: %d %q", c.in, w.Code, d.FormErr)
		}
	}
	// Fehler der API: Status und Code durchgereicht
	e.api.addStatus, e.api.addCode = http.StatusForbidden, "limit_reached"
	w = e.do(mux, http.MethodPost, "/honeypot/watch", url.Values{"cidr": {"192.0.2.0/24"}})
	if d := e.render[len(e.render)-1].data.(watchData); w.Code != http.StatusForbidden || !strings.Contains(d.FormErr, "honeypot.watch.err.limit_reached") {
		t.Fatalf("limit: %d %q", w.Code, d.FormErr)
	}
	e.api.addStatus = 0

	// Loeschen: 204, dann 404 = schon weg, ungueltige ID
	w = e.do(mux, http.MethodPost, "/honeypot/watch/1/delete", url.Values{"cidr": {"203.0.113.0/24"}})
	if w.Code != http.StatusSeeOther || len(e.api.deleted) != 1 || e.flashes[len(e.flashes)-1].kind != "success" || e.audit[len(e.audit)-1].action != "honeypot.watch.delete" {
		t.Fatalf("delete: %d %+v %+v", w.Code, e.api.deleted, e.flashes)
	}
	e.do(mux, http.MethodPost, "/honeypot/watch/1/delete", url.Values{})
	if f := e.flashes[len(e.flashes)-1]; f.kind != "warning" || !strings.Contains(f.text, "honeypot.watch.gone") {
		t.Fatalf("404: %+v", f)
	}
	e.do(mux, http.MethodPost, "/honeypot/watch/abc/delete", url.Values{})
	if f := e.flashes[len(e.flashes)-1]; f.kind != "danger" {
		t.Fatalf("bad id: %+v", f)
	}

	// Jetzt abrufen
	w = e.do(mux, http.MethodPost, "/honeypot/watch/check", url.Values{})
	if f := e.flashes[len(e.flashes)-1]; w.Code != http.StatusSeeOther || f.kind != "success" {
		t.Fatalf("check: %d %+v", w.Code, f)
	}

	// Key abgelehnt: Seite zeigt es
	e.api.status = http.StatusUnauthorized
	e.do(mux, http.MethodGet, "/honeypot/watch", nil)
	if d := e.render[len(e.render)-1].data.(watchData); !d.AuthErr || d.Loaded {
		t.Fatalf("auth view: %+v", d)
	}
}

func TestWatchPagesWithoutKey(t *testing.T) {
	e := watchTest(t, false)
	mux := e.mux()
	e.do(mux, http.MethodGet, "/honeypot/watch", nil)
	if d := e.render[0].data.(watchData); d.KeySet || d.Loaded {
		t.Fatalf("view: %+v", d)
	}
	w := e.do(mux, http.MethodPost, "/honeypot/watch", url.Values{"cidr": {"203.0.113.0/24"}})
	if w.Code != http.StatusSeeOther || e.flashes[0].kind != "danger" || len(e.api.added) != 0 {
		t.Fatalf("add without key: %d %+v", w.Code, e.flashes)
	}
	if lists, _ := e.api.counts(); lists != 0 {
		t.Fatal("request without key")
	}
}

// watchFakeView bildet die Hilfen des Layouts nach, die watch.html nutzt.
type watchFakeView struct {
	Data any
	CSRF string
}

func (watchFakeView) T(key string, args ...any) string { return key }
func (watchFakeView) Time(t time.Time) string          { return t.Format(time.RFC3339) }
func (watchFakeView) Int(n int64) string               { return strconv.FormatInt(n, 10) }
func (watchFakeView) Doc(string) template.HTML         { return "" }

// Das Template laesst sich mit allen Zustaenden ausfuehren (Felder und Methoden passen).
func TestWatchTemplate(t *testing.T) {
	tpl, err := template.New("x").Funcs(template.FuncMap{"join": strings.Join}).ParseFS(templateFS, "templates/pages/watch.html")
	if err != nil {
		t.Fatal(err)
	}
	full := watchData{Tabs: tabsFor("watch"), Running: true, KeySet: true, Loaded: true, Limits: ipv64api.ThreatWatchLimits{Max: 3, MinPrefixV4: 16, MinPrefixV6: 32},
		Networks: []watchNetView{{ThreatWatchNetwork: ipv64api.ThreatWatchNetwork{ID: 1, CIDR: "203.0.113.0/24", Label: "<b>Buero</b>"}, Created: time.Now()}},
		DynDNS:   []ipv64api.ThreatWatchDynDNS{{IP: "198.51.100.7", Domain: "x.ipv64.net"}},
		State:    watchState{LastSuccess: time.Now(), NextAttempt: time.Now(), ErrorStatus: 401, LastError: "x", LastErrorAt: time.Now(), Total: 3},
		Hits: []watchHitView{{watchHit: watchHit{ID: 1, IP: "203.0.113.9", CIDR: "203.0.113.0/24", Label: "Buero", Source: "network", Listed: true, Kinds: []string{"ssh:bruteforce"},
			FirstSeen: "2026-10-19", LastSeen: "2026-10-20", Details: &ipv64api.ThreatWatchDetails{Sensors: 2, Accounts: 1, Events: 10, Lists: []string{"v64"},
				Seen: []ipv64api.ThreatWatchSeen{{Origin: "honeypot", Service: "ssh", Port: 22, Kind: "ssh:bruteforce", Count: 10, Sensors: 2}}}}, At: time.Now()},
			{watchHit: watchHit{ID: 2, IP: "198.51.100.7", Source: "dyndns"}}},
		FormErr: "err", CIDR: "1.2.3.4"}
	for i, d := range []watchData{full, {Tabs: tabsFor("watch")}, {KeySet: true, Err: "boom"}, {KeySet: true, AuthErr: true, Loaded: true, Full: true, Limits: ipv64api.ThreatWatchLimits{Max: 3}}} {
		var b bytes.Buffer
		if err := tpl.ExecuteTemplate(&b, "content", watchFakeView{Data: d, CSRF: "tok"}); err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if i == 0 && (!strings.Contains(b.String(), "ssh/22 ssh:bruteforce") || !strings.Contains(b.String(), "honeypot.watch.why_sum") || strings.Contains(b.String(), "<b>Buero</b>") || !strings.Contains(b.String(), `action="/honeypot/watch/1/delete"`) || !strings.Contains(b.String(), `value="tok"`)) {
			t.Fatalf("case 0 output:\n%s", b.String())
		}
		if i == 1 && (!strings.Contains(b.String(), "honeypot.watch.nokey") || strings.Contains(b.String(), `action="/honeypot/watch"`)) {
			t.Fatalf("no key must show hint instead of form:\n%s", b.String())
		}
	}
}

// Die Seiten-Daten ueberleben einen Neustart (Zustand in den Einstellungen).
func TestWatchStateRoundTrip(t *testing.T) {
	e := watchTest(t, true)
	ctx := context.Background()
	in := watchState{Next: "n", Hits: []watchHit{{ID: 5, IP: "203.0.113.5", Kinds: []string{"a"}}}, Total: 1, ErrorStatus: 403, KeyFP: "k"}
	e.m.watchSave(ctx, in)
	out := e.m.watchLoad(ctx)
	if out.Next != "n" || len(out.Hits) != 1 || out.Hits[0].ID != 5 || !out.AuthFailed() {
		t.Fatalf("round trip: %+v", out)
	}
	_ = e.m.core.SetSetting(ctx, setWatch, "{kaputt")
	if s := e.m.watchLoad(ctx); s.Next != "" || len(s.Hits) != 0 {
		t.Fatalf("broken state: %+v", s)
	}
}

// Details eines Treffers in der Benachrichtigung: je Herkunft, Dienst, Port, Art, Regel und Anzahl, dazu Sensoren/Accounts.
func TestHitLineDetails(t *testing.T) {
	h := watchHit{IP: "203.0.113.9", CIDR: "203.0.113.0/24", Source: "network", Score: 40, Details: &ipv64api.ThreatWatchDetails{Sensors: 3, Accounts: 2,
		Seen: []ipv64api.ThreatWatchSeen{{Origin: "honeypot", Service: "ssh", Port: 22, Kind: "ssh:bruteforce", Count: 10}, {Origin: "log", Service: "http", Port: 443, Kind: "http:bruteforce", Rule: "nginx/auth", Count: 4}}}}
	want := "203.0.113.9 · 203.0.113.0/24 · Score 40\n  honeypot ssh/22 ssh:bruteforce ×10 · log http/443 http:bruteforce (nginx/auth) ×4 – sensors 3, accounts 2"
	if got := hitLine(h); got != want {
		t.Fatalf("got %q", got)
	}
	h.Details = nil
	if got := hitLine(h); strings.Contains(got, "\n") {
		t.Fatalf("without details: %q", got)
	}
}
