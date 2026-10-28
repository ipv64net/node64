package cdn64

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeStatus spielt die Statusseiten der Healthchecks (Seite 7 an, Seite 8 aus, sonst unbekannt).
type fakeStatus struct {
	off   atomic.Bool // Healthchecks ausgeschaltet
	calls atomic.Int64
}

func (f *fakeStatus) StatusSite(id int64) http.Handler {
	if f.off.Load() {
		return nil
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		if id != 7 {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("status page " + strconv.FormatInt(id, 10) + " path=" + r.URL.Path))
	})
}

func (f *fakeStatus) StatusPageList(context.Context) []StatusPageInfo {
	if f.off.Load() {
		return nil
	}
	return []StatusPageInfo{{ID: 7, Slug: "home", Title: "Heimnetz", Enabled: true}, {ID: 8, Slug: "alt", Title: "Alt", Enabled: false}}
}

// Hostart "status": normalisieren, speichern (Spalte aus 0006), ausliefern, ohne Healthchecks 503, API.
func TestStatusHost(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	fs := &fakeStatus{}
	e.m.SetStatusPages(fs)
	e.enable(t)

	var fe *FieldError
	bad := newHostKind(KindStatus)
	bad.Names = []string{"status.test"}
	if err := e.m.saveHost(ctx, bad); !errors.As(err, &fe) || fe.Field != "status_page_id" || fe.Key != "cdn64.err.status_page" {
		t.Fatalf("without page: %v", err)
	}
	h := newHostKind(KindStatus)
	h.Names, h.StatusPageID, h.CertID = []string{"status.test"}, 7, CertNone
	h.TargetHost, h.RedirectTarget, h.CacheAssets, h.BlockExploits = "192.168.1.5", "x.test", true, true
	h.Locations = []Location{{Path: "/x", Scheme: "http", TargetHost: "127.0.0.1", TargetPort: 1}}
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if h.TargetHost != "" || h.TargetPort != 0 || h.RedirectTarget != "" || h.CacheAssets || len(h.Locations) != 0 || !h.BlockExploits {
		t.Fatalf("normalized: %+v", h)
	}
	got, err := e.m.host(ctx, h.ID)
	if err != nil || got.Kind != KindStatus || got.StatusPageID != 7 || !got.BlockExploits {
		t.Fatalf("stored: %+v %v", got, err)
	}
	if h.probed() {
		t.Fatal("status host must not be probed")
	}
	// andere Arten tragen keine Seite
	p := newHost()
	p.Names, p.TargetHost, p.StatusPageID = []string{"proxy.test"}, "127.0.0.1", 7
	if err := e.m.saveHost(ctx, p); err != nil || p.StatusPageID != 0 {
		t.Fatalf("proxy: %v %d", err, p.StatusPageID)
	}

	c := e.client(false)
	if code, body, _ := do(t, c, "GET", "http://status.test/item/3?x=1"); code != 200 || body != "status page 7 path=/item/3" {
		t.Fatalf("serve: %d %q", code, body)
	}
	if code, _, _ := do(t, c, "GET", "http://status.test/.env"); code != http.StatusForbidden {
		t.Fatalf("exploit filter: %d", code)
	}
	if n := e.m.statsOf(h.ID).requests.Load(); n != 2 {
		t.Fatalf("requests counted: %d", n)
	}
	// Seite auf dieser Node unbekannt (z. B. nach Import): Host bleibt, Seite antwortet 404
	h.StatusPageID = 99
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := do(t, c, "GET", "http://status.test/"); code != http.StatusNotFound {
		t.Fatalf("unknown page: %d", code)
	}
	// Healthchecks aus: neutrale Seite 503
	fs.off.Store(true)
	if code, _, _ := do(t, c, "GET", "http://status.test/"); code != http.StatusServiceUnavailable {
		t.Fatalf("healthchecks off: %d", code)
	}
	fs.off.Store(false)

	// API: kind und status_page_id im JSON
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, httptest.NewRequest("POST", "/api/cdn64/hosts", strings.NewReader(`{"kind":"status","names":["s2.test"],"status_page_id":8}`)))
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"kind":"status"`) || !strings.Contains(rec.Body.String(), `"status_page_id":8`) {
		t.Fatalf("api create: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	e.mux.ServeHTTP(rec, httptest.NewRequest("POST", "/api/cdn64/hosts", strings.NewReader(`{"kind":"status","names":["s3.test"]}`)))
	var out map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusUnprocessableEntity || out["field"] != "status_page_id" {
		t.Fatalf("api without page: %d %s", rec.Code, rec.Body.String())
	}
	rows, err := e.m.rowsOf(ctx, KindStatus)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows: %d %v", len(rows), err)
	}
	for _, r := range rows {
		switch r.Names[0] {
		case "s2.test":
			if r.Status == nil || r.Status.Title != "Alt" || r.Status.Enabled {
				t.Fatalf("row s2: %+v", r.Status)
			}
		case "status.test":
			if r.Status != nil { // Seite 99 gibt es nicht
				t.Fatalf("row status: %+v", r.Status)
			}
		}
	}
}

// Laendersperre und Blocklisten greifen vor der Statusseite (echte Client-IP hinter vertrauenswuerdigem Proxy).
func TestStatusHostGeoAndBlocklist(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(testIndex))
		case "/countries/ipv64_blocklist_DE.txt":
			_, _ = w.Write([]byte("5.1.0.0/16\n"))
		case "/ipv64_blocklist_feodo.txt":
			_, _ = w.Write([]byte("198.51.100.7/32\n"))
		default:
			http.Error(w, "<html>404</html>", http.StatusNotFound)
		}
	}))
	defer srv.Close()
	e.m.bl.base = srv.URL + "/"
	e.m.SetDataDir(t.TempDir())
	fs := &fakeStatus{}
	e.m.SetStatusPages(fs)
	e.enable(t)
	h := newHostKind(KindStatus)
	h.Names, h.StatusPageID, h.CertID = []string{"status.test"}, 7, CertNone
	h.Advanced.GeoMode, h.Advanced.GeoCountries = geoBlock, []string{"DE"}
	h.Advanced.TrustedProxies = []string{"127.0.0.1"}
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	e.m.blRefresh(ctx)
	if err := e.m.blSave(ctx, []string{"feodo"}, ""); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 250 && (e.m.bl.set.Load() == nil || !e.m.geoBlocked(&h.Advanced, netip.MustParseAddr("5.1.9.9"))); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	c := e.client(false)
	for _, x := range []struct {
		ip   string
		code int
	}{{"5.1.2.3", http.StatusForbidden}, {"198.51.100.7", http.StatusForbidden}, {"8.8.8.8", http.StatusOK}} {
		if code, _, _ := do(t, c, "GET", "http://status.test/", "X-Forwarded-For", x.ip); code != x.code {
			t.Fatalf("%s: %d, want %d", x.ip, code, x.code)
		}
	}
	if fs.calls.Load() != 1 {
		t.Fatalf("status page reached %d times, want 1", fs.calls.Load())
	}
	if n := e.m.statsOf(h.ID).blocked.Load(); n != 2 {
		t.Fatalf("blocked counted: %d", n)
	}
}

// Export/Import: Hostart und Seiten-ID kommen mit, auch wenn es die Seite auf der Ziel-Node nicht gibt.
func TestStatusHostExportImport(t *testing.T) {
	ctx := context.Background()
	a := newEnv(t)
	a.m.SetStatusPages(&fakeStatus{})
	a.enable(t)
	h := newHostKind(KindStatus)
	h.Names, h.StatusPageID = []string{"status.test"}, 42
	h.Advanced.GeoMode, h.Advanced.GeoCountries = geoAllow, []string{"DE"}
	if err := a.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	exp, err := a.m.Export(ctx)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(exp)
	if !strings.Contains(string(raw), `"status_page_id":42`) {
		t.Fatalf("export: %s", raw)
	}
	b := newEnv(t) // ohne Healthchecks
	b.enable(t)
	// Seite 42 gibt es auf der Quelle nicht: kein Slug im Export, der Host kommt ausgeschaltet (mit Meldung)
	if n, err := b.m.Import(ctx, raw); err == nil || n != 1 || !strings.Contains(err.Error(), "status.test") {
		t.Fatalf("import: n=%d err=%v", n, err)
	}
	list, _ := b.m.hosts(ctx)
	if len(list) != 1 || list[0].Kind != KindStatus || list[0].StatusPageID != 42 || list[0].Advanced.GeoMode != geoAllow || list[0].Enabled {
		t.Fatalf("imported: %+v", list)
	}
	if code, _, _ := do(t, b.client(false), "GET", "http://status.test/"); code == http.StatusOK {
		t.Fatalf("imported host must be off: %d", code)
	}
}
