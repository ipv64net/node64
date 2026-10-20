package geoip

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testData = `# country_ranges von ipv64 (Test)
# CC erste letzte

DE 192.0.2.0 192.0.2.127
de 192.0.2.128 192.0.2.255
US 198.51.100.0 198.51.100.255
FR 203.0.113.0 203.0.113.63
NL 203.0.113.32 203.0.113.95
XX1 1.2.3.4 1.2.3.5
DE 1.2.3.9 1.2.3.4
DE 2001:db8:1:: 2001:db8:1::5
JP 2001:db8:: 2001:db8:0:ffff:ffff:ffff:ffff:ffff
US 2001:db8:1:: 2001:db8:1:ffff:ffff:ffff:ffff:ffff
DE 192.0.2.0
EU 2a00:: 2a00:ff:ffff:ffff:ffff:ffff:ffff:ffff
`

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := io.WriteString(w, s); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestParseMergeLookup(t *testing.T) {
	tab, skipped, err := parse(strings.NewReader(testData))
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 3 { // XX1, umgekehrter Bereich, Zeile mit zwei Feldern
		t.Errorf("skipped %d", skipped)
	}
	// DE zusammengefasst (zwei angrenzende Bereiche, einer klein geschrieben), FR/NL ueberschneiden sich: NL beginnt nach FR
	if len(tab.v4s) != 4 {
		t.Fatalf("v4 ranges: %d %v %v", len(tab.v4s), tab.v4s, tab.v4e)
	}
	for ip, want := range map[string]string{
		"192.0.2.0": "DE", "192.0.2.200": "DE", "192.0.2.255": "DE", "198.51.100.1": "US", "203.0.113.40": "FR", "203.0.113.64": "NL",
		"203.0.113.95": "NL", "203.0.113.96": "", "198.51.101.0": "", "1.2.3.4": "", "::ffff:192.0.2.5": "DE",
		"2001:db8::1": "JP", "2001:db8:0:ffff::1": "JP", "2001:db8:1::1": "DE", "2001:db8:1:5::1": "US", "2001:db8:2::1": "",
		"2a00:12::1": "EU", "10.1.2.3": "", "127.0.0.1": "", "fe80::1": "", "fd00::1": "", "100.64.1.1": "", "0.0.0.0": "",
	} {
		got := ccString(tab.lookup(netip.MustParseAddr(ip)))
		if tab.lookup(netip.MustParseAddr(ip)) == 0 {
			got = ""
		}
		if got != want {
			t.Errorf("%s: %q, want %q", ip, got, want)
		}
	}
	if tab.bytes() != len(tab.v4s)*10+len(tab.v6s)*18 {
		t.Error("bytes")
	}
	if (*table)(nil).lookup(netip.MustParseAddr("192.0.2.1")) != 0 {
		t.Error("nil table")
	}
}

func TestParseLimits(t *testing.T) {
	if _, _, err := parse(strings.NewReader("# nur Kommentar\n\nXX 1.2.3.4\n")); err != errNoRanges {
		t.Errorf("empty: %v", err)
	}
	if _, _, err := parse(strings.NewReader("DE 1.2.3.4 1.2.3.5 " + strings.Repeat("x", 300) + "\n")); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Errorf("long line: %v", err)
	}
	oldLines, oldRaw := maxLines, maxRaw
	defer func() { maxLines, maxRaw = oldLines, oldRaw }()
	maxLines = 3
	if _, _, err := parse(strings.NewReader("DE 1.0.0.0 1.0.0.255\n#\n#\n#\n")); err == nil || !strings.Contains(err.Error(), "lines") {
		t.Errorf("lines: %v", err)
	}
	maxLines, maxRaw = oldLines, 30
	if _, _, err := parse(strings.NewReader("DE 1.0.0.0 1.0.0.255\nDE 1.0.1.0 1.0.1.255\n")); err != errTooLarge {
		t.Errorf("raw: %v", err)
	}
	maxRaw = oldRaw
	if _, _, err := parseGzip(strings.NewReader("kein gzip")); err == nil {
		t.Error("gzip expected to fail")
	}
}

func TestFlagName(t *testing.T) {
	if Flag("DE") != "\U0001F1E9\U0001F1EA" || Flag("EU") != "\U0001F1EA\U0001F1FA" {
		t.Errorf("flag %q", Flag("DE"))
	}
	if Flag("XX") != "" || Flag("") != "" || Flag("de") != "" || Flag("DEU") != "" {
		t.Error("unknown codes must not have a flag")
	}
	if Name("DE", "de") != "Deutschland" || Name("DE", "en") != "Germany" || Name("US", "de-AT") != "Vereinigte Staaten" || Name("AP", "de") != "AP" {
		t.Errorf("names: %q %q %q", Name("DE", "de"), Name("DE", "en"), Name("US", "de-AT"))
	}
}

// geoServer ist ein Blocklisten-Server: index.json mit geo (oder ohne), Datei mit ETag.
type geoServer struct {
	srv        *httptest.Server
	mu         sync.Mutex
	index      string
	file       []byte
	fileStatus int
	full       atomic.Int32 // vollstaendige Abrufe der Datei
	cond       atomic.Int32 // bedingte Abrufe mit passendem ETag
}

func newGeoServer(t *testing.T, data string) *geoServer {
	g := &geoServer{index: `{"lists":[],"geo":{"file":"country_ranges.txt.gz","updated":"2026-10-20T00:00:00Z","ranges":9}}`, file: gz(t, data)}
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		switch r.URL.Path {
		case "/blocklists/index.json":
			if g.index == "" {
				http.NotFound(w, r)
				return
			}
			_, _ = io.WriteString(w, g.index)
		case "/blocklists/country_ranges.txt.gz":
			if g.fileStatus != 0 {
				w.WriteHeader(g.fileStatus)
				return
			}
			sum := sha256.Sum256(g.file)
			etag := `"` + hex.EncodeToString(sum[:8]) + `"`
			if r.Header.Get("If-None-Match") == etag {
				g.cond.Add(1)
				w.WriteHeader(http.StatusNotModified)
				return
			}
			g.full.Add(1)
			w.Header().Set("ETag", etag)
			w.Header().Set("Last-Modified", "Tue, 20 Oct 2026 00:00:00 GMT")
			w.Header().Set("Content-Type", "application/gzip")
			_, _ = w.Write(g.file)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *geoServer) base() string { return g.srv.URL + "/blocklists/" }

func TestRefreshCacheETag(t *testing.T) {
	g := newGeoServer(t, testData)
	dir := filepath.Join(t.TempDir(), "geoip")
	ctx := context.Background()
	d := New(dir, g.base(), "Node64/test", quiet())
	if _, ok := d.Lookup(netip.MustParseAddr("192.0.2.1")); ok || d.Status().Loaded {
		t.Fatal("no data before refresh")
	}
	if err := d.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if cc, ok := d.Lookup(netip.MustParseAddr("192.0.2.1")); !ok || cc != "DE" {
		t.Fatalf("lookup: %q %v", cc, ok)
	}
	if st := d.Status(); !st.Loaded || st.Ranges4 != 4 || st.Ranges6 == 0 || st.Bytes == 0 {
		t.Fatalf("status %+v", st)
	}
	for _, f := range []string{cacheFile, metaFile} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("cache %s: %v", f, err)
		}
	}
	// zweiter Abruf: 304 (ETag), Daten bleiben
	if err := d.Refresh(ctx); err != nil || g.full.Load() != 1 || g.cond.Load() != 1 {
		t.Fatalf("etag: %v full=%d cond=%d", err, g.full.Load(), g.cond.Load())
	}
	// Neustart: aus dem Zwischenspeicher sofort nutzbar, bedingter Abruf dank meta.json
	d2 := New(dir, g.base(), "", quiet())
	if err := d2.LoadCache(); err != nil {
		t.Fatal(err)
	}
	if cc, _ := d2.Lookup(netip.MustParseAddr("2001:db8::7")); cc != "JP" {
		t.Fatalf("cache lookup %q", cc)
	}
	if err := d2.Refresh(ctx); err != nil || g.full.Load() != 1 || g.cond.Load() != 2 {
		t.Fatalf("etag after restart: %v full=%d cond=%d", err, g.full.Load(), g.cond.Load())
	}
	// geaenderte Datei wird geladen
	g.mu.Lock()
	g.file = gz(t, "FR 192.0.2.0 192.0.2.255\n")
	g.mu.Unlock()
	if err := d2.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if cc, _ := d2.Lookup(netip.MustParseAddr("192.0.2.1")); cc != "FR" || g.full.Load() != 2 {
		t.Fatalf("changed data %q", cc)
	}
	// kaputte Datei: Fehler, alter Stand bleibt
	g.mu.Lock()
	g.file = []byte("kaputt-und-anders-lang")
	g.mu.Unlock()
	if err := d2.Refresh(ctx); err == nil {
		t.Fatal("broken file must fail")
	}
	if !d2.Status().Loaded {
		t.Fatal("old data must stay")
	}
}

func TestRefreshMissing(t *testing.T) {
	g := newGeoServer(t, testData)
	var logs bytes.Buffer
	d := New("", g.base(), "", slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	ctx := context.Background()
	// index.json ohne geo (Datei bei ipv64 noch nicht live)
	g.mu.Lock()
	g.index = `{"lists":[{"id":"all"}]}`
	g.mu.Unlock()
	err := d.Refresh(ctx)
	if err != errMissing || d.report(err) != missingEvery {
		t.Fatalf("no geo: %v", err)
	}
	// Datei 404
	g.mu.Lock()
	g.index = `{"geo":{"file":"country_ranges.txt.gz"}}`
	g.fileStatus = http.StatusNotFound
	g.mu.Unlock()
	if err := d.Refresh(ctx); err != errMissing {
		t.Fatalf("404: %v", err)
	}
	d.report(err)
	// index.json 404
	g.mu.Lock()
	g.index = ""
	g.mu.Unlock()
	if err := d.Refresh(ctx); err != errMissing {
		t.Fatalf("index 404: %v", err)
	}
	if logs.Len() != 0 {
		t.Fatalf("missing file must not log at info/warn: %s", logs.String())
	}
	if d.Status().Loaded || d.Status().Error != "" {
		t.Fatalf("status %+v", d.Status())
	}
	// ungueltiger Dateiname, Serverfehler: Warnung einmal
	g.mu.Lock()
	g.index = `{"geo":{"file":"../etc/passwd.txt.gz"}}`
	g.mu.Unlock()
	err = d.Refresh(ctx)
	if err == nil || err == errMissing {
		t.Fatalf("bad name: %v", err)
	}
	if d.report(err) != errorEvery || d.report(err) != errorEvery || strings.Count(logs.String(), "WARN") != 1 {
		t.Fatalf("warn once: %s", logs.String())
	}
	g.mu.Lock()
	g.index = `{"geo":{"file":"country_ranges.txt.gz"}}`
	g.fileStatus = 0
	g.mu.Unlock()
	if err := d.Refresh(ctx); err != nil || d.report(err) != refreshEvery {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "available again") {
		t.Errorf("recovery not logged: %s", logs.String())
	}
}

func TestRefreshLimitsAndHTML(t *testing.T) {
	g := newGeoServer(t, testData)
	d := New("", g.base(), "", quiet())
	old := maxFile
	maxFile = 10
	err := d.Refresh(context.Background())
	maxFile = old
	if err != errTooLarge {
		t.Fatalf("size: %v", err)
	}
	html := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html>")
	}))
	defer html.Close()
	if err := New("", html.URL, "", quiet()).Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "html") {
		t.Fatalf("html: %v", err)
	}
}

func TestStartRelease(t *testing.T) {
	g := newGeoServer(t, testData)
	t.Setenv(EnvBase, g.base())
	dir := t.TempDir()
	if _, ok := Lookup(netip.MustParseAddr("192.0.2.1")); ok {
		t.Fatal("no data without Start")
	}
	r1 := Start(dir, "Node64/test", quiet())
	r2 := Start(dir, "Node64/test", quiet()) // zweiter Nutzer: kein zweites Laden
	deadline := time.Now().Add(10 * time.Second)
	for !Current().Loaded && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if cc, ok := Lookup(netip.MustParseAddr("198.51.100.9")); !ok || cc != "US" {
		t.Fatalf("lookup after start: %q %v", cc, ok)
	}
	if g.full.Load() != 1 {
		t.Fatalf("downloads: %d", g.full.Load())
	}
	r1()
	r1() // mehrfach = einmal
	if !Current().Loaded {
		t.Fatal("still one user")
	}
	r2()
	if Current().Loaded {
		t.Fatal("data must be released without users")
	}
	if _, err := os.Stat(filepath.Join(dir, "geoip", cacheFile)); err != nil {
		t.Fatalf("cache: %v", err)
	}
	if baseFromEnv() != g.base() {
		t.Error("env base")
	}
	t.Setenv(EnvBase, "file:///etc")
	if baseFromEnv() != DefaultBase {
		t.Error("only http(s) from env")
	}
}
