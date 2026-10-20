package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/metrics"
)

// fakeNFT merkt sich die Aufrufe statt nftables.
type fakeNFT struct {
	mu        sync.Mutex
	exists    bool
	v4, v6    []Range
	applies   int
	updates   int
	upd4      bool
	upd6      bool
	removes   int
	failApply error
	failUpd   error
}

func (f *fakeNFT) Apply(v4, v6 []Range) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failApply != nil {
		return f.failApply
	}
	f.applies++
	f.exists, f.v4, f.v6 = true, v4, v6
	return nil
}

func (f *fakeNFT) Update(v4, v6 *[]Range) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failUpd != nil {
		return f.failUpd
	}
	f.updates++
	f.upd4, f.upd6 = v4 != nil, v6 != nil
	if v4 != nil {
		f.v4 = *v4
	}
	if v6 != nil {
		f.v6 = *v6
	}
	return nil
}

func (f *fakeNFT) Exists() (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.exists, nil
}

func (f *fakeNFT) Remove() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removes++
	f.exists = false
	return nil
}

const testToken = "abcdefghijklmnopqrstuvwxyz012345"

const testIndex = `{"lists":[
 {"id":"v64","category":"honeypot","files":{"all":"ipv64_blocklist_v64.txt"}},
 {"id":"v64_ssh","category":"honeypot","files":{"all":"ipv64_blocklist_v64_ssh.txt"}},
 {"id":"feodo","category":"botnet","files":{"all":"ipv64_blocklist_feodo.txt"}},
 {"id":"bad","files":{"all":"../x.txt"}}],
 "combined":[{"id":"all","files":{"all":"ipv64_blocklist_all.txt"}}]}`

// listServer liefert index.json und Listen mit ETag; live[datei] = Inhalt der Live-Fassung.
type listServer struct {
	mu      sync.Mutex
	files   map[string]string // Pfad unter /blocklists/ -> Inhalt
	status  map[string]int    // Pfad -> erzwungener Status
	header  map[string]string // Pfad -> X-IPv64-List
	paths   []string
	cond    int // Anfragen mit If-None-Match
	srv     *httptest.Server
	baseURL string
}

func newListServer(t *testing.T) *listServer {
	ls := &listServer{files: map[string]string{"index.json": testIndex}, status: map[string]int{}, header: map[string]string{}}
	ls.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ls.mu.Lock()
		defer ls.mu.Unlock()
		p := strings.TrimPrefix(r.URL.Path, "/blocklists/")
		ls.paths = append(ls.paths, p)
		if h := ls.header[p]; h != "" {
			w.Header().Set(listHeader, h)
		}
		if st := ls.status[p]; st != 0 {
			w.WriteHeader(st)
			return
		}
		body, ok := ls.files[p]
		if !ok {
			http.NotFound(w, r)
			return
		}
		etag := fmt.Sprintf(`"%x"`, sha256.Sum256([]byte(body)))
		if r.Header.Get("If-None-Match") != "" {
			ls.cond++
		}
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(body))
	}))
	ls.baseURL = ls.srv.URL + "/blocklists/"
	t.Cleanup(ls.srv.Close)
	return ls
}

func (ls *listServer) set(path, body string) {
	ls.mu.Lock()
	ls.files[path] = body
	ls.mu.Unlock()
}

func (ls *listServer) took(path string) bool {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	for _, p := range ls.paths {
		if p == path {
			return true
		}
	}
	return false
}

func newTestHelper(t *testing.T, ls *listServer, be Backend, mod func(*Config)) *Helper {
	t.Helper()
	cfg := Config{Mode: ModeNFTables, Base: ls.baseURL, Backend: be, Version: "test", CacheDir: t.TempDir(),
		HostAddrs: func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("5.6.7.8")} }}
	if mod != nil {
		mod(&cfg)
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestNewValidates(t *testing.T) {
	be := &fakeNFT{}
	if _, err := New(Config{Mode: "iptables", Backend: be}); err == nil {
		t.Fatal("iptables accepted")
	}
	if _, err := New(Config{Mode: ModeNFTables, Backend: be, Token: "short"}); err == nil {
		t.Fatal("bad token accepted")
	}
	if _, err := New(Config{Mode: ModeNFTables, Backend: be, Lists: []string{"../x"}}); err == nil {
		t.Fatal("bad list accepted")
	}
	h, err := New(Config{Mode: ModeNFTables, Backend: be})
	if err != nil || len(h.cfg.Lists) != 1 || h.cfg.Lists[0] != DefaultList || h.cfg.Base != DefaultBase {
		t.Fatal(h.cfg, err)
	}
}

func TestDailyApplyUpdateAndUnchanged(t *testing.T) {
	ls := newListServer(t)
	ls.set("ipv64_blocklist_v64.txt", "# v64\n1.2.3.4\n1.2.3.5\n10.0.0.1\n5.6.7.8\n2a01:4f8::/48\nfd00::1\n")
	be := &fakeNFT{}
	h := newTestHelper(t, ls, be, nil)
	ctx := context.Background()
	if !h.Refresh(ctx) {
		t.Fatal(h.Status())
	}
	if be.applies != 1 || be.updates != 0 {
		t.Fatalf("applies %d updates %d", be.applies, be.updates)
	}
	eqRanges(t, be.v4, rs(t, "1.2.3.4-1.2.3.5")) // privat und eigene Adresse 5.6.7.8 raus
	eqRanges(t, be.v6, rs(t, "2a01:4f8::-2a01:4f8:0:ffff:ffff:ffff:ffff:ffff"))
	if !ls.took("ipv64_blocklist_v64.txt") || ls.took("live/"+testToken+"/ipv64_blocklist_v64.txt") {
		t.Fatal(ls.paths)
	}
	st := h.Status()
	if !st.Active || st.V4 != 1 || st.V6 != 1 || st.Lists[0].Edition != "daily" || st.Lists[0].Entries != 6 || st.Updated.IsZero() || st.Live {
		t.Fatalf("%+v", st)
	}

	// unveraendert: 304, kein Update
	if !h.Refresh(ctx) || be.applies != 1 || be.updates != 0 || ls.cond < 2 {
		t.Fatalf("applies %d updates %d cond %d", be.applies, be.updates, ls.cond)
	}

	// nur IPv4 geaendert: Update nur fuer das IPv4-Set
	ls.set("ipv64_blocklist_v64.txt", "1.2.3.4\n9.9.9.9\n2a01:4f8::/48\n")
	if !h.Refresh(ctx) || be.updates != 1 || !be.upd4 || be.upd6 {
		t.Fatalf("updates %d v4 %v v6 %v", be.updates, be.upd4, be.upd6)
	}
	eqRanges(t, be.v4, rs(t, "1.2.3.4", "9.9.9.9"))

	// Tabelle verschwunden (nft flush ruleset): wieder ganz anlegen
	be.mu.Lock()
	be.exists = false
	be.mu.Unlock()
	ls.set("ipv64_blocklist_v64.txt", "1.2.3.4\n9.9.9.9\n2a01:4f8::/48\n#x\n")
	if !h.Refresh(ctx) || be.applies != 2 {
		t.Fatalf("applies %d", be.applies)
	}

	var buf bytes.Buffer
	w := metrics.New()
	h.WriteMetrics(w)
	_, _ = w.WriteTo(&buf)
	for _, want := range []string{`node64_firewall_entries{family="ipv4"} 2`, `node64_firewall_entries{family="ipv6"} 1`,
		"node64_firewall_last_update_timestamp ", "node64_firewall_errors_total 0", `node64_firewall_list_entries{list="v64",edition="daily"} 3`} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("metrics without %q:\n%s", want, buf.String())
		}
	}
}

func TestLiveWithTokenAndFallback(t *testing.T) {
	ls := newListServer(t)
	ls.set("ipv64_blocklist_v64.txt", "1.1.1.1\n")
	ls.set("live/"+testToken+"/ipv64_blocklist_v64.txt", "1.1.1.1\n2.2.2.2\n")
	ls.set("ipv64_blocklist_feodo.txt", "3.3.3.3\n")
	be := &fakeNFT{}
	h := newTestHelper(t, ls, be, func(c *Config) { c.Token, c.Lists = testToken, []string{"v64", "feodo"} })
	ctx := context.Background()
	if !h.Refresh(ctx) {
		t.Fatal(h.Status())
	}
	eqRanges(t, be.v4, rs(t, "1.1.1.1", "2.2.2.2", "3.3.3.3"))
	st := h.Status()
	if st.Lists[0].Edition != "live" || st.Lists[1].Edition != "daily" || !st.Live {
		t.Fatalf("%+v", st.Lists)
	}
	if ls.took("live/" + testToken + "/ipv64_blocklist_feodo.txt") {
		t.Fatal("feodo live loaded")
	}

	// Token ohne Berechtigung: ipv64 liefert den Tagesstand mit X-IPv64-List: daily
	ls.mu.Lock()
	ls.header["live/"+testToken+"/ipv64_blocklist_v64.txt"] = "daily"
	ls.files["live/"+testToken+"/ipv64_blocklist_v64.txt"] = "1.1.1.1\n"
	ls.mu.Unlock()
	h.Refresh(ctx)
	if st := h.Status(); st.Lists[0].Edition != "daily" || !st.Lists[0].LiveDenied {
		t.Fatalf("%+v", st.Lists[0])
	}

	// widerrufen: 403 -> Tagesstand
	ls.mu.Lock()
	ls.status["live/"+testToken+"/ipv64_blocklist_v64.txt"] = 403
	ls.mu.Unlock()
	if !h.Refresh(ctx) {
		t.Fatal(h.Status())
	}
	st = h.Status()
	if st.Lists[0].Edition != "daily" || st.Lists[0].LiveError != "live: HTTP 403" || st.Lists[0].Error != "" {
		t.Fatalf("%+v", st.Lists[0])
	}
	eqRanges(t, be.v4, rs(t, "1.1.1.1", "3.3.3.3"))

	// Fehler nennen das Token nie
	ls.mu.Lock()
	ls.status["live/"+testToken+"/ipv64_blocklist_v64.txt"] = 500
	ls.mu.Unlock()
	if h.Refresh(ctx) {
		t.Fatal("500 not reported")
	}
	st = h.Status()
	if st.Errors == 0 || strings.Contains(st.LastError, testToken) || st.Lists[0].Error == "" || strings.Contains(st.Lists[0].Error, testToken) {
		t.Fatalf("%+v", st)
	}
	if !st.Active { // Sets bleiben mit dem letzten Stand
		t.Fatal("not active after fetch error")
	}
}

func TestMaskToken(t *testing.T) {
	err := mask(errors.New(`Get "https://ipv64.net/blocklists/live/`+testToken+`/x.txt": timeout`), testToken)
	if strings.Contains(err.Error(), testToken) || !strings.Contains(err.Error(), "live/***/") {
		t.Fatal(err)
	}
}

func TestUnknownListAndNothingLoaded(t *testing.T) {
	ls := newListServer(t)
	be := &fakeNFT{}
	h := newTestHelper(t, ls, be, func(c *Config) { c.Lists = []string{"nope"} })
	if h.Refresh(context.Background()) {
		t.Fatal("unknown list ok")
	}
	st := h.Status()
	if be.applies != 0 || st.Active || st.Lists[0].Error != "list not in index.json" || st.Errors < 2 {
		t.Fatalf("%+v", st)
	}
}

func TestEmptyListSetsUpTable(t *testing.T) {
	ls := newListServer(t)
	ls.set("ipv64_blocklist_v64.txt", "") // v64 ohne Eintraege ist ein gueltiger Stand
	be := &fakeNFT{}
	h := newTestHelper(t, ls, be, nil)
	if !h.Refresh(context.Background()) || be.applies != 1 || len(be.v4)+len(be.v6) != 0 || !h.Status().Active {
		t.Fatalf("applies %d %+v", be.applies, h.Status())
	}
	ls.set("ipv64_blocklist_v64.txt", "1.1.1.1\n")
	if !h.Refresh(context.Background()) || be.updates != 1 {
		t.Fatalf("updates %d", be.updates)
	}
	eqRanges(t, be.v4, rs(t, "1.1.1.1"))
}

func TestUpdateErrorReappliesAndApplyError(t *testing.T) {
	ls := newListServer(t)
	ls.set("ipv64_blocklist_v64.txt", "1.1.1.1\n")
	be := &fakeNFT{}
	h := newTestHelper(t, ls, be, nil)
	ctx := context.Background()
	h.Refresh(ctx)
	ls.set("ipv64_blocklist_v64.txt", "1.1.1.1\n2.2.2.2\n")
	be.failUpd = errors.New("netlink broken")
	if h.Refresh(ctx) {
		t.Fatal("update error not reported")
	}
	be.failUpd = nil
	if !h.Refresh(ctx) || be.applies != 2 {
		t.Fatalf("applies %d", be.applies)
	}
	eqRanges(t, be.v4, rs(t, "1.1.1.1", "2.2.2.2"))

	be2 := &fakeNFT{failApply: errors.New("operation not permitted")}
	h2 := newTestHelper(t, ls, be2, nil)
	if h2.Refresh(ctx) || h2.Status().Active || !strings.Contains(h2.Status().LastError, "not permitted") {
		t.Fatalf("%+v", h2.Status())
	}
}

func TestCacheAfterRestartWithoutNetwork(t *testing.T) {
	ls := newListServer(t)
	ls.set("ipv64_blocklist_v64.txt", "1.1.1.1\n")
	dir := t.TempDir()
	h := newTestHelper(t, ls, &fakeNFT{}, func(c *Config) { c.CacheDir = dir })
	h.Refresh(context.Background())
	ls.srv.Close()

	be := &fakeNFT{}
	h2 := newTestHelper(t, ls, be, func(c *Config) { c.CacheDir = dir })
	h2.loadCache()
	if h2.Refresh(context.Background()) {
		t.Fatal("refresh without server ok")
	}
	eqRanges(t, be.v4, rs(t, "1.1.1.1"))
	if st := h2.Status(); !st.Active || st.Lists[0].Edition != "cache" {
		t.Fatalf("%+v", st)
	}
}

func TestRunRemovesTableOrKeeps(t *testing.T) {
	for _, keep := range []bool{false, true} {
		ls := newListServer(t)
		ls.set("ipv64_blocklist_v64.txt", "1.1.1.1\n")
		be := &fakeNFT{}
		h := newTestHelper(t, ls, be, func(c *Config) { c.Keep = keep })
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { h.Run(ctx); close(done) }()
		deadline := time.Now().Add(5 * time.Second)
		for !h.Status().Active && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
		<-done
		be.mu.Lock()
		removed, exists := be.removes, be.exists
		be.mu.Unlock()
		if keep && (removed != 0 || !exists) {
			t.Fatalf("keep: removes %d exists %v", removed, exists)
		}
		if !keep && (removed != 1 || exists) {
			t.Fatalf("removes %d exists %v", removed, exists)
		}
	}
}

func TestParseIndex(t *testing.T) {
	ix, err := parseIndex([]byte(testIndex))
	if err != nil {
		t.Fatal(err)
	}
	if ix["v64"].Category != catHoneypot || ix["all"].File != "ipv64_blocklist_all.txt" {
		t.Fatal(ix)
	}
	if _, ok := ix["bad"]; ok {
		t.Fatal("bad file accepted")
	}
	if _, err := parseIndex([]byte(`{"lists":[]}`)); err == nil {
		t.Fatal("empty index accepted")
	}
	if e := fallbackEntry("v64_ssh"); e.Category != catHoneypot || e.File != "ipv64_blocklist_v64_ssh.txt" {
		t.Fatal(e)
	}
	if e := fallbackEntry("all"); e.Category != "" {
		t.Fatal(e)
	}
}
