package honeypot

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/hpbridge"
)

// bridgeCapture sammelt Ereignisse (thread-sicher).
type bridgeCapture struct {
	mu sync.Mutex
	ev []Event
}

func (c *bridgeCapture) sink(e Event) {
	c.mu.Lock()
	c.ev = append(c.ev, e)
	c.mu.Unlock()
}

func (c *bridgeCapture) list() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Event(nil), c.ev...)
}

func bridgeReset() { bridgeCounts.lastDecoy.Store(0) }

func TestBridgeDecoy(t *testing.T) {
	bridgeReset()
	var c bridgeCapture
	d := newBridgeDecoy(nil, c.sink, "")

	r := httptest.NewRequest(http.MethodPost, "/wp-login.php", strings.NewReader("log=admin&pwd=geheim"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "198.51.100.7:4444"
	r.Host = "192.0.2.10"
	w := httptest.NewRecorder()
	d.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Invalid username or password") {
		t.Fatalf("antwort %d: %s", w.Code, w.Body.String())
	}
	ev := c.list()
	if len(ev) != 1 {
		t.Fatalf("ereignisse: %+v", ev)
	}
	e := ev[0]
	if e.Kind != KindHTTPBrute || e.Username != "admin" || e.Password != "geheim" || e.Service != SvcHTTP || e.Port != 80 ||
		e.Src != netip.MustParseAddr("198.51.100.7") || e.SrcPort != 4444 || storeSource(e.Source) != SrcHoneypot {
		t.Fatalf("ereignis: %+v", e)
	}
	if !strings.HasPrefix(e.Detail, bridgeDetail) {
		t.Fatalf("detail %q", e.Detail)
	}
	if r.RemoteAddr != "198.51.100.7:4444" {
		t.Fatal("anfrage des aufrufers veraendert")
	}

	// TLS, Port aus Host, Quelle ohne Port
	r = httptest.NewRequest(http.MethodGet, "/.env", nil)
	r.TLS = &tls.ConnectionState{ServerName: "x"}
	r.Host = "192.0.2.10:8443"
	r.RemoteAddr = "2001:db8::5"
	w = httptest.NewRecorder()
	d.ServeHTTP(w, r)
	ev = c.list()
	if len(ev) != 2 {
		t.Fatalf("ereignisse: %+v", ev)
	}
	e = ev[1]
	if e.Service != SvcHTTPS || e.Port != 8443 || e.Kind != KindHTTPExploit || e.Src != netip.MustParseAddr("2001:db8::5") ||
		!strings.Contains(e.Detail, bridgeDetail) || w.Code != http.StatusForbidden {
		t.Fatalf("ereignis: %+v (code %d)", e, w.Code)
	}
	if !bridgeDecoyUsed(time.Now()) {
		t.Fatal("koeder nicht als genutzt vermerkt")
	}
}

// bridgeEngine ist eine Engine nur mit den proxy64-Regeln und fester Uhr.
func bridgeEngine(t *testing.T, c *bridgeCapture) *logEngine {
	t.Helper()
	var rules []*LogRule
	for _, r := range LogRules() {
		if strings.HasPrefix(r.ID, "proxy64/") {
			rules = append(rules, r)
		}
	}
	if len(rules) != 5 {
		t.Fatalf("proxy64-regeln: %d", len(rules))
	}
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	e := newLogEngine(nil, rules, func() time.Time { return now })
	e.setSink(c.sink)
	return e
}

func TestBridgeAccessRules(t *testing.T) {
	ts := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	acc := func(ip string, f func(a *hpbridge.Access)) hpbridge.Access {
		a := hpbridge.Access{Time: ts, Src: netip.MustParseAddr(ip), Host: "app.example.org", Known: true, Method: "GET", Path: "/", Status: 200, TLS: true}
		if f != nil {
			f(&a)
		}
		return a
	}
	cases := []struct {
		name string
		a    hpbridge.Access
		n    int    // so oft einspeisen
		at   int    // Ereignis beim n-ten Mal (0 = keins)
		rule string // erwartete Regel
		kind string
	}{
		{"scan", acc("8.8.4.4", func(a *hpbridge.Access) { a.Path, a.Status = "/nix", 404 }), 30, 30, "proxy64/scan@1", KindHTTPScan},
		{"scan unter schwelle", acc("8.8.4.5", func(a *hpbridge.Access) { a.Path, a.Status = "/nix", 404 }), 29, 0, "", ""},
		{"exploit stark", acc("8.8.4.6", func(a *hpbridge.Access) { a.Path, a.Status = "/.env", 404 }), 1, 1, "proxy64/exploit@1", KindHTTPExploit},
		{"exploit ausgeliefert", acc("8.8.4.7", func(a *hpbridge.Access) { a.Path = "/.env" }), 3, 0, "", ""},
		{"exploit schwach", acc("8.8.4.8", func(a *hpbridge.Access) { a.Path, a.Status = "/xmlrpc.php", 403 }), 3, 3, "proxy64/exploit@1", KindHTTPExploit},
		{"exploit fremder host", acc("8.8.4.9", func(a *hpbridge.Access) { a.Path, a.Known, a.Status = "/.git/config", false, 421 }), 1, 1, "proxy64/exploit@1", KindHTTPExploit},
		{"bad ua", acc("8.8.5.1", func(a *hpbridge.Access) { a.UA = "sqlmap/1.7" }), 3, 3, "proxy64/bad-useragent@1", KindBadUA},
		{"auth", acc("8.8.5.2", func(a *hpbridge.Access) { a.Method, a.Path, a.Status, a.AuthFail = "POST", "/login", 401, true }), 10, 10, "proxy64/auth@1", KindHTTPBrute},
		{"unknown host", acc("8.8.5.3", func(a *hpbridge.Access) { a.Known, a.Host, a.Status = false, "1.2.3.4", 421 }), 5, 5, "proxy64/unknown-host@1", KindHTTPScan},
		{"normal", acc("8.8.5.4", nil), 50, 0, "", ""},
		{"privat zaehlt lokal", acc("192.168.1.9", func(a *hpbridge.Access) { a.UA = "nuclei" }), 3, 3, "proxy64/bad-useragent@1", KindBadUA},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c bridgeCapture
			e := bridgeEngine(t, &c)
			for i := 1; i <= tc.n; i++ {
				e.feed(proxyLine(tc.a))
				got := c.list()
				if i < tc.at || tc.at == 0 {
					if len(got) != 0 {
						t.Fatalf("zu frueh bei %d: %+v", i, got)
					}
					continue
				}
				if i == tc.at {
					if len(got) != 1 || got[0].Rule != tc.rule || got[0].Kind != tc.kind || got[0].Src != tc.a.Src ||
						got[0].Source != SrcLog || got[0].Path != "" || got[0].UA != "" || got[0].Detail != strings.TrimSuffix(tc.rule, "@1") {
						t.Fatalf("bei %d: %+v", i, got)
					}
					if got[0].Port != 443 {
						t.Fatalf("port %d", got[0].Port)
					}
				}
			}
		})
	}
}

func TestBridgeAccessFeed(t *testing.T) {
	bridgeReset()
	var c bridgeCapture
	ls := NewLogSensor(slog.Default())
	ls.Apply(context.Background(), LogConfig{}, c.sink)
	defer ls.Stop()
	a := hpbridge.Access{Src: netip.MustParseAddr("9.9.9.9"), Host: "1.2.3.4", Known: false, Method: "GET", Path: "/", Status: 421}
	for range 5 {
		bridgeAccess(ls.FeedLine, a)
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(c.list()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if ev := c.list(); len(ev) != 1 || ev[0].Rule != "proxy64/unknown-host@1" {
		t.Fatalf("ereignisse: %+v", ev)
	}

	// Koeder genutzt: Zugriffe auf fremde Hosts zaehlt der Koeder, nicht die Regel
	bridgeCounts.lastDecoy.Store(time.Now().UnixNano())
	defer bridgeReset()
	before := ls.Status().Lines
	for range 5 {
		bridgeAccess(ls.FeedLine, a)
	}
	bridgeAccess(ls.FeedLine, hpbridge.Access{Src: a.Src, Known: true, Path: "/", Status: 200})
	deadline = time.Now().Add(3 * time.Second)
	for ls.Status().Lines < before+1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if got := ls.Status().Lines - before; got != 1 {
		t.Fatalf("eingespeist %d, erwartet 1", got)
	}

	// gestoppt: verwerfen
	ls.Stop()
	if ls.FeedLine(proxyLine(a)) {
		t.Fatal("FeedLine nach Stop angenommen")
	}
}

func TestBridgeBlocks(t *testing.T) {
	var mu sync.Mutex
	var got []hpbridge.Block
	cancel := hpbridge.SubscribeBlocks(func(b hpbridge.Block) {
		mu.Lock()
		got = append(got, b)
		mu.Unlock()
	})
	defer cancel()
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	b := &bridgeBlocker{now: func() time.Time { return now }, sent: map[netip.Addr]time.Time{}}
	ev := func(ip, kind, rule string) Event {
		return Event{Src: netip.MustParseAddr(ip), Kind: kind, Rule: rule}
	}
	cases := []struct {
		e    Event
		want bool
	}{
		{ev("8.8.8.8", KindSSHBrute, ""), true},
		{ev("8.8.8.8", KindHTTPExploit, ""), false}, // gedrosselt
		{ev("8.8.8.9", KindHTTPSQLi, ""), true},
		{ev("8.8.8.10", KindDBExploit, ""), true},
		{ev("8.8.8.11", KindPortScan, ""), true},
		{ev("8.8.8.12", KindBadUA, ""), true},
		{ev("8.8.8.13", KindSIPScan, ""), false}, // UDP: Quelle faelschbar, keine Sofort-Sperre
		{ev("8.8.8.13", KindSIPBrute, ""), false},
		{ev("8.8.8.13", KindSNMPBrute, ""), false},
		{ev("8.8.8.14", KindMailBrute, "postfix/sasl-bruteforce@1"), true},
		{ev("8.8.8.15", KindProbe, ""), false},
		{ev("8.8.8.16", KindHTTPScan, ""), false},
		{ev("8.8.8.17", KindHTTPScan, "nginx/scan@1"), false},
		{ev("8.8.8.18", KindHTTPScan, "proxy64/scan@1"), true},
		{ev("8.8.8.19", KindScannerResch, ""), false},
		{ev("192.168.1.5", KindSSHBrute, ""), false},
		{ev("127.0.0.1", KindSSHBrute, ""), false},
		{ev("10.1.2.3", KindHTTPExploit, "proxy64/exploit@1"), false},
		{ev("::ffff:8.8.8.8", KindSSHBrute, ""), false}, // gleiche IP (gemappt), gedrosselt
	}
	for i, tc := range cases {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		b.check(tc.e)
		mu.Lock()
		published := len(got) > n
		var last hpbridge.Block
		if published {
			last = got[len(got)-1]
		}
		mu.Unlock()
		if published != tc.want {
			t.Fatalf("fall %d (%s %s): gemeldet=%v", i, tc.e.Src, tc.e.Kind, published)
		}
		if published && (last.IP != tc.e.Src.Unmap() || last.Reason != tc.e.Kind || !last.Until.Equal(now.Add(bridgeBlockFor))) {
			t.Fatalf("fall %d: %+v", i, last)
		}
	}
	now = now.Add(bridgeBlockEvery)
	b.check(ev("8.8.8.8", KindSSHBrute, ""))
	mu.Lock()
	last := got[len(got)-1]
	mu.Unlock()
	if last.IP != netip.MustParseAddr("8.8.8.8") || !last.Until.Equal(now.Add(bridgeBlockFor)) {
		t.Fatalf("nach einer stunde nicht erneut gemeldet: %+v", last)
	}

	// Obergrenze der Drossel
	b2 := &bridgeBlocker{now: func() time.Time { return now }, sent: map[netip.Addr]time.Time{}}
	base := netip.MustParseAddr("8.0.0.0")
	a := base
	for range bridgeBlockMax + 5 {
		a = a.Next()
		b2.check(Event{Src: a, Kind: KindSSHBrute})
	}
	if len(b2.sent) > bridgeBlockMax {
		t.Fatalf("drossel zu gross: %d", len(b2.sent))
	}
}

func TestBridgeModuleStartStop(t *testing.T) {
	bridgeReset()
	m, _ := modTest(t, modFreePort(t))
	var c bridgeCapture
	m.sink = bridgeBlockSink(c.sink)
	m.newLogs = func(log *slog.Logger) logSensorAPI { return NewLogSensor(log) }
	var mu sync.Mutex
	var blocks []hpbridge.Block
	cancel := hpbridge.SubscribeBlocks(func(b hpbridge.Block) {
		mu.Lock()
		blocks = append(blocks, b)
		mu.Unlock()
	})
	defer cancel()

	if hpbridge.Decoy() != nil || hpbridge.AccessActive() {
		t.Fatal("vor dem Start angemeldet")
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if hpbridge.Decoy() == nil || !hpbridge.AccessActive() {
		t.Fatal("nach dem Start nicht angemeldet")
	}
	if !hpbridge.Wanted() { // Voreinstellung "Nur ueber PROXY64": PROXY64 soll seine Anfragen abgeben
		t.Fatal("Vorlage proxy meldet sich nicht bei PROXY64")
	}
	if !hpbridge.BlockWanted() || !hpbridge.Blockers() { // Sofort-Sperre: Standard an (auch ohne Meldung an ipv64)
		t.Fatal("Sofort-Sperre nicht gewuenscht")
	}
	// Koeder ohne eigene Fallen-Dienste (Einstellung nie gespeichert)
	r := httptest.NewRequest(http.MethodGet, "/phpmyadmin/?pma_username=root&pma_password=toor", nil)
	r.RemoteAddr = "8.8.8.8:5555"
	hpbridge.Decoy().ServeHTTP(httptest.NewRecorder(), r)
	bridgeReset() // Koeder gilt sonst als genutzt
	// Zugriffe: 30 x 404 auf eingerichtetem Host
	for range 30 {
		hpbridge.Report(hpbridge.Access{Src: netip.MustParseAddr("9.9.9.9"), Known: true, Path: "/x", Status: 404})
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(c.list()) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	ev := c.list()
	if len(ev) != 2 || ev[0].Kind != KindHTTPBrute || !strings.Contains(ev[0].Detail, bridgeDetail) || ev[1].Rule != "proxy64/scan@1" {
		t.Fatalf("ereignisse: %+v", ev)
	}
	mu.Lock()
	nb := len(blocks)
	mu.Unlock()
	if nb != 2 {
		t.Fatalf("sperren: %+v", blocks)
	}
	if v := (overviewData{}).Proxy64(); !v.Connected || v.Decoy < 1 || v.Access < 30 || v.Blocks < 2 {
		t.Fatalf("uebersicht: %+v", v)
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if hpbridge.Decoy() != nil || hpbridge.AccessActive() || hpbridge.Wanted() || hpbridge.BlockWanted() {
		t.Fatal("nach dem Stop noch angemeldet")
	}
}
