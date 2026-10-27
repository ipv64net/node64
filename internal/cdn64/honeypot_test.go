package cdn64

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/hpbridge"
)

// Unbekannte Anfragen: an den Koeder (Schalter an, Honeypot da), sonst Standardseite; Zugriffe werden gemeldet.
func TestHoneypotDecoyAndAccess(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "app") }))
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)
	bport, _ := strconv.Atoi(bu.Port())
	certPEM, keyPEM := selfSigned(t, "app.test")
	if _, err := e.crt.Upload(ctx, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	e.enable(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort = []string{"app.test"}, "127.0.0.1", bport
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []hpbridge.Access
	var decoyAddr, decoyHost string
	hpbridge.SetDecoy(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		decoyAddr, decoyHost = r.RemoteAddr, r.Host
		mu.Unlock()
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, "decoy")
	}))
	hpbridge.SetAccessSink(func(a hpbridge.Access) { mu.Lock(); got = append(got, a); mu.Unlock() })
	t.Cleanup(func() { hpbridge.SetDecoy(nil); hpbridge.SetAccessSink(nil) })
	c := e.client(false)

	// alles aus: Standardseite, nichts gemeldet
	if code, _, _ := do(t, c, "GET", "https://fremd.example/x?a=1"); code != http.StatusNotFound {
		t.Fatalf("off: %d", code)
	}
	if err := e.m.hpSave(ctx, HoneypotSettings{Decoy: true, Access: true}); err != nil {
		t.Fatal(err)
	}
	if code, body, _ := do(t, c, "GET", "https://fremd.example/x?a=1"); code != http.StatusTeapot || body != "decoy" {
		t.Fatalf("decoy: %d %q", code, body)
	}
	if code, body, _ := do(t, c, "GET", "http://fremd.example/wp-login.php"); code != http.StatusTeapot || body != "decoy" {
		t.Fatalf("decoy on port 80: %d %q", code, body)
	}
	if code, body, _ := do(t, c, "GET", "https://app.test/login"); code != http.StatusOK || body != "app" {
		t.Fatalf("known host: %d %q", code, body)
	}
	mu.Lock()
	if ap, err := netip.ParseAddrPort(decoyAddr); err != nil || !ap.Addr().IsLoopback() || ap.Port() == 0 || decoyHost != "fremd.example" {
		t.Fatalf("decoy request: remote %q host %q", decoyAddr, decoyHost)
	}
	if len(got) != 3 || !got[2].Known || got[2].Host != "app.test" || got[2].Status != http.StatusOK || got[0].Known || got[0].Path != "/x" || got[0].Status != http.StatusTeapot || !got[0].TLS || got[0].Host != "fremd.example" ||
		got[1].TLS || got[1].Path != "/wp-login.php" {
		t.Fatalf("access: %+v", got)
	}
	mu.Unlock()

	// Standard "schliessen": mit aktivem Koeder trotzdem TLS fuer unbekannte Namen
	cfg := e.cfg
	cfg.Default = edge.DefaultClose
	if err := e.edge.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := do(t, c, "GET", "https://anders.example/"); code != http.StatusTeapot {
		t.Fatalf("decoy with default close: %d", code)
	}
	if !e.edge.Status().UnknownReplaced || !e.m.hpView().DefaultClose {
		t.Fatal("settings must show that the decoy replaces the default page (close)")
	}
	_ = e.m.hpSave(ctx, HoneypotSettings{Access: true})
	if e.edge.Status().UnknownReplaced {
		t.Fatal("without decoy the default page applies again")
	}
	c2 := e.client(false) // neue Verbindung: jetzt ohne Koeder wieder ohne TLS
	if _, err := c2.Get("https://anders.example/"); err == nil {
		t.Fatal("without decoy an unknown name must be refused again (default close)")
	}
}

// Sofort-Sperre: Uebernahme aus dem Honeypot, Ausnahmen, Ablauf, Aufheben, Abschalten.
func TestHoneypotBlock(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	m := e.m
	bad, lan := netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("192.168.1.9")
	hpbridge.PublishBlock(hpbridge.Block{IP: bad, Reason: "ssh:bruteforce"})
	if m.hpBlocked(bad) {
		t.Fatal("switch off: no block")
	}
	if err := m.hpSave(ctx, HoneypotSettings{Block: true, BlockHours: 2}); err != nil {
		t.Fatal(err)
	}
	hpbridge.PublishBlock(hpbridge.Block{IP: bad, Reason: "ssh:bruteforce"})
	hpbridge.PublishBlock(hpbridge.Block{IP: lan, Reason: "http:scan"})
	hpbridge.PublishBlock(hpbridge.Block{IP: netip.MustParseAddr("100.64.1.1"), Reason: "x"}) // CGNAT
	if !m.hpBlocked(bad) || !m.blockedAny(bad) || m.hpBlocked(lan) {
		t.Fatal("block: public blocked, private never")
	}
	list := m.hpList()
	if len(list) != 1 || list[0].IP != bad.String() || list[0].Reason != "ssh:bruteforce" || time.Until(list[0].Until) < time.Hour {
		t.Fatalf("list: %+v", list)
	}
	// Neustart: die Liste kommt aus cdn_hp_blocks zurueck
	m.hp.mu.Lock()
	m.hp.m = nil
	m.hp.mu.Unlock()
	m.hpRestore(ctx)
	if l := m.hpList(); len(l) != 1 || l[0].IP != bad.String() || l[0].Reason != "ssh:bruteforce" || !m.hpBlocked(bad) {
		t.Fatalf("restored: %+v", l)
	}
	if !m.hpUnblock(bad.String()) || m.hpBlocked(bad) {
		t.Fatal("unblock")
	}
	hpbridge.PublishBlock(hpbridge.Block{IP: bad, Reason: "again"})
	_ = m.hpSave(ctx, HoneypotSettings{}) // Sperre aus: Liste leer
	if len(m.hpList()) != 0 || m.hpBlocked(bad) {
		t.Fatal("switching off must clear the list")
	}
	if err := m.hpSave(ctx, HoneypotSettings{Block: true, BlockHours: 1000}); err == nil {
		t.Fatal("hours out of range")
	}
	m.hpRestore(ctx)
	if len(m.hpList()) != 0 {
		t.Fatal("switching off must clear the saved list")
	}
	// Schalter im Honeypot (Standard an): sperrt ohne eigenen Schalter, Abschalten hier leert die Liste dann nicht
	hpbridge.SetBlockWanted(true)
	defer hpbridge.SetBlockWanted(false)
	hpbridge.PublishBlock(hpbridge.Block{IP: bad, Reason: "http:exploit"})
	if !m.hpBlocked(bad) || !m.hpView().BlockWanted {
		t.Fatal("block wanted by honeypot")
	}
	_ = m.hpSave(ctx, HoneypotSettings{})
	if !m.hpBlocked(bad) {
		t.Fatal("honeypot switch keeps the list")
	}
	if !m.hpUnblock(bad.String()) {
		t.Fatal("unblock")
	}
	m.hpRestore(ctx)
	if m.hpBlocked(bad) {
		t.Fatal("unblock must remove the saved entry")
	}
}

// Als schaedlich erkannte Anfragen gehen mit Koeder und Weg an den Honeypot statt 403; Ueberlast nie; der Eingang
// laesst gesperrte IPs dafuer durch, Durchreichen trennt sie weiter; Vorlage "Nur ueber PROXY64" schaltet den Koeder an.
func TestHoneypotRoute(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.m.SetDataDir(t.TempDir()) // Statistik (cdn64.db)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "app") }))
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)
	bport, _ := strconv.Atoi(bu.Port())
	certPEM, keyPEM := selfSigned(t, "app.test")
	if _, err := e.crt.Upload(ctx, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	e.enable(t)
	m := e.m
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.BlockExploits = []string{"app.test"}, "127.0.0.1", bport, true
	if err := m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hpbridge.SetDecoy(nil); hpbridge.SetWanted(false) })
	c := e.client(false)
	exploit := "https://app.test/index.php?file=../../../../etc/passwd"

	// ohne Honeypot: 403 wie bisher
	if code, _, _ := do(t, c, "GET", exploit); code != http.StatusForbidden {
		t.Fatalf("no honeypot: %d", code)
	}
	hpbridge.SetDecoy(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, "decoy")
	}))
	// Koeder-Schalter aus und keine Vorlage "proxy": weiter 403
	if code, _, _ := do(t, c, "GET", exploit); code != http.StatusForbidden {
		t.Fatalf("decoy off: %d", code)
	}
	// Vorlage "Nur ueber PROXY64": Koeder gilt als an, Standard-Wege (Exploit an)
	hpbridge.SetWanted(true)
	if code, body, _ := do(t, c, "GET", exploit); code != http.StatusTeapot || body != "decoy" {
		t.Fatalf("proxy only: %d %q", code, body)
	}
	if code, body, _ := do(t, c, "GET", "https://app.test/ok"); code != http.StatusOK || body != "app" {
		t.Fatalf("normal request: %d %q", code, body)
	}
	// Statistik: die umgeleitete Anfrage zaehlt "an den Honeypot", nicht als abgewiesen oder 4xx
	if sdb := m.stats2.Load(); sdb == nil {
		t.Fatal("stats db not open")
	} else {
		var hs HostStat
		for i := 0; i < 60; i++ {
			sums, _ := sdb.sums(ctx, time.Now().Add(-2*time.Hour))
			if hs = sums[h.ID]; hs.Decoy > 0 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		// davor: zwei 403 der Exploit-Sperre (ohne Honeypot bzw. Koeder aus) = abgewiesen, nicht 4xx
		if hs.Decoy != 1 || hs.Blocked != 2 || hs.S4 != 0 || hs.S2 != 1 {
			t.Fatalf("stats: %+v", hs)
		}
	}
	// Weg Exploit aus: wieder 403
	off := hpDefaultRoute()
	off.Exploit = false
	if err := m.hpSave(ctx, HoneypotSettings{Route: &off}); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := do(t, c, "GET", exploit); code != http.StatusForbidden {
		t.Fatalf("route off: %d", code)
	}

	// Eingang: gesperrte IP mit Weg durchlassen, ohne Weg/Koeder trennen; Ueberlast und Streams immer trennen
	bad := netip.MustParseAddr("203.0.113.7")
	if err := m.hpSave(ctx, HoneypotSettings{Block: true, BlockHours: 1}); err != nil { // Route nil = Standard
		t.Fatal(err)
	}
	hpbridge.PublishBlock(hpbridge.Block{IP: bad, Reason: "ssh:bruteforce"})
	if !m.hpBlocked(bad) || m.blockedAny(bad) || !m.connBlocked(bad, "stream :25565") {
		t.Fatal("web entrance must let the reported IP through to the decoy, streams must not")
	}
	// Durchreichen: TLS gehoert dem Ziel, kein Koeder - Verbindung trennen
	p := newHostKind(KindPass)
	p.Names, p.TargetHost, p.TargetPort = []string{"pass.test"}, "127.0.0.1", bport
	if rt := m.routeFor(p); rt.Allow == nil || rt.Allow(bad) || !rt.Allow(netip.MustParseAddr("198.51.100.20")) {
		t.Fatal("passthrough must reject blocked IPs itself")
	}
	hpbridge.SetWanted(false) // Koeder aus: Eingang trennt wieder
	if !m.blockedAny(bad) {
		t.Fatal("without decoy the entrance must reject")
	}
	if s := m.hpSettings(); s.Route == nil || !s.Route.Blocklist || !s.Route.Honeypot || s.Route.Geo {
		t.Fatalf("default route: %+v", s.Route)
	}
}
