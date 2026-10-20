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
	hpbridge.SetDecoy(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	_ = e.m.hpSave(ctx, HoneypotSettings{Access: true})
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
}
