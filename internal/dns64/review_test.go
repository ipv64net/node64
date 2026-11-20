package dns64

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/dns64/upstream"
)

// Neustart (neue Einstellungen) und Abschalten gleichzeitig: am Ende ist das Modul aus und der Port frei.
func TestRestartVersusStop(t *testing.T) {
	m, port := testModule(t)
	ctx := context.Background()
	for round := 0; round < 5; round++ {
		if err := m.Start(ctx); err != nil || m.running() == nil {
			t.Fatalf("start: %v %s", err, m.startError())
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = m.restart(ctx) }()
		go func() {
			defer wg.Done()
			sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			_ = m.Stop(sctx)
		}()
		wg.Wait()
		// Stop vor dem Neustart: der Neustart sieht das Modul aus; Stop danach: stoppt den neu gestarteten Dienst
		if m.running() != nil {
			t.Fatalf("round %d: dns service still running after stop", round)
		}
		m.mu.Lock()
		on := m.life != nil
		m.mu.Unlock()
		if on {
			t.Fatal("module still on")
		}
		pc, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("round %d: port still bound: %v", round, err)
		}
		pc.Close()
	}
}

func TestConfigAddRemove(t *testing.T) {
	m, _ := testModule(t)
	c := m.loadConfig(context.Background())
	s := upstream.Server{Name: "Test", URL: "tls://dns.example", IPs: []string{"192.0.2.1"}}
	if err := c.addUpstream(s); err != nil {
		t.Fatal(err)
	}
	if err := c.addUpstream(s); err == nil {
		t.Fatal("duplicate upstream accepted")
	}
	if err := c.addList("Eigene", "https://lists.example/hosts.txt"); err != nil {
		t.Fatal(err)
	}
	if err := c.addList("", "ftp://x"); err == nil {
		t.Fatal("invalid list url accepted")
	}
	if c.removeCustom(upstream.Presets[0].URL) {
		t.Fatal("preset removed")
	}
	if !c.removeCustom("tls://dns.example") || !c.removeCustom("https://lists.example/hosts.txt") {
		t.Fatal("custom entries not removed")
	}
}

// Listen und Upstreams: Haken und Loeschen meinen die Zeile nach URL, nicht nach Position - hat sich die Liste
// inzwischen geaendert (Cluster, zweiter Tab), trifft es sonst die falsche Liste.
func TestFormSwitchByURL(t *testing.T) {
	post := func(v url.Values) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/dns64/lists", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}
	// Formular mit B (aus) und C (an); in der Konfiguration steht inzwischen A davor
	r := post(url.Values{"url_0": {"https://b"}, "url_1": {"https://c"}, "on_1": {"1"}})
	sw := formSwitch(r, "")
	cfg := []listSetting{{URL: "https://a", Enabled: true}, {URL: "https://b", Enabled: true}, {URL: "https://c"}}
	for i := range cfg {
		if on, ok := sw(i, cfg[i].URL); ok {
			cfg[i].Enabled = on
		}
	}
	if !cfg[0].Enabled || cfg[1].Enabled || !cfg[2].Enabled {
		t.Fatalf("switches by url: %+v", cfg)
	}
	// Seite einer aelteren Version (ohne URL-Felder): Position
	old := formSwitch(post(url.Values{"on_1": {"1"}}), "")
	if on, ok := old(0, "x"); on || !ok {
		t.Fatal("old page row 0")
	}
	if on, ok := old(1, "y"); !on || !ok {
		t.Fatal("old page row 1")
	}
	// Freigabe-Listen mit eigenem Praefix
	if on, ok := formSwitch(post(url.Values{"aurl_0": {"https://f"}, "aon_0": {"1"}}), "a")(5, "https://f"); !on || !ok {
		t.Fatal("allow list switch")
	}
	// Loeschen: URL, sonst Zahl (alte Seite), unbekannte URL trifft nichts
	if i := formIndex(post(url.Values{"remove": {"https://c"}}), "remove", cfg, listURL); i != 2 {
		t.Fatalf("remove by url: %d", i)
	}
	if i := formIndex(post(url.Values{"remove": {"1"}}), "remove", cfg, listURL); i != 1 {
		t.Fatalf("remove by position: %d", i)
	}
	if i := formIndex(post(url.Values{"remove": {"https://weg"}}), "remove", cfg, listURL); i != -1 {
		t.Fatalf("remove unknown url: %d", i)
	}
}

// Jeder Text, den dns64.js mit t("...") holt, steht in jsKeys - sonst zeigt die Seite den rohen Schluessel.
func TestJSKeysComplete(t *testing.T) {
	js, err := os.ReadFile("../web/static/js/dns64.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range regexp.MustCompile(`\bt\("([^"]+)"`).FindAllStringSubmatch(string(js), -1) {
		k := m[1]
		if strings.HasSuffix(k, ".") || strings.HasSuffix(k, "_") { // Praefix, Rest kommt dazu (t("status." + s))
			continue
		}
		if !slices.Contains(jsKeys, k) {
			t.Errorf("dns64.js uses %q, missing in jsKeys", k)
		}
	}
}
