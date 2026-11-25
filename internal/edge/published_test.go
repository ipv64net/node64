package edge

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Docker-Bridge-Netz: HTTP- und HTTPS-Port gelten als veroeffentlicht, wenn die Pruefanfrage ueber das Gateway beim
// eigenen Eingang ankommt; ein anderes Programm am Port des Hosts zaehlt nicht.
func TestPublished(t *testing.T) {
	e, cfg := newEdge(t, nil)
	if err := e.Set("cdn64", []Route{{Names: []string{"app.test"}, Handler: http.NotFoundHandler(), HTTP3: true}}); err != nil {
		t.Fatal(err)
	}
	oldNet, oldGw, oldDocker, oldWait := bridgeNet, bridgeGateway, pubDockerHost, pubFirstWait
	defer func() { bridgeNet, bridgeGateway, pubDockerHost, pubFirstWait = oldNet, oldGw, oldDocker, oldWait }()
	pubFirstWait = time.Minute                      // ohne gemerktes Ergebnis auf die Pruefung warten
	pubDockerHost = func() string { return "none" } // keine Docker-API: nur die Pruefanfrage zaehlt
	gw := netip.MustParseAddr("127.0.0.1")
	bridgeGateway = func() netip.Addr { return gw }
	ctx := context.Background()

	bridgeNet = func() bool { return false }
	if p := e.Published(ctx); p.Bridge || len(p.Missing) != 0 {
		t.Fatalf("host network: %+v", p)
	}
	bridgeNet = func() bool { return true }
	if p := e.Published(ctx); !p.Bridge || len(p.Missing) != 0 || p.Gateway != "127.0.0.1" ||
		p.PortState(cfg.HTTPPort) != "yes" || p.PortState(cfg.HTTPSPort) != "yes" {
		t.Fatalf("published: %+v", p)
	}

	// Docker-Host ohne die Ports: am Gateway antwortet ein anderes Programm (HTTP) bzw. niemand (HTTPS)
	gw = netip.MustParseAddr("127.0.0.2")
	ln, err := net.Listen("tcp", net.JoinHostPort(gw.String(), strconv.Itoa(cfg.HTTPPort)))
	if err != nil {
		t.Skip("no second loopback address:", err)
	}
	other := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })}
	go func() { _ = other.Serve(ln) }()
	defer other.Close()
	p := e.Published(ctx)
	if len(p.Missing) != 2 || !p.MissingPort(cfg.HTTPPort) || !p.MissingPort(cfg.HTTPSPort) || len(p.Unknown) != 0 ||
		p.PortState(cfg.HTTPSPort) != "no" {
		t.Fatalf("not published: %+v", p)
	}
	h, s := strconv.Itoa(cfg.HTTPPort), strconv.Itoa(cfg.HTTPSPort)
	want := "-p " + h + ":" + h + " -p " + s + ":" + s // nach Port sortiert
	if cfg.HTTPSPort < cfg.HTTPPort {
		want = "-p " + s + ":" + s + " -p " + h + ":" + h
	}
	if a := p.RunArgs(); a != want+" -p "+s+":"+s+"/udp" {
		t.Fatalf("run args: %q", a)
	}
	if c := p.Compose(); !strings.HasPrefix(c, "    ports:\n") || !strings.Contains(c, "      - \""+h+":"+h+"\"\n") || !strings.HasSuffix(c, "/udp\"") {
		t.Fatalf("compose: %q", c)
	}
	// unbekannter Pruefwert: normale Antwort des Eingangs
	resp, err := http.Get("http://127.0.0.1:" + h + probePath + "0123")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		t.Fatal("unknown probe answered as hit")
	}
}

// Docker-Host ohne Hairpin (#243, z. B. UFW auf dem Host): die Pruefanfrage ueber das Gateway bleibt ohne Antwort.
// Ohne Docker-API ist das keine Warnung (nicht pruefbar); mit Docker-API entscheiden die Port-Bindings.
func TestPublishedNoHairpin(t *testing.T) {
	e, cfg := newEdge(t, nil)
	if err := e.Set("cdn64", []Route{{Names: []string{"app.test"}, Handler: http.NotFoundHandler()}}); err != nil {
		t.Fatal(err)
	}
	gw := netip.MustParseAddr("127.0.0.3")
	var hold atomic.Bool // erste Runde: Verbindung annehmen und nie antworten (Zeitueberschreitung), danach gleich trennen
	hold.Store(true)
	var mu sync.Mutex
	var held []net.Conn
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			_ = c.Close()
		}
	}()
	for _, port := range []int{cfg.HTTPPort, cfg.HTTPSPort} {
		ln, err := net.Listen("tcp", net.JoinHostPort(gw.String(), strconv.Itoa(port)))
		if err != nil {
			t.Skip("no third loopback address:", err)
		}
		defer ln.Close()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				if !hold.Load() {
					_ = c.Close()
					continue
				}
				mu.Lock()
				held = append(held, c)
				mu.Unlock()
			}
		}()
	}
	defer BridgeForTest(true, gw)()
	var ports atomic.Pointer[string] // Port-Bindings laut Docker-API (nil = Container unbekannt)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := ports.Load()
		if b == nil || r.URL.Path != "/containers/self/json" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, `{"NetworkSettings":{"Ports":%s}}`, *b)
	}))
	defer api.Close()
	oldDocker, oldSelf := pubDockerHost, pubSelf
	defer func() { pubDockerHost, pubSelf = oldDocker, oldSelf }()
	pubDockerHost = func() string { return api.URL }
	pubSelf = func() (string, error) { return "self", nil }
	ctx := context.Background()
	h, s := strconv.Itoa(cfg.HTTPPort), strconv.Itoa(cfg.HTTPSPort)

	p := e.Published(ctx)
	if len(p.Missing) != 0 || len(p.Unknown) != 2 || p.PortState(cfg.HTTPPort) != "unknown" || p.PortState(cfg.HTTPSPort) != "unknown" || p.RunArgs() != "" {
		t.Fatalf("no hairpin, no docker api: %+v", p)
	}
	hold.Store(false)

	// Docker-API: veroeffentlicht (HTTPS nur an die LAN-Adresse gebunden, #137)
	b := `{"` + h + `/tcp":[{"HostIp":"0.0.0.0","HostPort":"` + h + `"}],"` + s + `/tcp":[{"HostIp":"192.168.1.3","HostPort":"` + s + `"}]}`
	ports.Store(&b)
	e.pub.Store(nil)
	if p := e.Published(ctx); len(p.Missing) != 0 || len(p.Unknown) != 0 || p.PortState(cfg.HTTPPort) != "yes" || p.PortState(cfg.HTTPSPort) != "yes" {
		t.Fatalf("docker api bindings: %+v", p)
	}

	// Docker-API: HTTP fehlt, HTTPS nur an 127.0.0.1 - beides sicher nicht von aussen erreichbar
	lo := `{"` + s + `/tcp":[{"HostIp":"127.0.0.1","HostPort":"` + s + `"}]}`
	ports.Store(&lo)
	e.pub.Store(nil)
	if p := e.Published(ctx); len(p.Missing) != 2 || len(p.Unknown) != 0 || p.PortState(cfg.HTTPSPort) != "no" {
		t.Fatalf("docker api without bindings: %+v", p)
	}
}

// #276: ein abgelaufenes Ergebnis kommt sofort zurueck, die Neupruefung laeuft einmal im Hintergrund (auch bei
// mehreren Seitenaufrufen zugleich); ohne Ergebnis wartet der Aufruf nur kurz und liefert dann "nicht geprueft".
func TestPublishedStale(t *testing.T) {
	e, cfg := newEdge(t, nil)
	if err := e.Set("cdn64", []Route{{Names: []string{"app.test"}, Handler: http.NotFoundHandler()}}); err != nil {
		t.Fatal(err)
	}
	h, s := strconv.Itoa(cfg.HTTPPort), strconv.Itoa(cfg.HTTPSPort)
	bound := `{"` + h + `/tcp":[{"HostIp":"0.0.0.0","HostPort":"` + h + `"}],"` + s + `/tcp":[{"HostIp":"0.0.0.0","HostPort":"` + s + `"}]}`
	var calls atomic.Int32
	var ports atomic.Pointer[string]
	ports.Store(&bound)
	gate := make(chan struct{}) // Docker-API antwortet erst, wenn geschlossen
	close(gate)
	var gateMu sync.Mutex
	asked := make(chan struct{}, 10)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		asked <- struct{}{}
		gateMu.Lock()
		g := gate
		gateMu.Unlock()
		<-g
		fmt.Fprintf(w, `{"NetworkSettings":{"Ports":%s}}`, *ports.Load())
	}))
	defer api.Close()
	defer BridgeForTest(true, netip.Addr{})() // ohne Gateway: nur die Docker-API (eine Anfrage je Pruefung)
	oldDocker, oldSelf := pubDockerHost, pubSelf
	defer func() { pubDockerHost, pubSelf = oldDocker, oldSelf }()
	pubDockerHost = func() string { return api.URL }
	pubSelf = func() (string, error) { return "self", nil }
	ctx := context.Background()

	if p := e.Published(ctx); p.PortState(cfg.HTTPSPort) != "yes" || calls.Load() != 1 {
		t.Fatalf("first: %+v (%d calls)", p, calls.Load())
	}
	<-asked

	// Ergebnis abgelaufen, die Docker-API haengt und meldet danach fehlende Ports
	c := e.pub.Load()
	old := *c
	old.res.At = time.Now().Add(-2 * probeTTL)
	e.pub.Store(&old)
	none := `{}`
	ports.Store(&none)
	gateMu.Lock()
	gate = make(chan struct{})
	held := gate
	gateMu.Unlock()
	start := time.Now()
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if p := e.Published(ctx); p.PortState(cfg.HTTPSPort) != "yes" || len(p.Missing) != 0 {
				t.Errorf("stale result not returned: %+v", p)
			}
		}()
	}
	wg.Wait()
	if d := time.Since(start); d > time.Second {
		t.Errorf("stale result took %v", d)
	}
	select {
	case <-asked:
	case <-time.After(5 * time.Second):
		t.Fatal("no refresh in the background")
	}
	if p := e.Published(ctx); p.PortState(cfg.HTTPSPort) != "yes" || calls.Load() != 2 {
		t.Fatalf("during refresh: %+v (%d calls)", p, calls.Load())
	}
	close(held)
	deadline := time.Now().Add(5 * time.Second)
	for e.Published(ctx).PortState(cfg.HTTPSPort) != "no" {
		if time.Now().After(deadline) {
			t.Fatal("refreshed result not stored")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("refresh ran %d times", n)
	}

	// kein gemerktes Ergebnis und eine haengende Pruefung: nach kurzer Wartezeit leer, ohne Warnung
	gateMu.Lock()
	gate = make(chan struct{})
	held = gate
	gateMu.Unlock()
	defer func() { // Pruefung im Hintergrund beenden, bevor die Testwerte zurueckgesetzt werden
		e.pubMu.Lock()
		run := e.pubRun
		e.pubMu.Unlock()
		close(held)
		if run != nil {
			<-run
		}
	}()
	e.pub.Store(nil)
	pubFirstWait = 50 * time.Millisecond
	start = time.Now()
	if p := e.Published(ctx); !p.Bridge || len(p.Missing) != 0 || len(p.Found) != 0 || p.PortState(cfg.HTTPSPort) != "" {
		t.Fatalf("unchecked: %+v", p)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("first call took %v", d)
	}
}

// pubBound: Loopback zaehlt nicht, HTTPS darf unter dem Port nach aussen veroeffentlicht sein (-p 8443:443).
func TestPubBound(t *testing.T) {
	b := map[string][]pubBinding{"443/tcp": {{HostIP: "127.0.0.1", HostPort: "443"}, {HostIP: "::ffff:127.0.0.1", HostPort: "443"}, {HostIP: "", HostPort: "8443"}}}
	if pubBound(b, 443, 443) || !pubBound(b, 443, 443, 8443) || pubBound(b, 80, 80) || pubBound(nil, 443, 443) {
		t.Fatalf("pubBound: %+v", b)
	}
}
