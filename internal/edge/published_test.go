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
)

// Docker-Bridge-Netz: HTTP- und HTTPS-Port gelten als veroeffentlicht, wenn die Pruefanfrage ueber das Gateway beim
// eigenen Eingang ankommt; ein anderes Programm am Port des Hosts zaehlt nicht.
func TestPublished(t *testing.T) {
	e, cfg := newEdge(t, nil)
	if err := e.Set("cdn64", []Route{{Names: []string{"app.test"}, Handler: http.NotFoundHandler(), HTTP3: true}}); err != nil {
		t.Fatal(err)
	}
	oldNet, oldGw, oldDocker := bridgeNet, bridgeGateway, pubDockerHost
	defer func() { bridgeNet, bridgeGateway, pubDockerHost = oldNet, oldGw, oldDocker }()
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

// pubBound: Loopback zaehlt nicht, HTTPS darf unter dem Port nach aussen veroeffentlicht sein (-p 8443:443).
func TestPubBound(t *testing.T) {
	b := map[string][]pubBinding{"443/tcp": {{HostIP: "127.0.0.1", HostPort: "443"}, {HostIP: "::ffff:127.0.0.1", HostPort: "443"}, {HostIP: "", HostPort: "8443"}}}
	if pubBound(b, 443, 443) || !pubBound(b, 443, 443, 8443) || pubBound(b, 80, 80) || pubBound(nil, 443, 443) {
		t.Fatalf("pubBound: %+v", b)
	}
}
