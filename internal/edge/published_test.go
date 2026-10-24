package edge

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

// Docker-Bridge-Netz: HTTP- und HTTPS-Port gelten als veroeffentlicht, wenn die Pruefanfrage ueber das Gateway beim
// eigenen Eingang ankommt; ein anderes Programm am Port des Hosts zaehlt nicht.
func TestPublished(t *testing.T) {
	e, cfg := newEdge(t, nil)
	if err := e.Set("cdn64", []Route{{Names: []string{"app.test"}, Handler: http.NotFoundHandler(), HTTP3: true}}); err != nil {
		t.Fatal(err)
	}
	oldNet, oldGw := bridgeNet, bridgeGateway
	defer func() { bridgeNet, bridgeGateway = oldNet, oldGw }()
	gw := netip.MustParseAddr("127.0.0.1")
	bridgeGateway = func() netip.Addr { return gw }
	ctx := context.Background()

	bridgeNet = func() bool { return false }
	if p := e.Published(ctx); p.Bridge || len(p.Missing) != 0 {
		t.Fatalf("host network: %+v", p)
	}
	bridgeNet = func() bool { return true }
	if p := e.Published(ctx); !p.Bridge || len(p.Missing) != 0 || p.Gateway != "127.0.0.1" {
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
	if len(p.Missing) != 2 || !p.MissingPort(cfg.HTTPPort) || !p.MissingPort(cfg.HTTPSPort) {
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
