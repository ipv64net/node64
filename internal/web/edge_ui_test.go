package web

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/edge"
)

func freeEdgePort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 200; i++ {
		p := 20000 + rand.IntN(10000)
		if ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p)); err == nil {
			ln.Close()
			if pc, err := net.ListenPacket("udp", "127.0.0.1:"+strconv.Itoa(p)); err == nil {
				pc.Close()
				return p
			}
		}
	}
	t.Fatal("no free port")
	return 0
}

func TestUIViaEdge(t *testing.T) {
	ctx := context.Background()
	a := newTestApp(t)
	cfg := edge.Config{Bind: "127.0.0.1", HTTPPort: freeEdgePort(t), HTTPSPort: freeEdgePort(t), Default: edge.DefaultNotFound}
	e, err := edge.New(cfg, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(ctx)
	a.s.Edge = e
	_ = a.store.SetSetting(ctx, setUIName, "node.test")
	if err := a.s.uiRoute(ctx); err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "node.test"}}} //nolint:gosec // Test
	req, _ := http.NewRequest("GET", "https://127.0.0.1:"+strconv.Itoa(cfg.HTTPSPort)+"/api/health", nil)
	req.Host = "node.test"
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("ui via edge: %d", resp.StatusCode)
	}
	for ip, want := range map[string]bool{"192.168.1.5": true, "127.0.0.1": true, "fd00::1": true, "100.100.1.1": true, "203.0.113.9": false, "2001:db8::1": false} {
		if got := lanOnly(netip.MustParseAddr(ip)); got != want {
			t.Errorf("lanOnly(%s) = %v", ip, got)
		}
	}
	// Docker-Bridge-Netz ohne veroeffentlichte Ports (Gateway ohne Dienst): Seite Ports warnt mit Beispiel
	t.Setenv("NODE64_DOCKER_HOST", "none") // keine Docker-API: nur die Pruefanfrage zaehlt
	defer edge.BridgeForTest(true, netip.MustParseAddr("127.0.0.2"))()
	if d := a.s.portsPageData(ctx, "", ""); !d.Pub.Bridge || !d.Pub.MissingPort(cfg.HTTPSPort) {
		t.Fatalf("published: %+v", d.Pub)
	}
	loginAs(t, a, "admin", "sehr geheimes passwort")
	_, body := a.get(t, "/settings/ports")
	hp := strconv.Itoa(cfg.HTTPSPort)
	for _, want := range []string{`id="published"`, "-p " + hp + ":" + hp, `- &#34;` + hp + ":" + hp + `&#34;`, "network_mode: host"} {
		if !strings.Contains(body, want) {
			t.Errorf("ports page lacks %q", want)
		}
	}
	// Docker-Host ohne Hairpin (#243): das Gateway nimmt an, antwortet aber nie - keine Warnung, nur "nicht pruefbar"
	for _, p := range []int{cfg.HTTPPort, cfg.HTTPSPort} {
		ln, err := net.Listen("tcp", "127.0.0.4:"+strconv.Itoa(p))
		if err != nil {
			t.Skip("no fourth loopback address:", err)
		}
		defer ln.Close()
		go func() {
			var held []net.Conn // offen halten, bis der Listener schliesst
			defer func() {
				for _, c := range held {
					_ = c.Close()
				}
			}()
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				held = append(held, c)
			}
		}()
	}
	defer edge.BridgeForTest(true, netip.MustParseAddr("127.0.0.4"))()
	d := a.s.portsPageData(ctx, "", "")
	if len(d.Pub.Missing) != 0 || d.Pub.PortState(cfg.HTTPSPort) != "unknown" {
		t.Fatalf("published without hairpin: %+v", d.Pub)
	}
	if _, body = a.get(t, "/settings/ports"); strings.Contains(body, `id="published"`) {
		t.Error("ports page warns without hairpin")
	}
	_ = a.store.SetSetting(ctx, setUIName, "")
	if err := a.s.uiRoute(ctx); err != nil || len(e.Status().Names) != 0 {
		t.Fatalf("removed: %v %+v", err, e.Status().Names)
	}
}
