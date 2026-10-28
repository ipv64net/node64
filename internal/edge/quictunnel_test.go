package edge

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/ipv64net/node64/internal/tunnel"
)

// quicBridge: UDP-Socket fuer den Test-Client, dessen Datagramme wie vom CDN64-Server als Tunnel-Stream bei
// ServeQUICStreamFor ankommen (Besucher-Adresse visitor, Name host). Liefert die Adresse fuer den Client und das
// Ende des Streams auf Server-Seite (Schliessen = Stream zu).
func quicBridge(t *testing.T, e *Edge, visitor, host string) (string, net.Conn) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close() })
	e.ServeQUICStreamFor(b, netip.MustParseAddrPort(visitor), host)
	var from atomic.Pointer[net.Addr]
	go func() { // Client -> Stream
		buf := make([]byte, 64<<10)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			from.Store(&addr)
			if tunnel.WriteDatagram(a, buf[:n]) != nil {
				return
			}
		}
	}()
	go func() { // Stream -> Client
		buf := make([]byte, tunnel.MaxDatagram)
		for {
			n, err := tunnel.ReadDatagram(a, buf)
			if err != nil {
				return
			}
			if to := from.Load(); to != nil {
				_, _ = pc.WriteTo(buf[:n], *to)
			}
		}
	}()
	return pc.LocalAddr().String(), a
}

func h3Get(addr, sni string) (int, string, error) {
	h3 := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: sni}} //nolint:gosec // Test
	defer h3.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/", nil)
	req.Host = sni
	resp, err := h3.RoundTrip(req)
	if err != nil {
		return 0, "", err
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(b), nil
}

// HTTP/3 ueber den Tunnel: nur das SNI, fuer das der CDN64-Server durchreicht; Verbindungs-Limits erst nach dem
// Handshake (gefaelschte Absender zaehlen nicht), Platz wird mit dem Stream frei.
func TestServeQUICStreamFor(t *testing.T) {
	e, _ := newEdge(t, nil)
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "app "+r.RemoteAddr) })
	dns := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "dns") })
	if err := e.Set("cdn64", []Route{{Names: []string{"app.test"}, Handler: app, HTTP3: true}, {Names: []string{"dns.test"}, Handler: dns, HTTP3: true}}); err != nil {
		t.Fatal(err)
	}
	var gated, released atomic.Int32
	e.SetGate(func(a netip.Addr) (func(), bool) {
		gated.Add(1)
		return func() { released.Add(1) }, true
	})
	// anderes SNI als der durchgereichte Name: Handshake abgewiesen, Limits nicht belastet
	addr, srv1 := quicBridge(t, e, "203.0.113.20:5000", "app.test")
	if code, body, err := h3Get(addr, "dns.test"); err == nil {
		t.Fatalf("other SNI must fail: %d %q", code, body)
	}
	if gated.Load() != 0 {
		t.Fatalf("gate charged before handshake: %d", gated.Load())
	}
	// passender Name
	addr, srv := quicBridge(t, e, "203.0.113.21:5001", "APP.test")
	code, body, err := h3Get(addr, "app.test")
	if err != nil || code != 200 || body != "app 203.0.113.21:5001" {
		t.Fatalf("routed name: %d %q %v", code, body, err)
	}
	for i := 0; i < 200 && gated.Load() != 1; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if gated.Load() != 1 {
		t.Fatalf("gate after handshake: %d", gated.Load())
	}
	_ = srv.Close()
	_ = srv1.Close()
	for i := 0; i < 200 && released.Load() != 1; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if released.Load() != 1 {
		t.Fatal("gate slot not released with the stream")
	}
	n := -1
	for i := 0; i < 200 && n != 0; i++ {
		e.vq.pc.mu.Lock()
		n = e.vq.pc.pendingN
		e.vq.pc.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	if n != 0 {
		t.Fatalf("pending handshakes left: %d", n)
	}
}

// Grenzen fuer Streams ohne fertigen Handshake: je Adresse und insgesamt.
func TestQUICPending(t *testing.T) {
	p := newVirtPacketConn()
	p.pendingMx = 20
	a, b := netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("198.51.100.2")
	for range quicPendingPerIP {
		if !p.reserve(a) {
			t.Fatal("reserve within the limit")
		}
	}
	if p.reserve(a) {
		t.Fatal("per address limit")
	}
	for range 4 {
		if !p.reserve(b) {
			t.Fatal("other address")
		}
	}
	if p.reserve(netip.MustParseAddr("198.51.100.3")) {
		t.Fatal("total limit")
	}
	p.unreserve(a)
	if !p.reserve(a) || len(p.pending) != 2 || p.pendingN != 20 {
		t.Fatalf("after release: %v %d", p.pending, p.pendingN)
	}
}
