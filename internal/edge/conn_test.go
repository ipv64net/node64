package edge

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type remoteConn struct {
	net.Conn
	remote net.Addr
}

func (c remoteConn) RemoteAddr() net.Addr { return c.remote }

// pair: Verbindung wie aus dem Tunnel (RemoteAddr = Besucher), die andere Seite fuer den Test.
func pair(t *testing.T, visitor string) (served net.Conn, client net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); ch <- c }()
	cl, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return remoteConn{Conn: <-ch, remote: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(visitor))}, cl
}

// ServeConn: TLS nach SNI und Port 80 ohne offene Ports, echte Besucher-IP, Sperrliste greift, kein Alt-Svc.
func TestServeConn(t *testing.T) {
	e, _ := newEdge(t, nil)
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "app "+r.RemoteAddr) })
	if err := e.Set("cdn64", []Route{{Names: []string{"app.test"}, Handler: app, HTTP: app, HTTP3: true}}); err != nil {
		t.Fatal(err)
	}
	e.h3On.Store(true)
	// Port 443
	served, cl := pair(t, "203.0.113.9:4444")
	e.ServeConn(served, 443)
	tc := tls.Client(cl, &tls.Config{ServerName: "app.test", InsecureSkipVerify: true}) //nolint:gosec // Test
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(tc, "GET / HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	tc.Close()
	if string(b) != "app 203.0.113.9:4444" || resp.Header.Get("Alt-Svc") != "" {
		t.Fatalf("443: %q alt-svc=%q", b, resp.Header.Get("Alt-Svc"))
	}
	// Port 80
	served, cl = pair(t, "[2001:db8::5]:5555")
	e.ServeConn(served, 80)
	_ = cl.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(cl, "GET / HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n")
	resp, err = http.ReadResponse(bufio.NewReader(cl), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	cl.Close()
	if string(b) != "app [2001:db8::5]:5555" {
		t.Fatalf("80: %q", b)
	}
	// Sperrliste: sofort getrennt
	e.SetBlocker(func(a netip.Addr) bool { return a.String() == "198.51.100.1" })
	served, cl = pair(t, "198.51.100.1:1")
	e.ServeConn(served, 443)
	_ = cl.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := cl.Read(make([]byte, 1)); err == nil || strings.Contains(err.Error(), "timeout") {
		t.Fatalf("blocked visitor must be cut off: %v", err)
	}
	cl.Close()
}
