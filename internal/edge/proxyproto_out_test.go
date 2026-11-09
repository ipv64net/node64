package edge

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

// Kopf zum Ziel: Schreiben und Lesen ergeben dieselben Adressen (v1/v2, IPv4, IPv6, gemischt, ohne Adressen).
func TestProxyHeaderRoundTrip(t *testing.T) {
	tcp := func(s string) net.Addr { return net.TCPAddrFromAddrPort(netip.MustParseAddrPort(s)) }
	pipe, other := net.Pipe()
	defer pipe.Close()
	defer other.Close()
	cases := []struct {
		name             string
		src, dst         net.Addr
		wantSrc, wantDst string // "" = Adressen der Verbindung
		wantV1, wantFam  string
	}{
		{"ipv4", tcp("203.0.113.7:4444"), tcp("192.0.2.1:443"), "203.0.113.7:4444", "192.0.2.1:443", "PROXY TCP4 203.0.113.7 192.0.2.1 4444 443\r\n", "\x11"},
		{"ipv6", tcp("[2001:db8::1]:5555"), tcp("[2001:db8::2]:993"), "[2001:db8::1]:5555", "[2001:db8::2]:993", "PROXY TCP6 2001:db8::1 2001:db8::2 5555 993\r\n", "\x21"},
		{"ipv4-mapped", tcp("[::ffff:198.51.100.9]:6000"), tcp("[::ffff:192.0.2.1]:587"), "198.51.100.9:6000", "192.0.2.1:587", "PROXY TCP4 198.51.100.9 192.0.2.1 6000 587\r\n", "\x11"},
		{"ipv6 zu ipv4", tcp("[2001:db8::9]:7000"), tcp("192.0.2.1:443"), "[2001:db8::9]:7000", "192.0.2.1:443", "PROXY TCP6 2001:db8::9 ::ffff:192.0.2.1 7000 443\r\n", "\x21"},
		{"ipv4 zu ipv6", tcp("203.0.113.8:8000"), tcp("[2001:db8::2]:443"), "203.0.113.8:8000", "0.0.0.0:443", "PROXY TCP4 203.0.113.8 0.0.0.0 8000 443\r\n", "\x11"},
		{"ohne ziel", tcp("203.0.113.9:9000"), nil, "203.0.113.9:9000", "0.0.0.0:0", "PROXY TCP4 203.0.113.9 0.0.0.0 9000 0\r\n", "\x11"},
		{"zone", &net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 1, Zone: "eth0"}, tcp("[fe80::2]:2"), "[fe80::1]:1", "[fe80::2]:2", "PROXY TCP6 fe80::1 fe80::2 1 2\r\n", "\x21"},
		{"ohne quelle", nil, tcp("192.0.2.1:443"), "", "", "PROXY UNKNOWN\r\n", "\x00"},
		{"pipe", pipe.RemoteAddr(), pipe.LocalAddr(), "", "", "PROXY UNKNOWN\r\n", "\x00"},
	}
	for _, tc := range cases {
		for _, v := range []int{ProxyV1, ProxyV2} {
			raw := ProxyHeader(v, tc.src, tc.dst)
			if v == ProxyV1 && string(raw) != tc.wantV1 {
				t.Fatalf("%s v1: %q, want %q", tc.name, raw, tc.wantV1)
			}
			if v == ProxyV2 && (len(raw) < 16 || !bytes.Equal(raw[:12], ppV2Sig) || raw[12] != 0x21 || string(raw[13:14]) != tc.wantFam ||
				int(binary.BigEndian.Uint16(raw[14:16])) != len(raw)-16) {
				t.Fatalf("%s v2: % x", tc.name, raw)
			}
			c, err := readHeader(t, raw)
			if err != nil {
				t.Fatalf("%s v%d: %v", tc.name, v, err)
			}
			wantSrc := tc.wantSrc
			if wantSrc == "" {
				wantSrc = "10.0.0.5:4000" // Adresse der Verbindung (readHeader)
			}
			if got := c.RemoteAddr().String(); got != wantSrc {
				t.Fatalf("%s v%d: src %s, want %s", tc.name, v, got, wantSrc)
			}
			if got := c.LocalAddr().String(); tc.wantDst != "" && got != tc.wantDst {
				t.Fatalf("%s v%d: dst %s, want %s", tc.name, v, got, tc.wantDst)
			}
			line, _ := bufio.NewReader(c).ReadString('\n')
			if line != "GET / HTTP/1.1\r\n" {
				t.Fatalf("%s v%d: rest %q", tc.name, v, line)
			}
		}
	}
	if ProxyHeader(0, tcp("192.0.2.1:1"), nil) != nil || ProxyHeader(3, tcp("192.0.2.1:1"), nil) != nil {
		t.Fatal("unknown version must give no header")
	}
	// laengster v1-Kopf passt in die Grenze des Lesers
	long := ProxyHeader(ProxyV1, tcp("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe]:65535"), tcp("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffd]:65535"))
	if len(long) > ppV1Max {
		t.Fatalf("v1 header %d bytes", len(long))
	}
}

// ppSeen: was das Ziel gelesen hat - Adressen aus dem Kopf und das ClientHello danach.
type ppSeen struct {
	src, dst string
	header   bool // ein Kopf kam an
	sni      string
	hello    []byte
}

// ppTarget: Ziel, das den PROXY-Kopf mit dem vorhandenen Leser liest und danach das ClientHello.
func ppTarget(t *testing.T) (string, chan ppSeen) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ch := make(chan ppSeen, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				pc, err := readProxyHeader(c)
				if err != nil {
					ch <- ppSeen{src: "error: " + err.Error()}
					return
				}
				s := ppSeen{src: pc.RemoteAddr().String(), dst: pc.LocalAddr().String(), header: pc.RemoteAddr().String() != c.RemoteAddr().String()}
				s.sni, _, s.hello, _ = PeekHello(pc)
				ch <- s
			}()
		}
	}()
	return ln.Addr().String(), ch
}

// recConn merkt sich, was der TLS-Client zuerst schreibt (das ClientHello).
type recConn struct {
	net.Conn
	first chan []byte
}

func (c *recConn) Write(p []byte) (int, error) {
	select {
	case c.first <- append([]byte(nil), p...):
	default:
	}
	return c.Conn.Write(p)
}

// localConn: Verbindung wie aus dem Tunnel mit der Adresse beim CDN64-Server als LocalAddr.
type localConn struct {
	net.Conn
	local net.Addr
}

func (c localConn) LocalAddr() net.Addr { return c.local }

// TLS durchreichen mit PROXY-Kopf: das Ziel liest den Kopf (Besucher und Eingang) und danach das unveraenderte
// ClientHello; aus = kein Kopf. Ueber ServeConnFor (CDN64 Modus 1) traegt der Kopf die Adresse aus dem Tunnel, hinter
// einem vertrauten Proxy mit eigenem Kopf dessen Adressen.
func TestEdgePassthroughProxyProtocol(t *testing.T) {
	e, cfg := newEdge(t, nil)
	target, seen := ppTarget(t)
	hello := func(c net.Conn) []byte {
		t.Helper()
		rc := &recConn{Conn: c, first: make(chan []byte, 1)}
		tc := tls.Client(rc, &tls.Config{ServerName: "pass.test", InsecureSkipVerify: true}) //nolint:gosec // Test
		_ = tc.SetDeadline(time.Now().Add(3 * time.Second))
		go func() { _ = tc.Handshake() }()
		select {
		case b := <-rc.first:
			return b
		case <-time.After(3 * time.Second):
			t.Fatal("no client hello")
			return nil
		}
	}
	wait := func(name string) ppSeen {
		t.Helper()
		select {
		case s := <-seen:
			return s
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: target got nothing", name)
			return ppSeen{}
		}
	}
	dial := func(pre string) net.Conn {
		t.Helper()
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(cfg.HTTPSPort), 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		if pre != "" {
			_, _ = io.WriteString(c, pre)
		}
		return c
	}
	if err := e.Set("bad", []Route{{Names: []string{"x.test"}, Handler: http.NotFoundHandler(), ProxyProtocol: ProxyV1}}); err == nil {
		t.Fatal("proxy protocol without passthrough must be refused")
	}
	if err := e.Set("bad", []Route{{Names: []string{"x.test"}, Passthrough: target, ProxyProtocol: 3}}); err == nil {
		t.Fatal("unknown proxy protocol version must be refused")
	}
	for _, v := range []int{0, ProxyV1, ProxyV2} {
		name := "v" + strconv.Itoa(v)
		if err := e.Set("cdn64", []Route{{Names: []string{"pass.test"}, Passthrough: target, ProxyProtocol: v}}); err != nil {
			t.Fatal(err)
		}
		c := dial("")
		sent := hello(c)
		s := wait(name)
		if v == 0 {
			if s.header || s.sni != "pass.test" || !bytes.Equal(s.hello, sent) {
				t.Fatalf("off: header=%v sni=%q", s.header, s.sni)
			}
			continue
		}
		if s.src != c.LocalAddr().String() || s.dst != "127.0.0.1:"+strconv.Itoa(cfg.HTTPSPort) {
			t.Fatalf("%s: src %s dst %s, want %s -> 127.0.0.1:%d", name, s.src, s.dst, c.LocalAddr(), cfg.HTTPSPort)
		}
		if s.sni != "pass.test" || !bytes.Equal(s.hello, sent) {
			t.Fatalf("%s: client hello changed (sni %q, %d/%d bytes)", name, s.sni, len(s.hello), len(sent))
		}
		// wie aus dem Tunnel: RemoteAddr = Besucher, LocalAddr = Adresse beim CDN64-Server
		served, cl := pair(t, "[2001:db8::77]:40000")
		e.ServeConnFor(localConn{Conn: served, local: &net.TCPAddr{IP: net.ParseIP("192.0.2.80"), Port: 443}}, 443, "pass.test")
		sent = hello(cl)
		s = wait(name + " tunnel")
		if s.src != "[2001:db8::77]:40000" || s.dst != "[::ffff:192.0.2.80]:443" && s.dst != "192.0.2.80:443" || !bytes.Equal(s.hello, sent) {
			t.Fatalf("%s tunnel: src %s dst %s", name, s.src, s.dst)
		}
		cl.Close()
	}
	// vorgeschalteter vertrauter Proxy mit eigenem Kopf: dessen Adressen gehen weiter
	cfg.ProxyProtocol = "127.0.0.1"
	if err := e.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	c := dial("PROXY TCP4 203.0.113.7 198.51.100.1 4444 8443\r\n")
	sent := hello(c)
	if s := wait("chain"); s.src != "203.0.113.7:4444" || s.dst != "198.51.100.1:8443" || !bytes.Equal(s.hello, sent) {
		t.Fatalf("chain: src %s dst %s", s.src, s.dst)
	}
}
