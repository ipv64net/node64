package edge

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func ppV2Header(cmd byte, fam byte, addr []byte) []byte {
	h := append([]byte{}, ppV2Sig...)
	h = append(h, 0x20|cmd, fam)
	h = binary.BigEndian.AppendUint16(h, uint16(len(addr)))
	return append(h, addr...)
}

func TestParseTrustedNets(t *testing.T) {
	n, err := parseTrustedNets("192.168.1.10, 172.18.0.0/16\n2001:db8::/32 [::1]")
	if err != nil || len(n) != 4 || n[0].Bits() != 32 || n[3].Bits() != 128 {
		t.Fatalf("nets %v %v", n, err)
	}
	if _, err := parseTrustedNets("traefik"); err == nil {
		t.Fatal("name must be rejected")
	}
	if n, err := parseTrustedNets("  "); err != nil || len(n) != 0 {
		t.Fatal("empty = off")
	}
	c := DefaultConfig()
	c.ProxyProtocol = "10.0.0.0/33"
	if c.Validate() == nil {
		t.Fatal("validate must reject bad network")
	}
}

// pipeConn: Verbindung mit fester Gegenstelle (wie vom Listener angenommen).
type pipeConn struct {
	net.Conn
	ra net.Addr
}

func (p pipeConn) RemoteAddr() net.Addr { return p.ra }

func readHeader(t *testing.T, raw []byte) (net.Conn, error) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	go func() { _, _ = b.Write(append(raw, []byte("GET / HTTP/1.1\r\n")...)) }()
	return readProxyHeader(pipeConn{a, &net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 4000}})
}

func TestReadProxyHeader(t *testing.T) {
	v6 := make([]byte, 36)
	copy(v6, net.ParseIP("2001:db8::7").To16())
	binary.BigEndian.PutUint16(v6[32:], 51000)
	cases := []struct {
		name, want string
		raw        []byte
	}{
		{"v1 tcp4", "203.0.113.7:4444", []byte("PROXY TCP4 203.0.113.7 192.0.2.1 4444 443\r\n")},
		{"v1 tcp6", "[2001:db8::1]:5555", []byte("PROXY TCP6 2001:db8::1 2001:db8::2 5555 443\r\n")},
		{"v1 unknown", "10.0.0.5:4000", []byte("PROXY UNKNOWN\r\n")},
		{"v2 ipv4", "198.51.100.9:61000", ppV2Header(1, 0x11, []byte{198, 51, 100, 9, 192, 0, 2, 1, 0xee, 0x48, 0x01, 0xbb})},
		{"v2 ipv6 mit tlv", "[2001:db8::7]:51000", ppV2Header(1, 0x21, append(v6, 0x03, 0x00, 0x04, 1, 2, 3, 4))},
		{"v2 local", "10.0.0.5:4000", ppV2Header(0, 0x00, nil)},
		{"ohne kopf", "10.0.0.5:4000", nil},
	}
	for _, tc := range cases {
		c, err := readHeader(t, tc.raw)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := c.RemoteAddr().String(); got != tc.want {
			t.Fatalf("%s: remote %s, want %s", tc.name, got, tc.want)
		}
		line, _ := bufio.NewReader(c).ReadString('\n') // danach kommt der Rest unveraendert
		if line != "GET / HTTP/1.1\r\n" {
			t.Fatalf("%s: rest %q", tc.name, line)
		}
	}
	for _, bad := range [][]byte{
		[]byte("PROXY TCP4 nicht-ip 192.0.2.1 1 2\r\n"),
		[]byte("PROXY TCP4 203.0.113.7 192.0.2.1 4444 443\n"), // ohne CR
		[]byte("PROXY TCP4 " + strings.Repeat("1", 120) + "\r\n"),
		ppV2Header(1, 0x11, []byte{1, 2, 3}), // zu kurz
		ppV2Header(5, 0x11, make([]byte, 12)),
	} {
		if _, err := readHeader(t, bad); err == nil {
			t.Fatalf("bad header accepted: %q", bad)
		}
	}
}

// Ende zu Ende: der Eingang sieht nur bei vertrauten Absendern die Adresse aus dem Kopf.
func TestEdgeProxyProtocol(t *testing.T) {
	e, cfg := newEdge(t, nil)
	got := make(chan string, 4)
	if err := e.Set("t", []Route{{Names: []string{"app.test"}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.RemoteAddr
		_, _ = io.WriteString(w, "ok")
	})}}); err != nil {
		t.Fatal(err)
	}
	send := func(port int, pre string, tlsOn bool) string {
		t.Helper()
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if pre != "" {
			_, _ = io.WriteString(c, pre)
		}
		var rw net.Conn = c
		if tlsOn {
			tc := tls.Client(c, &tls.Config{ServerName: "app.test", InsecureSkipVerify: true}) //nolint:gosec // Test
			if err := tc.Handshake(); err != nil {
				return "handshake: " + err.Error()
			}
			rw = tc
		}
		_, _ = io.WriteString(rw, "GET / HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(rw), nil)
		if err != nil {
			return "read: " + err.Error()
		}
		resp.Body.Close()
		select {
		case a := <-got:
			return a
		case <-time.After(3 * time.Second):
			return "no request"
		}
	}
	hdr := "PROXY TCP4 203.0.113.7 192.0.2.1 4444 443\r\n"
	if a := send(cfg.HTTPSPort, "", true); !strings.HasPrefix(a, "127.0.0.1:") { // aus: Adresse der Verbindung
		t.Fatalf("plain: %s", a)
	}
	cfg.ProxyProtocol = "127.0.0.1"
	if err := e.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	if a := send(cfg.HTTPSPort, hdr, true); a != "203.0.113.7:4444" {
		t.Fatalf("https with header: %s", a)
	}
	if a := send(cfg.HTTPSPort, "", true); !strings.HasPrefix(a, "127.0.0.1:") { // ohne Kopf (Health-Check des Proxys)
		t.Fatalf("trusted without header: %s", a)
	}
	// Port 80 mit Kopf: der Kopf wird gelesen, die Anfrage danach normal beantwortet (Weiterleitung auf HTTPS)
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(cfg.HTTPPort), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, hdr+"GET /x HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	c.Close()
	if err != nil || resp.StatusCode >= 400 {
		t.Fatalf("http with header: %v %v", resp, err)
	}
	// nicht vertraut: der Kopf wird nicht gelesen (keine fremde Adresse; TLS scheitert am Kopf)
	cfg.ProxyProtocol = "192.0.2.0/24"
	if err := e.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	if a := send(cfg.HTTPSPort, hdr, true); a == "203.0.113.7:4444" {
		t.Fatal("untrusted source could set its address")
	}
}
