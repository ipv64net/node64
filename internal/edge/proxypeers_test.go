package edge

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuf: Log-Ausgabe fuer Tests (mehrere Goroutinen schreiben).
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// tlsWithHeader: Verbindung zum Eingang, zuerst der PROXY-Kopf, dann TLS mit SNI app.test (Ergebnis: Status oder Fehler).
func tlsWithHeader(t *testing.T, port int, hdr []byte) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write(hdr)
	tc := tls.Client(c, &tls.Config{ServerName: "app.test", InsecureSkipVerify: true}) //nolint:gosec // Test
	if err := tc.Handshake(); err != nil {
		return "handshake: " + err.Error()
	}
	_, _ = io.WriteString(tc, "GET / HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n")
	buf := make([]byte, 15)
	n, _ := io.ReadFull(tc, buf)
	return string(buf[:n])
}

// #138 (a): PROXY-Kopf von einer Quelle, die nicht freigegeben ist - die Verbindung wird geschlossen, aber nicht mehr
// still: Eintrag im Log (gebremst je Quelle) und an den Beobachter (Zugriffs-Log von PROXY64).
func TestProxyHeaderUntrustedLogged(t *testing.T) {
	e, cfg := newEdge(t, nil)
	logs := &syncBuf{}
	e.log = slog.New(slog.NewTextHandler(logs, nil))
	if err := e.Set("t", []Route{{Names: []string{"app.test"}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})}}); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var kinds []string
	e.SetWatch(func(ip netip.Addr, host, method, path string, status int, kind string) {
		mu.Lock()
		kinds = append(kinds, kind+" "+ip.String())
		mu.Unlock()
	})
	v2 := ppV2Header(1, 0x11, []byte{203, 0, 113, 7, 127, 0, 0, 1, 0x9c, 0x40, 0x01, 0xbb})
	v1 := []byte("PROXY TCP4 203.0.113.7 127.0.0.1 40000 443\r\n")
	for _, pp := range []string{"", "192.0.2.0/24"} { // ohne Eintrag und mit Eintrag, der die Quelle nicht enthaelt
		cfg.ProxyProtocol = pp
		if err := e.Configure(cfg); err != nil {
			t.Fatal(err)
		}
		if r := tlsWithHeader(t, cfg.HTTPSPort, v2); !strings.HasPrefix(r, "handshake:") {
			t.Fatalf("%q: untrusted v2 header must close: %s", pp, r)
		}
		if r := tlsWithHeader(t, cfg.HTTPSPort, v1); !strings.HasPrefix(r, "handshake:") {
			t.Fatalf("%q: untrusted v1 header must close: %s", pp, r)
		}
		if r := tlsWithHeader(t, cfg.HTTPSPort, nil); r != "HTTP/1.1 200 OK" { // ohne Kopf normal
			t.Fatalf("%q: without header: %s", pp, r)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for strings.Count(logs.String(), "PROXY protocol header from untrusted source") < 1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	out := logs.String()
	if n := strings.Count(out, "PROXY protocol header from untrusted source"); n != 1 { // vier Verbindungen, gebremst: ein Eintrag
		t.Fatalf("log entries: %d\n%s", n, out)
	}
	if !strings.Contains(out, "ip=127.0.0.1") || !strings.Contains(out, "Accept PROXY protocol from") {
		t.Fatalf("log without source or hint:\n%s", out)
	}
	mu.Lock()
	defer mu.Unlock()
	if n := slices.Index(kinds, WatchProxyUntrusted+" 127.0.0.1"); n < 0 || slices.Contains(kinds, WatchNoTLS+" 127.0.0.1") {
		t.Fatalf("watch kinds: %v", kinds)
	}
}

func TestIsProxyHeader(t *testing.T) {
	for _, c := range []struct {
		b    string
		want bool
	}{
		{"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n", true}, {"PROXY", true}, {string(ppV2Sig), true}, {string(ppV2Sig[:5]), true},
		{"\x16\x03\x01\x02\x00", false}, {"GET / HTTP/1.1\r\n", false}, {"PRO", false}, {"PROXX", false},
	} {
		if got := isProxyHeader([]byte(c.b)); got != c.want {
			t.Errorf("%q: %v", c.b, got)
		}
	}
}

func TestResolvePeers(t *testing.T) {
	lookup := func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "node-b.lan" {
			return []netip.Addr{netip.MustParseAddr("192.168.20.7"), netip.MustParseAddr("fd00::7")}, nil
		}
		return nil, errors.New("not found")
	}
	got := resolvePeers(context.Background(), []string{"https://192.168.20.5:8443", "https://node-b.lan:8443/", "https://[fd00::5]:8443",
		"https://gone.lan", "192.168.20.5", " ", "https://0.0.0.0:1"}, lookup)
	want := "[192.168.20.5 192.168.20.7 fd00::5 fd00::7]"
	if fmtAddrs(got) != want {
		t.Fatalf("peers %v", got)
	}
}

func fmtAddrs(a []netip.Addr) string {
	s := make([]string, len(a))
	for i, x := range a {
		s[i] = x.String()
	}
	return "[" + strings.Join(s, " ") + "]"
}

// #138 (b): Mit "von den Cluster-Nodes annehmen" gilt die aktuelle Adresse der Nodes - wechselt sie, zieht die Freigabe
// mit, ohne dass jemand die Liste von Hand nachtraegt.
func TestProxyPeersFollowAddress(t *testing.T) {
	e, cfg := newEdge(t, nil)
	got := make(chan string, 8)
	if err := e.Set("t", []Route{{Names: []string{"app.test"}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.RemoteAddr
		_, _ = io.WriteString(w, "ok")
	})}}); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	peer := "https://192.0.2.10:8443" // alte Adresse der anderen Node
	e.SetProxyPeers(func(context.Context) []string {
		mu.Lock()
		defer mu.Unlock()
		return []string{peer}
	})
	cfg.ProxyProtocolPeers = true
	if err := e.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	waitPeers := func(want string) {
		t.Helper()
		e.kickPeers()
		deadline := time.Now().Add(3 * time.Second)
		for fmtAddrs(e.ProxyPeers()) != want && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if fmtAddrs(e.ProxyPeers()) != want {
			t.Fatalf("peers %v, want %s", e.ProxyPeers(), want)
		}
	}
	waitPeers("[192.0.2.10]")
	hdr := []byte("PROXY TCP4 203.0.113.7 127.0.0.1 4444 443\r\n")
	if r := tlsWithHeader(t, cfg.HTTPSPort, hdr); !strings.HasPrefix(r, "handshake:") { // 127.0.0.1 ist (noch) keine Node
		t.Fatalf("not a peer yet: %s", r)
	}
	mu.Lock()
	peer = "https://127.0.0.1:8443" // Umzug: neue Adresse
	mu.Unlock()
	waitPeers("[127.0.0.1]")
	if r := tlsWithHeader(t, cfg.HTTPSPort, hdr); r != "HTTP/1.1 200 OK" {
		t.Fatalf("peer after move: %s", r)
	}
	if a := <-got; a != "203.0.113.7:4444" {
		t.Fatalf("remote %s", a)
	}
	if st := e.Status(); fmtAddrs(st.ProxyPeers) != "[127.0.0.1]" || !st.Config.ProxyProtocolPeers {
		t.Fatalf("status %+v", st.ProxyPeers)
	}
	cfg.ProxyProtocolPeers = false // Schalter aus: Nodes nicht mehr vertraut
	if err := e.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	if r := tlsWithHeader(t, cfg.HTTPSPort, hdr); !strings.HasPrefix(r, "handshake:") {
		t.Fatalf("switch off: %s", r)
	}
	if len(e.ProxyPeers()) != 0 {
		t.Fatal("ProxyPeers with switch off")
	}
	c := LoadConfig(func(k, def string) string { return cfg.Settings()[k] })
	if c.ProxyProtocolPeers {
		t.Fatal("setting off")
	}
	cfg.ProxyProtocolPeers = true
	if c := LoadConfig(func(k, def string) string { return cfg.Settings()[k] }); !c.ProxyProtocolPeers {
		t.Fatal("setting on")
	}
}
