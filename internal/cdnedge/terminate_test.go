package cdnedge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/tunnel"
)

// oneConn: Listener fuer genau eine Verbindung (ein Stream aus dem Tunnel an einen http.Server).
type oneConn struct {
	c    net.Conn
	once sync.Once
	done chan struct{}
}

func (l *oneConn) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.c })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *oneConn) Close() error   { return nil }
func (l *oneConn) Addr() net.Addr { return &net.TCPAddr{} }

// Modus 2 ueber zwei Server: TLS und HTTP/2 enden auf dem Server, jede Anfrage als Stream "http" mit echter
// Besucher-Adresse zur Node (auch ueber den Nachbarn), grosser Upload, WebSocket, Port 80 -> HTTPS, kein
// Domain-Fronting, Anfrage-Limit, Seite bei fehlender Node, ohne Zertifikat durchreichen wie Modus 1.
func TestTerminate(t *testing.T) {
	cf, kf, pool, _ := testCA(t, "edge.test")
	m2c, m2k, m2pool, _ := testCA(t, "m2.test", "*.m2.test")
	secret := strings.Repeat("s", 40)
	tok := "node-token"
	hosts := []HostEntry{{Name: "m2.test", Tunnel: "t1", Mode: 2}, {Name: "nocert.test", Tunnel: "t1", Mode: 2},
		{Name: "off.test", Tunnel: "t9", Mode: 2}}
	cfgB := &Config{Name: "B", ListenHTTP: freeAddr(t), ListenHTTPS: freeAddr(t), TunnelListen: freeAddr(t), PeerListen: freeAddr(t),
		PeerSecret: secret, TLSCert: cf, TLSKey: kf, Hosts: hosts, Tunnels: []TunnelEntry{{ID: "t1", TokenSHA256: sha256hex(tok)}}, DataDir: t.TempDir(),
		Shield: ShieldConfig{ReqRate: 3}}
	cfgA := &Config{Name: "A", ListenHTTP: freeAddr(t), ListenHTTPS: freeAddr(t), PeerListen: freeAddr(t), PeerSecret: secret,
		TLSCert: cf, TLSKey: kf, Hosts: hosts, Peers: []PeerEntry{{Name: "B", Addr: cfgB.PeerListen}}, DataDir: t.TempDir()}
	b := startEdge(t, cfgB, pool)
	a := startEdge(t, cfgA, pool)
	offc, offk, offpool, _ := testCA(t, "off.test")
	for _, s := range []*Server{a, b} {
		for n, f := range map[string][2]string{"m2.test": {m2c, m2k}, "off.test": {offc, offk}} {
			cp, _ := os.ReadFile(f[0])
			kp, _ := os.ReadFile(f[1])
			if err := s.certs.put(n, cp, kp); err != nil {
				t.Fatal(err)
			}
		}
	}
	kinds := make(chan string, 64)
	node := tunnel.NewClient(tunnel.ClientConfig{Tunnel: "t1", Token: tok, RootCAs: pool,
		Edges: []tunnel.Edge{{Name: "B", Host: "127.0.0.1", Port: port(cfgB.TunnelListen)}},
		Handler: func(st tunnel.Stream, h tunnel.Header) {
			kinds <- h.Kind
			if h.Kind != tunnel.KindHTTP {
				_ = st.Close()
				return
			}
			done := make(chan struct{})
			srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Upgrade") == "websocket" {
					hj, _, _ := w.(http.Hijacker).Hijack()
					_, _ = io.WriteString(hj, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
					buf := make([]byte, 5)
					_, _ = io.ReadFull(hj, buf)
					_, _ = hj.Write(bytes.ToUpper(buf))
					hj.Close()
					return
				}
				n, _ := io.Copy(io.Discard, r.Body)
				_, _ = io.WriteString(w, "node "+r.Host+" client="+h.Client+" proto="+r.Header.Get("X-Forwarded-Proto")+" xff="+r.Header.Get("X-Forwarded-For")+
					" body="+strconv.FormatInt(n, 10))
			})}
			_ = srv.Serve(&oneConn{c: st, done: done})
		}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go node.Run(ctx)
	for i := 0; i < 200 && b.peer("t1") == nil; i++ {
		time.Sleep(25 * time.Millisecond)
	}
	if b.peer("t1") == nil {
		t.Fatal("node not connected")
	}
	client := func(addr string) *http.Client {
		return &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: m2pool},
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				}}}
	}
	get := func(c *http.Client, method, url, host string, body io.Reader) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(method, url, body)
		if host != "" {
			req.Host = host
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, url, err)
		}
		bb, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(bb)
	}
	cb := client(cfgB.ListenHTTPS)
	resp, body := get(cb, "GET", "https://m2.test/x?y=1", "", nil)
	if resp.StatusCode != 200 || resp.ProtoMajor != 2 || !strings.HasPrefix(body, "node m2.test client=127.0.0.1:") ||
		!strings.Contains(body, "proto=https") || !strings.Contains(body, "xff= ") {
		t.Fatalf("terminated: %d %s %q", resp.StatusCode, resp.Proto, body)
	}
	if k := <-kinds; k != tunnel.KindHTTP {
		t.Fatalf("stream kind %s", k)
	}
	// grosser Upload (gestreamt) ueber den Nachbarn A
	ca := client(cfgA.ListenHTTPS)
	resp, body = get(ca, "POST", "https://m2.test/up", "", bytes.NewReader(make([]byte, 6<<20)))
	if resp.StatusCode != 200 || !strings.HasSuffix(body, "body=6291456") {
		t.Fatalf("upload via peer: %d %q", resp.StatusCode, body)
	}
	if b.stats.of("m2.test").BytesIn.Load() < 6<<20 || a.stats.of("m2.test").ViaPeer.Load() != 1 {
		t.Fatalf("counters: in=%d via=%d", b.stats.of("m2.test").BytesIn.Load(), a.stats.of("m2.test").ViaPeer.Load())
	}
	// Domain-Fronting: SNI m2.test, Host fremd
	resp, _ = get(cb, "GET", "https://m2.test/", "evil.test", nil)
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("fronting: %d", resp.StatusCode)
	}
	// WebSocket (HTTP/1.1-Upgrade)
	wc, err := tls.Dial("tcp", cfgB.ListenHTTPS, &tls.Config{ServerName: "m2.test", RootCAs: m2pool, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(wc, "GET /ws HTTP/1.1\r\nHost: m2.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	br := bufio.NewReader(wc)
	wr, err := http.ReadResponse(br, nil)
	if err != nil || wr.StatusCode != 101 {
		t.Fatalf("websocket: %v %v", err, wr)
	}
	_, _ = io.WriteString(wc, "hallo")
	echo := make([]byte, 5)
	_ = wc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(br, echo); err != nil || string(echo) != "HALLO" {
		t.Fatalf("websocket echo: %v %q", err, echo)
	}
	wc.Close()
	// Port 80 -> HTTPS
	r80, err := http.NewRequest("GET", "http://"+cfgB.ListenHTTP+"/a?b=c", nil)
	if err != nil {
		t.Fatal(err)
	}
	r80.Host = "m2.test"
	rr, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(r80)
	if err != nil {
		t.Fatal(err)
	}
	rr.Body.Close()
	if rr.StatusCode != 301 || rr.Header.Get("Location") != "https://m2.test/a?b=c" {
		t.Fatalf("port 80: %d %s", rr.StatusCode, rr.Header.Get("Location"))
	}
	// Node nicht verbunden: verstaendliche Seite
	co := client(cfgB.ListenHTTPS)
	co.Transport.(*http.Transport).TLSClientConfig.RootCAs = offpool
	resp, body = get(co, "GET", "https://off.test/", "", nil)
	if resp.StatusCode != 502 || !strings.Contains(body, "nicht erreichbar") {
		t.Fatalf("offline: %d %q", resp.StatusCode, body)
	}
	// ohne Zertifikat: durchreichen wie Modus 1 (Stream "tls")
	for len(kinds) > 0 {
		<-kinds
	}
	nc, err := tls.Dial("tcp", cfgB.ListenHTTPS, &tls.Config{ServerName: "nocert.test", InsecureSkipVerify: true}) //nolint:gosec // Test
	if err == nil {
		nc.Close()
	}
	select {
	case k := <-kinds:
		if k != tunnel.KindTLS {
			t.Fatalf("no cert: stream kind %s", k)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no cert: not passed through")
	}
	// Anfrage-Limit: 3/s, kurzzeitig 30
	limited := 0
	for i := 0; i < 45; i++ {
		if r, _ := get(cb, "GET", "https://m2.test/r", "", nil); r.StatusCode == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 || b.stats.of("m2.test").Rejected.Load() == 0 {
		t.Fatalf("rate limit: %d", limited)
	}
}

func TestCertSealAndRound(t *testing.T) {
	c, k, _, _ := testCA(t, "a.test", "*.a.test")
	cp, _ := os.ReadFile(c)
	kp, _ := os.ReadFile(k)
	s := New(&Config{Name: "A", DataDir: t.TempDir(), CertKey: strings.Repeat("ab", 32)}, slog.New(slog.DiscardHandler), "test")
	blob, err := s.sealCert("a.test", cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	if c2, k2, err := s.openCert("a.test", blob); err != nil || !bytes.Equal(c2, cp) || !bytes.Equal(k2, kp) {
		t.Fatalf("open: %v", err)
	}
	if _, _, err := s.openCert("b.test", blob); err == nil {
		t.Fatal("blob must be bound to the name")
	}
	if err := s.certs.put("b.test", cp, kp); err == nil {
		t.Fatal("certificate for another name accepted")
	}
	// Runde: Modus-2-Name ohne Zertifikat -> bestellen (Hook) und ablegen; nach Neustart aus der Datei
	s.cfg.ACMEPrimary = true
	s.cfg.APIURL = "http://127.0.0.1:1" // ipv64 nicht erreichbar: Ablage scheitert, Zertifikat bleibt lokal
	s.apiCfg.Store(&apiConfig{Hosts: []apiHost{{ID: 1, Name: "a.test", Mode: 2}, {ID: 2, Name: "m1.test", Mode: 1}}})
	n := 0
	s.obtainHook = func(_ context.Context, name string) ([]byte, []byte, error) { n++; return cp, kp, nil }
	s.certRound(context.Background(), &certPlan{missingSince: map[string]time.Time{}, nextTry: map[string]time.Time{}, backoff: map[string]time.Duration{}})
	if n != 1 || !s.certs.has("a.test") || s.certs.has("m1.test") {
		t.Fatalf("round: obtained %d", n)
	}
	if !newCertStore(s.certs.dir).has("a.test") {
		t.Fatal("not reloaded from disk")
	}
	// Zweiter Server (nicht primaer, mit Ablage): wartet zunaechst
	s2 := New(&Config{Name: "B", DataDir: t.TempDir(), CertKey: strings.Repeat("ab", 32), APIURL: "http://127.0.0.1:1"}, slog.New(slog.DiscardHandler), "test")
	s2.apiCfg.Store(s.apiCfg.Load())
	s2.obtainHook = s.obtainHook
	s2.certRound(context.Background(), &certPlan{missingSince: map[string]time.Time{}, nextTry: map[string]time.Time{}, backoff: map[string]time.Duration{}})
	if n != 1 || s2.certs.has("a.test") {
		t.Fatal("secondary must wait")
	}
}
