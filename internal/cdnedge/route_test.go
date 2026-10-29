package cdnedge

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/tunnel"
)

// testCA: Zertifikat fuer 127.0.0.1 und Namen, als Dateien (Server) und Pool (Clients).
func testCA(t *testing.T, names ...string) (certFile, keyFile string, pool *x509.CertPool, cert tls.Certificate) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "test"}, DNSNames: names,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	kb, _ := x509.MarshalECPrivateKey(k)
	_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	crt, _ := x509.ParseCertificate(der)
	pool = x509.NewCertPool()
	pool.AddCert(crt)
	return certFile, keyFile, pool, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := l.Addr().String()
	l.Close()
	return a
}

func startEdge(t *testing.T, cfg *Config, pool *x509.CertPool) *Server {
	t.Helper()
	s := New(cfg, slog.New(slog.DiscardHandler), "test")
	s.peerRoots = pool
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	for i := 0; i < 100; i++ { // bereit, wenn Port 80 antwortet
		if r, err := http.Get("http://" + cfg.ListenHTTP + "/health"); err == nil {
			r.Body.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return s
}

func port(a string) int {
	ap := netip.MustParseAddrPort(a)
	return int(ap.Port())
}

// Modus 1 mit zwei Servern: B hat den Tunnel, A reicht ueber den Nachbar-Port an B; die Node beendet TLS selbst und
// sieht die echte Besucher-Adresse; Port 80 nach Host; unbekannte Namen.
func TestPassthroughAndPeer(t *testing.T) {
	cf, kf, pool, _ := testCA(t, "edge.test")
	_, _, _, nodeCert := testCA(t, "app.test")
	secret := strings.Repeat("s", 40)
	hosts := []HostEntry{{Name: "app.test", Tunnel: "t1"}, {Name: "*.wild.test", Tunnel: "t1"}}
	tok := "node-token"
	sum := sha256hex(tok)
	cfgB := &Config{Name: "B", ListenHTTP: freeAddr(t), ListenHTTPS: freeAddr(t), TunnelListen: freeAddr(t), PeerListen: freeAddr(t),
		PeerSecret: secret, TLSCert: cf, TLSKey: kf, Hosts: hosts, Tunnels: []TunnelEntry{{ID: "t1", TokenSHA256: sum}}, DataDir: t.TempDir()}
	cfgA := &Config{Name: "A", ListenHTTP: freeAddr(t), ListenHTTPS: freeAddr(t), PeerListen: freeAddr(t), PeerSecret: secret,
		TLSCert: cf, TLSKey: kf, Hosts: hosts, Peers: []PeerEntry{{Name: "B", Addr: cfgB.PeerListen}}, DataDir: t.TempDir()}
	b := startEdge(t, cfgB, pool)
	a := startEdge(t, cfgA, pool)
	// Node: TLS fuer app.test selbst, Port 80 roh
	node := tunnel.NewClient(tunnel.ClientConfig{Tunnel: "t1", Token: tok, RootCAs: pool,
		Edges: []tunnel.Edge{{Name: "B", Host: "127.0.0.1", Port: port(cfgB.TunnelListen)}},
		Handler: func(st tunnel.Stream, h tunnel.Header) {
			var c net.Conn = st
			if h.Kind == tunnel.KindTLS {
				c = tls.Server(st, &tls.Config{Certificates: []tls.Certificate{nodeCert}})
			}
			defer c.Close()
			req, err := http.ReadRequest(bufio.NewReader(c))
			if err != nil {
				return
			}
			body := "node " + h.Kind + " " + req.Host + " " + h.Client
			_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body)
		}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go node.Run(ctx)
	for i := 0; i < 200 && b.peer("t1") == nil; i++ {
		time.Sleep(25 * time.Millisecond)
	}
	if b.peer("t1") == nil {
		t.Fatal("node not connected to B")
	}
	get := func(addr, sni string) string {
		t.Helper()
		c, err := tls.Dial("tcp", addr, &tls.Config{ServerName: sni, InsecureSkipVerify: true}) //nolint:gosec // Test
		if err != nil {
			return "ERR " + err.Error()
		}
		defer c.Close()
		_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: "+sni+"\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			return "ERR " + err.Error()
		}
		bb, _ := io.ReadAll(resp.Body)
		return string(bb)
	}
	if got := get(cfgB.ListenHTTPS, "app.test"); !strings.HasPrefix(got, "node tls app.test 127.0.0.1:") {
		t.Fatalf("direct: %q", got)
	}
	if got := get(cfgA.ListenHTTPS, "x.wild.test"); !strings.HasPrefix(got, "node tls x.wild.test 127.0.0.1:") {
		t.Fatalf("via peer: %q", got)
	}
	if v := a.stats.of("*.wild.test").ViaPeer.Load(); v != 1 {
		t.Fatalf("via peer counter: %d", v)
	}
	if got := get(cfgB.ListenHTTPS, "unknown.test"); !strings.HasPrefix(got, "ERR") {
		t.Fatalf("unknown name must be closed: %q", got)
	}
	// Port 80: bekannter Name in den Tunnel, sonst die eigene Seite
	resp, err := http.Get("http://" + cfgA.ListenHTTP + "/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("own page: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest("GET", "http://"+cfgB.ListenHTTP+"/y", nil)
	req.Host = "app.test"
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	bb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.HasPrefix(string(bb), "node http80 app.test 127.0.0.1:") {
		t.Fatalf("port 80: %q", bb)
	}
	st := b.stats.of("app.test")
	if st.Conns.Load() < 2 || st.BytesIn.Load() == 0 || st.BytesOut.Load() == 0 {
		t.Fatalf("stats: conns=%d in=%d out=%d", st.Conns.Load(), st.BytesIn.Load(), st.BytesOut.Load())
	}
	// falsches Geheimnis am Nachbar-Port: getrennt
	c, err := tls.Dial("tcp", cfgB.PeerListen, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, `{"secret":"falsch","kind":"tls","host":"app.test","port":443,"client":"1.2.3.4:5"}`+"\n")
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("wrong peer secret must be rejected")
	}
	c.Close()

	// Node weg: Port 80 ueber A (kein Tunnel) -> Nachbar B (auch keiner) -> Fehlerseite statt stummer Trennung
	// (Test 2026-10-29: der Nachbar schloss bei fromPeer ohne Antwort)
	cancel()
	for i := 0; i < 200 && b.peer("t1") != nil; i++ {
		time.Sleep(25 * time.Millisecond)
	}
	req, _ = http.NewRequest("GET", "http://"+cfgA.ListenHTTP+"/z", nil)
	req.Host = "app.test"
	req.Header.Set("Accept-Language", "de")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("node offline, port 80 via peer: %v", err)
	}
	bb, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(string(bb), "nicht erreichbar") {
		t.Fatalf("node offline: %d %.80q", resp.StatusCode, bb)
	}
}

func TestGuard(t *testing.T) {
	now := time.Unix(1000, 0)
	g := newGuard(ShieldConfig{ConnsPerIP: 2, ConnRate: 1, MaxConns: 3})
	g.now = func() time.Time { return now }
	a := netip.MustParseAddr("203.0.113.1")
	r1, w1 := g.admit(a)
	r2, w2 := g.admit(a)
	if w1 != "" || w2 != "" {
		t.Fatal("first two")
	}
	if _, why := g.admit(a); why != "conns" {
		t.Fatalf("conns: %q", why)
	}
	r1()
	r1() // doppelt freigeben schadet nicht
	if _, why := g.admit(netip.MustParseAddr("2001:db8::1")); why != "" {
		t.Fatal("other ip")
	}
	if _, why := g.admit(netip.MustParseAddr("2001:db8::2")); why != "" { // gleiches /64, zweite Verbindung
		t.Fatal("same /64 second")
	}
	if _, why := g.admit(netip.MustParseAddr("198.51.100.9")); why != "max_conns" {
		t.Fatalf("max: %q", why)
	}
	r2()
	if g.open.Load() != 2 {
		t.Fatalf("open: %d", g.open.Load())
	}
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
