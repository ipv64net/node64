package cdn64

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/tunnel"
)

// edgeCert: Zertifikat des Test-Servers fuer 127.0.0.1 (die Node prueft es gegen roots).
func edgeCert(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "edge"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	crt, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(crt)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}}, pool
}

// Ganzer Weg Modus 1: Server (Test) <- Tunnel (von der Node geoeffnet) -> Eingang -> Proxy-Host -> Dienst; die
// Node sieht die echte Besucher-IP, TLS endet in der Node, Port 80 geht auch.
func TestOnlineTunnelEndToEnd(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello via tunnel, xff=" + r.Header.Get("X-Forwarded-For")))
	}))
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)
	bport, _ := strconv.Atoi(bu.Port())
	certPEM, keyPEM := selfSigned(t, "app.test")
	if _, err := e.crt.Upload(ctx, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	e.enable(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort = []string{"app.test"}, "127.0.0.1", bport
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	// Test-Server wie srv07
	conf, pool := edgeCert(t)
	peers := make(chan *tunnel.Peer, 4)
	srv := &tunnel.Server{Name: "srv07", TLS: conf, Up: func(p *tunnel.Peer) { peers <- p }, Auth: func(hl tunnel.Hello) error {
		if hl.Tunnel != "t-test" || hl.Token != "geheim" {
			t.Errorf("hello: %+v", hl)
		}
		return nil
	}}
	addr, err := srv.ServeQUIC("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	e.m.online.roots = pool
	b, _ := json.Marshal(onlineConf{Tunnel: "t-test", Token: "geheim", Edges: []tunnel.Edge{{Name: "srv07", Host: "127.0.0.1", Port: addr.(*net.UDPAddr).Port}}})
	if err := e.m.core.SetSetting(ctx, setOnline, string(b)); err != nil {
		t.Fatal(err)
	}
	e.m.onlineStart(ctx)
	defer e.m.onlineStop()
	var p *tunnel.Peer
	select {
	case p = <-peers:
	case <-time.After(10 * time.Second):
		t.Fatal("node did not connect")
	}
	// Besucher per TLS (Port 443) durch den Tunnel
	st, err := tunnel.OpenStream(ctx, p, tunnel.Header{Kind: tunnel.KindTLS, Client: "203.0.113.50:40000", Host: "app.test", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(st, &tls.Config{ServerName: "app.test", InsecureSkipVerify: true}) //nolint:gosec // Test
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(tc, "GET / HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	tc.Close()
	if resp.StatusCode != 200 || string(body) != "hello via tunnel, xff=203.0.113.50" {
		t.Fatalf("443: %d %q", resp.StatusCode, body)
	}
	// Port 80 (Host leitet auf HTTPS um)
	st, err = tunnel.OpenStream(ctx, p, tunnel.Header{Kind: tunnel.KindHTTP80, Client: "[2001:db8::50]:40001", Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	_ = st.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(st, "GET /x HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n")
	resp, err = http.ReadResponse(bufio.NewReader(st), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	st.Close()
	if resp.StatusCode/100 != 2 && resp.StatusCode != http.StatusMovedPermanently && resp.StatusCode != http.StatusFound {
		t.Fatalf("80: %d", resp.StatusCode)
	}
	// Port 80 bzw. Modus 2 fuer einen Namen: ein anderer Host (absolute URL bzw. Host-Kopf) bekommt 421
	for _, x := range []struct{ kind, req string }{
		{tunnel.KindHTTP80, "GET http://lan.test/ HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n"},
		{tunnel.KindHTTP, "GET / HTTP/1.1\r\nHost: lan.test\r\nConnection: close\r\n\r\n"},
	} {
		st, err = tunnel.OpenStream(ctx, p, tunnel.Header{Kind: x.kind, Client: "[2001:db8::50]:40003", Host: "app.test", Port: 80})
		if err != nil {
			t.Fatal(err)
		}
		_ = st.SetDeadline(time.Now().Add(10 * time.Second))
		_, _ = io.WriteString(st, x.req)
		resp, err = http.ReadResponse(bufio.NewReader(st), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		st.Close()
		if resp.StatusCode != http.StatusMisdirectedRequest {
			t.Fatalf("%s other host: %d", x.kind, resp.StatusCode)
		}
	}
	// Modus 2: TLS endete auf dem Server, die Node bekommt HTTP und behandelt es als HTTPS (keine Umleitung); je
	// Anfrage ein Stream - das Limit fuer neue Verbindungen (hier 1/s, kurz 10) darf das nicht bremsen
	lim := DefaultLimits()
	lim.ConnRate = 1
	e.m.lim.cfg.Store(&lim)
	for i := 0; i < 30; i++ {
		st, err = tunnel.OpenStream(ctx, p, tunnel.Header{Kind: tunnel.KindHTTP, Client: "[2001:db8::51]:40002", Host: "app.test", Port: 443})
		if err != nil {
			t.Fatal(err)
		}
		_ = st.SetDeadline(time.Now().Add(10 * time.Second))
		_, _ = io.WriteString(st, "GET / HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n")
		resp, err = http.ReadResponse(bufio.NewReader(st), nil)
		if err != nil {
			t.Fatalf("mode 2 request %d: %v", i, err)
		}
		body, _ = io.ReadAll(resp.Body)
		st.Close()
		if resp.StatusCode != 200 || string(body) != "hello via tunnel, xff=2001:db8::51" {
			t.Fatalf("mode 2 request %d: %d %q", i, resp.StatusCode, body)
		}
	}
	def := DefaultLimits()
	e.m.lim.cfg.Store(&def)
	// Status in der API
	var v onlineView
	rec := httptest.NewRecorder()
	e.m.apiOnlineGet(rec, httptest.NewRequest("GET", "/api/cdn64/online", nil))
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if !v.Configured || len(v.Edges) != 1 || !v.Edges[0].Connected || v.Edges[0].Transport != "quic" || v.Edges[0].Total < 2 {
		t.Fatalf("status: %+v", v)
	}
}
