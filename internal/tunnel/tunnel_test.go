package tunnel

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func testCert(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "edge.test"}, DNSNames: []string{"edge.test"},
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

type fixture struct {
	srv   *Server
	addrQ net.Addr
	addrT net.Addr
	peers chan *Peer
	pool  *x509.CertPool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	conf, pool := testCert(t)
	f := &fixture{peers: make(chan *Peer, 8), pool: pool}
	f.srv = &Server{Name: "e1", TLS: conf, Up: func(p *Peer) { f.peers <- p }, Auth: func(h Hello) error {
		if h.Token != "secret" {
			return errors.New("bad token")
		}
		return nil
	}}
	var err error
	if f.addrQ, err = f.srv.ServeQUIC("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	if f.addrT, err = f.srv.ServeTCP("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fixture) client(token string, tcp bool, handler func(Stream, Header)) *Client {
	port := f.addrQ.(*net.UDPAddr).Port
	if tcp {
		port = f.addrT.(*net.TCPAddr).Port
	}
	c := NewClient(ClientConfig{Tunnel: "t1", Token: token, Node: "test", Edges: []Edge{{Name: "e1", Host: "edge.test", Port: port}},
		RootCAs: f.pool, Handler: handler})
	c.resolve = func(context.Context, Edge) []net.IP { return []net.IP{net.ParseIP("127.0.0.1")} }
	c.forceTCP = tcp
	return c
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 200 && !cond(); i++ {
		time.Sleep(25 * time.Millisecond)
	}
	if !cond() {
		t.Fatal("timeout: " + what)
	}
}

// Echo ueber beide Wege: Server oeffnet je Besucher einen Stream mit Kopf, die Node bekommt die echte Besucher-IP,
// halbes Schliessen funktioniert, offene Streams werden gezaehlt.
func TestTunnelBothTransports(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		name := "quic"
		if tcp {
			name = "tcp"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			got := make(chan Header, 1)
			c := f.client("secret", tcp, func(st Stream, h Header) {
				got <- h
				_, _ = io.Copy(st, st)
				_ = st.CloseWrite()
				_ = st.Close()
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go c.Run(ctx)
			var p *Peer
			select {
			case p = <-f.peers:
			case <-time.After(10 * time.Second):
				t.Fatal("no tunnel")
			}
			if p.Tunnel != "t1" || p.Session.Transport() != name {
				t.Fatalf("peer: %+v %s", p, p.Session.Transport())
			}
			st, err := OpenStream(ctx, p, Header{Kind: KindTLS, Client: "203.0.113.7:4444", Host: "a.test", Port: 443, Ray: "r1"})
			if err != nil {
				t.Fatal(err)
			}
			payload := bytes.Repeat([]byte("cdn64 "), 200000) // 1,2 MB
			go func() { _, _ = st.Write(payload); _ = st.CloseWrite() }()
			back, err := io.ReadAll(st)
			if err != nil || !bytes.Equal(back, payload) {
				t.Fatalf("echo: %d bytes, %v", len(back), err)
			}
			_ = st.Close()
			h := <-got
			if h.Kind != KindTLS || h.Host != "a.test" || h.Ray != "r1" || h.Edge != "e1" || h.ClientAddr().String() != "203.0.113.7:4444" {
				t.Fatalf("header: %+v %v", h, h.ClientAddr())
			}
			waitFor(t, "status", func() bool {
				s := c.Status()[0]
				return s.Connected && s.Transport == name && s.Total == 1 && s.Streams == 0
			})
		})
	}
}

// Falscher Token: abgelehnt, gilt nicht als UDP-Problem.
func TestTunnelRejected(t *testing.T) {
	f := newFixture(t)
	c := f.client("wrong", false, func(st Stream, h Header) { _ = st.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	waitFor(t, "rejected", func() bool { return strings.Contains(c.Status()[0].LastError, "bad token") })
	if s := c.Status()[0]; s.Connected || s.UDPBlocked {
		t.Fatalf("status: %+v", s)
	}
}

// Server weg und wieder da (Neustart): die Node verbindet sich von selbst neu.
func TestTunnelReconnect(t *testing.T) {
	f := newFixture(t)
	c := f.client("secret", false, func(st Stream, h Header) { _ = st.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	waitFor(t, "connected", func() bool { return c.Status()[0].Connected })
	r0 := c.Status()[0].Reconnects
	addr := f.addrQ.String()
	f.srv.Close()
	for len(f.peers) > 0 { // alle Verbindungen des alten Servers trennen (wie beim Neustart)
		p := <-f.peers
		p.GoAway()
		_ = p.Session.Close("restart")
	}
	waitFor(t, "disconnected", func() bool { return !c.Status()[0].Connected })
	srv2 := &Server{Name: "e1", TLS: f.srv.TLS}
	var err error
	for i := 0; i < 50; i++ { // quic-go gibt den UDP-Port erst frei, wenn die letzte Verbindung zu ist
		if _, err = srv2.ServeQUIC(addr); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer srv2.Close()
	for i := 0; i < 400; i++ {
		if s := c.Status()[0]; s.Connected && s.Reconnects > r0 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("not connected again: %+v", c.Status()[0])
}

// Ohne Anmeldung wird nach der Frist getrennt (G7).
func TestTunnelAuthTimeout(t *testing.T) {
	conf, pool := testCert(t)
	srv := &Server{Name: "e1", TLS: conf, auth: 300 * time.Millisecond}
	addr, err := srv.ServeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	tc, err := tls.Dial("tcp", addr.String(), &tls.Config{ServerName: "edge.test", RootCAs: pool, NextProtos: []string{ALPN}})
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	_ = tc.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	_, err = io.ReadAll(tc)
	if time.Since(start) > 2*time.Second {
		t.Fatalf("not closed in time: %v", err)
	}
}

func TestHeader(t *testing.T) {
	var b bytes.Buffer
	if err := WriteHeader(&b, Header{Kind: KindHTTP80, Client: "[2001:db8::1]:80", Port: 80}); err != nil {
		t.Fatal(err)
	}
	h, err := ReadHeader(&b)
	if err != nil || h.Kind != KindHTTP80 || h.ClientAddr().String() != "[2001:db8::1]:80" {
		t.Fatalf("%+v %v", h, err)
	}
	if _, err := ReadHeader(strings.NewReader("GET / HTTP/1.1\r\n")); err == nil {
		t.Fatal("bad magic")
	}
}
