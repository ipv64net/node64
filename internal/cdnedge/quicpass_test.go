package cdnedge

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/tunnel"
)

type fixedCerts struct{ c *tls.Certificate }

func (f fixedCerts) ForName(string) *tls.Certificate { return f.c }
func (f fixedCerts) ByID(int64) *tls.Certificate     { return f.c }

type remoteConn struct {
	tunnel.Stream
	ra net.Addr
}

func (c *remoteConn) RemoteAddr() net.Addr { return c.ra }

// HTTP/3 in Modus 1: Besucher -> UDP 443 des Servers -> Weiche (Name aus dem Initial) -> Tunnel -> HTTP/3 der Node.
// TLS endet erst in der Node, die Node sieht die echte Besucher-Adresse; ueber TCP kommt der Hinweis Alt-Svc
// erst, wenn der Server QUIC durchreichen kann. Modus 2 (HTTP/3 auf dem Server) laeuft daneben weiter.
func TestQUICPassthroughMode1(t *testing.T) {
	cf, kf, pool, _ := testCA(t, "edge.test")
	_, _, hpool, crt := testCA(t, "h1.test")
	tok := "node-token"
	cfg := &Config{Name: "B", PublicHost: "edge.test", ListenHTTP: freeAddr(t), ListenHTTPS: freeAddr(t), TunnelListen: freeAddr(t),
		TLSCert: cf, TLSKey: kf, Hosts: []HostEntry{{Name: "h1.test", Tunnel: "t1", Mode: 1}}, HTTP3: true,
		Tunnels: []TunnelEntry{{ID: "t1", TokenSHA256: sha256hex(tok)}}, DataDir: t.TempDir(),
		PeerListen: freeAddr(t), PeerSecret: "peer-secret-0123456789abcdef0123456789"}
	s := startEdge(t, cfg, pool)
	// A: Nachbar ohne Tunnel der Node (der Besucher landet dort, die Node haengt an B)
	cfgA := &Config{Name: "A", ListenHTTP: freeAddr(t), ListenHTTPS: freeAddr(t), HTTP3: true, PeerListen: freeAddr(t), PeerSecret: cfg.PeerSecret,
		TLSCert: cf, TLSKey: kf, Hosts: cfg.Hosts, Peers: []PeerEntry{{Name: "B", Addr: cfg.PeerListen}}, DataDir: t.TempDir()}
	sA := startEdge(t, cfgA, pool)

	// Node: echter Eingang (internal/edge) mit einer Route fuer h1.test, HTTP/3 erlaubt
	ne, err := edge.New(edge.Config{Bind: "127.0.0.1", HTTPPort: 0, HTTPSPort: 0, Default: edge.DefaultNotFound}, fixedCerts{&crt}, nil,
		slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer ne.Close(context.Background())
	if err := ne.Set("test", []edge.Route{{Names: []string{"h1.test"}, HTTP3: true, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "node "+r.Proto+" from "+r.RemoteAddr)
	})}}); err != nil {
		t.Fatal(err)
	}
	node := tunnel.NewClient(tunnel.ClientConfig{Tunnel: "t1", Token: tok, RootCAs: pool, Caps: []string{tunnel.CapQUIC},
		Edges: []tunnel.Edge{{Name: "B", Host: "edge.test", Port: port(cfg.TunnelListen), IPs: []string{"127.0.0.1"}}},
		Handler: func(st tunnel.Stream, h tunnel.Header) {
			ap, err := netip.ParseAddrPort(h.Client)
			if err != nil {
				_ = st.Close()
				return
			}
			switch h.Kind {
			case tunnel.KindTLS:
				ne.ServeConn(&remoteConn{Stream: st, ra: net.TCPAddrFromAddrPort(ap)}, 443)
			case tunnel.KindQUIC:
				ne.ServeQUICStream(st, ap)
			default:
				_ = st.Close()
			}
		}})
	ne.SetTunnelHTTP3(func() bool { return node.AllHave(tunnel.CapQUIC) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go node.Run(ctx)
	for i := 0; i < 1200 && (s.peer("t1") == nil || !node.AllHave(tunnel.CapQUIC)); i++ { // bis 30 s (Windows unter Last)
		time.Sleep(25 * time.Millisecond)
	}
	if p := s.peer("t1"); p == nil || !tunnel.HasCap(p.Caps, tunnel.CapQUIC) {
		t.Fatal("node not connected or without quic capability")
	}

	// TCP (Modus 1, TLS in der Node): Hinweis auf HTTP/3 ueber Port 443
	https := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: hpool},
		DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, cfg.ListenHTTPS)
		}}}
	resp, err := https.Get("https://h1.test/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.HasPrefix(string(b), "node HTTP/") || resp.Header.Get("Alt-Svc") != `h3=":443"; ma=86400` {
		t.Fatalf("tcp: %q alt-svc %q", b, resp.Header.Get("Alt-Svc"))
	}

	// HTTP/3 ueber den Server: TLS endet in der Node, echte Absender-Adresse
	var local string
	h3 := &http.Client{Timeout: 10 * time.Second, Transport: &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: hpool},
		Dial: func(ctx context.Context, _ string, tc *tls.Config, qc *quic.Config) (*quic.Conn, error) {
			c, err := quic.DialAddr(ctx, cfg.ListenHTTPS, tc, slowQUIC(qc))
			if err == nil {
				local = c.LocalAddr().String()
			}
			return c, err
		}}}
	for i := 0; i < 3; i++ { // mehrere Anfragen ueber dieselbe Verbindung
		resp, err := h3.Get("https://h1.test/x")
		if err != nil {
			t.Fatalf("http3: %v", err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		_, lport, _ := net.SplitHostPort(local)
		if resp.ProtoMajor != 3 || string(b) != "node HTTP/3.0 from 127.0.0.1:"+lport {
			t.Fatalf("http3: %s %q (local %s)", resp.Proto, b, local)
		}
	}
	if st := s.stats.of("h1.test"); st.BytesIn.Load() == 0 || st.BytesOut.Load() == 0 || st.Conns.Load() < 2 {
		t.Fatalf("stats: in %d out %d conns %d", st.BytesIn.Load(), st.BytesOut.Load(), st.Conns.Load())
	}
	if s.qd.Load().open() != 1 {
		t.Fatalf("open passthrough flows: %d", s.qd.Load().open())
	}

	// ueber den Nachbarn: A hat keinen Tunnel, reicht an B
	h3a := &http.Client{Timeout: 10 * time.Second, Transport: &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: hpool},
		Dial: func(ctx context.Context, _ string, tc *tls.Config, qc *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, cfgA.ListenHTTPS, tc, slowQUIC(qc))
		}}}
	resp, err = h3a.Get("https://h1.test/peer")
	if err != nil {
		t.Fatalf("http3 via peer: %v", err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.ProtoMajor != 3 || !strings.HasPrefix(string(b), "node HTTP/3.0 from 127.0.0.1:") || sA.stats.of("h1.test").ViaPeer.Load() != 1 {
		t.Fatalf("http3 via peer: %q via %d", b, sA.stats.of("h1.test").ViaPeer.Load())
	}

	// Liste des Namens gilt auch fuer QUIC
	s.routes.Store(newRoutes(nil, &apiConfig{Hosts: []apiHost{{ID: 1, Name: "h1.test", Mode: 1, UserID: 1, Tunnels: []string{"t1"},
		ACL: &apiACL{Default: "deny", List: []string{"10.0.0.0/8"}}}}}))
	h3b := &http.Client{Timeout: 3 * time.Second, Transport: &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: hpool},
		Dial: func(ctx context.Context, _ string, tc *tls.Config, qc *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, cfg.ListenHTTPS, tc, slowQUIC(qc))
		}}}
	t0 := time.Now()
	if resp, err := h3b.Get("https://h1.test/"); err == nil {
		resp.Body.Close()
		t.Fatal("http3 with deny list answered")
	}
	t.Logf("deny list: refused after %v", time.Since(t0))
}

// slowQUIC: laengere Fristen fuer Tests (UDP auf dem Loopback verliert unter Last Pakete, v. a. unter Windows).
func slowQUIC(qc *quic.Config) *quic.Config {
	c := &quic.Config{}
	if qc != nil {
		c = qc.Clone()
	}
	c.HandshakeIdleTimeout, c.MaxIdleTimeout = 20*time.Second, 30*time.Second
	return c
}
