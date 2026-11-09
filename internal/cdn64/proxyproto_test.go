package cdn64

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/tunnel"
)

// readPP liest einen PROXY-Kopf wie ein Ziel (v1 Text, v2 binaer); "" = kein Kopf.
func readPP(br *bufio.Reader) (src, dst string, err error) {
	first, err := br.Peek(1)
	if err != nil || first[0] != 'P' && first[0] != '\r' {
		return "", "", err // kein Kopf (Daten fangen anders an)
	}
	head, err := br.Peek(12)
	if err != nil {
		return "", "", err
	}
	switch {
	case bytes.HasPrefix(head, []byte("PROXY ")):
		line, err := br.ReadString('\n')
		if err != nil {
			return "", "", err
		}
		f := strings.Fields(line)
		if len(f) != 6 {
			return "", "", errors.New("bad v1: " + line)
		}
		return net.JoinHostPort(f[2], f[4]), net.JoinHostPort(f[3], f[5]), nil
	case bytes.Equal(head, []byte("\r\n\r\n\x00\r\nQUIT\n")):
		h := make([]byte, 16)
		if _, err := io.ReadFull(br, h); err != nil {
			return "", "", err
		}
		body := make([]byte, binary.BigEndian.Uint16(h[14:16]))
		if _, err := io.ReadFull(br, body); err != nil {
			return "", "", err
		}
		n := 4
		if h[13]>>4 == 2 {
			n = 16
		}
		if h[12] != 0x21 || len(body) < 2*n+4 {
			return "", "", errors.New("bad v2")
		}
		a, _ := netip.AddrFromSlice(body[:n])
		b, _ := netip.AddrFromSlice(body[n : 2*n])
		return netip.AddrPortFrom(a, binary.BigEndian.Uint16(body[2*n:])).String(), netip.AddrPortFrom(b, binary.BigEndian.Uint16(body[2*n+2:])).String(), nil
	}
	return "", "", nil
}

// ppEcho: Ziel, das den Kopf liest und mit "src dst daten" antwortet (Kopf fehlt: "- -").
func ppEcho(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				src, dst, err := readPP(br)
				if err != nil {
					_, _ = io.WriteString(c, "error "+err.Error()+"\n")
					return
				}
				if src == "" {
					src, dst = "-", "-"
				}
				if first, _ := br.Peek(1); len(first) == 1 && first[0] == 0x16 { // TLS: ClientHello nach dem Kopf
					sni, data, ok := edge.PeekSNI(brConn{c, br})
					_, _ = io.WriteString(c, src+" "+dst+" sni="+sni+" ok="+strconv.FormatBool(ok)+" len="+strconv.Itoa(len(data))+"\n")
					return
				}
				line, _ := br.ReadString('\n')
				_, _ = io.WriteString(c, src+" "+dst+" "+line)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// brConn liest aus dem Puffer, schreibt auf die Verbindung.
type brConn struct {
	net.Conn
	r *bufio.Reader
}

func (c brConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// clientHello: die erste Nachricht eines TLS-Clients fuer sni.
func clientHello(t *testing.T, sni string) []byte {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() { _ = tls.Client(a, &tls.Config{ServerName: sni, InsecureSkipVerify: true}).Handshake() }() //nolint:gosec // Test
	_ = b.SetDeadline(time.Now().Add(3 * time.Second))
	_, data, ok := edge.PeekSNI(b)
	if !ok {
		t.Fatal("no client hello")
	}
	return data
}

func formReq(v url.Values) *http.Request {
	r := httptest.NewRequest("POST", "/", strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = r.ParseForm()
	return r
}

// Einstellung, Pruefung, Formulare und Vorlagen fuer "TLS durchreichen" und Streams.
func TestProxyProtocolSettings(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	var fe *FieldError
	h := newHostKind(KindPass)
	h.Names, h.TargetHost, h.TargetPort, h.Advanced.ProxyProtocol = []string{"mail.test"}, "127.0.0.1", 993, "v3"
	if err := e.m.saveHost(ctx, h); !errors.As(err, &fe) || fe.Key != "cdn64.err.proxy_protocol" || fe.Field != "proxy_protocol" {
		t.Fatalf("unknown value: %v", err)
	}
	h.Advanced.ProxyProtocol = " V2 "
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	got, _ := e.m.host(ctx, h.ID)
	if got.Advanced.ProxyProtocol != ProxyV2 || e.m.routeFor(got).ProxyProtocol != edge.ProxyV2 || !strings.Contains(got.summary(), "proxy_protocol=v2") {
		t.Fatalf("stored %q route %d", got.Advanced.ProxyProtocol, e.m.routeFor(got).ProxyProtocol)
	}
	p := newHost() // Proxy-Host: der Proxy setzt X-Forwarded-For, kein Kopf
	p.Names, p.TargetHost, p.TargetPort, p.Advanced.ProxyProtocol = []string{"web.test"}, "127.0.0.1", 80, ProxyV1
	if err := e.m.saveHost(ctx, p); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.m.host(ctx, p.ID); got.Advanced.ProxyProtocol != "" || e.m.routeFor(got).ProxyProtocol != 0 {
		t.Fatalf("proxy host keeps %q", got.Advanced.ProxyProtocol)
	}
	// API-JSON: advanced.proxy_protocol
	b, _ := json.Marshal(toAPI(hostRow{Host: got}))
	if !strings.Contains(string(b), `"proxy_protocol":"v2"`) {
		t.Fatalf("api: %s", b)
	}

	// Streams: nur TCP, unbekannte Werte abgewiesen, gespeichert in der Datenbank
	s := &Stream{Enabled: true, ListenPort: freePort(t), UDP: true, TargetHost: "127.0.0.1", TargetPort: 53, ProxyProtocol: ProxyV1}
	if err := e.m.saveStream(ctx, s); !errors.As(err, &fe) || fe.Key != "cdn64.err.stream_proxy_protocol" {
		t.Fatalf("udp: %v", err)
	}
	s.TCP, s.ProxyProtocol = true, "v9"
	if err := e.m.saveStream(ctx, s); !errors.As(err, &fe) || fe.Key != "cdn64.err.proxy_protocol" {
		t.Fatalf("unknown stream value: %v", err)
	}
	s.ProxyProtocol = "V1"
	if err := e.m.saveStream(ctx, s); err != nil {
		t.Fatal(err)
	}
	if gs, err := e.m.stream(ctx, s.ID); err != nil || gs.ProxyProtocol != ProxyV1 || !strings.Contains(gs.summary(), "proxy_protocol=v1") {
		t.Fatalf("stream stored: %v %+v", err, gs)
	}

	// Formulare
	fh := newHostKind(KindPass)
	hostFromForm(formReq(url.Values{"has_pp": {"1"}, "adv_proxy_protocol": {"v1"}}), fh)
	if fh.Advanced.ProxyProtocol != ProxyV1 {
		t.Fatalf("host form: %q", fh.Advanced.ProxyProtocol)
	}
	fs := newStream()
	streamFromForm(formReq(url.Values{"tcp": {"on"}, "has_pp": {"1"}, "proxy_protocol": {"v2"}}), fs)
	if fs.ProxyProtocol != ProxyV2 {
		t.Fatalf("stream form: %q", fs.ProxyProtocol)
	}
	streamFromForm(formReq(url.Values{"udp": {"on"}, "has_pp": {"1"}, "proxy_protocol": {"v2"}}), fs) // ohne TCP: aus
	if fs.ProxyProtocol != ProxyOff {
		t.Fatalf("stream form without tcp: %q", fs.ProxyProtocol)
	}

	// Vorlagen: Auswahl nur bei "TLS durchreichen" bzw. im Stream-Formular (fuer TCP)
	page := aiRender(t, "host_form.html", e.m.form(ctx, got, false))
	if !strings.Contains(page, `name="adv_proxy_protocol"`) || !strings.Contains(page, `<option value="v2" selected>`) || !strings.Contains(page, "cdn64.f.proxy_protocol_hint") {
		t.Fatal("passthrough form misses the proxy protocol")
	}
	pp, _ := e.m.host(ctx, p.ID)
	if page := aiRender(t, "host_form.html", e.m.form(ctx, pp, false)); strings.Contains(page, "adv_proxy_protocol") {
		t.Fatal("proxy host form must not offer the proxy protocol")
	}
	gs, _ := e.m.stream(ctx, s.ID)
	sp := renderPage(t, "stream_form.html", e.m.streamFormData(ctx, gs, false))
	if !strings.Contains(sp, "data-tcp-only") || !strings.Contains(sp, `name="proxy_protocol"`) || !strings.Contains(sp, `<option value="v1" selected>`) {
		t.Fatal("stream form misses the proxy protocol")
	}
}

// TCP-Stream: mit Kopf sieht das Ziel den Besucher und den Port des Streams, ohne Kopf nichts; Umschalten ohne
// Neustart. Aus dem Tunnel (Portmapper) traegt der Kopf die Besucher-Adresse und den Port beim CDN64-Server.
func TestStreamProxyProtocol(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	tport := ppEcho(t)
	sp := freePort(t)
	s := &Stream{Enabled: true, ListenPort: sp, TCP: true, TargetHost: "127.0.0.1", TargetPort: tport}
	if err := e.m.saveStream(ctx, s); err != nil {
		t.Fatal(err)
	}
	send := func() (string, string) {
		t.Helper()
		var c net.Conn
		var err error
		for i := 0; i < 50; i++ {
			if c, err = net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(sp), time.Second); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.WriteString(c, "hi\n")
		line, _ := bufio.NewReader(c).ReadString('\n')
		return strings.TrimSpace(line), c.LocalAddr().String()
	}
	if got, _ := send(); got != "- - hi" {
		t.Fatalf("off: %q", got)
	}
	e.m.smu.Lock()
	run := e.m.runs[s.ID]
	e.m.smu.Unlock()
	for _, v := range []string{ProxyV1, ProxyV2} {
		s.ProxyProtocol = v
		if err := e.m.saveStream(ctx, s); err != nil {
			t.Fatal(err)
		}
		got, me := send()
		if want := me + " 127.0.0.1:" + strconv.Itoa(sp) + " hi"; got != want {
			t.Fatalf("%s: %q, want %q", v, got, want)
		}
	}
	e.m.smu.Lock()
	same := e.m.runs[s.ID] == run
	e.m.smu.Unlock()
	if !same {
		t.Fatal("changing the proxy protocol restarted the stream")
	}

	// aus dem Tunnel: Stream des Servers 192.0.2.77, Besucher-Port 31000 beim Server
	idx := map[portKey]pmRef{{name: "game.test", port: sp}: {stream: s.ID, listen: 31000}}
	e.m.online.portIdx.Store(&idx)
	for _, visitor := range []string{"198.51.100.7:40000", "[2001:db8::7]:40001"} {
		a, b := net.Pipe()
		st := addrStream{pipeStream{b}, &net.UDPAddr{IP: net.ParseIP("192.0.2.77"), Port: 7844}}
		go e.m.onlineHandle(st, tunnel.Header{Kind: tunnel.KindTCP, Host: "game.test", Port: sp, Client: visitor})
		_ = a.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.WriteString(a, "hi\n")
		line, _ := bufio.NewReader(a).ReadString('\n')
		a.Close()
		want := visitor + " 192.0.2.77:31000 hi"
		if strings.HasPrefix(visitor, "[") {
			want = visitor + " [::ffff:192.0.2.77]:31000 hi"
		}
		if strings.TrimSpace(line) != want {
			t.Fatalf("tunnel %s: %q, want %q", visitor, line, want)
		}
	}
	// Erreichbarkeit: nur verbinden und schliessen (das Ziel bekommt weder Kopf noch Daten)
	if r := e.m.probeStream(ctx, s); r.State != ReachUp && r.State != ReachSlow {
		t.Fatalf("probe: %+v", r)
	}
}

// addrStream: Tunnel-Stream mit der Adresse des CDN64-Servers als Gegenstelle.
type addrStream struct {
	pipeStream
	ra net.Addr
}

func (s addrStream) RemoteAddr() net.Addr { return s.ra }

// Ganzer Weg ueber den Tunnel (QUIC wie srv07): "TLS durchreichen" (Modus 1) und ein Portmapper-Stream - der Kopf
// traegt die Besucher-Adresse aus dem Tunnel, nicht die des Servers, und als Ziel den Server mit dem Besucher-Port.
func TestOnlineProxyProtocolEndToEnd(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	tport := ppEcho(t)
	h := newHostKind(KindPass)
	h.Names, h.TargetHost, h.TargetPort, h.Advanced.ProxyProtocol = []string{"mail.test"}, "127.0.0.1", tport, ProxyV2
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	sp := freePort(t)
	s := &Stream{Enabled: true, ListenPort: sp, TCP: true, TargetHost: "127.0.0.1", TargetPort: tport, ProxyProtocol: ProxyV1}
	if err := e.m.saveStream(ctx, s); err != nil {
		t.Fatal(err)
	}
	conf, pool := edgeCert(t)
	peers := make(chan *tunnel.Peer, 4)
	srv := &tunnel.Server{Name: "srv07", TLS: conf, Up: func(p *tunnel.Peer) { peers <- p }, Auth: func(tunnel.Hello) error { return nil }}
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
	// TLS durchreichen: das ClientHello kommt nach dem Kopf; das Ziel antwortet mit den Adressen und der ersten Zeile
	st, err := tunnel.OpenStream(ctx, p, tunnel.Header{Kind: tunnel.KindTLS, Client: "203.0.113.50:40000", Host: "mail.test", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	_ = st.SetDeadline(time.Now().Add(10 * time.Second))
	hello := clientHello(t, "mail.test")
	_, _ = st.Write(hello)
	line, _ := bufio.NewReader(st).ReadString('\n')
	st.Close()
	if want := "203.0.113.50:40000 127.0.0.1:443 sni=mail.test ok=true len=" + strconv.Itoa(len(hello)); strings.TrimSpace(line) != want {
		t.Fatalf("passthrough via tunnel: %q, want %q", line, want)
	}
	// Portmapper-Stream: Port beim Server aus dem Mapping
	idx := map[portKey]pmRef{{name: "mail.test", port: sp}: {stream: s.ID, listen: 31993}}
	e.m.online.portIdx.Store(&idx)
	st, err = tunnel.OpenStream(ctx, p, tunnel.Header{Kind: tunnel.KindTCP, Client: "[2001:db8::50]:40002", Host: "mail.test", Port: sp})
	if err != nil {
		t.Fatal(err)
	}
	_ = st.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(st, "a1 LOGIN\n")
	out, _ := bufio.NewReader(st).ReadString('\n')
	st.Close()
	if strings.TrimSpace(out) != "[2001:db8::50]:40002 [::ffff:127.0.0.1]:31993 a1 LOGIN" {
		t.Fatalf("stream via tunnel: %q", out)
	}
}
