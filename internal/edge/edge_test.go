package edge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/ipv64net/node64/internal/ports"
)

type fakeCerts struct{ crt map[string]*tls.Certificate }

func (f fakeCerts) ForName(n string) *tls.Certificate { return f.crt[n] }
func (f fakeCerts) ByID(int64) *tls.Certificate       { return nil }

func selfSigned(t *testing.T, names ...string) *tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// freePort sucht einen Port, der fuer TCP und UDP frei ist.
func freePort(t *testing.T) int {
	t.Helper()
	// eigener Bereich unterhalb der Ports, die das System fuer ":0" vergibt: so greifen parallel laufende
	// Testpakete (z. B. DNS64) nicht nach denselben gerade freigegebenen Ports
	for i := 0; i < 200; i++ {
		p := 20000 + mrand.IntN(10000)
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
		if err != nil {
			continue
		}
		ln.Close()
		if pc, err := net.ListenPacket("udp", "127.0.0.1:"+strconv.Itoa(p)); err == nil {
			pc.Close()
			return p
		}
	}
	t.Fatal("no free port")
	return 0
}

func newEdge(t *testing.T, check func(context.Context, []ports.Claim) error) (*Edge, Config) {
	t.Helper()
	cfg := Config{Bind: "127.0.0.1", HTTPPort: freePort(t), HTTPSPort: freePort(t), HTTP3: true, Default: DefaultNotFound}
	crt := selfSigned(t, "app.test", "dns.test")
	e, err := New(cfg, fakeCerts{crt: map[string]*tls.Certificate{"app.test": crt, "dns.test": crt}}, check, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close(context.Background()) })
	return e, cfg
}

// client verbindet immer mit dem Eingang, der Name kommt aus der URL (SNI und Host).
func client(cfg Config, h2 bool) *http.Client {
	addr := "127.0.0.1:" + strconv.Itoa(cfg.HTTPSPort)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: h2, //nolint:gosec // Test
		DialContext: func(ctx context.Context, network, a string) (net.Conn, error) {
			if strings.HasSuffix(a, ":80") {
				a = "127.0.0.1:" + strconv.Itoa(cfg.HTTPPort)
			} else {
				a = addr
			}
			return (&net.Dialer{}).DialContext(ctx, network, a)
		}}
	return &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func get(t *testing.T, c *http.Client, url string, hdr ...string) (int, string, http.Header, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i] == "Host" {
			req.Host = hdr[i+1]
		} else {
			req.Header.Set(hdr[i], hdr[i+1])
		}
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err.Error(), nil, ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header, resp.Proto
}

func running(e *Edge, name string) bool {
	for _, l := range e.Status().Listeners {
		if l.Name == name {
			return l.Running
		}
	}
	return false
}

func TestEdgeRouting(t *testing.T) {
	e, cfg := newEdge(t, nil)
	if running(e, "http") || running(e, "https") || running(e, "http3") {
		t.Fatal("no consumer: no port may be open")
	}
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "app "+r.URL.Path) })
	doh := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "dns") })
	lan := func(ip netip.Addr) bool { return ip.IsPrivate() } // 127.0.0.1 ist nicht privat: wie ein Client aus dem Internet
	if err := e.Set("cdn64", []Route{{Names: []string{"app.test"}, Handler: app, HTTP3: true}}); err != nil {
		t.Fatal(err)
	}
	if err := e.Set("dns64", []Route{{Names: []string{"dns.test"}, Path: "/dns-query", Handler: doh, Allow: lan}}); err != nil {
		t.Fatal(err)
	}
	var taken *NameTakenError
	if err := e.Set("other", []Route{{Names: []string{"APP.test."}, Handler: app}}); !errors.As(err, &taken) || taken.Owner != "cdn64" {
		t.Fatalf("name of another owner: %v", err)
	}
	if !running(e, "http") || !running(e, "https") || !running(e, "http3") {
		t.Fatalf("ports must be open: %+v", e.Status().Listeners)
	}

	c := client(cfg, true)
	code, body, hdr, proto := get(t, c, "https://app.test/x")
	if code != 200 || body != "app /x" || proto != "HTTP/2.0" {
		t.Fatalf("app: %d %q %s", code, body, proto)
	}
	if !strings.Contains(hdr.Get("Alt-Svc"), `h3=":`+strconv.Itoa(cfg.HTTPSPort)+`"`) {
		t.Fatalf("alt-svc missing: %q", hdr.Get("Alt-Svc"))
	}
	// unbekannter Name: neutrale 404
	if code, body, _, _ := get(t, c, "https://unknown.test/"); code != 404 || strings.Contains(strings.ToLower(body), "node64") {
		t.Fatalf("unknown: %d %q", code, body)
	}
	// Name der Verbindung app.test, Host-Kopf dns.test: 421
	if code, _, _, _ := get(t, c, "https://app.test/dns-query", "Host", "dns.test"); code != http.StatusMisdirectedRequest {
		t.Fatalf("misdirected: %d", code)
	}
	// DNS nur aus dem eigenen Netz; ein gefaelschter Kopf aendert daran nichts
	if code, _, _, _ := get(t, c, "https://dns.test/dns-query", "X-Forwarded-For", "192.168.1.5", "X-Real-IP", "192.168.1.5"); code != 404 {
		t.Fatalf("dns from outside must be 404: %d", code)
	}
	// anderer Pfad unter dem DNS-Namen gibt es nicht
	if code, _, _, _ := get(t, c, "https://dns.test/admin"); code != 404 {
		t.Fatalf("dns other path: %d", code)
	}
	// Port 80: Weiterleitung auf HTTPS
	if code, _, hdr, _ := get(t, c, "http://app.test/a?b=1"); code != 301 || hdr.Get("Location") != "https://app.test:"+strconv.Itoa(cfg.HTTPSPort)+"/a?b=1" {
		t.Fatalf("redirect: %d %q", code, hdr.Get("Location"))
	}
	// HTTP/3
	h3 := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "app.test"}} //nolint:gosec // Test
	defer h3.Close()
	req, _ := http.NewRequest(http.MethodGet, "https://127.0.0.1:"+strconv.Itoa(cfg.HTTPSPort)+"/q", nil)
	req.Host = "app.test"
	resp, err := h3.RoundTrip(req)
	if err != nil {
		t.Fatalf("http/3: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != "app /q" || resp.ProtoMajor != 3 {
		t.Fatalf("http/3: %d %q %s", resp.StatusCode, b, resp.Proto)
	}

	// alle abgemeldet: Ports zu und wieder frei
	e.Remove("cdn64")
	if running(e, "http3") {
		t.Fatal("http/3 must close without consumer that wants it")
	}
	e.Remove("dns64")
	e.stopping.Wait()
	if running(e, "http") || running(e, "https") {
		t.Fatal("ports must close")
	}
	if err := ports.Probe(ports.TCP, "127.0.0.1", cfg.HTTPSPort); err != nil {
		t.Fatalf("https port must be free again: %v", err)
	}
}

func TestEdgeDefaultCloseAndHTTP2Off(t *testing.T) {
	e, cfg := newEdge(t, nil)
	cfg.Default = DefaultClose
	if err := e.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	if err := e.Set("cdn64", []Route{{Names: []string{"app.test"}, Handler: app, NoHTTP2: true, MinTLS: tls.VersionTLS13}}); err != nil {
		t.Fatal(err)
	}
	c := client(cfg, true)
	if code, _, _, proto := get(t, c, "https://app.test/"); code != 200 || proto != "HTTP/1.1" {
		t.Fatalf("http/2 off: %d %s", code, proto)
	}
	if code, _, _, _ := get(t, c, "https://unknown.test/"); code != 0 {
		t.Fatalf("unknown name must fail the handshake: %d", code)
	}
	if code, _, _, _ := get(t, c, "http://unknown.test/"); code != 0 {
		t.Fatalf("unknown name on http must close: %d", code)
	}
	old := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}, //nolint:gosec // Test
		DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, "127.0.0.1:"+strconv.Itoa(cfg.HTTPSPort))
		}}, Timeout: 5 * time.Second}
	if code, _, _, _ := get(t, old, "https://app.test/"); code != 0 {
		t.Fatalf("TLS 1.2 must be refused when 1.3 is required: %d", code)
	}
}

func TestEdgePortConflictAndChallenge(t *testing.T) {
	busy := true
	e, cfg := newEdge(t, func(_ context.Context, want []ports.Claim) error {
		for _, w := range want {
			if busy && w.Proto == ports.TCP && w.Purpose == "HTTPS" {
				return &ports.ConflictError{Want: w, With: ports.Claim{Owner: "dns64", Purpose: "DoH", Proto: ports.TCP, Port: w.Port, Active: true}}
			}
		}
		return nil
	})
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	if err := e.Set("cdn64", []Route{{Names: []string{"app.test"}, Handler: app}}); err != nil {
		t.Fatal(err)
	}
	var https ListenerStatus
	for _, l := range e.Status().Listeners {
		if l.Name == "https" {
			https = l
		}
	}
	if https.Running || !strings.Contains(https.Error, "dns64 (DoH)") {
		t.Fatalf("conflict must be reported: %+v", https)
	}
	e.Remove("cdn64")
	e.stopping.Wait()

	// ACME HTTP-01 ohne andere Abnehmer: Port 80 nur fuer die Dauer der Pruefung offen
	release, err := e.Present("tok123", "tok123.key")
	if err != nil {
		t.Fatal(err)
	}
	c := client(cfg, false)
	if code, body, _, _ := get(t, c, "http://any.example/.well-known/acme-challenge/tok123"); code != 200 || body != "tok123.key" {
		t.Fatalf("challenge: %d %q", code, body)
	}
	if code, _, _, _ := get(t, c, "http://any.example/.well-known/acme-challenge/other"); code != 404 {
		t.Fatalf("unknown token: %d", code)
	}
	release()
	e.stopping.Wait()
	if running(e, "http") {
		t.Fatal("port 80 must close after the challenge")
	}
}

func TestNormalizeName(t *testing.T) {
	ok := map[string]string{"Nas.Example.COM.": "nas.example.com", "*.home.ipv64.de": "*.home.ipv64.de", "a-b.x.de": "a-b.x.de"}
	for in, want := range ok {
		if got, err := NormalizeName(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "*.de", "a..b", "-a.de", "a b.de", "*.*.a.de", "a/b.de"} {
		if _, err := NormalizeName(bad); err == nil {
			t.Errorf("%q must be invalid", bad)
		}
	}
}

// Mit der echten Port-Verwaltung, bei der Edge selbst seine Ports meldet: das Oeffnen darf nicht haengen.
func TestEdgeWithRegistry(t *testing.T) {
	reg := ports.New()
	var e *Edge
	e, _ = newEdge(t, func(ctx context.Context, want []ports.Claim) error { return reg.Check(ctx, Owner, want) })
	reg.Provide(Owner, e.Claims)
	reg.Provide("dns64", func(context.Context) []ports.Claim { // fragt wie DNS64 dabei den Eingang (Config)
		return []ports.Claim{{Purpose: "DoH", Proto: ports.TCP, Port: e.Config().HTTPSPort, Active: true}}
	})
	done := make(chan error, 1)
	go func() {
		done <- e.Set("cdn64", []Route{{Names: []string{"app.test"}, Handler: http.NotFoundHandler()}})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Set hangs (edge asks the registry, the registry asks the edge)")
	}
	if running(e, "https") || !running(e, "http") {
		t.Fatalf("https must be refused (DoH has the port), http open: %+v", e.Status().Listeners)
	}
	if ov := reg.Overview(context.Background()); len(ov) == 0 {
		t.Fatal("overview empty")
	}
}

// TLS durchreichen: das Ziel beendet TLS mit seinem eigenen Zertifikat, Edge sieht nur den Namen.
func TestEdgePassthrough(t *testing.T) {
	e, cfg := newEdge(t, nil)
	var opened, released atomic.Int32 // Limits am Eingang: jede Verbindung wird eingehuellt und wieder freigegeben
	e.SetGate(func(netip.Addr) (func(), bool) { opened.Add(1); return func() { released.Add(1) }, true })
	backendCert := selfSigned(t, "pass.test")
	backend := httptestTLS(t, backendCert, "from backend")
	var count atomic.Int32
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "app") })
	if err := e.Set("cdn64", []Route{
		{Names: []string{"pass.test"}, Passthrough: backend, Count: func() { count.Add(1) }},
		{Names: []string{"app.test"}, Handler: app},
	}); err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(cfg.HTTPSPort), &tls.Config{ServerName: "pass.test", InsecureSkipVerify: true}) //nolint:gosec // Test
	if err != nil {
		t.Fatal(err)
	}
	if got := conn.ConnectionState().PeerCertificates[0].Subject.CommonName; got != "pass.test" {
		t.Fatalf("certificate must come from the backend: %q", got)
	}
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: pass.test\r\nConnection: close\r\n\r\n")
	b, _ := io.ReadAll(conn)
	conn.Close()
	if !strings.Contains(string(b), "from backend") || count.Load() != 1 {
		t.Fatalf("passthrough: %q count=%d", b, count.Load())
	}
	// andere Namen weiter ueber den TLS-Server von Edge
	if code, body, _, _ := get(t, client(cfg, true), "https://app.test/"); code != 200 || body != "app" {
		t.Fatalf("normal host next to passthrough: %d %q", code, body)
	}
	if err := e.Set("bad", []Route{{Names: []string{"x.test"}, Passthrough: backend, Handler: app}}); err == nil {
		t.Fatal("passthrough with handler must be refused")
	}
	if opened.Load() == 0 {
		t.Fatal("gate not asked")
	}
	for i := 0; i < 50 && released.Load() < 1; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if released.Load() < 1 {
		t.Fatal("passthrough connection not released")
	}
	e.SetGate(func(netip.Addr) (func(), bool) { return nil, false })
	if c, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(cfg.HTTPSPort), &tls.Config{ServerName: "pass.test", InsecureSkipVerify: true}); err == nil { //nolint:gosec // Test
		c.Close()
		t.Fatal("gate refused, connection must be closed")
	}
}

// gateConn reicht das halbe Schliessen an TCP weiter: die Gegenseite liest EOF, die Antwort kommt noch an.
func TestGateConnCloseWrite(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		b, _ := io.ReadAll(c) // bis EOF
		_, _ = c.Write(append([]byte("got "), b...))
		c.Close()
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var released atomic.Int32
	c := &gateConn{Conn: raw, release: func() { released.Add(1) }}
	_, _ = io.WriteString(c, "ping")
	closeWrite(c)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	b, _ := io.ReadAll(c)
	if string(b) != "got ping" {
		t.Fatalf("half close: %q", b)
	}
	c.Close()
	c.Close()
	if released.Load() != 1 {
		t.Fatalf("released %d times", released.Load())
	}
}

// httptestTLS startet einen TLS-Server mit eigenem Zertifikat und liefert host:port.
func httptestTLS(t *testing.T, crt *tls.Certificate, text string) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*crt}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, text) })}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func TestEdgeDefaultPages(t *testing.T) {
	e, cfg := newEdge(t, nil)
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	if err := e.Set("cdn64", []Route{{Names: []string{"app.test"}, Handler: app}}); err != nil {
		t.Fatal(err)
	}
	bad := cfg
	bad.Default = DefaultRedirect
	if err := e.Configure(bad); err == nil {
		t.Fatal("redirect without url must be refused")
	}
	cfg.Default, cfg.DefaultURL = DefaultRedirect, "https://www.ipv64.net/"
	if err := e.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	c := client(cfg, true)
	if code, _, hdr, _ := get(t, c, "https://unknown.test/x"); code != http.StatusFound || hdr.Get("Location") != "https://www.ipv64.net/" {
		t.Fatalf("redirect: %d %q", code, hdr.Get("Location"))
	}
	cfg.Default, cfg.DefaultPage = DefaultHTML, "<h1>Willkommen</h1>"
	if err := e.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	if code, body, _, _ := get(t, c, "http://unknown.test/"); code != 200 || body != "<h1>Willkommen</h1>" {
		t.Fatalf("html: %d %q", code, body)
	}
	// ungueltige gespeicherte Standardseite setzt nicht die Ports zurueck
	got := LoadConfig(func(k, def string) string {
		switch k {
		case SetHTTPSPort:
			return "8443"
		case SetDefault:
			return DefaultRedirect
		}
		return def
	})
	if got.HTTPSPort != 8443 || got.Default != DefaultNotFound {
		t.Fatalf("load config: %+v", got)
	}
}

// Sofort wieder abmelden (Stop, bevor Serve laeuft): der Port muss danach frei sein.
func TestEdgeStopBeforeServe(t *testing.T) {
	e, cfg := newEdge(t, nil)
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	for i := 0; i < 50; i++ {
		if err := e.Set("cdn64", []Route{{Names: []string{"app.test"}, Handler: app}}); err != nil {
			t.Fatal(err)
		}
		e.Remove("cdn64")
		e.stopping.Wait()
		if err := ports.Probe(ports.TCP, "127.0.0.1", cfg.HTTPPort); err != nil {
			t.Fatalf("round %d: http port still bound: %v", i, err)
		}
		if err := ports.Probe(ports.TCP, "127.0.0.1", cfg.HTTPSPort); err != nil {
			t.Fatalf("round %d: https port still bound: %v", i, err)
		}
	}
}

// Ersatz-Route (DoH per IP) mit eigenem Zertifikat; fremde Clients sehen nur 404.
func TestEdgeFallbackAndOwnCert(t *testing.T) {
	e, cfg := newEdge(t, nil)
	own := selfSigned(t, "dns.lan")
	doh := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "doh") })
	allowLocal := true
	if err := e.Set("dns64", []Route{{Names: []string{"dns.lan"}, Path: "/dns-query", Handler: doh, Fallback: true, NoHTTP: true, HTTP3: true,
		GetCert: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return own, nil }, Allow: func(netip.Addr) bool { return allowLocal }}}); err != nil {
		t.Fatal(err)
	}
	if running(e, "http") || !running(e, "https") || !running(e, "http3") {
		t.Fatalf("only DoH: 443 (TCP+UDP) open, 80 closed: %+v", e.Status().Listeners)
	}
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "app") })
	if err := e.Set("cdn64", []Route{{Names: []string{"app.test"}, Handler: app}}); err != nil {
		t.Fatal(err)
	}
	var taken *NameTakenError
	if err := e.Set("other", []Route{{Path: "/other", Handler: doh, Fallback: true}}); !errors.As(err, &taken) || taken.Owner != "dns64" {
		t.Fatalf("second fallback owner: %v", err)
	}
	if code, _, _, _ := get(t, client(cfg, false), "http://dns.lan/dns-query"); code != 404 {
		t.Fatalf("NoHTTP route must not answer on port 80: %d", code)
	}
	// Aufruf per IP (kein SNI): Zertifikat der Ersatz-Route, DoH antwortet
	conn, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(cfg.HTTPSPort), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // Test
	if err != nil {
		t.Fatal(err)
	}
	if cn := conn.ConnectionState().PeerCertificates[0].Subject.CommonName; cn != "dns.lan" {
		t.Fatalf("fallback certificate: %q", cn)
	}
	conn.Close()
	ipc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 5 * time.Second} //nolint:gosec // Test
	base := "https://127.0.0.1:" + strconv.Itoa(cfg.HTTPSPort)
	if code, body, _, _ := get(t, ipc, base+"/dns-query"); code != 200 || body != "doh" {
		t.Fatalf("doh via ip: %d %q", code, body)
	}
	if code, _, _, _ := get(t, ipc, base+"/admin"); code != 404 {
		t.Fatalf("other path via ip: %d", code)
	}
	// ueber den Namen eines anderen Hosts gibt es kein DoH
	if code, body, _, _ := get(t, client(cfg, true), "https://app.test/dns-query"); code != 200 || body != "app" {
		t.Fatalf("proxy host keeps its path: %d %q", code, body)
	}
	if code, body, _, _ := get(t, client(cfg, true), "https://dns.lan/dns-query"); code != 200 || body != "doh" {
		t.Fatalf("doh via name: %d %q", code, body)
	}
	allowLocal = false
	if code, _, _, _ := get(t, ipc, base+"/dns-query"); code != 404 {
		t.Fatalf("not allowed client: %d", code)
	}
	names := map[string]string{}
	for _, n := range e.Status().Names {
		names[n.Name+n.Path] = n.Owner
	}
	if names["*/dns-query"] != "dns64" {
		t.Fatalf("status: %v", names)
	}
}

// Ersatz-Route nur fuer Port 80 (Hinweisseite von DNS64): antwortet bei unbekanntem Host nur Clients, die Allow
// zulaesst, sonst bleibt die Standardseite; sie vertraegt sich mit einer HTTPS-Ersatz-Route eines anderen Abnehmers.
func TestFallbackHTTPOnly(t *testing.T) {
	e, cfg := newEdge(t, nil)
	ok := func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "doh") }
	if err := e.Set("dns", []Route{{Path: "/dns-query", Handler: http.HandlerFunc(ok), Fallback: true, NoHTTP: true}}); err != nil {
		t.Fatal(err)
	}
	var blocked atomic.Bool
	blocked.Store(true)
	hint := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "gesperrt") })
	if err := e.Set("hint", []Route{{HTTP: hint, Fallback: true, Allow: func(netip.Addr) bool { return blocked.Load() }}}); err != nil {
		t.Fatal(err)
	}
	if err := e.Set("other", []Route{{HTTP: hint, Fallback: true}}); err == nil {
		t.Fatal("second http fallback accepted")
	}
	if err := e.Set("bad", []Route{{Fallback: true}}); err == nil {
		t.Fatal("fallback without handler accepted")
	}
	waitFor(t, func() bool {
		c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(cfg.HTTPPort))
		if err == nil {
			c.Close()
		}
		return err == nil
	})
	c := client(cfg, false)
	defer c.CloseIdleConnections()
	if code, body, _, _ := get(t, c, "http://gesperrt.example/x"); code != 200 || body != "gesperrt" {
		t.Fatalf("blocked client: %d %q", code, body)
	}
	blocked.Store(false)
	if code, body, _, _ := get(t, c, "http://frei.example/x"); code != http.StatusNotFound || body == "gesperrt" {
		t.Fatalf("other client: %d %q", code, body)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timeout")
}
