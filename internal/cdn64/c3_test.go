package cdn64

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/ports"
)

func TestRedirectAndDeadHosts(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	r := newHostKind(KindRedirect)
	r.Names, r.RedirectTarget, r.RedirectCode = []string{"old.test"}, "https://www.new.test/start/", 308
	if err := e.m.saveHost(ctx, r); err != nil {
		t.Fatal(err)
	}
	if r.RedirectTarget != "www.new.test/start" || r.TargetHost != "" {
		t.Fatalf("normalized: %+v", r)
	}
	c := e.client(false)
	code, _, hdr := do(t, c, "GET", "http://old.test/a/b?c=1")
	if code != 308 || hdr.Get("Location") != "http://www.new.test/start/a/b?c=1" {
		t.Fatalf("redirect: %d %q", code, hdr.Get("Location"))
	}
	r.PreservePath, r.RedirectScheme = false, "https"
	if err := e.m.saveHost(ctx, r); err != nil {
		t.Fatal(err)
	}
	if code, _, hdr := do(t, c, "GET", "http://old.test/a"); code != 308 || hdr.Get("Location") != "https://www.new.test/start" {
		t.Fatalf("redirect without path: %d %q", code, hdr.Get("Location"))
	}
	self := newHostKind(KindRedirect)
	self.Names, self.RedirectTarget = []string{"loop.test"}, "loop.test/x"
	var fe *FieldError
	if err := e.m.saveHost(ctx, self); !errors.As(err, &fe) || fe.Key != "cdn64.err.redirect_self" {
		t.Fatalf("self redirect: %v", err)
	}
	bad := newHostKind(KindRedirect)
	bad.Names, bad.RedirectTarget, bad.RedirectCode = []string{"bad.test"}, "x.test", 304
	if err := e.m.saveHost(ctx, bad); !errors.As(err, &fe) || fe.Field != "redirect_code" {
		t.Fatalf("bad code: %v", err)
	}
	d := newHostKind(KindDead)
	d.Names = []string{"gone.test"}
	if err := e.m.saveHost(ctx, d); err != nil {
		t.Fatal(err)
	}
	if code, body, _ := do(t, c, "GET", "http://gone.test/"); code != 404 || !strings.Contains(body, "404") {
		t.Fatalf("dead: %d %q", code, body)
	}
}

func TestPassthroughHost(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	certPEM, keyPEM := selfSigned(t, "nas.test")
	crt, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{crt}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "nas itself") })}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	h := newHostKind(KindPass)
	h.Names, h.TargetHost, h.TargetPort = []string{"nas.test"}, "127.0.0.1", port
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if h.HTTPS() || h.CertID != CertNone {
		t.Fatalf("passthrough terminates nothing here: %+v", h)
	}
	code, body, _ := do(t, e.client(true), "GET", "https://nas.test/")
	if code != 200 || body != "nas itself" {
		t.Fatalf("passthrough: %d %q", code, body)
	}
	if code, _, hdr := do(t, e.client(false), "GET", "http://nas.test/x"); code != 301 || !strings.HasPrefix(hdr.Get("Location"), "https://nas.test") {
		t.Fatalf("http to https: %d %q", code, hdr.Get("Location"))
	}
	if r := e.m.probe(ctx, h); r.State != ReachUp {
		t.Fatalf("reach: %+v", r)
	}
	if n := e.m.statsOf(h.ID).requests.Load(); n != 1 {
		t.Fatalf("passthrough connections counted: %d", n)
	}
	w := newHostKind(KindPass)
	w.Names, w.TargetHost, w.TargetPort = []string{"*.wild.test"}, "127.0.0.1", port
	var fe *FieldError
	if err := e.m.saveHost(ctx, w); !errors.As(err, &fe) || fe.Key != "cdn64.err.pass_wildcard" {
		t.Fatalf("wildcard passthrough: %v", err)
	}
}

// echoTCP antwortet zeilenweise mit "echo:<zeile>".
func echoTCP(t *testing.T) int {
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
			go func(c net.Conn) {
				defer c.Close()
				sc := bufio.NewScanner(c)
				for sc.Scan() {
					_, _ = io.WriteString(c, "echo:"+sc.Text()+"\n")
				}
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func echoUDP(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(append([]byte("echo:"), b[:n]...), a)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func TestStreams(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	reg := ports.New()
	reg.Provide(Name, e.m.Claims)
	reg.Provide(edge.Owner, e.edge.Claims)
	busy := freePort(t)
	reg.Provide("dns64", func(context.Context) []ports.Claim {
		return []ports.Claim{{Purpose: "DNS", Proto: ports.UDP, Port: busy, Active: true}}
	})
	e.m.SetPorts(reg)
	e.enable(t)
	tcpPort, udpPort := echoTCP(t), echoUDP(t)
	listen := freePort(t)
	s := newStream()
	s.Name, s.ListenPort, s.TCP, s.UDP, s.TargetHost, s.TargetPort = "echo", listen, true, false, "127.0.0.1", tcpPort
	if err := e.m.saveStream(ctx, s); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(listen), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(conn, "hallo\n")
	line, _ := bufio.NewReader(conn).ReadString('\n')
	conn.Close()
	if line != "echo:hallo\n" {
		t.Fatalf("tcp stream: %q", line)
	}
	// UDP auf einem eigenen Port
	us := newStream()
	us.ListenPort, us.TCP, us.UDP, us.TargetHost, us.TargetPort = freePort(t), false, true, "127.0.0.1", udpPort
	if err := e.m.saveStream(ctx, us); err != nil {
		t.Fatal(err)
	}
	uc, err := net.Dial("udp", "127.0.0.1:"+strconv.Itoa(us.ListenPort))
	if err != nil {
		t.Fatal(err)
	}
	_ = uc.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = uc.Write([]byte("ping"))
	b := make([]byte, 64)
	n, err := uc.Read(b)
	uc.Close()
	if err != nil || string(b[:n]) != "echo:ping" {
		t.Fatalf("udp stream: %q %v", b[:n], err)
	}
	// Port gehoert schon einem anderen Teil: gespeichert, aber nicht offen, mit Grund
	bs := newStream()
	bs.ListenPort, bs.TCP, bs.UDP, bs.TargetHost, bs.TargetPort = busy, false, true, "127.0.0.1", udpPort
	if err := e.m.saveStream(ctx, bs); err != nil {
		t.Fatal(err)
	}
	if errs := e.m.streamErrs(bs.ID); !strings.Contains(errs["udp"], "dns64") {
		t.Fatalf("conflict with dns64: %v", errs)
	}
	// Ports des Eingangs und doppelte Ports werden gar nicht erst gespeichert
	var fe *FieldError
	es := newStream()
	es.ListenPort, es.TargetHost, es.TargetPort = e.cfg.HTTPSPort, "127.0.0.1", 1
	if err := e.m.saveStream(ctx, es); !errors.As(err, &fe) || fe.Key != "cdn64.err.stream_port_edge" {
		t.Fatalf("edge port: %v", err)
	}
	ds := newStream()
	ds.ListenPort, ds.TargetHost, ds.TargetPort = listen, "127.0.0.1", 1
	if err := e.m.saveStream(ctx, ds); !errors.As(err, &fe) || fe.Key != "cdn64.err.stream_port_taken" {
		t.Fatalf("duplicate port: %v", err)
	}
	// Uebersicht: aktive Ports der Streams
	active := 0
	for _, c := range reg.All(ctx) {
		if c.Owner == Name && c.Active {
			active++
		}
	}
	if active != 2 {
		t.Fatalf("active stream ports: %d", active)
	}
	st := e.m.streamStatsOf(s.ID)
	for i := 0; i < 100 && st.bytesIn.Load() == 0; i++ { // Zaehler kommen, wenn die Verbindung zu ist
		time.Sleep(20 * time.Millisecond)
	}
	if st.conns.Load() != 1 || st.bytesIn.Load() != 6 {
		t.Fatalf("stats: %d conns, %d bytes", st.conns.Load(), st.bytesIn.Load())
	}
	// ausschalten schliesst den Port
	if err := e.m.setStreamEnabled(ctx, s.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := ports.Probe(ports.TCP, "", listen); err != nil {
		t.Fatalf("port must be free after disabling: %v", err)
	}
	// Modul aus: alle Streams zu
	if err := e.reg.Disable(ctx, Name); err != nil {
		t.Fatal(err)
	}
	if err := ports.Probe(ports.UDP, "", us.ListenPort); err != nil {
		t.Fatalf("udp port must be free after module stop: %v", err)
	}
	if len(e.m.Claims(ctx)) != 0 {
		t.Fatal("no claims while stopped")
	}
}

func TestStreamTLS(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	certPEM, keyPEM := selfSigned(t, "mqtt.test")
	c, err := e.crt.Upload(ctx, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	s := newStream()
	s.ListenPort, s.TargetHost, s.TargetPort, s.TLSCertID = freePort(t), "127.0.0.1", echoTCP(t), c.ID
	if err := e.m.saveStream(ctx, s); err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(s.ListenPort), &tls.Config{ServerName: "mqtt.test", InsecureSkipVerify: true}) //nolint:gosec // Test
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if cn := conn.ConnectionState().PeerCertificates[0].Subject.CommonName; cn != "mqtt.test" {
		t.Fatalf("cert: %q", cn)
	}
	_, _ = io.WriteString(conn, "x\n")
	line, _ := bufio.NewReader(conn).ReadString('\n')
	if line != "echo:x\n" {
		t.Fatalf("tls stream: %q", line)
	}
	us := newStream()
	us.ListenPort, us.TCP, us.UDP, us.TargetHost, us.TargetPort, us.TLSCertID = freePort(t), false, true, "127.0.0.1", 1, c.ID
	var fe *FieldError
	if err := e.m.saveStream(ctx, us); !errors.As(err, &fe) || fe.Field != "tls_cert_id" {
		t.Fatalf("tls on udp: %v", err)
	}
}

func TestDefaultPage(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"a.test"}, "127.0.0.1", 9, CertNone
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.saveDefault(ctx, "redirect", "ftp://x", ""); err == nil {
		t.Fatal("invalid redirect url must be refused")
	}
	if _, err := e.m.saveDefault(ctx, "html", "", "<p>Hallo</p>"); err != nil {
		t.Fatal(err)
	}
	if code, body, _ := do(t, e.client(false), "GET", "http://other.test/"); code != 200 || body != "<p>Hallo</p>" {
		t.Fatalf("default html: %d %q", code, body)
	}
	if got := edge.LoadConfig(func(k, def string) string { return e.st.SettingOr(ctx, k, def) }); got.Default != "html" || got.DefaultPage != "<p>Hallo</p>" {
		t.Fatalf("stored: %+v", got)
	}
}
