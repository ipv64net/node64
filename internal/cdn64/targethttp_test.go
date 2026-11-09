package cdn64

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/ipv64net/node64/internal/edge"
)

// HTTP/2 zum Ziel (#53): automatisch (h2 per ALPN bei https), nur HTTP/1.1, h2c; gRPC mit Trailern und Streams in
// beide Richtungen, lokal und wie CDN64 Modus 2 (HTTP/1.1 durch den Tunnel); WebSockets bleiben HTTP/1.1.

// h2Targets: ein http-Ziel mit HTTP/1.1 und h2c (Vorwissen) und ein https-Ziel mit h2 per ALPN; beide antworten
// mit "<ProtoMajor> <TLS>", /ws ist ein WebSocket-Echo, /svc.Echo/Bidi ein gRPC-aehnlicher Echo-Stream.
func h2Targets(t *testing.T) (plain, tlsPort int) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "%d %v", r.ProtoMajor, r.TLS != nil)
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		if typ, b, err := c.Read(r.Context()); err == nil {
			_ = c.Write(r.Context(), typ, append([]byte("echo:"+strconv.Itoa(r.ProtoMajor)+":"), b...))
		}
	})
	mux.HandleFunc("/svc.Echo/Bidi", grpcEcho)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := new(http.Protocols)
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	srv := &http.Server{Handler: mux, Protocols: p, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	ts := httptest.NewUnstartedServer(mux)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)
	u, _ := url.Parse(ts.URL)
	tlsPort, _ = strconv.Atoi(u.Port())
	return ln.Addr().(*net.TCPAddr).Port, tlsPort
}

// grpcEcho: wie ein gRPC-Server - nur HTTP/2, sofort eine Nachricht, dann jede Zeile des Bodys als Echo (waehrend
// der Body noch laeuft), am Ende die Trailer grpc-status und grpc-message (nicht angekuendigt, wie grpc-go).
func grpcEcho(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor != 2 || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
		http.Error(w, "grpc needs http/2", http.StatusHTTPVersionNotSupported)
		return
	}
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "hello "+r.Header.Get("Te")+"\n")
	_ = rc.Flush()
	br := bufio.NewReader(r.Body)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		_, _ = io.WriteString(w, "echo:"+line)
		_ = rc.Flush()
	}
	w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	w.Header().Set(http.TrailerPrefix+"Grpc-Message", "done")
}

// h2Host: Host app.test mit Zertifikat (HTTPS ueber den Eingang).
func h2Host(t *testing.T, e *env) *Host {
	t.Helper()
	certPEM, keyPEM := selfSigned(t, "app.test")
	if _, err := e.crt.Upload(context.Background(), certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	h := newHost()
	h.Names, h.TargetHost = []string{"app.test"}, "127.0.0.1"
	return h
}

func TestTargetHTTPModes(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	plain, tlsPort := h2Targets(t)
	h := h2Host(t, e)
	c := e.client(true)
	for _, x := range []struct {
		scheme  string
		mode    string
		timeout int
		want    string
	}{
		{"https", "", 0, "2 true"}, // automatisch: h2 per ALPN
		{"https", "auto", 0, "2 true"},
		{"https", "h1", 0, "1 true"},
		{"https", "h2c", 0, "2 true"}, // https: nur HTTP/2
		{"https", "h1", 30, "1 true"}, // eigener Transport (Timeout) mit Protokoll
		{"https", "", 30, "2 true"},   // ... nach dem Speichern neu gebaut
		{"http", "", 0, "1 false"},    // http-Ziel: automatisch bleibt HTTP/1.1
		{"http", "h1", 0, "1 false"},
		{"http", "h2c", 0, "2 false"}, // h2c mit Vorwissen
		{"http", "h2c", 30, "2 false"},
		{"http", "", 0, "1 false"}, // zurueck
	} {
		h.Scheme, h.TargetPort = x.scheme, plain
		if x.scheme == "https" {
			h.TargetPort = tlsPort
		}
		h.Advanced.TargetHTTP, h.Advanced.TimeoutSeconds = x.mode, x.timeout
		if err := e.m.saveHost(ctx, h); err != nil {
			t.Fatal(err)
		}
		if code, body, _ := do(t, c, "GET", "https://app.test/"); code != 200 || body != x.want {
			t.Errorf("%s %q timeout %d: %d %q, want %q", x.scheme, x.mode, x.timeout, code, body, x.want)
		}
		if r := e.m.probe(ctx, h); r.State == ReachDown {
			t.Errorf("%s %q: reach %+v", x.scheme, x.mode, r)
		}
	}
	if got, _ := e.m.host(ctx, h.ID); got.Advanced.TargetHTTP != "" {
		t.Fatalf("stored: %q", got.Advanced.TargetHTTP)
	}
}

// Location vor Host (Host h1, Location h2c bzw. automatisch, leer = wie der Host); unbekannte Werte abgewiesen.
func TestTargetHTTPLocations(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	plain, tlsPort := h2Targets(t)
	h := h2Host(t, e)
	h.Scheme, h.TargetPort, h.Advanced.TargetHTTP = "https", tlsPort, " H1 "
	h.Locations = []Location{
		{Path: "/grpc", Scheme: "http", TargetHost: "127.0.0.1", TargetPort: plain, Advanced: &LocationAdvanced{TargetHTTP: "h2c"}},
		{Path: "/auto", Scheme: "https", TargetHost: "127.0.0.1", TargetPort: tlsPort, Advanced: &LocationAdvanced{TargetHTTP: "auto"}},
		{Path: "/timeout", Scheme: "https", TargetHost: "127.0.0.1", TargetPort: tlsPort, Advanced: &LocationAdvanced{TimeoutSeconds: 20}},
		{Path: "/like", Scheme: "https", TargetHost: "127.0.0.1", TargetPort: tlsPort},
	}
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	got, _ := e.m.host(ctx, h.ID)
	if got.Advanced.TargetHTTP != "h1" || got.Locations[0].Advanced.TargetHTTP != "h2c" || got.Locations[1].Advanced.TargetHTTP != "auto" {
		t.Fatalf("stored: %q %+v", got.Advanced.TargetHTTP, got.Locations)
	}
	form := aiRender(t, "host_form.html", e.m.form(ctx, got, false))
	for _, want := range []string{`<option value="h1" selected>`, `name="loc_0_target_http"`, `<option value="h2c" selected>`, `<option value="auto" selected>`} {
		if !strings.Contains(form, want) {
			t.Errorf("form misses %s", want)
		}
	}
	c := e.client(true)
	for p, want := range map[string]string{"/": "1 true", "/grpc/x": "2 false", "/auto": "2 true", "/timeout": "1 true", "/like": "1 true"} {
		if code, body, _ := do(t, c, "GET", "https://app.test"+p); code != 200 || body != want {
			t.Errorf("%s: %d %q, want %q", p, code, body, want)
		}
	}
	var fe *FieldError
	b := h2Host(t, e)
	b.Names = []string{"bad.test"}
	b.Advanced.TargetHTTP = "h3"
	if err := e.m.saveHost(ctx, b); !errors.As(err, &fe) || fe.Field != "advanced" || fe.Key != "cdn64.err.target_http" {
		t.Fatalf("host h3: %v", err)
	}
	b.Advanced.TargetHTTP = "auto" // beim Host = automatisch
	b.Locations = []Location{{Path: "/x", Scheme: "http", TargetHost: "127.0.0.1", TargetPort: plain, Advanced: &LocationAdvanced{TargetHTTP: "http2"}}}
	if err := e.m.saveHost(ctx, b); !errors.As(err, &fe) || fe.Field != "locations" || fe.Key != "cdn64.err.target_http" {
		t.Fatalf("location http2: %v", err)
	}
	b.Locations = nil
	if err := e.m.saveHost(ctx, b); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.m.host(ctx, b.ID); got.Advanced.TargetHTTP != "" {
		t.Fatalf("auto stored as %q", got.Advanced.TargetHTTP)
	}
	// Formular: Host- und Location-Auswahl
	r := httptest.NewRequest("POST", "/", strings.NewReader(url.Values{"has_advanced": {"1"}, "adv_target_http": {"h2c"}, "has_locations": {"1"},
		"loc_count": {"1"}, "loc_0_path": {"/api"}, "loc_0_scheme": {"http"}, "loc_0_host": {"127.0.0.1"}, "loc_0_port": {"80"},
		"loc_0_target_http": {"h1"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = r.ParseForm()
	f := newHost()
	hostFromForm(r, f)
	if f.Advanced.TargetHTTP != "h2c" || len(f.Locations) != 1 || f.Locations[0].Advanced == nil || f.Locations[0].Advanced.TargetHTTP != "h1" {
		t.Fatalf("form: %q %+v", f.Advanced.TargetHTTP, f.Locations)
	}
}

// WebSockets bleiben HTTP/1.1 - auch bei einem https-Ziel mit h2 (automatisch und nur HTTP/2) und bei h2c.
func TestTargetHTTPWebSocket(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	e := newEnv(t)
	e.enable(t)
	plain, tlsPort := h2Targets(t)
	h := h2Host(t, e)
	for _, x := range []struct{ scheme, mode string }{{"https", ""}, {"https", "h2c"}, {"http", "h2c"}, {"https", "h1"}} {
		h.Scheme, h.TargetPort, h.Advanced.TargetHTTP = x.scheme, plain, x.mode
		if x.scheme == "https" {
			h.TargetPort = tlsPort
		}
		if err := e.m.saveHost(ctx, h); err != nil {
			t.Fatal(err)
		}
		conn, _, err := websocket.Dial(ctx, "wss://app.test/ws", &websocket.DialOptions{HTTPClient: e.client(false)})
		if err != nil {
			t.Fatalf("%s %q: websocket: %v", x.scheme, x.mode, err)
		}
		if err := conn.Write(ctx, websocket.MessageText, []byte("hi")); err != nil {
			t.Fatal(err)
		}
		if _, b, err := conn.Read(ctx); err != nil || string(b) != "echo:1:hi" {
			t.Fatalf("%s %q: websocket echo: %q %v", x.scheme, x.mode, b, err)
		}
		conn.CloseNow()
	}
}

// grpcCall: POST application/grpc mit Body als Stream - erst nach der ersten Antwort-Nachricht den naechsten Teil
// senden (beweist Streaming in beide Richtungen), Daten stueckweise, Trailer am Ende, nichts komprimiert.
func grpcCall(t *testing.T, c *http.Client, u, host string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pr, pw := io.Pipe()
	defer pw.Close()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, u, pr)
	req.Host = host
	req.Header.Set("Content-Type", "application/grpc+json") // "json": waere ohne Ausnahme komprimierbar
	req.Header.Set("TE", "trailers")
	req.Header.Set("Accept-Encoding", "gzip, br, zstd")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("grpc: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.ProtoMajor != 2 || resp.Header.Get("Content-Encoding") != "" || resp.Header.Get("Content-Type") != "application/grpc+json" {
		t.Fatalf("grpc response: %d proto %d enc %q type %q", resp.StatusCode, resp.ProtoMajor, resp.Header.Get("Content-Encoding"), resp.Header.Get("Content-Type"))
	}
	br := bufio.NewReader(resp.Body)
	read := func(want string) {
		t.Helper()
		line, err := br.ReadString('\n')
		if err != nil || line != want {
			t.Fatalf("grpc stream: %q %v, want %q", line, err, want)
		}
	}
	read("hello trailers\n") // vor dem ersten Teil des Bodys
	for _, m := range []string{"a\n", "b\n", "c\n"} {
		if _, err := io.WriteString(pw, m); err != nil {
			t.Fatal(err)
		}
		read("echo:" + m)
	}
	_ = pw.Close()
	if rest, err := io.ReadAll(br); err != nil || len(rest) != 0 {
		t.Fatalf("grpc end: %q %v", rest, err)
	}
	if resp.Trailer.Get("Grpc-Status") != "0" || resp.Trailer.Get("Grpc-Message") != "done" {
		t.Fatalf("grpc trailer: %v", resp.Trailer)
	}
}

// gRPC ueber PROXY64 mit allem, was die Antwort umhuellt (Komprimierung, Cache, Exploit-Sperre, eigene Fehlerseite,
// Upload-Grenze, Ziel-Limits): lokal per HTTP/2 und wie CDN64 Modus 2 (Client -> CDN64-Server per HTTP/2, von dort
// HTTP/1.1 durch den Tunnel, Node -> Ziel per h2c bzw. h2).
func TestTargetHTTPGRPC(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	plain, tlsPort := h2Targets(t)
	h := h2Host(t, e)
	h.BlockExploits, h.CacheAssets = true, true
	h.Advanced.Gzip, h.Advanced.MaxBodyMB, h.Advanced.ErrorOverride, h.Advanced.ErrorHTML = true, 10, true, "<p>{{STATUS}}</p>"
	// wie der CDN64-Server (internal/cdnedge/terminate.go): HTTP/2 zum Besucher, je Anfrage ein Stream mit HTTP/1.1
	// zur Node (edge.PortTerminated), sofort weiterreichen
	tr := &http.Transport{DisableKeepAlives: true, ExpectContinueTimeout: time.Second, DialContext: func(context.Context, string, string) (net.Conn, error) {
		served, cl := tunnelPair(t)
		e.edge.ServeConnFor(served, edge.PortTerminated, "app.test")
		return cl, nil
	}}
	frontend := func(tr *http.Transport) (*httptest.Server, *http.Client) {
		front := httptest.NewUnstartedServer(&httputil.ReverseProxy{Transport: tr, FlushInterval: -1, Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme, pr.Out.URL.Host, pr.Out.Host = "http", pr.In.Host, pr.In.Host
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
		}})
		front.EnableHTTP2 = true
		front.StartTLS()
		t.Cleanup(front.Close)
		return front, front.Client()
	}
	front, fc := frontend(tr)
	// mit Keep-Alive (ohne "Connection: close"): Streaming in beide Richtungen nur dank EnableFullDuplex der Node
	ka := tr.Clone()
	ka.DisableKeepAlives = false
	frontKA, fcKA := frontend(ka)
	for _, x := range []struct{ scheme, mode string }{{"http", "h2c"}, {"https", ""}} {
		h.Scheme, h.TargetPort, h.Advanced.TargetHTTP = x.scheme, plain, x.mode
		if x.scheme == "https" {
			h.TargetPort = tlsPort
		}
		if err := e.m.saveHost(ctx, h); err != nil {
			t.Fatal(err)
		}
		t.Run(x.scheme+"-local", func(t *testing.T) { grpcCall(t, e.client(true), "https://app.test/svc.Echo/Bidi", "app.test") })
		t.Run(x.scheme+"-mode2", func(t *testing.T) { grpcCall(t, fc, front.URL+"/svc.Echo/Bidi", "app.test") })
		t.Run(x.scheme+"-mode2-keepalive", func(t *testing.T) { grpcCall(t, fcKA, frontKA.URL+"/svc.Echo/Bidi", "app.test") })
	}
	// ohne h2c: das Ziel bekommt HTTP/1.1 und lehnt ab (wie ein echter gRPC-Server); die eigene Fehlerseite bleibt aus
	h.Scheme, h.TargetPort, h.Advanced.TargetHTTP = "http", plain, ""
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, "https://app.test/svc.Echo/Bidi", strings.NewReader("a\n"))
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := e.client(true).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusHTTPVersionNotSupported || strings.Contains(string(b), "<p>") {
		t.Fatalf("grpc over http/1.1: %d %q", resp.StatusCode, b)
	}
}

// tunnelPair: Verbindung wie aus dem Tunnel (RemoteAddr = Besucher) und die Gegenseite fuer den CDN64-Server.
func tunnelPair(t *testing.T) (served, client net.Conn) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Error(err)
		return nil, nil
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); ch <- c }()
	cl, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Error(err)
		return nil, nil
	}
	return &visitorConn{Conn: <-ch, ra: net.TCPAddrFromAddrPort(netip.MustParseAddrPort("203.0.113.20:4000"))}, cl
}
