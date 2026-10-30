package cdn64

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

type env struct {
	mux  *http.ServeMux
	m    *Module
	reg  *module.Registry
	edge *edge.Edge
	cfg  edge.Config
	crt  *certs.Manager
	st   *store.Store
}

// freePortUsed: schon vergebene Ports - nie zweimal ausgeben (z. B. Edge-Ports, die erst spaeter geoeffnet werden).
var (
	freePortMu   sync.Mutex
	freePortUsed = map[int]bool{}
)

func freePort(t *testing.T) int {
	t.Helper()
	freePortMu.Lock()
	defer freePortMu.Unlock()
	// eigener Bereich unterhalb der Ports, die das System fuer ":0" vergibt: so greifen parallel laufende
	// Testpakete (z. B. DNS64) nicht nach denselben gerade freigegebenen Ports
	for i := 0; i < 200; i++ {
		p := 20000 + mrand.IntN(10000)
		if freePortUsed[p] {
			continue
		}
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
		if err != nil {
			continue
		}
		ln.Close()
		if pc, err := net.ListenPacket("udp", "127.0.0.1:"+strconv.Itoa(p)); err == nil {
			pc.Close()
			freePortUsed[p] = true
			return p
		}
	}
	t.Fatal("no free port")
	return 0
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(ctx, filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cm, _ := store.CoreMigrations()
	if err := st.Migrate(ctx, "core", cm); err != nil {
		t.Fatal(err)
	}
	ms, _ := certs.Migrations()
	if err := st.Migrate(ctx, "certs", ms); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	box, _ := secrets.New(key)
	cm2, err := certs.New(ctx, certs.Deps{Store: st, Box: box, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cm2.Close)
	cfg := edge.Config{Bind: "127.0.0.1", HTTPPort: freePort(t), HTTPSPort: freePort(t), HTTP3: true, Default: edge.DefaultNotFound}
	e, err := edge.New(cfg, cm2, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close(context.Background()) })
	m := New(st, log, e, cm2, "test")
	reg := module.NewRegistry(st, log)
	reg.Register(m)
	mux := http.NewServeMux()
	pass := func(h http.Handler) http.Handler { return h }
	reg.Routes(mux, http.NotFoundHandler(), module.Guards{Auth: pass, Audit: func(*http.Request, string, string, string) {},
		Translate: func(_, key string, _ ...any) string { return key }})
	reg.StartEnabled(ctx)
	t.Cleanup(reg.StopAll)
	return &env{mux: mux, m: m, reg: reg, edge: e, cfg: cfg, crt: cm2, st: st}
}

func (e *env) enable(t *testing.T) {
	t.Helper()
	if err := e.reg.Enable(context.Background(), Name); err != nil {
		t.Fatal(err)
	}
}

func running(e *edge.Edge, name string) bool {
	for _, l := range e.Status().Listeners {
		if l.Name == name {
			return l.Running
		}
	}
	return false
}

func selfSigned(t *testing.T, names ...string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(60 * 24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	kd, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}))
}

// client verbindet immer mit dem Eingang; Name aus der URL (SNI, Host).
func (e *env) client(h2 bool) *http.Client {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: h2, //nolint:gosec // Test
		DialContext: func(ctx context.Context, network, a string) (net.Conn, error) {
			port := e.cfg.HTTPSPort
			if strings.HasSuffix(a, ":80") {
				port = e.cfg.HTTPPort
			}
			return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:"+strconv.Itoa(port))
		}}
	return &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func do(t *testing.T, c *http.Client, method, u string, hdr ...string) (int, string, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(method, u, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err.Error(), nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func TestLifecycleAndPorts(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	var n int
	_ = e.st.Reader().QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name = 'cdn_hosts'`).Scan(&n)
	if e.reg.IsRunning(Name) || n != 0 {
		t.Fatal("disabled module must not run or create tables")
	}
	e.enable(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"plain.test"}, "127.0.0.1", 9, CertNone
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if !running(e.edge, "http") || running(e.edge, "https") {
		t.Fatalf("HTTP-only host: only port 80 must be open: %+v", e.edge.Status().Listeners)
	}
	if err := e.reg.Disable(ctx, Name); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if running(e.edge, "http") || len(e.edge.Status().Names) != 0 {
		t.Fatal("disabled module: no routes, ports closed")
	}
}

func TestValidation(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	base := func() *Host {
		h := newHost()
		h.Names, h.TargetHost, h.TargetPort = []string{"a.test"}, "192.168.1.5", 80
		return h
	}
	cases := map[string]func(h *Host){
		"names":       func(h *Host) { h.Names = []string{"bad name"} },
		"scheme":      func(h *Host) { h.Scheme = "ftp" },
		"target_host": func(h *Host) { h.TargetHost = "http://x" },
		"target_port": func(h *Host) { h.TargetPort = 70000 },
		"cert_id":     func(h *Host) { h.CertID = 99 },
	}
	for field, mod := range cases {
		h := base()
		mod(h)
		var fe *FieldError
		if err := e.m.saveHost(ctx, h); !errors.As(err, &fe) || fe.Field != field {
			t.Errorf("%s: %v", field, err)
		}
	}
	h := base()
	h.Names, h.TargetHost = []string{"A.test", "b.test."}, "[FD00::1]"
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if h.TargetHost != "fd00::1" || strings.Join(h.Names, ",") != "a.test,b.test" || h.Target() != "http://[fd00::1]:80" {
		t.Fatalf("normalized: %+v", h)
	}
	dup := base()
	dup.Names = []string{"b.test"}
	var fe *FieldError
	if err := e.m.saveHost(ctx, dup); !errors.As(err, &fe) || fe.Key != "cdn64.err.name_taken" || fe.Name != "b.test" {
		t.Fatalf("duplicate name: %v", err)
	}
	h.CertID, h.ForceSSL, h.HSTS = CertNone, true, true
	if err := e.m.saveHost(ctx, h); err != nil || h.ForceSSL || h.HSTS {
		t.Fatalf("HTTP-only host keeps no HTTPS options: %v %+v", err, h)
	}
}

func TestProxyThroughEdge(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	var assets atomic.Int64
	var seen atomic.Value
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/ws":
			c, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer c.CloseNow()
			typ, b, err := c.Read(r.Context())
			if err == nil {
				_ = c.Write(r.Context(), typ, append([]byte("echo:"), b...))
			}
		case strings.HasSuffix(r.URL.Path, ".css"):
			assets.Add(1)
			w.Header().Set("Content-Type", "text/css")
			_, _ = io.WriteString(w, "body{}")
		default:
			b, _ := json.Marshal(map[string]string{"host": r.Host, "xff": r.Header.Get("X-Forwarded-For"), "real": r.Header.Get("X-Real-IP"),
				"proto": r.Header.Get("X-Forwarded-Proto"), "fhost": r.Header.Get("X-Forwarded-Host")})
			seen.Store(string(b))
			_, _ = w.Write(b)
		}
	}))
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)
	bport, _ := strconv.Atoi(bu.Port())
	certPEM, keyPEM := selfSigned(t, "app.test")
	if _, err := e.crt.Upload(ctx, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort = []string{"app.test"}, "127.0.0.1", bport
	h.BlockExploits, h.CacheAssets, h.ForceSSL, h.HSTS, h.HSTSSubdomains = true, true, true, true, true
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	c := e.client(true)

	code, body, hdr := do(t, c, "GET", "https://app.test/x", "X-Forwarded-For", "6.6.6.6", "X-Real-IP", "6.6.6.6")
	var got map[string]string
	_ = json.Unmarshal([]byte(body), &got)
	if code != 200 || got["host"] != "app.test" || got["xff"] != "127.0.0.1" || got["real"] != "127.0.0.1" || got["proto"] != "https" || got["fhost"] != "app.test" {
		t.Fatalf("proxied: %d %v", code, got)
	}
	if hdr.Get("Strict-Transport-Security") != "max-age=63072000; includeSubDomains" {
		t.Fatalf("hsts: %q", hdr.Get("Strict-Transport-Security"))
	}
	// Block Common Exploits
	for _, p := range []string{"/?id=1+union+select+(1)", "/.env", "/.git/config", "/?q=%3Cscript%3Ealert(1)%3C/script%3E"} {
		if code, _, _ := do(t, c, "GET", "https://app.test"+p); code != 403 {
			t.Errorf("%s must be blocked: %d", p, code)
		}
	}
	if code, _, _ := do(t, c, "GET", "https://app.test/?next=/home&q=selection"); code != 200 {
		t.Errorf("normal request blocked: %d", code)
	}
	// Cache Assets
	_, _, h1 := do(t, c, "GET", "https://app.test/static/app.css")
	_, b2, h2 := do(t, c, "GET", "https://app.test/static/app.css")
	if assets.Load() != 1 || h1.Get("X-Cache-Status") != "MISS" || h2.Get("X-Cache-Status") != "HIT" || b2 != "body{}" {
		t.Fatalf("cache: backend %d, %q/%q", assets.Load(), h1.Get("X-Cache-Status"), h2.Get("X-Cache-Status"))
	}
	// HTTPS erzwingen
	if code, _, hdr := do(t, c, "GET", "http://app.test/a?b=1"); code != 301 || !strings.HasPrefix(hdr.Get("Location"), "https://app.test") {
		t.Fatalf("force ssl: %d %q", code, hdr.Get("Location"))
	}
	// WebSocket ueber den Proxy
	wsc := e.client(false)
	conn, _, err := websocket.Dial(ctx, "wss://app.test/ws", &websocket.DialOptions{HTTPClient: wsc})
	if err != nil {
		t.Fatalf("websocket: %v", err)
	}
	if err := conn.Write(ctx, websocket.MessageText, []byte("hi")); err != nil {
		t.Fatal(err)
	}
	if _, b, err := conn.Read(ctx); err != nil || string(b) != "echo:hi" {
		t.Fatalf("websocket echo: %q %v", b, err)
	}
	conn.CloseNow()
	h.WebSockets = false
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if conn, _, err := websocket.Dial(ctx, "wss://app.test/ws", &websocket.DialOptions{HTTPClient: e.client(false)}); err == nil {
		conn.CloseNow()
		t.Fatal("websocket must fail when switched off")
	}
	// Erreichbarkeit
	if r := e.m.probe(ctx, h); r.State != ReachUp {
		t.Fatalf("reach up: %+v", r)
	}
	// Ziel weg: neutrale 502, Erreichbarkeit "down"
	backend.Close()
	if code, body, _ := do(t, c, "GET", "https://app.test/x"); code != 502 || strings.Contains(body, "127.0.0.1") {
		t.Fatalf("down: %d %q", code, body)
	}
	if r := e.m.probe(ctx, h); r.State != ReachDown || r.Error == "" {
		t.Fatalf("reach down: %+v", r)
	}
	st := e.m.statsOf(h.ID)
	if st.requests.Load() < 8 || st.blocked.Load() != 4 || st.errors.Load() < 1 {
		t.Fatalf("stats: req %d blocked %d err %d", st.requests.Load(), st.blocked.Load(), st.errors.Load())
	}
}

func TestLoopDetected(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	certPEM, keyPEM := selfSigned(t, "loop.test")
	if _, err := e.crt.Upload(ctx, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	h := newHost()
	h.Names, h.Scheme, h.TargetHost, h.TargetPort = []string{"loop.test"}, "https", "127.0.0.1", e.cfg.HTTPSPort
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := do(t, e.client(true), "GET", "https://loop.test/"); code != http.StatusLoopDetected {
		t.Fatalf("loop: %d", code)
	}
}

func TestNameTakenByOtherOwner(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	if err := e.edge.Set("dns64", []edge.Route{{Names: []string{"dns.test"}, Path: "/dns-query", Handler: http.NotFoundHandler()}}); err != nil {
		t.Fatal(err)
	}
	e.enable(t)
	for _, n := range []string{"dns.test", "ok.test"} {
		h := newHost()
		h.Names, h.TargetHost, h.TargetPort = []string{n}, "127.0.0.1", 9
		if err := e.m.saveHost(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	rows, _ := e.m.rows(ctx)
	for _, r := range rows {
		want := r.Names[0] == "dns.test"
		if (r.RouteErr != "") != want {
			t.Errorf("%s: route error %q", r.Names[0], r.RouteErr)
		}
	}
	owners := map[string]string{}
	for _, n := range e.edge.Status().Names {
		owners[n.Name] = n.Owner
	}
	if owners["dns.test"] != "dns64" || owners["ok.test"] != Name {
		t.Fatalf("owners: %v", owners)
	}
}

func TestExploitRules(t *testing.T) {
	block := []string{"/?a=http://evil", "/?x=../../etc/passwd", "/?GLOBALS[x]=1", "/?q=base64_decode(abc)", "/?q=viagra", "/wp-config.php"}
	pass := []string{"/", "/?page=2", "/search?q=union+station", "/static/app.js", "/?redirect=/dashboard", "/environment"}
	for _, p := range block {
		r := httptest.NewRequest("GET", "http://x"+p, nil)
		if !blocked(r) {
			t.Errorf("%s must be blocked", p)
		}
	}
	for _, p := range pass {
		r := httptest.NewRequest("GET", "http://x"+p, nil)
		if blocked(r) {
			t.Errorf("%s must pass", p)
		}
	}
	r := httptest.NewRequest("GET", "http://x/", nil)
	r.Header.Set("User-Agent", "libwww-perl/6.0")
	if !blocked(r) {
		t.Error("bad user agent must be blocked")
	}
}

// Host per API mit "Zertifikat gleich mit anfordern": der Host wird gespeichert, ein Fehler beim Anfordern steht
// in der Antwort (hier: ohne Eingang fuer HTTP-01 und ohne ipv64-Key).
func TestHostAPIRequestCertificate(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	post := func(body string) (int, map[string]any) {
		req := httptest.NewRequest("POST", "/api/cdn64/hosts", strings.NewReader(body))
		rec := httptest.NewRecorder()
		e.mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	code, out := post(`{"names":["a.test"],"target_host":"127.0.0.1","target_port":9,"request_certificate":{"source":"http"}}`)
	if ce, _ := out["certificate_error"].(string); code != 201 || !strings.Contains(ce, "http-01 not available") {
		t.Fatalf("http-01 without entrance: %d %v", code, out)
	}
	if err := e.crt.SetAccount(ctx, "", true); err != nil {
		t.Fatal(err)
	}
	code, out = post(`{"names":["b.test"],"target_host":"127.0.0.1","target_port":9,"request_certificate":{"source":"auto"}}`)
	if ce, _ := out["certificate_error"].(string); code != 201 || !strings.Contains(ce, "http-01") {
		t.Fatalf("auto without ipv64 key and without http-01: %d %v", code, out)
	}
	code, out = post(`{"names":["c.test"],"target_host":"127.0.0.1","target_port":9}`)
	if _, has := out["certificate_error"]; code != 201 || has {
		t.Fatalf("plain create: %d %v", code, out)
	}
	if e.m.autoSource(ctx, []string{"x.test"}) != certs.SourceHTTP {
		t.Fatal("without ipv64 key: http-01")
	}
}

// Umleitung auf HTTPS mit IPv6-Literal im Host-Kopf: genau ein Paar Klammern, Port faellt weg.
func TestToHTTPSIPv6(t *testing.T) {
	for host, want := range map[string]string{
		"[2001:db8::1]": "https://[2001:db8::1]/a?b", "[2001:db8::1]:80": "https://[2001:db8::1]/a?b",
		"app.test:80": "https://app.test/a?b", "192.0.2.1": "https://192.0.2.1/a?b",
	} {
		r := httptest.NewRequest("GET", "http://x/a?b", nil)
		r.Host = host
		w := httptest.NewRecorder()
		(&Module{}).toHTTPS(w, r)
		if got := w.Header().Get("Location"); got != want {
			t.Errorf("%s: %s, want %s", host, got, want)
		}
	}
}
