package cdnedge

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Modus 3: TLS hier, Ziel per http/https (Pruefung waehlbar), echte Besucher-IP, Frontend-Stufen, Liste, Cache,
// SSRF-Schutz.
func TestDirect(t *testing.T) {
	cf, kf, pool, _ := testCA(t, "edge.test")
	dc, dk, dpool, _ := testCA(t, "d.test", "*.d.test")
	var hits atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/static.css":
			w.Header().Set("Cache-Control", "public, max-age=60")
		case "/cookie":
			w.Header().Set("Cache-Control", "max-age=60")
			w.Header().Set("Set-Cookie", "a=b")
		}
		_, _ = io.WriteString(w, "target "+r.Host+" xff="+r.Header.Get("X-Forwarded-For")+" real="+r.Header.Get("X-Real-IP")+" proto="+r.Header.Get("X-Forwarded-Proto"))
	}))
	defer backend.Close()
	tlsBackend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "tls target") }))
	defer tlsBackend.Close()
	bp := func(s *httptest.Server) int { u, _ := url.Parse(s.URL); p, _ := strconv.Atoi(u.Port()); return p }

	cfg := &Config{Name: "B", ListenHTTP: freeAddr(t), ListenHTTPS: freeAddr(t), TLSCert: cf, TLSKey: kf, DataDir: t.TempDir(), Shield: ShieldConfig{ReqRate: -1}}
	s := startEdge(t, cfg, pool)
	s.targetOK = func(a netip.Addr) bool { return a.IsLoopback() }
	cp, _ := os.ReadFile(dc)
	kp, _ := os.ReadFile(dk)
	if err := s.certs.put("d.test", cp, kp); err != nil {
		t.Fatal(err)
	}
	tgt := func(port int, scheme string, verify bool, frontend, cache int) *apiTarget {
		return &apiTarget{Addrs: []string{"127.0.0.1"}, Port: port, Scheme: scheme, Verify: verify, Frontend: frontend, CacheMB: cache, CacheMinutes: 5}
	}
	// je Fall ein Name (das Zertifikat d.test deckt *.d.test; je Name ein eigener Host wie bei ipv64)
	s.applyConfig(&apiConfig{Hosts: []apiHost{
		{ID: 1, Name: "d.test", Mode: 3, UserID: 1, Target: tgt(bp(backend), "http", false, 2, 10)},
		{ID: 2, Name: "v.d.test", Mode: 3, UserID: 1, Target: tgt(bp(tlsBackend), "https", true, 2, 0)},
		{ID: 3, Name: "nv.d.test", Mode: 3, UserID: 1, Target: tgt(bp(tlsBackend), "https", false, 2, 0)},
		{ID: 4, Name: "f1.d.test", Mode: 3, UserID: 1, Target: tgt(bp(backend), "http", false, 1, 0)},
		{ID: 5, Name: "f3.d.test", Mode: 3, UserID: 1, Target: tgt(bp(backend), "http", false, 3, 0)},
		{ID: 6, Name: "acl.d.test", Mode: 3, UserID: 1, Target: tgt(bp(backend), "http", false, 2, 0), ACL: &apiACL{Default: "deny", List: []string{"127.0.0.0/8"}}},
		{ID: 7, Name: "deny.d.test", Mode: 3, UserID: 1, Target: tgt(bp(backend), "http", false, 2, 0), ACL: &apiACL{Default: "allow", List: []string{"127.0.0.1"}}},
		{ID: 8, Name: "name.d.test", Mode: 3, UserID: 1, Target: &apiTarget{Host: "localhost", Port: bp(backend), Scheme: "http", Frontend: 2}},
	}})
	for _, n := range []string{"v.d.test", "nv.d.test", "f1.d.test", "f3.d.test", "acl.d.test", "deny.d.test", "name.d.test"} {
		if err := s.certs.put(n, cp, kp); err != nil {
			t.Fatal(err)
		}
	}
	https := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: dpool},
		DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, cfg.ListenHTTPS)
		}}}
	plain := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, cfg.ListenHTTP)
		}}}
	get := func(c *http.Client, u string, hdr ...string) (int, string, http.Header) {
		t.Helper()
		req, _ := http.NewRequest("GET", u, nil)
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		resp, err := c.Do(req)
		if err != nil {
			return 0, err.Error(), nil
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b), resp.Header
	}
	if code, body, _ := get(https, "https://d.test/x", "X-Forwarded-For", "6.6.6.6"); code != 200 || !strings.HasPrefix(body, "target d.test xff=127.0.0.1 real=127.0.0.1 proto=https") {
		t.Fatalf("https -> http target: %d %q", code, body)
	}
	if code, _, h := get(plain, "http://d.test/a?b=1"); code != 301 || h.Get("Location") != "https://d.test/a?b=1" {
		t.Fatalf("frontend 2 port 80: %d", code)
	}
	if code, body, _ := get(https, "https://nv.d.test/"); code != 200 || body != "tls target" {
		t.Fatalf("https target without verify: %d %q", code, body)
	}
	if code, _, _ := get(https, "https://v.d.test/"); code != 502 {
		t.Fatalf("https target with verify (self-signed) must fail: %d", code)
	}
	if code, body, _ := get(plain, "http://f1.d.test/"); code != 200 || !strings.Contains(body, "proto=http") {
		t.Fatalf("frontend 1 (http only): %d %q", code, body)
	}
	if code, _, _ := get(https, "https://f1.d.test/"); code != 0 {
		t.Fatalf("frontend 1 must not answer on 443: %d", code)
	}
	if code, _, _ := get(plain, "http://f3.d.test/"); code != 403 {
		t.Fatalf("frontend 3 port 80: %d", code)
	}
	if code, _, _ := get(https, "https://acl.d.test/"); code != 200 {
		t.Fatalf("acl allow-list: %d", code)
	}
	if code, _, _ := get(https, "https://deny.d.test/"); code != 0 && code != 403 {
		t.Fatalf("acl deny-list: %d", code)
	}
	if code, body, _ := get(https, "https://name.d.test/"); code != 200 || !strings.HasPrefix(body, "target name.d.test") {
		t.Fatalf("fixed hostname target: %d %q", code, body)
	}
	// Cache: nur was das Ziel erlaubt; Cache-Control der Anfrage geht vorbei
	hits.Store(0)
	_, _, h1 := get(https, "https://d.test/static.css")
	_, b2, h2 := get(https, "https://d.test/static.css")
	if h1.Get("X-Proxy-Cache") != "MISS" || h2.Get("X-Proxy-Cache") != "HIT" || hits.Load() != 1 || !strings.HasPrefix(b2, "target d.test") {
		t.Fatalf("cache: %s %s hits=%d", h1.Get("X-Proxy-Cache"), h2.Get("X-Proxy-Cache"), hits.Load())
	}
	get(https, "https://d.test/static.css", "Cache-Control", "no-cache")
	get(https, "https://d.test/cookie")
	get(https, "https://d.test/cookie")
	if hits.Load() != 4 {
		t.Fatalf("bypass / Set-Cookie must reach the target: hits=%d", hits.Load())
	}
	// Ziel aendert sich (DynDNS): sofort, auch bei offener Keep-Alive-Verbindung zum alten Ziel
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "new target") }))
	defer other.Close()
	cfgNow := *s.apiCfg.Load()
	hosts := append([]apiHost(nil), cfgNow.Hosts...)
	hosts[0].Target = tgt(bp(other), "http", false, 2, 0)
	s.applyConfig(&apiConfig{Hosts: hosts})
	if code, body, _ := get(https, "https://d.test/after"); code != 200 || body != "new target" {
		t.Fatalf("target change: %d %q", code, body)
	}
	// SSRF: ohne Freigabe sind lokale Ziele verboten
	s.targetOK = nil
	s.applyConfig(s.apiCfg.Load()) // neuer Stand (wie nach einer Aenderung bei ipv64)
	s.term.direct.Transport.(*http.Transport).CloseIdleConnections()
	if code, body, _ := get(https, "https://d.test/other"); code != 502 || !strings.Contains(body, "not a public address") {
		t.Fatalf("ssrf: %d %q", code, body)
	}
	// Modus 1 mit Liste: abgewiesen schon beim Verbindungsaufbau (Port 80: 503)
	s.applyConfig(&apiConfig{Hosts: []apiHost{{ID: 9, Name: "m1.test", Mode: 1, Tunnels: []string{"t1"}, ACL: &apiACL{Default: "deny"}}}})
	c, err := net.Dial("tcp", cfg.ListenHTTP)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: m1.test\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	c.Close()
	if err != nil || resp.StatusCode != 503 {
		t.Fatalf("mode 1 acl: %v %v", err, resp)
	}
}

func TestPublicTarget(t *testing.T) {
	s := New(&Config{Name: "A", DataDir: t.TempDir()}, slog.New(slog.DiscardHandler), "test")
	s.apiCfg.Store(&apiConfig{Edges: []struct {
		Name string   `json:"name"`
		IPs  []string `json:"ips"`
	}{{Name: "srv07", IPs: []string{"91.99.98.96", "2a01:4f8:1c18:5887::1"}}}})
	for ip, want := range map[string]bool{"1.1.1.1": true, "2606:4700::1111": true, "178.203.252.242": true,
		"10.0.0.1": false, "192.168.1.1": false, "172.16.0.1": false, "100.64.1.1": false, "127.0.0.1": false, "0.0.0.0": false, "169.254.1.1": false,
		"::1": false, "fe80::1": false, "fd00::1": false, "2001:db8::1": false, "::ffff:10.0.0.1": false, "64:ff9b::a00:1": false,
		"91.99.98.96": false, "2a01:4f8:1c18:5887::1": false, "224.0.0.1": false, "255.255.255.255": false} {
		if got := s.publicTarget(netip.MustParseAddr(ip)); got != want {
			t.Errorf("%s: %v, want %v", ip, got, want)
		}
	}
}

// Cache: Grenze je Name und fuer alle Namen zusammen, die am laengsten ungenutzten gehen zuerst.
func TestCacheLimits(t *testing.T) {
	rc := newRespCache(t.TempDir(), 1) // 1 MB fuer alle
	now := time.Now()
	add := func(host int, key string, size int, used time.Time) {
		f, _ := os.CreateTemp(rc.dir, "tmp-*")
		_, _ = f.Write(make([]byte, size))
		f.Close()
		rc.put(host, key, &cacheItem{file: f.Name(), size: int64(size), expires: now.Add(time.Hour), used: used, header: http.Header{}}, 600<<10)
	}
	add(1, "a", 300<<10, now.Add(-3*time.Minute))
	add(1, "b", 300<<10, now.Add(-2*time.Minute))
	add(1, "c", 300<<10, now.Add(-time.Minute)) // Name 1 ueber 600 KB: a faellt
	if it, _ := rc.get(1, "a", now); it != nil {
		t.Fatal("per-name limit")
	}
	add(2, "x", 500<<10, now) // zusammen ueber 1 MB: der aelteste (b) faellt
	if it, f := rc.get(1, "b", now); it != nil {
		f.Close()
		t.Fatal("total limit")
	}
	if rc.total > 1<<20 {
		t.Fatalf("total %d", rc.total)
	}
	rc.sweep(now, map[int]time.Duration{2: time.Minute}) // Name 1 hat keinen Cache mehr
	if len(rc.hosts) != 1 || rc.total != 500<<10 {
		t.Fatalf("sweep: %d hosts, total %d", len(rc.hosts), rc.total)
	}
}
