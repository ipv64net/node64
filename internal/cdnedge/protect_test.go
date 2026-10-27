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
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/fingerprint"
	"github.com/ipv64net/node64/internal/shield"
)

// waitFor wartet bis zu 3 s auf eine Bedingung.
func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 150; i++ {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout: %s", what)
}

// rawHTTP schickt eine Anfrage roh (Pfad unveraendert) und liefert den Status (0 = keine Antwort).
func rawHTTP(t *testing.T, addr, host, path, ua string) int {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, "GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\nUser-Agent: "+ua+"\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

// goJA4: JA4 eines ClientHello von crypto/tls mit dieser Konfiguration.
func goJA4(t *testing.T, conf *tls.Config) string {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() { _ = tls.Client(a, conf.Clone()).Handshake() }()
	var buf []byte
	tmp := make([]byte, 4096)
	_ = b.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		n, err := b.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if h, more := fingerprint.TLSHello(buf); !more {
			return fingerprint.JA4(h)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

func plainTarget(t *testing.T) *apiTarget {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	t.Cleanup(backend.Close)
	u, _ := url.Parse(backend.URL)
	p, _ := strconv.Atoi(u.Port())
	return &apiTarget{Addrs: []string{"127.0.0.1"}, Port: p, Scheme: "http", Frontend: 1}
}

// Zaehler je Grund und Zuordnung zum Namen: Blocklisten (Name aus SNI bzw. Host), Ueberlast (zuletzt angefragter
// Name der IP), Zugriffsliste (Modus 1, Modus 3 auf 80 und 443), IPv4-Verbindungen.
func TestProtectCounters(t *testing.T) {
	cf, kf, pool, _ := testCA(t, "edge.test")
	cfg := &Config{Name: "A", ListenHTTP: freeAddr(t), ListenHTTPS: freeAddr(t), TLSCert: cf, TLSKey: kf, DataDir: t.TempDir(),
		Shield: ShieldConfig{ConnsPerIP: 2, ConnRate: -1, ReqRate: -1}}
	s := startEdge(t, cfg, pool)
	s.targetOK = func(a netip.Addr) bool { return a.IsLoopback() }
	tgt := plainTarget(t)
	s.applyConfig(&apiConfig{Hosts: []apiHost{
		{ID: 1, Name: "bl.test", Mode: 1, Tunnels: []string{"t1"}},
		{ID: 2, Name: "fl.test", Mode: 3, Target: tgt},
		{ID: 3, Name: "acl1.test", Mode: 1, Tunnels: []string{"t1"}, ACL: &apiACL{Default: "deny"}},
		{ID: 4, Name: "acl3.test", Mode: 3, Target: tgt, ACL: &apiACL{Default: "deny"}},
		{ID: 5, Name: "acl3s.test", Mode: 3, Target: &apiTarget{Addrs: tgt.Addrs, Port: tgt.Port, Scheme: "http", Frontend: 2},
			ACL: &apiACL{Default: "allow", List: []string{"127.0.0.0/8"}}},
	}})
	acf, akf, _, _ := testCA(t, "acl3s.test")
	cp, _ := os.ReadFile(acf)
	kp, _ := os.ReadFile(akf)
	if err := s.certs.put("acl3s.test", cp, kp); err != nil {
		t.Fatal(err)
	}
	st := func(n string) *hostStat { return s.stats.of(n) }

	// Blocklisten: 443 (SNI) und 80 (Host-Kopf) beim Namen, unbekannter Name nur gesamt
	s.guard.set.Store(shield.BuildSet([][]netip.Prefix{{netip.MustParsePrefix("127.0.0.1/32")}}, nil))
	c, err := net.Dial("tcp", cfg.ListenHTTPS)
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(c, &tls.Config{ServerName: "bl.test", InsecureSkipVerify: true}) //nolint:gosec // Test
	_ = tc.SetDeadline(time.Now().Add(3 * time.Second))
	if tc.Handshake() == nil {
		t.Fatal("blocklisted visitor got TLS")
	}
	c.Close()
	waitFor(t, "blocklist 443", func() bool { return st("bl.test").BlockedList.Load() == 1 })
	rawHTTP(t, cfg.ListenHTTP, "bl.test", "/", "x")
	rawHTTP(t, cfg.ListenHTTP, "unknown.test", "/", "x")
	waitFor(t, "blocklist 80", func() bool { return st("bl.test").BlockedList.Load() == 2 && s.guard.rej[0].Load() == 3 })
	time.Sleep(50 * time.Millisecond)
	s.stats.mu.Lock()
	_, unknown := s.stats.m["unknown.test"]
	s.stats.mu.Unlock()
	if unknown {
		t.Fatal("unknown name counted")
	}
	s.guard.set.Store(nil)

	// Ueberlast: fl.test angefragt (Modus 3 nur HTTP), dann haelt eine Verbindung ohne Anfrage den zweiten Platz
	if code := rawHTTP(t, cfg.ListenHTTP, "fl.test", "/", "x"); code != 200 {
		t.Fatalf("fl.test: %d", code)
	}
	hold1, _ := net.Dial("tcp", cfg.ListenHTTP)
	hold2, _ := net.Dial("tcp", cfg.ListenHTTP)
	defer hold1.Close()
	defer hold2.Close()
	waitFor(t, "slots taken", func() bool { return s.guard.open.Load() == 2 })
	if code := rawHTTP(t, cfg.ListenHTTP, "fl.test", "/", "x"); code != 0 {
		t.Fatalf("over conns_per_ip: %d", code)
	}
	waitFor(t, "flood", func() bool { return st("fl.test").BlockedFlood.Load() == 1 })
	hold1.Close()
	hold2.Close()
	waitFor(t, "slots free", func() bool { return s.guard.open.Load() == 0 })

	// Zugriffsliste: Modus 1 (80: 503), Modus 3 auf 80 (403) und 443 (zu)
	if code := rawHTTP(t, cfg.ListenHTTP, "acl1.test", "/", "x"); code != 503 {
		t.Fatalf("acl mode 1: %d", code)
	}
	if code := rawHTTP(t, cfg.ListenHTTP, "acl3.test", "/", "x"); code != 403 {
		t.Fatalf("acl mode 3: %d", code)
	}
	c, err = net.Dial("tcp", cfg.ListenHTTPS)
	if err != nil {
		t.Fatal(err)
	}
	tc = tls.Client(c, &tls.Config{ServerName: "acl3s.test", InsecureSkipVerify: true}) //nolint:gosec // Test
	_ = tc.SetDeadline(time.Now().Add(3 * time.Second))
	if tc.Handshake() == nil {
		t.Fatal("acl mode 3 on 443: TLS")
	}
	c.Close()
	waitFor(t, "acl", func() bool {
		return st("acl1.test").BlockedACL.Load() == 1 && st("acl3.test").BlockedACL.Load() == 1 && st("acl3s.test").BlockedACL.Load() == 1
	})
	if st("acl3.test").Rejected.Load() != 0 {
		t.Fatal("acl counted as rejected (request limit)")
	}

	// IPv4: Verbindungen von 127.0.0.1 zaehlen auch als conns_v4; gesperrte IPs je Name einmal
	if f := st("fl.test"); f.Conns.Load() != 1 || f.ConnsV4.Load() != 1 {
		t.Fatalf("conns %d v4 %d", f.Conns.Load(), f.ConnsV4.Load())
	}
	for _, n := range []string{"bl.test", "fl.test", "acl1.test"} {
		if ips, _ := st(n).takeSets(); len(ips) != 1 {
			t.Fatalf("%s: blocked ips %v", n, ips)
		}
	}
}

// Schutz ohne Server: Ueberlast beim zuletzt angefragten Namen (conns, conn_rate, max_conns), bekannter Name
// (QUIC, Portmapper UDP), IPv6 je /64.
func TestGuardHostCounters(t *testing.T) {
	now := time.Unix(1000, 0)
	g := newGuard(ShieldConfig{ConnsPerIP: 1, ConnRate: 1, MaxConns: 2})
	g.now = func() time.Time { return now }
	a, b := netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")
	h, other := &hostStat{}, &hostStat{}
	if _, _, why := g.admitG(a, nil); why != "" { // ohne gemerkten Namen: nur gesamt
		t.Fatal(why)
	}
	if _, _, why := g.admitG(a, nil); why != "conns" || h.BlockedFlood.Load() != 0 {
		t.Fatalf("conns without name: %q", why)
	}
	g.ips[gkey(a)].conns = 0
	g.open.Store(0)
	ra, gs, why := g.admitG(a, nil)
	if why != "" {
		t.Fatal(why)
	}
	gs.mark(h)
	if _, _, why := g.admitG(a, nil); why != "conns" { // conns_per_ip
		t.Fatalf("conns: %q", why)
	}
	rb, _, _ := g.admitG(b, nil)
	if _, _, why := g.admitG(a, nil); why != "max_conns" { // max_conns
		t.Fatalf("max: %q", why)
	}
	ra()
	rb()
	g.ips[gkey(a)].tok = 0
	if _, _, why := g.admitG(a, nil); why != "conn_rate" { // conn_rate
		t.Fatalf("rate: %q", why)
	}
	if _, _, why := g.admitG(a, other); why != "conn_rate" { // bekannter Name geht vor
		t.Fatalf("rate: %q", why)
	}
	if h.BlockedFlood.Load() != 3 || other.BlockedFlood.Load() != 1 {
		t.Fatalf("flood: %d %d", h.BlockedFlood.Load(), other.BlockedFlood.Load())
	}
	g.set.Store(shield.BuildSet([][]netip.Prefix{{netip.MustParsePrefix("2001:db8::/32")}}, nil))
	for _, ip := range []string{"2001:db8::1", "2001:db8::2", "2001:db8:0:1::1"} {
		g.admitG(netip.MustParseAddr(ip), other)
	}
	if other.BlockedList.Load() != 3 {
		t.Fatalf("blocklist: %d", other.BlockedList.Load())
	}
	if ips, _ := other.takeSets(); len(ips) != 3 { // 203.0.113.1, 2001:db8::/64, 2001:db8:0:1::/64
		t.Fatalf("ips: %v", ips)
	}
	var none *hostStat
	none.block(bFlood, a) // ohne Namen: nichts
}

// Muster-WAF in Modus 3 (gleicher Weg wie Modus 2: serveTerm): Pfade, ../, Gross-/Kleinschreibung, Scanner,
// harmlose Anfragen; waf = false schaltet ab.
func TestWAF(t *testing.T) {
	cf, kf, pool, _ := testCA(t, "edge.test")
	cfg := &Config{Name: "A", ListenHTTP: freeAddr(t), TLSCert: cf, TLSKey: kf, DataDir: t.TempDir(), Shield: ShieldConfig{ReqRate: -1}}
	s := startEdge(t, cfg, pool)
	s.targetOK = func(a netip.Addr) bool { return a.IsLoopback() }
	tgt := plainTarget(t)
	off := false
	s.applyConfig(&apiConfig{Hosts: []apiHost{{ID: 1, Name: "w.test", Mode: 3, Target: tgt}, {ID: 2, Name: "nw.test", Mode: 3, Target: tgt, WAF: &off}}})
	for _, c := range []struct {
		path, ua string
		hit      bool
	}{
		{"/", "Mozilla/5.0", false},
		{"/environment/index.html", "curl/8.0", false},
		{"/.git/config", "Mozilla/5.0", true},
		{"/app/.ENV", "", true},
		{"/static/../../etc/passwd", "x", true},
		{"/wp-config.php.bak", "x", true},
		{"/%2e%2e/secret", "x", true},
		{"/", "sqlmap/1.7#stable", true},
		{"/", "Mozilla/5.0 (Nuclei - Open-source project)", true},
	} {
		want := map[bool]int{true: 403, false: 200}[c.hit]
		if code := rawHTTP(t, cfg.ListenHTTP, "w.test", c.path, c.ua); code != want {
			t.Fatalf("%s %q: %d, want %d", c.path, c.ua, code, want)
		}
		if code := rawHTTP(t, cfg.ListenHTTP, "nw.test", c.path, c.ua); code != 200 {
			t.Fatalf("waf off %s: %d", c.path, code)
		}
	}
	if w, nw := s.stats.of("w.test"), s.stats.of("nw.test"); w.BlockedWAF.Load() != 7 || nw.BlockedWAF.Load() != 0 || w.Requests.Load() != 2 {
		t.Fatalf("counters: waf %d off %d requests %d", w.BlockedWAF.Load(), nw.BlockedWAF.Load(), w.Requests.Load())
	}
}

// JA4 auf 443 je Name: block schliesst, count zaehlt nur, off prueft nicht; auch Modus 3 (vor dem Zertifikat).
func TestJA4Edge(t *testing.T) {
	cf, kf, pool, _ := testCA(t, "edge.test")
	cfg := &Config{Name: "A", ListenHTTP: freeAddr(t), ListenHTTPS: freeAddr(t), TLSCert: cf, TLSKey: kf, DataDir: t.TempDir()}
	s := startEdge(t, cfg, pool)
	conf := &tls.Config{ServerName: "probe.test", InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}} //nolint:gosec // Test
	j := goJA4(t, conf)
	l := parseJA4List([]byte("# Honeypot64\n" + j + "\n"))
	s.ja4List.Store(&l)
	s.applyConfig(&apiConfig{Hosts: []apiHost{
		{ID: 1, Name: "j1.test", Mode: 1, Tunnels: []string{"t1"}, JA4: "block"},
		{ID: 2, Name: "j2.test", Mode: 1, Tunnels: []string{"t1"}}, // fehlt = count
		{ID: 3, Name: "j3.test", Mode: 1, Tunnels: []string{"t1"}, JA4: "off"},
		{ID: 4, Name: "j4.test", Mode: 3, Target: &apiTarget{Addrs: []string{"127.0.0.1"}, Port: 1, Frontend: 2}, JA4: "block"},
	}})
	hello := func(name string) {
		t.Helper()
		c, err := net.Dial("tcp", cfg.ListenHTTPS)
		if err != nil {
			t.Fatal(err)
		}
		cc := conf.Clone()
		cc.ServerName = name
		tc := tls.Client(c, cc)
		_ = tc.SetDeadline(time.Now().Add(3 * time.Second))
		_ = tc.Handshake() // ohne Node bzw. Zertifikat: immer zu
		c.Close()
	}
	for _, n := range []string{"j1.test", "j2.test", "j3.test", "j4.test"} {
		hello(n)
	}
	st := func(n string) *hostStat { return s.stats.of(n) }
	waitFor(t, "ja4", func() bool {
		return st("j1.test").BlockedJA4.Load() == 1 && st("j2.test").NoTunnel.Load() == 1 && st("j3.test").NoTunnel.Load() == 1 &&
			st("j4.test").BlockedJA4.Load() == 1
	})
	if a := st("j1.test"); a.JA4Hits.Load() != 1 || a.NoTunnel.Load() != 0 {
		t.Fatalf("block: hits %d notunnel %d", a.JA4Hits.Load(), a.NoTunnel.Load())
	}
	if b := st("j2.test"); b.JA4Hits.Load() != 1 || b.BlockedJA4.Load() != 0 {
		t.Fatalf("count: hits %d blocked %d", b.JA4Hits.Load(), b.BlockedJA4.Load())
	}
	if c := st("j3.test"); c.JA4Hits.Load() != 0 {
		t.Fatalf("off: hits %d", c.JA4Hits.Load())
	}
	if _, top := st("j1.test").takeSets(); top[j] != 1 {
		t.Fatalf("top: %v", top)
	}
	// anderer Fingerabdruck: kein Treffer
	l2 := parseJA4List([]byte("t13d1516h2_8daaf6152771_e5627efa2ab1\n"))
	s.ja4List.Store(&l2)
	hello("j1.test")
	waitFor(t, "no hit", func() bool { return st("j1.test").NoTunnel.Load() == 1 })
	if st("j1.test").JA4Hits.Load() != 1 {
		t.Fatal("hit without list entry")
	}
}

// Liste laden: Format, Obergrenze, ETag, Zwischenspeicher, HTML abweisen.
func TestJA4List(t *testing.T) {
	var b strings.Builder
	b.WriteString("# JA4 aus Honeypot64\n\nja4:T13D1516H2_8daaf6152771_e5627efa2ab1\r\nkaputt!\n" + strings.Repeat("x", 65) + "\n")
	for i := 0; i < 1100; i++ {
		b.WriteString("t13d" + strconv.Itoa(i) + "_x\n")
	}
	l := parseJA4List([]byte(b.String()))
	if _, ok := l["t13d1516h2_8daaf6152771_e5627efa2ab1"]; !ok || len(l) != ja4Max {
		t.Fatalf("parse: %d", len(l))
	}
	body, html := "t13d1516h2_8daaf6152771_e5627efa2ab1\n", false
	var n304 int
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/blocklists/ipv64_ja4.txt" {
			http.NotFound(w, r)
			return
		}
		if html {
			_, _ = io.WriteString(w, "<html>wartung</html>")
			return
		}
		if r.Header.Get("If-None-Match") == `"v1"` {
			n304++
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = io.WriteString(w, body)
	}))
	defer hs.Close()
	cfg := &Config{Name: "A", DataDir: t.TempDir(), Shield: ShieldConfig{BlocklistBase: hs.URL + "/blocklists/"}}
	s := New(cfg, slog.New(slog.DiscardHandler), "test")
	path := filepath.Join(cfg.DataDir, "blocklists", ja4File)
	ctx := context.Background()
	tag, err := s.fetchJA4(ctx, hs.Client(), blocklistBase(cfg)+ja4File, "", path)
	if err != nil || tag != `"v1"` || len(*s.ja4List.Load()) != 1 {
		t.Fatalf("fetch: %v %q", err, tag)
	}
	if raw, _ := os.ReadFile(path); string(raw) != body {
		t.Fatalf("cache: %q", raw)
	}
	if tag, err := s.fetchJA4(ctx, hs.Client(), blocklistBase(cfg)+ja4File, tag, path); err != nil || tag != `"v1"` || n304 != 1 {
		t.Fatalf("etag: %v %q %d", err, tag, n304)
	}
	html = true
	if _, err := s.fetchJA4(ctx, hs.Client(), blocklistBase(cfg)+ja4File, "", path); err == nil || len(*s.ja4List.Load()) != 1 {
		t.Fatal("html accepted")
	}
	if ja4Mode("") != ja4Count || ja4Mode("block") != ja4Block || ja4Mode("off") != ja4Off || ja4Mode("x") != ja4Count {
		t.Fatal("ja4Mode")
	}
}

// Meldung: neue Felder als Differenzen, gesperrte IPs und JA4-Treffer je Intervall (top 20), bei Fehler nachgeholt.
func TestReportProtection(t *testing.T) {
	cf, kf, pool, _ := testCA(t, "edge.test")
	api := &fakeAPI{secret: strings.Repeat("e", 40), cfg: apiConfig{Version: "v1",
		Hosts: []apiHost{{ID: 7, Name: "r.test", Mode: 1, Tunnels: []string{"t1"}}, {ID: 8, Name: "q.test", Mode: 1, Tunnels: []string{"t1"}}}}}
	hs := httptest.NewServer(http.HandlerFunc(api.handler))
	defer hs.Close()
	cfg := &Config{Name: "A", ListenHTTP: freeAddr(t), TLSCert: cf, TLSKey: kf, DataDir: t.TempDir(), APIURL: hs.URL, APISecret: api.secret,
		Shield: ShieldConfig{BlocklistBase: hs.URL + "/blocklists/"}}
	s := startEdge(t, cfg, pool)
	waitFor(t, "config", func() bool { return s.routes.Load().lookup("r.test") != nil })
	ctx := context.Background()
	st := s.stats.of("r.test")
	v4, v6 := netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("2001:db8::1")
	st.block(bList, v4)
	st.block(bList, v4)
	st.block(bACL, v6)
	st.block(bACL, netip.MustParseAddr("2001:db8::2")) // gleiches /64
	st.block(bFlood, v4)
	st.block(bWAF, v4)
	st.block(bJA4, v4)
	st.block(bLimit, v4)
	st.conn(v4)
	st.conn(netip.MustParseAddr("::ffff:198.51.100.2"))
	st.conn(v6)
	for i := 0; i < 25; i++ { // 25 verschiedene, i+1 Treffer
		for k := 0; k <= i; k++ {
			st.ja4Hit("t13d" + strconv.Itoa(100+i) + "_a_b")
		}
	}
	last := func() map[string]any {
		api.mu.Lock()
		defer api.mu.Unlock()
		tr, _ := api.reports[len(api.reports)-1]["traffic"].([]any)
		for _, x := range tr {
			if m := x.(map[string]any); m["host_id"].(float64) == 7 {
				return m
			}
		}
		return nil
	}
	// erste Meldung scheitert: alles bleibt fuer die naechste
	api.mu.Lock()
	api.down = true
	api.mu.Unlock()
	s.apiReport(ctx)
	api.mu.Lock()
	api.down = false
	api.mu.Unlock()
	s.apiReport(ctx)
	m := last()
	want := map[string]float64{"blocked_list": 2, "blocked_acl": 2, "blocked_flood": 1, "blocked_waf": 1, "blocked_ja4": 1, "rejected": 1,
		"ja4_hits": 325, "blocked_ips": 2, "conns": 3, "conns_v4": 2}
	for k, v := range want {
		if m == nil || m[k] != v {
			t.Fatalf("%s: %v, want %v (%v)", k, m[k], v, m)
		}
	}
	top, _ := m["ja4_top"].([]any)
	if len(top) != ja4TopMax || top[0].(map[string]any)["ja4"] != "t13d124_a_b" || top[0].(map[string]any)["hits"].(float64) != 25 ||
		top[19].(map[string]any)["hits"].(float64) != 6 {
		t.Fatalf("ja4_top: %v", top)
	}
	// naechste Meldung: nur Neues
	st.block(bWAF, v4)
	s.apiReport(ctx)
	m = last()
	if m == nil || m["blocked_waf"] != 1.0 || m["blocked_ips"] != 1.0 || m["blocked_list"] != nil || m["ja4_top"] != nil || m["conns"] != 0.0 {
		t.Fatalf("second report: %v", m)
	}
	s.apiReport(ctx)
	if last() != nil {
		t.Fatal("report without news")
	}
}

// forgetGone: mit dem Namen verschwinden gesperrte IPs, JA4-Treffer und der gemerkte Name im Schutz.
func TestForgetGoneProtection(t *testing.T) {
	cf, kf, pool, _ := testCA(t, "edge.test")
	s := startEdge(t, &Config{Name: "A", ListenHTTP: freeAddr(t), TLSCert: cf, TLSKey: kf, DataDir: t.TempDir()}, pool)
	hosts := []apiHost{{ID: 1, Name: "keep.test", Mode: 1, Tunnels: []string{"t1"}}, {ID: 2, Name: "gone.test", Mode: 1, Tunnels: []string{"t1"}}}
	s.applyConfig(&apiConfig{Hosts: hosts})
	a, b := netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("198.51.100.2")
	gone, keep := s.stats.of("gone.test"), s.stats.of("keep.test")
	gone.block(bWAF, a)
	gone.ja4Hit("t13d_x_y")
	r1, gs1, _ := s.guard.admitG(a, nil)
	r2, gs2, _ := s.guard.admitG(b, nil)
	gs1.mark(gone)
	gs2.mark(keep)
	r1()
	r2()
	s.applyConfig(&apiConfig{Hosts: hosts[:1]})
	s.stats.mu.Lock()
	_, still := s.stats.m["gone.test"]
	s.stats.mu.Unlock()
	if still || gs1.host.Load() != nil || gs2.host.Load() != keep {
		t.Fatalf("after removal: stats %v guard %p %p", still, gs1.host.Load(), gs2.host.Load())
	}
}
