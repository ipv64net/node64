package cdn64

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	l := newLimiter()
	l.now = func() time.Time { return now }
	c := Limits{Enabled: true, ConnsPerIP: 2, ConnRate: 1, ReqRate: 2, ReqBurst: 4, MaxConns: 5, BanAfter: 3, BanMinutes: 10, ExemptLAN: true}
	l.cfg.Store(&c)
	a := netip.MustParseAddr("203.0.113.5")
	open := func(a netip.Addr) (func(), bool) { r, why := l.open(a); return r, why == "" }

	// gleichzeitige Verbindungen je IP
	r1, ok1 := open(a)
	r2, ok2 := open(a)
	if !ok1 || !ok2 {
		t.Fatal("first two connections must pass")
	}
	if _, why := l.open(a); why != rejConns {
		t.Fatalf("third concurrent connection must be rejected: %q", why)
	}
	r1()
	r3, ok3 := open(a)
	if !ok3 {
		t.Fatal("after release a slot is free again")
	}
	r2()
	r3()
	// Heimnetz ausgenommen, IPv6 je /64
	for i := 0; i < 50; i++ {
		if _, ok := open(netip.MustParseAddr("192.168.1.10")); !ok {
			t.Fatal("LAN must be exempt")
		}
	}
	// Anfragen: Eimer 4, danach 2/s
	b := netip.MustParseAddr("2001:db8:1:2::1")
	for i := 0; i < 4; i++ {
		if !l.request(b) {
			t.Fatalf("burst request %d", i)
		}
	}
	if l.request(netip.MustParseAddr("2001:db8:1:2::ffff")) {
		t.Fatal("same /64 shares the bucket")
	}
	if !l.request(netip.MustParseAddr("2001:db8:1:3::1")) {
		t.Fatal("other /64 has its own bucket")
	}
	now = now.Add(time.Second)
	if !l.request(b) || !l.request(b) || l.request(b) {
		t.Fatal("refill 2 per second")
	}
	// zweimal abgewiesen (oben), das dritte Mal: gesperrt
	if l.banned(b) {
		t.Fatal("not yet banned")
	}
	if l.request(b) {
		t.Fatal("still limited")
	}
	if !l.banned(netip.MustParseAddr("2001:db8:1:2::abc")) {
		t.Fatal("whole /64 banned after 3 rejections")
	}
	if bl := l.banList(); len(bl) != 1 || bl[0].IP != "2001:db8:1:2::/64" {
		t.Fatalf("ban list: %+v", bl)
	}
	now = now.Add(11 * time.Minute)
	if l.banned(b) {
		t.Fatal("ban expired")
	}
	// Freigeben von Hand
	for i := 0; i < 10; i++ {
		l.request(b)
	}
	if !l.banned(b) || !l.unban("2001:db8:1:2::/64") || l.banned(b) {
		t.Fatal("unban")
	}
	// insgesamt
	var rel []func()
	for i := 0; i < 5; i++ {
		now = now.Add(2 * time.Second)
		r, ok := open(netip.MustParseAddr("198.51.100." + strconv.Itoa(i+1)))
		if !ok {
			t.Fatalf("conn %d", i)
		}
		rel = append(rel, r)
	}
	if _, why := l.open(netip.MustParseAddr("198.51.100.99")); why != rejMaxConns {
		t.Fatalf("max conns in total: %q", why)
	}
	for _, r := range rel {
		r()
	}
	if l.conns.Load() != 0 {
		t.Fatalf("open: %d", l.conns.Load())
	}
	// neue Verbindungen je Sekunde (Eimer 10)
	d := netip.MustParseAddr("198.51.100.200")
	c2 := c
	c2.ConnsPerIP, c2.BanAfter = 0, 0
	l.cfg.Store(&c2)
	n := 0
	for i := 0; i < 20; i++ {
		if r, ok := open(d); ok {
			n++
			r()
		}
	}
	if _, why := l.open(d); n != 10 || why != rejConnRate {
		t.Fatalf("conn rate: %d %q", n, why)
	}
	// ausgeschaltet: nichts begrenzt, Sperren ruhen
	off := c2
	off.Enabled = false
	l.cfg.Store(&off)
	if _, ok := open(d); !ok || !l.request(d) {
		t.Fatal("disabled")
	}
	// aufraeumen
	now = now.Add(5 * time.Minute)
	l.sweep()
	if len(l.ips) != 0 {
		t.Fatalf("sweep left %d", len(l.ips))
	}
	if (&Limits{ReqRate: -1}).normalize() == nil {
		t.Fatal("negative value")
	}
}

// Ueber den Eingang: Anfrage-Limit (429), Sperre am Eingang vor TLS, Freigabe, Platzgrenze beim Ziel (503),
// Verbindungs-Limit, Ausnahme je Host.
func TestLimitsEnforced(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	release := make(chan struct{})
	var once sync.Once
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			<-release
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()
	defer once.Do(func() { close(release) })
	bu, _ := url.Parse(backend.URL)
	bport, _ := strconv.Atoi(bu.Port())
	certPEM, keyPEM := selfSigned(t, "app.test")
	if _, err := e.crt.Upload(ctx, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	e.m.SetDataDir(t.TempDir()) // Statistik und Log der Abweisungen
	e.enable(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort = []string{"app.test"}, "127.0.0.1", bport
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	c := e.client(true)
	get := func(path string) (int, error) {
		resp, err := c.Get("https://app.test" + path)
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}
	// Standard: eingeschaltet, Heimnetz (hier 127.0.0.1) ausgenommen
	for i := 0; i < 30; i++ {
		if code, err := get("/"); err != nil || code != 200 {
			t.Fatalf("default with LAN exempt: %d %v", code, err)
		}
	}
	lim := Limits{Enabled: true, ReqRate: 1, ReqBurst: 3, BanAfter: 4, BanMinutes: 10}
	if err := e.m.limSave(ctx, lim); err != nil {
		t.Fatal(err)
	}
	codes := map[int]int{}
	for i := 0; i < 6; i++ {
		code, _ := get("/")
		codes[code]++
	}
	if codes[200] < 3 || codes[429] < 1 {
		t.Fatalf("request limit: %v", codes)
	}
	// nach 4 Abweisungen gesperrt: neue Verbindungen werden vor TLS getrennt
	for i := 0; i < 4; i++ {
		_, _ = get("/")
	}
	c.CloseIdleConnections()
	if _, err := get("/"); err == nil {
		t.Fatal("banned client must be cut off at the entrance")
	}
	if bans := e.m.lim.banList(); len(bans) != 1 || bans[0].IP != "127.0.0.1" {
		t.Fatalf("bans: %+v", bans)
	}
	if !e.m.lim.unban("127.0.0.1") {
		t.Fatal("unban")
	}
	// Ausnahme je Host
	h.Advanced.NoLimits = true
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	c.CloseIdleConnections()
	for i := 0; i < 10; i++ {
		if code, err := get("/"); err != nil || code != 200 {
			t.Fatalf("host without limits: %d %v", code, err)
		}
	}
	h.Advanced.NoLimits = false
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	// Platzgrenze beim Ziel: eine Anfrage haengt, die zweite wartet und bekommt 503
	old := limQueueWait
	limQueueWait = 300 * time.Millisecond
	defer func() { limQueueWait = old }()
	if err := e.m.limSave(ctx, Limits{Enabled: true, TargetConns: 1}); err != nil {
		t.Fatal(err)
	}
	slow := make(chan int, 1)
	go func() { code, _ := get("/slow"); slow <- code }()
	time.Sleep(200 * time.Millisecond)
	if code, err := get("/"); err != nil || code != http.StatusServiceUnavailable {
		t.Fatalf("target busy: %d %v", code, err)
	}
	once.Do(func() { close(release) })
	if code := <-slow; code != 200 {
		t.Fatalf("slow request: %d", code)
	}
	if code, _ := get("/"); code != 200 {
		t.Fatalf("free again: %d", code)
	}
	// gleichzeitige Verbindungen je IP (roh, vor TLS)
	if err := e.m.limSave(ctx, Limits{Enabled: true, ConnsPerIP: 2}); err != nil {
		t.Fatal(err)
	}
	c.CloseIdleConnections()
	time.Sleep(100 * time.Millisecond)
	addr := "127.0.0.1:" + strconv.Itoa(e.cfg.HTTPSPort)
	var raw []net.Conn
	for i := 0; i < 2; i++ {
		cn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, cn)
	}
	time.Sleep(100 * time.Millisecond)
	cn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_ = cn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := cn.Read(make([]byte, 1)); err == nil {
		t.Fatal("third connection must be closed")
	}
	cn.Close()
	for _, x := range raw {
		x.Close()
	}
	time.Sleep(100 * time.Millisecond)
	if code, err := get("/"); err != nil || code != 200 {
		t.Fatalf("after closing: %d %v", code, err)
	}
	if e.m.lim.rejected.Load() == 0 {
		t.Fatal("not counted")
	}
	// Statistik und Log: jeder Grund steht im Log (auch ohne Zugriffs-Log am Host), Verbindungen unter Host 0
	sdb := e.m.stats2.Load()
	want := map[string]bool{rejReqRate: false, rejBan: false, rejTarget: false, rejConns: false}
	var list []LogEntry
	for i := 0; i < 50; i++ {
		list, _ = sdb.entries(ctx, LogFilter{Rejected: true, Limit: 500})
		for _, x := range list {
			if _, ok := want[x.Reason]; ok {
				want[x.Reason] = true
			}
		}
		if want[rejReqRate] && want[rejBan] && want[rejTarget] && want[rejConns] {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	for r, ok := range want {
		if !ok {
			t.Fatalf("reason %s not in log: %+v", r, list)
		}
	}
	for _, x := range list {
		switch x.Reason {
		case rejConns: // vor der ersten Anfrage
			if x.Status != 0 || x.HostID != 0 {
				t.Fatalf("connection rejection must be logged under host 0 without status: %+v", x)
			}
		case rejReqRate, rejTarget:
			if x.HostID != h.ID || x.Status != map[string]int{rejReqRate: 429, rejTarget: 503}[x.Reason] {
				t.Fatalf("request rejection: %+v", x)
			}
		}
	}
	if all, _ := sdb.entries(ctx, LogFilter{Limit: 500}); len(all) != len(list) {
		t.Fatalf("normal requests must not be logged without access log: %d vs %d", len(all), len(list))
	}
	pts, _ := sdb.hours(ctx, 0, time.Now().Add(-2*time.Hour))
	var blocked, conn, req int64
	for _, p := range pts {
		blocked, conn, req = blocked+p.Blocked, conn+p.ConnBlocked, req+p.Requests
	}
	if blocked < 5 || conn < 1 || conn >= blocked || req == 0 {
		t.Fatalf("hourly: blocked=%d conn=%d requests=%d", blocked, conn, req)
	}
}

// Aeltere cdn64.db (ohne blocked/reason) bekommt die Spalten beim Oeffnen, alte Zahlen bleiben.
func TestStatsAddColumns(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "cdn64.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE hourly (host_id INTEGER NOT NULL, hour TEXT NOT NULL, requests INTEGER NOT NULL DEFAULT 0, s2 INTEGER NOT NULL DEFAULT 0,
		s3 INTEGER NOT NULL DEFAULT 0, s4 INTEGER NOT NULL DEFAULT 0, s5 INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (host_id, hour));
		CREATE TABLE access (id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT NOT NULL, host_id INTEGER NOT NULL, client TEXT NOT NULL,
		method TEXT NOT NULL, host TEXT NOT NULL, path TEXT NOT NULL, status INTEGER NOT NULL, bytes INTEGER NOT NULL, ms INTEGER NOT NULL, ua TEXT NOT NULL);
		INSERT INTO hourly (host_id, hour, requests, s2) VALUES (1, ?, 7, 7);
		INSERT INTO access (time, host_id, client, method, host, path, status, bytes, ms, ua) VALUES (?, 1, '1.2.3.4', 'GET', 'a.test', '/', 200, 1, 1, 'x')`,
		time.Now().UTC().Truncate(time.Hour).Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	db.Close()
	s, err := openStats(dir, slog.New(slog.NewTextHandler(io.Discard, nil)), func() int { return 7 }, func() bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	pts, err := s.hours(context.Background(), 0, time.Now().Add(-2*time.Hour))
	if err != nil || len(pts) != 1 || pts[0].Requests != 7 || pts[0].Blocked != 0 {
		t.Fatalf("hours: %+v %v", pts, err)
	}
	if l, err := s.entries(context.Background(), LogFilter{}); err != nil || len(l) != 1 || l[0].Reason != "" {
		t.Fatalf("entries: %+v %v", l, err)
	}
}

// Volle Tabelle (Adressflut): neue Adressen zaehlen je /48 bzw. /24, zuletzt alle gemeinsam - nie ohne Limit, und
// gemeinsame Zaehler sperren nicht.
func TestLimiterFull(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	l := newLimiter()
	l.now = func() time.Time { return now }
	c := Limits{Enabled: true, ReqRate: 1, ReqBurst: 2, BanAfter: 1, BanMinutes: 10}
	l.cfg.Store(&c)
	for i := 0; i < limMaxIPs; i++ {
		l.ips[netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})] = &ipState{}
	}
	a, b := netip.MustParseAddr("2001:db8:1:1::1"), netip.MustParseAddr("2001:db8:1:2::1") // gleiches /48
	if !l.request(a) || !l.request(b) || l.request(a) {
		t.Fatal("full table: new addresses must share the /48 counter")
	}
	if l.nbans.Load() != 0 {
		t.Fatal("shared counter must not ban")
	}
	for i := len(l.nets); i < limMaxNets; i++ {
		l.nets[netip.AddrFrom4([4]byte{11, byte(i >> 8), byte(i), 0})] = &ipState{}
	}
	x, y := netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("2001:db8:9::1")
	if !l.request(x) || !l.request(y) || l.request(x) {
		t.Fatal("full nets: all new addresses share one counter")
	}
	if r, why := l.open(x); why != "" || r == nil {
		t.Fatalf("open on shared counter: %q", why)
	} else {
		r()
	}
}

// Heimnetz per IPv6-GUA: die /64 der eigenen Schnittstellen gelten als LAN (nur mit ExemptLAN); Zone faellt weg.
func TestLimiterLAN64(t *testing.T) {
	l := newLimiter()
	l.lan.nets, l.lan.at = []netip.Prefix{netip.MustParsePrefix("2001:db8:aa:1::/64")}, time.Now()
	on := Limits{Enabled: true, ExemptLAN: true}
	if !l.exempted(&on, netip.MustParseAddr("2001:db8:aa:1::5")) || l.exempted(&on, netip.MustParseAddr("2001:db8:aa:2::5")) ||
		l.exempted(&Limits{Enabled: true}, netip.MustParseAddr("2001:db8:aa:1::5")) {
		t.Fatal("own /64 counts as LAN only with ExemptLAN")
	}
	if a := netAddr(&net.TCPAddr{IP: net.ParseIP("fe80::5"), Zone: "eth0", Port: 1}); a != netip.MustParseAddr("fe80::5") {
		t.Fatalf("zone: %v", a)
	}
}
