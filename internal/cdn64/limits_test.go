package cdn64

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
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

	// gleichzeitige Verbindungen je IP
	r1, ok1 := l.open(a)
	r2, ok2 := l.open(a)
	if !ok1 || !ok2 {
		t.Fatal("first two connections must pass")
	}
	if _, ok := l.open(a); ok {
		t.Fatal("third concurrent connection must be rejected")
	}
	r1()
	r3, ok3 := l.open(a)
	if !ok3 {
		t.Fatal("after release a slot is free again")
	}
	r2()
	r3()
	// Heimnetz ausgenommen, IPv6 je /64
	for i := 0; i < 50; i++ {
		if _, ok := l.open(netip.MustParseAddr("192.168.1.10")); !ok {
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
		r, ok := l.open(netip.MustParseAddr("198.51.100." + strconv.Itoa(i+1)))
		if !ok {
			t.Fatalf("conn %d", i)
		}
		rel = append(rel, r)
	}
	if _, ok := l.open(netip.MustParseAddr("198.51.100.99")); ok {
		t.Fatal("max conns in total")
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
		if r, ok := l.open(d); ok {
			n++
			r()
		}
	}
	if n != 10 {
		t.Fatalf("conn rate: %d", n)
	}
	// ausgeschaltet: nichts begrenzt, Sperren ruhen
	off := c2
	off.Enabled = false
	l.cfg.Store(&off)
	if _, ok := l.open(d); !ok || !l.request(d) {
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
}
