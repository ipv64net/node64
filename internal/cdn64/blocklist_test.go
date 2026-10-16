package cdn64

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBlockSet(t *testing.T) {
	list, err := parseList(strings.NewReader(`# Kommentar
1.2.3.0/24
1.2.4.0/24 ; angrenzend
5.6.7.8
10.0.0.5/8
2001:db8:1::/48
2001:db8:1:5::/64   # enthalten
2a00:1450::1
kein-netz
`))
	if err != nil {
		t.Fatal(err)
	}
	s := buildSet([][]netip.Prefix{list}, []netip.Prefix{netip.MustParsePrefix("1.2.4.9/32")})
	if len(s.v4) != 3 { // 1.2.3.0-1.2.4.255 zusammen, 5.6.7.8, 10/8
		t.Fatalf("v4 ranges: %+v", s.v4)
	}
	for ip, want := range map[string]bool{
		"1.2.3.1": true, "1.2.4.200": true, "1.2.5.1": false, "5.6.7.8": true, "5.6.7.9": false, "10.200.1.1": true,
		"1.2.4.9":         false, // Ausnahme
		"2001:db8:1:5::7": true, "2001:db8:1:ffff::1": true, "2001:db8:2::1": false, "2a00:1450::1": true, "2a00:1450::2": false,
		"::ffff:5.6.7.8": true, // IPv4 ueber Dual-Stack
	} {
		if got := s.has(netip.MustParseAddr(ip)); got != want {
			t.Errorf("%s: %v, want %v", ip, got, want)
		}
	}
	var nilSet *blockSet
	if nilSet.has(netip.MustParseAddr("5.6.7.8")) {
		t.Fatal("nil set blocks nothing")
	}
}

// Liste von einem Testserver laden (ETag/304), am Eingang abweisen, Ausnahme greift, ausschalten gibt frei.
func TestBlocklistEnforced(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	var gets, notModified atomic.Int64
	list := "127.0.0.1/32\n203.0.113.0/24\n" // im Test sperren wir den eigenen Client
	lists := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gets.Add(1)
		if r.URL.Path != "/ipv64_blocklist_all.txt" {
			http.Error(w, "<html>404</html>", http.StatusNotFound)
			return
		}
		if r.Header.Get("If-None-Match") == `"v1"` {
			notModified.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(list))
	}))
	defer lists.Close()
	e.m.bl.base = lists.URL + "/"
	e.m.SetDataDir(t.TempDir())
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer backend.Close()
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
	get := func() (int, error) {
		resp, err := c.Get("https://app.test/")
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}
	if code, err := get(); err != nil || code != 200 {
		t.Fatalf("before: %d %v", code, err)
	}
	if err := e.m.blSave(ctx, []string{"all"}, ""); err != nil {
		t.Fatal(err)
	}
	wait := func(cond func() bool) {
		for i := 0; i < 100 && !cond(); i++ {
			time.Sleep(20 * time.Millisecond)
		}
	}
	wait(func() bool { return e.m.bl.set.Load() != nil })
	c.CloseIdleConnections()
	if _, err := get(); err == nil {
		t.Fatal("blocked client must be cut off at the entrance")
	}
	if e.m.bl.blocked.Load() == 0 {
		t.Fatal("not counted")
	}
	st := e.m.blStates(ctx)
	if !st[0].Enabled || st[0].Entries != 2 || st[0].Error != "" {
		t.Fatalf("state: %+v", st[0])
	}
	// zweites Laden: unveraendert (304)
	e.m.blKick(ctx)
	wait(func() bool { return notModified.Load() > 0 })
	if notModified.Load() == 0 {
		t.Fatal("ETag not used")
	}
	// Ausnahme fuer den eigenen Client
	if err := e.m.blSave(ctx, []string{"all"}, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	c.CloseIdleConnections()
	if code, err := get(); err != nil || code != 200 {
		t.Fatalf("exception: %d %v", code, err)
	}
	// unbekannte Liste, falsche Ausnahme
	if err := e.m.blSave(ctx, []string{"gibtsnicht"}, ""); err == nil {
		t.Fatal("unknown list")
	}
	if err := e.m.blSave(ctx, []string{"all"}, "kein-netz"); err == nil {
		t.Fatal("bad exception")
	}
	// ausschalten: sofort frei; der Zwischenspeicher bleibt
	if err := e.m.blSave(ctx, nil, ""); err != nil {
		t.Fatal(err)
	}
	if e.m.bl.set.Load() != nil {
		t.Fatal("still active")
	}
	c.CloseIdleConnections()
	if code, err := get(); err != nil || code != 200 {
		t.Fatalf("off: %d %v", code, err)
	}
	// HTML statt Liste (Fehlerseite von ipv64) wird nicht uebernommen
	e.m.bl.base = lists.URL + "/x/"
	if err := e.m.blFetch(ctx, "all"); err == nil {
		t.Fatal("404 html must fail")
	}
}
