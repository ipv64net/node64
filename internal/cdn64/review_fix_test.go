package cdn64

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// PUT ersetzt die Locations ganz: Felder mit omitempty duerfen nicht von der Location am alten Index stehen bleiben.
func TestAPIUpdateReplacesLocations(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort = []string{"loc.example.de"}, "192.168.1.20", 80
	h.Locations = []Location{
		{Path: "/admin", Action: LocBlock},
		{Path: "/web", TargetHost: "192.168.1.21", TargetPort: 81, Advanced: &LocationAdvanced{RequestHeaders: []Header{{Name: "Authorization", Value: "Bearer x"}}}},
	}
	h.Advanced.RequestHeaders = []Header{{Name: "X-A", Value: "1"}, {Name: "X-B", Value: "2"}}
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	p := "/api/cdn64/hosts/" + strconv.FormatInt(h.ID, 10)
	// Reihenfolge getauscht, die Proxy-Location jetzt vorne und ohne advanced
	body := `{"locations":[{"path":"/api","target_host":"192.168.1.22","target_port":82},{"path":"/other","target_host":"192.168.1.23","target_port":83}],
		"advanced":{"request_headers":[{"name":"X-C"}]}}`
	if code, out := e.call(t, "PUT", p, body); code != 200 {
		t.Fatalf("put: %d %v", code, out)
	}
	got, err := e.m.host(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Locations) != 2 {
		t.Fatalf("locations: %+v", got.Locations)
	}
	for _, l := range got.Locations {
		if l.Action != LocProxy || l.Status != 0 || l.Advanced != nil {
			t.Errorf("inherited fields: %+v (advanced %+v)", l, l.Advanced)
		}
	}
	if hd := got.Advanced.RequestHeaders; len(hd) != 1 || hd[0].Name != "X-C" || hd[0].Value != "" {
		t.Errorf("request headers merged: %+v", hd)
	}
	// fehlende Felder bleiben weiterhin
	if code, _ := e.call(t, "PUT", p, `{"websockets":false}`); code != 200 {
		t.Fatal(code)
	}
	if got, _ = e.m.host(ctx, h.ID); len(got.Locations) != 2 || got.TargetHost != "192.168.1.20" || got.WebSockets {
		t.Fatalf("partial put: %+v", got)
	}
}

// GET -> PUT mit grossen HTML-Feldern (writeJSON escapet < > als <) und 413 statt "invalid json".
func TestAPIUpdateBigBody(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort = []string{"big.example.de"}, "192.168.1.20", 80
	html := strings.Repeat("<p>Wartung</p>\n", 4000) // ~60 KB, als JSON gut 100 KB
	h.Advanced.ErrorHTML, h.Advanced.MaintenanceStyle, h.Advanced.MaintenanceHTML = html, "custom", html
	h.Locations = []Location{{Path: "/info", Action: LocRespond, Body: html, ContentType: "text/html"}}
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	p := "/api/cdn64/hosts/" + strconv.FormatInt(h.ID, 10)
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
	if rec.Code != 200 || rec.Body.Len() < 1<<16 {
		t.Fatalf("get: %d %d bytes", rec.Code, rec.Body.Len())
	}
	if code, out := e.call(t, "PUT", p, rec.Body.String()); code != 200 {
		t.Fatalf("round trip: %d %v", code, out)
	}
	huge := `{"advanced":{"error_html":"` + strings.Repeat("x", maxHostBody) + `"}}`
	if code, out := e.call(t, "PUT", p, huge); code != http.StatusRequestEntityTooLarge || !strings.Contains(out["error"].(string), "too large") {
		t.Fatalf("huge: %d %v", code, out)
	}
	if code, _ := e.call(t, "POST", "/api/cdn64/hosts", huge); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("huge create: %d", code)
	}
	if code, out := e.call(t, "PUT", p, `{"names":`); code != 400 || out["error"] != "invalid json" {
		t.Fatalf("broken: %d %v", code, out)
	}
}

// Location ohne Ziel mit access_list_id -1: wird 0 (wie der Host), sonst waere sie ohne Zugriffsliste erreichbar.
func TestLocationACLNormalizedForActions(t *testing.T) {
	list := []Location{{Path: "/a", Action: LocRespond, Body: "x", AccessListID: -1}, {Path: "/b", Action: LocBlock, AccessListID: -5},
		{Path: "/c", TargetHost: "nas", TargetPort: 80, AccessListID: -1}}
	if err := normalizeLocations(list); err != nil {
		t.Fatal(err)
	}
	for _, l := range list {
		if l.AccessListID != 0 {
			t.Errorf("%s: acl %d", l.Path, l.AccessListID)
		}
	}
}

// Letzter guter Stand nur bis dynMaxAge, danach leer (allow passt nicht, deny greift).
func TestDynStaleMaxAge(t *testing.T) {
	var mu sync.Mutex
	now := time.Unix(1_000_000, 0)
	fail := false
	d := newDynAddrs()
	d.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	d.lookup = func(context.Context, string) ([]netip.Addr, error) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			return nil, errors.New("servfail")
		}
		return []netip.Addr{netip.MustParseAddr("198.51.100.4")}, nil
	}
	set := func(dt time.Duration, f bool) { mu.Lock(); now = now.Add(dt); fail = f; mu.Unlock() }
	ip := netip.MustParseAddr("198.51.100.4")
	allow := &AccessList{Rules: []AccessRule{{Action: "allow", CIDR: "home.example.net"}}}
	deny := &AccessList{Rules: []AccessRule{{Action: "deny", CIDR: "home.example.net"}, {Action: "allow", CIDR: "all"}}}
	allow.prepare()
	deny.prepare()
	if !allow.ipAllowedDyn(ip, d) {
		t.Fatal("first lookup")
	}
	set(dynNameTTL+time.Second, true)
	if !allow.ipAllowedDyn(ip, d) { // abgelaufen: alter Stand, Erneuerung im Hintergrund (scheitert)
		t.Fatal("stale within max age")
	}
	waitIdle(t, d, "name:home.example.net")
	set(dynMaxAge("name:")+time.Second, true)
	if allow.ipAllowedDyn(ip, d) {
		t.Fatal("stale beyond max age must not match")
	}
	if deny.ipAllowedDyn(netip.MustParseAddr("203.0.113.1"), d) {
		t.Fatal("unresolvable deny rule must deny")
	}
	set(dynFailTTL+time.Second, false)
	if !allow.ipAllowedDyn(ip, d) || deny.ipAllowedDyn(ip, d) || !deny.ipAllowedDyn(netip.MustParseAddr("203.0.113.1"), d) {
		t.Fatal("after recovery")
	}
}

// waitIdle wartet, bis keine Abfrage zum Schluessel mehr laeuft.
func waitIdle(t *testing.T, d *dynAddrs, key string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		d.mu.Lock()
		e := d.cache[key]
		idle := e != nil && e.done == nil
		d.mu.Unlock()
		if idle {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("refresh still running")
}

// Parallele Erstanfragen warten auf dieselbe Abfrage (vorher: nil -> allow passt nicht, deny wird uebersprungen).
func TestDynParallelFirstRequests(t *testing.T) {
	var lookups atomic.Int32
	release := make(chan struct{})
	d := newDynAddrs()
	d.lookup = func(context.Context, string) ([]netip.Addr, error) {
		lookups.Add(1)
		<-release
		return []netip.Addr{netip.MustParseAddr("198.51.100.4")}, nil
	}
	allow := &AccessList{Rules: []AccessRule{{Action: "allow", CIDR: "home.example.net"}}}
	deny := &AccessList{Rules: []AccessRule{{Action: "deny", CIDR: "home.example.net"}, {Action: "allow", CIDR: "all"}}}
	allow.prepare()
	deny.prepare()
	ip := netip.MustParseAddr("198.51.100.4")
	var wg sync.WaitGroup
	var bad atomic.Int32
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if !allow.ipAllowedDyn(ip, d) {
				bad.Add(1)
			}
		}()
		go func() {
			defer wg.Done()
			if deny.ipAllowedDyn(ip, d) {
				bad.Add(1)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if bad.Load() != 0 || lookups.Load() != 1 {
		t.Fatalf("wrong decisions %d, lookups %d", bad.Load(), lookups.Load())
	}
}

// "self" fragt nur die Familie des Clients ab.
func TestDynSelfOneFamily(t *testing.T) {
	var fams []string
	var mu sync.Mutex
	d := newDynAddrs()
	d.publicIP = func(_ context.Context, fam string) (string, error) {
		mu.Lock()
		fams = append(fams, fam)
		mu.Unlock()
		if fam == "ipv6" {
			return "2001:db8:1:2::77", nil
		}
		return "203.0.113.9", nil
	}
	if !d.matches("self", "self", netip.MustParseAddr("2001:db8:1:2::1")) { // vorher erst ipv4 (bis 3 s), dann ipv6
		t.Fatal("v6")
	}
	if len(fams) != 1 || fams[0] != "ipv6" {
		t.Fatalf("queried %v", fams)
	}
	if d.matches("self", "self", netip.MustParseAddr("198.51.100.1")) || len(fams) != 2 || fams[1] != "ipv4" {
		t.Fatalf("v4: queried %v", fams)
	}
}

// DS-Lite/CGNAT laut DynDNS: "self" und "self4" nehmen keine IPv4 auf, IPv6 bleibt; Warnung nur einmal.
func TestDynSelfSharedIPv4(t *testing.T) {
	var logs strings.Builder
	var v4 atomic.Int32
	d := newDynAddrs()
	d.log = slog.New(slog.NewTextHandler(&logs, nil))
	d.publicIP = func(_ context.Context, fam string) (string, error) {
		if fam == "ipv6" {
			return "2001:db8:1:2::77", nil
		}
		v4.Add(1)
		return "203.0.113.9", nil
	}
	d.sharedV4 = func(context.Context) string { return "dslite" }
	for _, k := range []string{"self", "self4", "self"} {
		if d.matches(k, k, netip.MustParseAddr("203.0.113.9")) {
			t.Fatalf("%s: shared IPv4 must not match", k)
		}
	}
	if !d.matches("self", "self", netip.MustParseAddr("2001:db8:1:2::1")) {
		t.Fatal("IPv6 must still match")
	}
	if v4.Load() != 0 {
		t.Fatal("IPv4 lookup despite shared IPv4")
	}
	d.mu.Lock()
	d.cache = map[string]*dynEntry{}
	d.mu.Unlock()
	d.matches("self4", "self4", netip.MustParseAddr("203.0.113.9"))
	if n := strings.Count(logs.String(), "shares its IPv4"); n != 1 {
		t.Fatalf("warnings: %d (%s)", n, logs.String())
	}
	// ohne Befund wie bisher
	d2 := newDynAddrs()
	d2.publicIP, d2.sharedV4, d2.log = d.publicIP, func(context.Context) string { return "" }, slog.New(slog.NewTextHandler(io.Discard, nil))
	if !d2.matches("self", "self", netip.MustParseAddr("203.0.113.9")) {
		t.Fatal("own IPv4")
	}
}

// FQDN mit Punkt am Ende ist eine gueltige Namensregel und wird ohne Punkt gespeichert.
func TestDynRuleTrailingDot(t *testing.T) {
	if got := dynRule("Home.Example.NET."); got != "name" {
		t.Fatalf("dynRule = %q", got)
	}
	d := newDynAddrs()
	var hosts []string
	d.lookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		hosts = append(hosts, host)
		return []netip.Addr{netip.MustParseAddr("198.51.100.4")}, nil
	}
	if !d.matches("name", "home.example.net.", netip.MustParseAddr("198.51.100.4")) || !d.matches("name", "home.example.net", netip.MustParseAddr("198.51.100.4")) {
		t.Fatal("match")
	}
	if len(hosts) != 1 || hosts[0] != "home.example.net" {
		t.Fatalf("lookups %v", hosts)
	}
	e := newEnv(t)
	e.enable(t)
	a := &AccessList{Name: "Punkt", Rules: []AccessRule{{Action: "allow", CIDR: "Home.Example.NET."}}}
	if err := e.m.saveAccessList(context.Background(), a, nil); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(a.Rules)
	if a.Rules[0].CIDR != "home.example.net" {
		t.Fatalf("saved %s", b)
	}
}
