package cdn64

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/hpbridge"
)

// Eigene Sperrliste: am Eingang abgewiesen, die Freigabeliste geht vor, ungueltige Zeilen werden abgelehnt.
func TestDenyList(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
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
		c.CloseIdleConnections()
		resp, err := c.Get("https://app.test/")
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}
	str := func(s string) *string { return &s }
	if err := e.m.blListsSave(ctx, nil, str("203.0.113.0/24\n127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	if _, err := get(); err == nil {
		t.Fatal("denied client must be cut off at the entrance")
	}
	if e.m.bl.denied.Load() == 0 || e.m.bl.blocked.Load() != 0 {
		t.Fatal("counted as own block list, not as blocklist")
	}
	if !e.m.bl.Denied(netip.MustParseAddr("203.0.113.9")) || e.m.bl.Denied(netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("network entry")
	}
	if err := e.m.blListsSave(ctx, str("127.0.0.1"), nil); err != nil { // Freigabeliste geht vor
		t.Fatal(err)
	}
	if code, err := get(); err != nil || code != 200 {
		t.Fatalf("allow list: %d %v", code, err)
	}
	if v := e.m.blView(httptest.NewRequest("GET", "/", nil)); len(v.Deny) != 2 || len(v.Allow) != 1 {
		t.Fatalf("view: %+v %+v", v.Deny, v.Allow)
	}
	if err := e.m.blListsSave(ctx, nil, str("kein-netz")); err == nil {
		t.Fatal("bad line")
	}
	if err := e.m.blListsSave(ctx, str(""), str("")); err != nil {
		t.Fatal(err)
	}
	if e.m.bl.deny.Load() != nil {
		t.Fatal("empty list must not be active")
	}
	if code, err := get(); err != nil || code != 200 {
		t.Fatalf("cleared: %d %v", code, err)
	}
	// Blocklisten speichern ohne Feld "allow" (Reiter Sicherheit) laesst die Freigabeliste stehen
	_ = e.m.blListsSave(ctx, str("192.0.2.1"), nil)
	e.m.g.Flash = func(http.ResponseWriter, *http.Request, string, string) {}
	e.m.g.T = func(_ *http.Request, key string, args ...any) string { return key }
	e.m.g.Audit = func(*http.Request, string, string, string) {}
	req := httptest.NewRequest("POST", "/cdn64/blocklists", strings.NewReader(url.Values{"list": {"all"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	e.m.pageBlocklistsSave(rec, req)
	if v := e.m.blView(httptest.NewRequest("GET", "/", nil)); len(v.Allow) != 1 || rec.Header().Get("Location") != "/cdn64/security#blocklists" {
		t.Fatalf("allow list lost: %+v %s", v.Allow, rec.Header().Get("Location"))
	}
}

// Freigeben: automatische Sperre aufheben und in die Freigabeliste eintragen (der Honeypot sperrt sie nicht wieder).
func TestRelease(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	m := e.m
	m.g.Flash = func(http.ResponseWriter, *http.Request, string, string) {}
	m.g.T = func(_ *http.Request, key string, args ...any) string { return key }
	m.g.Audit = func(*http.Request, string, string, string) {}
	if err := m.hpSave(ctx, HoneypotSettings{Block: true, BlockHours: 2}); err != nil {
		t.Fatal(err)
	}
	bad := netip.MustParseAddr("203.0.113.5")
	hpbridge.PublishBlock(hpbridge.Block{IP: bad, Reason: "ssh:bruteforce"})
	if a := m.autoBlocks(); len(a) != 1 || a[0].From != "honeypot" || a[0].IP != bad.String() || a[0].Reason != "ssh:bruteforce" {
		t.Fatalf("auto: %+v", a)
	}
	req := httptest.NewRequest("POST", "/cdn64/access/release?from=honeypot", strings.NewReader(url.Values{"ip": {bad.String()}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	m.pageRelease(rec, req)
	if m.hpBlocked(bad) || rec.Header().Get("Location") != "/cdn64/access#sperrliste" {
		t.Fatal("released address still blocked")
	}
	if v := m.blView(httptest.NewRequest("GET", "/", nil)); len(v.Allow) != 1 || v.Allow[0] != bad.String() {
		t.Fatalf("not in allow list: %+v", v.Allow)
	}
	hpbridge.PublishBlock(hpbridge.Block{IP: bad, Reason: "again"})
	if m.hpBlocked(bad) {
		t.Fatal("allow list must keep the honeypot from blocking again")
	}
	_ = m.blAllowAdd(ctx, bad.String()) // schon drin: kein zweiter Eintrag
	if v := m.blView(httptest.NewRequest("GET", "/", nil)); len(v.Allow) != 1 {
		t.Fatalf("duplicate: %+v", v.Allow)
	}
}

// Seiten: Zugriffslisten mit Freigabe- und Sperrliste samt automatischer Sperren, Sicherheit mit den Karten.
func TestSecurityPages(t *testing.T) {
	d := aclsData{Allow: []string{"192.0.2.1"}, Deny: []string{"198.51.100.0/24"}, Denied: 3,
		Auto: []autoBlock{{IP: "203.0.113.5", From: "honeypot", Reason: "ssh:bruteforce", Until: time.Now().Add(time.Hour)}, {IP: "2001:db8::/64", From: "ban", Until: time.Now()}}}
	body := renderPage(t, "access.html", d)
	for _, want := range []string{`id="freigabeliste"`, `id="sperrliste"`, "192.0.2.1", "198.51.100.0/24", "cdn64.sec.from_honeypot", "cdn64.sec.from_ban",
		`formaction="/cdn64/access/release?from=honeypot"`, `formaction="/cdn64/limits/unban"`, `formaction="/cdn64/honeypot/unblock"`, "cdn64.acl.empty"} {
		if !strings.Contains(body, want) {
			t.Fatalf("access page misses %q", want)
		}
	}
	body = renderPage(t, "security.html", securityData{HP: honeypotView{Blocks: []HoneypotBlock{{IP: "203.0.113.5"}}}})
	for _, want := range []string{`id="blocklists"`, `id="limits"`, `id="honeypot"`, "cdn64.sec.blocked_now", "/cdn64/access#freigabeliste"} {
		if !strings.Contains(body, want) {
			t.Fatalf("security page misses %q", want)
		}
	}
	if strings.Contains(body, `name="allow"`) {
		t.Fatal("allow list belongs to the access lists tab")
	}
}
