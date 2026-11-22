package cdn64

import (
	"context"
	"io"
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

// Let's-Encrypt-Pruefungen (HTTP-01, Forum 5245): ipv64-Blocklisten, Honeypot-Sperre und Laendersperre lassen GET/HEAD
// auf /.well-known/acme-challenge/<token> ueber HTTP zum Ziel durch. Andere Pfade und Methoden, HTTPS, die eigene
// Sperrliste und die Zugriffsliste des Hosts sperren weiter - mit und ohne Koeder.
func TestACMEExempt(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.m.SetDataDir(t.TempDir())
	lists := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ipv64_blocklist_all.txt" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "127.0.0.1/32\n203.0.113.1/32\n") // auch der eigene Client (Eingang)
	}))
	defer lists.Close()
	e.m.bl.base = lists.URL + "/"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "app:"+r.URL.Path) }))
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)
	bport, _ := strconv.Atoi(bu.Port())
	certPEM, keyPEM := selfSigned(t, "app.test")
	if _, err := e.crt.Upload(ctx, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	e.enable(t)
	m := e.m
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.BlockExploits = []string{"app.test"}, "127.0.0.1", bport, true
	h.Advanced.GeoMode, h.Advanced.GeoCountries = geoBlock, []string{"DE"}
	if err := m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	acl := &AccessList{Name: "nur lan", Rules: []AccessRule{{Action: "allow", CIDR: "10.0.0.0/8"}}}
	if err := m.saveAccessList(ctx, acl, nil); err != nil {
		t.Fatal(err)
	}
	ha := newHost()
	ha.Names, ha.TargetHost, ha.TargetPort, ha.CertID, ha.AccessListID = []string{"acl.test"}, "127.0.0.1", bport, CertNone, acl.ID
	if err := m.saveHost(ctx, ha); err != nil {
		t.Fatal(err)
	}
	m.bl.geo.put("DE", []netip.Prefix{netip.MustParsePrefix("5.1.0.0/16")}, time.Now())
	if err := m.hpSave(ctx, HoneypotSettings{Block: true, BlockHours: 1}); err != nil { // Route nil = Standard
		t.Fatal(err)
	}
	hpbridge.PublishBlock(hpbridge.Block{IP: netip.MustParseAddr("203.0.113.2"), Reason: "ssh:bruteforce"})
	deny := "203.0.113.4"
	if err := m.blListsSave(ctx, nil, &deny); err != nil {
		t.Fatal(err)
	}
	if err := m.blSave(ctx, []string{"all"}, ""); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100 && m.bl.set.Load() == nil; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if !m.bl.Blocked(netip.MustParseAddr("203.0.113.1")) || !m.hpBlocked(netip.MustParseAddr("203.0.113.2")) ||
		!m.geoBlocked(&h.Advanced, netip.MustParseAddr("5.1.2.3")) || !m.bl.Denied(netip.MustParseAddr("203.0.113.4")) {
		t.Fatal("test setup: blocks not active")
	}
	hpbridge.SetDecoy(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, "decoy")
	}))
	t.Cleanup(func() { hpbridge.SetDecoy(nil); hpbridge.SetWanted(false) })

	hd, hdACL := m.handlerFor(h, &hostStats{}), m.handlerFor(ha, &hostStats{})
	call := func(hd http.Handler, method, u, ip string) (int, string) {
		req := httptest.NewRequest(method, u, nil) // https:// setzt req.TLS
		req.RemoteAddr = ip + ":4242"
		rec := httptest.NewRecorder()
		hd.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	const tok = "/.well-known/acme-challenge/Abc-123_xyz"
	passed := func(code int, body, path string) bool { return code == http.StatusOK && body == "app:"+path }
	c := e.client(false)
	for _, decoy := range []bool{false, true} {
		hpbridge.SetWanted(decoy) // Vorlage "Nur ueber PROXY64": Koeder an (Wege Blockliste und Honeypot)
		if m.hpDecoyActive() != decoy {
			t.Fatalf("decoy %v: not switched", decoy)
		}
		// Host: Blockliste, Honeypot-Sperre, Land
		for _, ip := range []string{"203.0.113.1", "203.0.113.2", "5.1.2.3"} {
			for _, method := range []string{"GET", "HEAD"} {
				if code, body := call(hd, method, "http://app.test"+tok, ip); code != http.StatusOK || (method == "GET" && !passed(code, body, tok)) {
					t.Fatalf("decoy %v %s %s acme: %d %q", decoy, ip, method, code, body)
				}
			}
			for _, r := range [][2]string{{"GET", "http://app.test/"}, {"GET", "https://app.test" + tok}, {"POST", "http://app.test" + tok},
				{"GET", "http://app.test" + tok + "/x"}, {"GET", "http://app.test/.well-known/acme-challenge/../admin"}} {
				if code, body := call(hd, r[0], r[1], ip); code == http.StatusOK || strings.HasPrefix(body, "app:") {
					t.Fatalf("decoy %v %s %s %s must stay blocked: %d %q", decoy, ip, r[0], r[1], code, body)
				}
			}
		}
		// eigene Sperrliste und Zugriffsliste gelten weiter
		if code, body := call(hd, "GET", "http://app.test"+tok, "203.0.113.4"); code != http.StatusForbidden {
			t.Fatalf("decoy %v deny list: %d %q", decoy, code, body)
		}
		for _, ip := range []string{"203.0.113.9", "203.0.113.1"} {
			if code, body := call(hdACL, "GET", "http://acl.test"+tok, ip); code == http.StatusOK || strings.HasPrefix(body, "app:") {
				t.Fatalf("decoy %v %s access list: %d %q", decoy, ip, code, body)
			}
		}
		if code, body := call(hdACL, "GET", "http://acl.test"+tok, "10.1.2.3"); !passed(code, body, tok) {
			t.Fatalf("decoy %v access list allowed: %d %q", decoy, code, body)
		}

		// Eingang (Port 80 und 443) mit dem eigenen Client auf der Blockliste
		c.CloseIdleConnections()
		if code, body, _ := do(t, c, "GET", "http://app.test"+tok); !passed(code, body, tok) {
			t.Fatalf("decoy %v entrance acme: %d %q", decoy, code, body)
		}
		release, err := e.edge.Present("owntoken", "owntoken.key")
		if err != nil {
			t.Fatal(err)
		}
		code, body, _ := do(t, c, "GET", "http://other.test/.well-known/acme-challenge/owntoken")
		release()
		if code != http.StatusOK || body != "owntoken.key" {
			t.Fatalf("decoy %v entrance own token: %d %q", decoy, code, body)
		}
		for _, u := range []string{"http://app.test/", "https://app.test" + tok} {
			c.CloseIdleConnections()
			if code, body, _ := do(t, c, "GET", u); code == http.StatusOK || strings.HasPrefix(body, "app:") {
				t.Fatalf("decoy %v entrance %s must stay blocked: %d %q", decoy, u, code, body)
			}
		}
		if !decoy { // ohne Koeder: 403 je Anfrage auf Port 80, HTTPS beim Annehmen getrennt
			if code, _, _ := do(t, c, "GET", "http://app.test/"); code != http.StatusForbidden {
				t.Fatalf("entrance port 80 without decoy: %d", code)
			}
		}
	}

	// HTTPS erzwingen: die Pruefung geht ueber HTTP direkt ans Ziel (auch gesperrt), alles andere wird umgeleitet
	hpbridge.SetWanted(false)
	hf := newHost()
	hf.Names, hf.TargetHost, hf.TargetPort, hf.ForceSSL = []string{"force.test"}, "127.0.0.1", bport, true
	if err := m.saveHost(ctx, hf); err != nil {
		t.Fatal(err)
	}
	rt := m.routeFor(hf)
	if rt.HTTP == nil || rt.Handler == nil {
		t.Fatalf("force ssl route: %+v", rt)
	}
	for _, ip := range []string{"203.0.113.9", "203.0.113.1", "5.1.2.3"} {
		if code, body := call(rt.HTTP, "GET", "http://force.test"+tok, ip); !passed(code, body, tok) {
			t.Fatalf("force ssl %s acme: %d %q", ip, code, body)
		}
		req := httptest.NewRequest("GET", "http://force.test/x?y=1", nil)
		req.RemoteAddr = ip + ":4242"
		rec := httptest.NewRecorder()
		rt.HTTP.ServeHTTP(rec, req)
		if rec.Code != http.StatusMovedPermanently || !strings.HasPrefix(rec.Header().Get("Location"), "https://force.test") ||
			!strings.HasSuffix(rec.Header().Get("Location"), "/x?y=1") {
			t.Fatalf("force ssl %s redirect: %d %q", ip, rec.Code, rec.Header().Get("Location"))
		}
		if code, _ := call(rt.HTTP, "POST", "http://force.test"+tok, ip); code != http.StatusMovedPermanently {
			t.Fatalf("force ssl %s post acme: %d", ip, code)
		}
	}
	if code, body := call(rt.HTTP, "GET", "http://force.test"+tok, "203.0.113.4"); code != http.StatusForbidden { // eigene Sperrliste
		t.Fatalf("force ssl deny list: %d %q", code, body)
	}
	c.CloseIdleConnections()
	if code, body, _ := do(t, c, "GET", "http://force.test"+tok); !passed(code, body, tok) { // Eingang, Client gesperrt
		t.Fatalf("force ssl entrance acme: %d %q", code, body)
	}
	release, err := e.edge.Present("owntoken2", "owntoken2.key") // eigene Tokens der Node gehen vor
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if code, body, _ := do(t, c, "GET", "http://force.test/.well-known/acme-challenge/owntoken2"); code != http.StatusOK || body != "owntoken2.key" {
		t.Fatalf("force ssl own token: %d %q", code, body)
	}
}
