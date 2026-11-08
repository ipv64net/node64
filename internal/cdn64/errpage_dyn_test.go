package cdn64

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Eigene Fehlerseite (GitHub #38): bei Ziel nicht erreichbar, optional statt 5xx des Ziels; sonst unveraendert.
func TestCustomErrorPage(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0") // geschlossener Port: Ziel nicht erreichbar
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ok" {
			_, _ = io.WriteString(w, "alles gut")
			return
		}
		w.Header().Set("Content-Encoding", "identity")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "stacktrace intern")
	}))
	defer srv.Close()
	live := srv.Listener.Addr().(*net.TCPAddr).Port
	page := "<h1>{{STATUS}} auf {{HOST}}</h1>"

	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"fehler.test"}, "127.0.0.1", dead, CertNone
	h.Advanced.ErrorHTML = page
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	c := e.client(false)
	if code, body, hdr := do(t, c, "GET", "http://fehler.test/"); code != 502 || body != "<h1>502 auf fehler.test</h1>" || hdr.Get("Cache-Control") != "no-store" || hdr.Get("CDN64-Error-Page") != "off" {
		t.Fatalf("unreachable: %d %q %v", code, body, hdr)
	}

	h.TargetPort = live
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if code, body, hdr := do(t, c, "GET", "http://fehler.test/x"); code != 500 || body != "stacktrace intern" || hdr.Get("CDN64-Error-Page") != "" {
		t.Fatalf("5xx without override: %d %q", code, body)
	}
	h.Advanced.ErrorOverride = true
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	code, body, hdr := do(t, c, "GET", "http://fehler.test/x")
	if code != 500 || !strings.Contains(body, "500 auf") || strings.Contains(body, "stacktrace") || hdr.Get("Content-Encoding") != "" || hdr.Get("Content-Length") != strconv.Itoa(len(body)) {
		t.Fatalf("5xx with override: %d %q %v", code, body, hdr)
	}
	if code, body, _ := do(t, c, "GET", "http://fehler.test/ok"); code != 200 || body != "alles gut" {
		t.Fatalf("2xx untouched: %d %q", code, body)
	}

	// leer = neutral, Schalter faellt weg; zu gross = Fehler; nur Proxy-Hosts
	h.Advanced.ErrorHTML = "  "
	if err := e.m.saveHost(ctx, h); err != nil || h.Advanced.ErrorOverride || h.Advanced.ErrorHTML != "" {
		t.Fatalf("empty: %v %+v", err, h.Advanced)
	}
	h.Advanced.ErrorHTML = strings.Repeat("x", maintMaxHTML+1)
	var fe *FieldError
	if err := e.m.saveHost(ctx, h); !errors.As(err, &fe) || fe.Field != "error_html" {
		t.Fatalf("too large: %v", err)
	}
	a := Advanced{ErrorHTML: "x", ErrorOverride: true}
	if err := a.normalizeErrPage(KindRedirect); err != nil || a.ErrorHTML != "" || a.ErrorOverride {
		t.Fatalf("redirect host: %+v", a)
	}
}

// Dynamische Regeln (GitHub #32): eigene oeffentliche IP und DNS-Namen.
func TestDynRules(t *testing.T) {
	for in, want := range map[string]string{"self": "self", "SELF6": "self6", "self4": "self4", "home.example.net": "name", "all": "",
		"10.0.0.1": "", "10.0.0.0/8": "", "2001:db8::1": "", "bad_name!.de": "", "nodot": ""} {
		if got := dynRule(in); got != want {
			t.Errorf("dynRule(%q) = %q, want %q", in, got, want)
		}
	}
	now := time.Unix(1_000_000, 0)
	var calls atomic.Int32
	d := newDynAddrs()
	d.now = func() time.Time { return now }
	d.publicIP = func(_ context.Context, fam string) (string, error) {
		calls.Add(1)
		if fam == "ipv6" {
			return "2001:db8:1:2::77", nil
		}
		return "203.0.113.9", nil
	}
	d.lookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "home.example.net" {
			return []netip.Addr{netip.MustParseAddr("198.51.100.4"), netip.MustParseAddr("2001:db8:5::1")}, nil
		}
		return nil, errors.New("nxdomain")
	}
	ip := netip.MustParseAddr
	cases := []struct {
		kind, cidr, ip string
		want           bool
	}{
		{"self", "self", "203.0.113.9", true},
		{"self", "self", "2001:db8:1:2:abcd::1", true}, // anderes Geraet im selben /64
		{"self", "self", "2001:db8:1:3::1", false},
		{"self4", "self4", "2001:db8:1:2::1", false},
		{"self6", "self6", "203.0.113.9", false},
		{"name", "home.example.net", "198.51.100.4", true},
		{"name", "home.example.net", "2001:db8:5::99", true},
		{"name", "home.example.net", "198.51.100.5", false},
		{"name", "gibtsnicht.example", "198.51.100.4", false},
	}
	for _, c := range cases {
		if got := d.matches(c.kind, c.cidr, ip(c.ip)); got != c.want {
			t.Errorf("%s %s %s = %v", c.kind, c.cidr, c.ip, got)
		}
	}
	n := calls.Load()
	d.matches("self", "self", ip("203.0.113.9"))
	if calls.Load() != n {
		t.Fatalf("cached: %d -> %d calls", n, calls.Load())
	}
	var nilD *dynAddrs
	if nilD.matches("self", "self", ip("203.0.113.9")) {
		t.Fatal("nil resolver must not match")
	}
}

// Zugriffsliste mit "allow self4": Heimgeraete ohne Anmeldung, andere mit Passwort.
func TestAccessListSelfRule(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	port, _ := echoBackend(t, "ziel")
	public := "127.0.0.1" // der Test-Client kommt von 127.0.0.1
	e.m.SetPublicIP(func(_ context.Context, fam string) (string, error) {
		if fam == "ipv4" {
			return public, nil
		}
		return "", errors.New("no ipv6")
	})
	a := &AccessList{Name: "Heim", SatisfyAny: true, Rules: []AccessRule{{Action: "allow", CIDR: "SELF4"}, {Action: "allow", CIDR: "home.example.test"}}}
	if err := e.m.saveAccessList(ctx, a, []UserInput{{Username: "anna", Password: "geheim123"}}); err != nil {
		t.Fatal(err)
	}
	if a.Rules[0].CIDR != "self4" || a.Rules[1].CIDR != "home.example.test" {
		t.Fatalf("saved rules: %+v", a.Rules)
	}
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID, h.AccessListID = []string{"heim.test"}, "127.0.0.1", port, CertNone, a.ID
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	c := e.client(false)
	if code, body, _ := do(t, c, "GET", "http://heim.test/"); code != 200 || !strings.Contains(body, "ziel") {
		t.Fatalf("own ip: %d %.80s", code, body)
	}
	e.m.dyn.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.9.9.9")}, nil
	}
	b := &AccessList{Name: "Fremd", SatisfyAny: true, Rules: []AccessRule{{Action: "allow", CIDR: "other.example.test"}}}
	if err := e.m.saveAccessList(ctx, b, []UserInput{{Username: "anna", Password: "geheim123"}}); err != nil {
		t.Fatal(err)
	}
	h2 := newHost()
	h2.Names, h2.TargetHost, h2.TargetPort, h2.CertID, h2.AccessListID = []string{"fremd.test"}, "127.0.0.1", port, CertNone, b.ID
	if err := e.m.saveHost(ctx, h2); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := do(t, c, "GET", "http://fremd.test/"); code != 401 {
		t.Fatalf("other name: %d", code)
	}
	if code, _, _ := do(t, c, "GET", "http://fremd.test/", "Authorization", basic("anna", "geheim123")); code != 200 {
		t.Fatalf("other name with login: %d", code)
	}
	bad := &AccessList{Name: "Kaputt", Rules: []AccessRule{{Action: "allow", CIDR: "kein name!"}}}
	var fe *FieldError
	if err := e.m.saveAccessList(ctx, bad, nil); !errors.As(err, &fe) || fe.Field != "rules" {
		t.Fatalf("invalid rule: %v", err)
	}
}
