package checks

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// localResolver loest alles auf 127.0.0.1 auf, damit Tests offline laufen.
type localResolver struct{}

func (localResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if host == "dual.test" {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("::1")}}, nil
	}
	if host == "nope.invalid" {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	if host == "v6only.test" {
		return []net.IPAddr{{IP: net.ParseIP("::1")}}, nil
	}
	return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
}

func testRunner() *Runner {
	r := NewRunner()
	r.Resolver = localResolver{}
	r.FamilyProbe = func(string) bool { return true }
	return r
}

func TestAutoSkipsUnavailableFamily(t *testing.T) {
	r := testRunner()
	// Node ohne IPv6: auto prueft nur IPv4
	r.FamilyProbe = func(fam string) bool { return fam == "ipv4" }
	res := r.Run(context.Background(), def(TypePort, "dual.test:1", nil))
	if len(res) != 1 || res[0].Family != "ipv4" {
		t.Fatalf("auto without ipv6 should check ipv4 only, got %+v", res)
	}
	// Node mit beidem: zwei Teilergebnisse (neuer Runner, die Probe wird eine Minute gecacht)
	r = testRunner()
	if res := r.Run(context.Background(), def(TypePort, "dual.test:1", nil)); len(res) != 2 {
		t.Fatalf("auto with both families should check both, got %d", len(res))
	}
	// Explizit both bleibt strikt, auch ohne IPv6 am Node
	r = testRunner()
	r.FamilyProbe = func(fam string) bool { return fam == "ipv4" }
	d := def(TypePort, "dual.test:1", nil)
	d.IPMode = IPBoth
	if res := r.Run(context.Background(), d); len(res) != 2 {
		t.Fatalf("both must stay strict, got %d", len(res))
	}
	// Probe wird gecacht: zweiter Aufruf fragt nicht erneut
	calls := 0
	r2 := testRunner()
	r2.FamilyProbe = func(string) bool { calls++; return true }
	r2.Run(context.Background(), def(TypePort, "dual.test:1", nil))
	r2.Run(context.Background(), def(TypePort, "dual.test:1", nil))
	if calls != 2 {
		t.Fatalf("expected 2 probe calls (one per family), got %d", calls)
	}
}

func def(t Type, target string, params any) Definition {
	raw, _ := json.Marshal(params)
	return Definition{Token: "t", Type: t, Target: target, Params: raw, Timeouts: Timeouts{Connect: 2 * time.Second, Total: 3 * time.Second}}
}

func one(t *testing.T, r *Runner, d Definition) Result {
	t.Helper()
	res := r.Run(context.Background(), d)
	if len(res) != 1 {
		t.Fatalf("expected one result, got %d: %+v", len(res), res)
	}
	return res[0]
}

func TestHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.Write([]byte("hello world"))
		case "/teapot":
			w.WriteHeader(418)
		case "/slow":
			time.Sleep(2 * time.Second)
		case "/redirect":
			http.Redirect(w, r, "/ok", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		case "/auth":
			if u, p, ok := r.BasicAuth(); !ok || u != "bob" || p != "secret" {
				w.WriteHeader(401)
				return
			}
			w.Write([]byte("welcome bob"))
		case "/post":
			if r.Method != "POST" || r.Header.Get("X-Test") != "1" {
				w.WriteHeader(400)
				return
			}
			w.Write([]byte("posted"))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	r := testRunner()
	// Ziel-Host "localhost" geht ueber den Test-Resolver auf 127.0.0.1
	base := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)

	res := one(t, r, def(TypeHTTP, base+"/ok", nil))
	if res.Status != Up || res.Reason != ReasonOK || res.Details["status"] != 200 || res.Family != "ipv4" {
		t.Fatalf("ok: %+v", res)
	}
	if res := one(t, r, def(TypeHTTP, base+"/teapot", nil)); res.Status != Down || res.Reason != ReasonStatusMismatch {
		t.Fatalf("teapot: %+v", res)
	}
	if res := one(t, r, def(TypeHTTP, base+"/teapot", HTTPParams{AcceptStatus: "400-499"})); res.Status != Up {
		t.Fatalf("accept range: %+v", res)
	}
	d := def(TypeHTTP, base+"/slow", nil)
	d.Timeouts.Total = 300 * time.Millisecond
	if res := one(t, r, d); res.Status != Down || res.Reason != ReasonTimeout {
		t.Fatalf("timeout: %+v", res)
	}
	if res := one(t, r, def(TypeHTTP, base+"/redirect", nil)); res.Status != Up || res.Details["final_url"] != srv.URL+"/ok" && res.Details["final_url"] != base+"/ok" {
		t.Fatalf("redirect: %+v", res)
	}
	f := false
	if res := one(t, r, def(TypeHTTP, base+"/redirect", HTTPParams{FollowRedirects: &f, AcceptStatus: "302"})); res.Status != Up {
		t.Fatalf("no follow: %+v", res)
	}
	if res := one(t, r, def(TypeHTTP, base+"/loop", HTTPParams{MaxRedirects: 3})); res.Reason != ReasonTooManyRedirect {
		t.Fatalf("loop: %+v", res)
	}
	if res := one(t, r, def(TypeHTTP, base+"/auth", HTTPParams{BasicUser: "bob", BasicPassword: "secret"})); res.Status != Up {
		t.Fatalf("basic auth: %+v", res)
	}
	if res := one(t, r, def(TypeHTTP, base+"/post", HTTPParams{Method: "post", Headers: map[string]string{"X-Test": "1"}, Body: "x=1"})); res.Status != Up {
		t.Fatalf("post: %+v", res)
	}
	if res := one(t, r, def(TypeHTTP, "http://nope.invalid/", nil)); res.Reason != ReasonDNSFailed {
		t.Fatalf("dns: %+v", res)
	}
	// Keyword
	if res := one(t, r, def(TypeKeyword, base+"/ok", HTTPParams{Keyword: "world"})); res.Status != Up {
		t.Fatalf("keyword present: %+v", res)
	}
	if res := one(t, r, def(TypeKeyword, base+"/ok", HTTPParams{Keyword: "error"})); res.Reason != ReasonKeywordMissing {
		t.Fatalf("keyword missing: %+v", res)
	}
	if res := one(t, r, def(TypeKeyword, base+"/ok", HTTPParams{Keyword: "world", KeywordAbsent: true})); res.Reason != ReasonKeywordPresent {
		t.Fatalf("keyword absent: %+v", res)
	}
	// Verbindung verweigert
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	if res := one(t, r, def(TypeHTTP, "http://localhost:"+strconv.Itoa(port)+"/", nil)); res.Reason != ReasonConnectFailed {
		t.Fatalf("refused: %+v", res)
	}
}

func TestHTTPSAndCert(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("tls ok")) }))
	defer srv.Close()
	r := testRunner()
	base := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	if res := one(t, r, def(TypeHTTP, base, nil)); res.Reason != ReasonTLSFailed {
		t.Fatalf("self-signed must fail: %+v", res)
	}
	if res := one(t, r, def(TypeHTTP, base, HTTPParams{InsecureTLS: true})); res.Status != Up || res.Details["tls_version"] == nil {
		t.Fatalf("insecure tls: %+v", res)
	}
	host := strings.TrimPrefix(base, "https://")
	// Zertifikat: Kette ungueltig (selbstsigniert)
	if res := one(t, r, def(TypeCert, host, nil)); res.Reason != ReasonCertInvalid {
		t.Fatalf("chain: %+v", res)
	}
	// Ohne Kettenpruefung: httptest-Zertifikat gilt fuer 127.0.0.1 und example.com, Hostname localhost passt nicht
	if res := one(t, r, def(TypeCert, host, CertParams{SkipChain: true})); res.Reason != ReasonCertHostname {
		t.Fatalf("hostname: %+v", res)
	}
	res := one(t, r, def(TypeCert, host, CertParams{SkipChain: true, ServerName: "example.com"}))
	if res.Status != Up || res.Details["days_left"].(int) < 1 {
		t.Fatalf("cert ok: %+v", res)
	}
	// Schwelle hoeher als Restlaufzeit
	if res := one(t, r, def(TypeCert, host, CertParams{SkipChain: true, ServerName: "example.com", MinDays: 30000})); res.Reason != ReasonCertExpiring {
		t.Fatalf("expiring: %+v", res)
	}
	_ = tls.VersionTLS12
}

func TestTCPAndPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.Write([]byte("220 test smtp ready\r\n"))
				buf := make([]byte, 64)
				n, _ := c.Read(buf)
				if strings.HasPrefix(string(buf[:n]), "EHLO") {
					c.Write([]byte("250 hello\r\n"))
				}
			}(c)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	r := testRunner()
	target := "localhost:" + strconv.Itoa(port)

	if res := one(t, r, def(TypeTCP, target, nil)); res.Status != Up {
		t.Fatalf("tcp connect: %+v", res)
	}
	if res := one(t, r, def(TypeTCP, "localhost", TCPParams{Port: port, Expect: "220"})); res.Status != Up {
		t.Fatalf("banner: %+v", res)
	}
	if res := one(t, r, def(TypeTCP, target, TCPParams{Send: `EHLO x\r\n`, Expect: "250 hello"})); res.Status != Up || !strings.Contains(res.Details["banner"].(string), "250") {
		t.Fatalf("send/expect: %+v", res)
	}
	if res := one(t, r, def(TypeTCP, target, TCPParams{Expect: "SSH"})); res.Reason != ReasonBannerMismatch {
		t.Fatalf("banner mismatch: %+v", res)
	}
	if res := one(t, r, def(TypePort, target, nil)); res.Status != Up {
		t.Fatalf("port open: %+v", res)
	}
	if res := one(t, r, def(TypePort, target, TCPParams{Expect: "closed"})); res.Reason != ReasonPortOpen {
		t.Fatalf("expect closed but open: %+v", res)
	}
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln2.Addr().(*net.TCPAddr).Port
	ln2.Close()
	if res := one(t, r, def(TypePort, "localhost:"+strconv.Itoa(closed), nil)); res.Reason != ReasonPortClosed || res.Details["state"] != "closed" {
		t.Fatalf("port closed: %+v", res)
	}
	if res := one(t, r, def(TypePort, "localhost:"+strconv.Itoa(closed), TCPParams{Expect: "closed"})); res.Status != Up {
		t.Fatalf("expect closed: %+v", res)
	}
}

func TestIPModes(t *testing.T) {
	r := testRunner()
	d := def(TypePort, "v6only.test:80", nil)
	d.IPMode = IPv4
	if res := one(t, r, d); res.Reason != ReasonNoAddress {
		t.Fatalf("v4 on v6-only host: %+v", res)
	}
	d = def(TypePort, "127.0.0.1:80", nil)
	d.IPMode = IPv6
	if res := one(t, r, d); res.Reason != ReasonNoAddress {
		t.Fatalf("v6 on v4 literal: %+v", res)
	}
	d = def(TypePort, "localhost:80", nil)
	d.IPMode = IPBoth
	if res := one(t, r, d); res.Reason != ReasonNoAddress {
		t.Fatalf("both on v4-only: %+v", res)
	}
	if res := r.Run(context.Background(), def(TypePush, "", nil)); res != nil {
		t.Fatal("push must not produce results")
	}
}

func TestValidate(t *testing.T) {
	good := []Definition{
		def(TypeHTTP, "https://example.com/", HTTPParams{AcceptStatus: "200-299,301"}),
		def(TypeKeyword, "example.com", HTTPParams{Keyword: "x"}),
		def(TypeTCP, "example.com:22", nil),
		def(TypePort, "example.com", TCPParams{Port: 443, Expect: "closed"}),
		def(TypeCert, "example.com", CertParams{MinDays: 30}),
		def(TypeICMP, "example.com", ICMPParams{Count: 5, MaxLossPercent: 20}),
		def(TypePush, "", map[string]int{"period_seconds": 60, "grace_seconds": 30}),
	}
	for _, d := range good {
		if err := Validate(d); err != nil {
			t.Errorf("%s %s: unexpected error %v", d.Type, d.Target, err)
		}
	}
	bad := []Definition{
		def(TypeHTTP, "ftp://example.com/", nil),
		def(TypeHTTP, "https://example.com/", HTTPParams{AcceptStatus: "abc"}),
		def(TypeKeyword, "https://example.com/", nil),
		def(TypeTCP, "example.com", nil),
		def(TypePort, "example.com:80", TCPParams{Expect: "maybe"}),
		def(TypeICMP, "example.com", ICMPParams{Count: 99}),
		def(Type("snmp"), "example.com", nil),
		{Type: TypeHTTP, Target: "https://example.com/", Params: json.RawMessage(`{"unknown_field":1}`)},
	}
	for _, d := range bad {
		if err := Validate(d); err == nil {
			t.Errorf("%s %s: expected error", d.Type, d.Target)
		}
	}
	if ranges, _ := parseStatusRanges(" 301, 200-204 "); len(ranges) != 2 || ranges[0].lo != 200 || !statusAccepted(301, ranges) || statusAccepted(205, ranges) {
		t.Fatalf("status ranges: %+v", ranges)
	}
}

// TestICMP laeuft nur mit NODE64_TEST_ICMP=1 (braucht Ping-Rechte).
func TestICMP(t *testing.T) {
	if os.Getenv("NODE64_TEST_ICMP") == "" {
		t.Skip("set NODE64_TEST_ICMP=1 to run")
	}
	r := testRunner()
	res := one(t, r, def(TypeICMP, "localhost", ICMPParams{Count: 2}))
	if res.Status != Up {
		t.Fatalf("icmp localhost: %+v", res)
	}
}

func TestDisplayTarget(t *testing.T) {
	cases := []struct {
		def  Definition
		want string
	}{
		{Definition{Type: TypeTCP, Target: "192.168.10.30", Params: []byte(`{"port":22}`)}, "192.168.10.30:22"},
		{Definition{Type: TypePort, Target: "2001:db8::1", Params: []byte(`{"port":443}`)}, "[2001:db8::1]:443"},
		{Definition{Type: TypeTCP, Target: "example.com:25", Params: []byte(`{}`)}, "example.com:25"},
		{Definition{Type: TypeCert, Target: "ipv64.net", Params: []byte(`{"port":443}`)}, "ipv64.net"},
		{Definition{Type: TypeCert, Target: "mail.example.com", Params: []byte(`{"port":993}`)}, "mail.example.com:993"},
		{Definition{Type: TypeHTTP, Target: "https://ipv64.net/", Params: []byte(`{}`)}, "https://ipv64.net/"},
		{Definition{Type: TypeICMP, Target: "1.1.1.1"}, "1.1.1.1"},
	}
	for _, c := range cases {
		if got := DisplayTarget(c.def); got != c.want {
			t.Errorf("DisplayTarget(%s %q) = %q, want %q", c.def.Type, c.def.Target, got, c.want)
		}
	}
}

func TestWithoutUnknownParams(t *testing.T) {
	def := Definition{Type: TypeTCP, Target: "example.com:443", Params: json.RawMessage(`{"port":443,"future":"x","later":1}`)}
	got := WithoutUnknownParams(def)
	def.Params = got
	if err := Validate(def); err != nil || strings.Contains(string(got), "future") || !strings.Contains(string(got), "443") {
		t.Fatalf("got %s (%v)", got, err)
	}
	ok := json.RawMessage(`{"port":443}`)
	if g := WithoutUnknownParams(Definition{Type: TypeTCP, Target: "example.com:443", Params: ok}); string(g) != string(ok) {
		t.Fatalf("valid params changed: %s", g)
	}
}

func TestHTTPHostHeader(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sni := ""
		if r.TLS != nil {
			sni = r.TLS.ServerName
		}
		w.Write([]byte("host=" + r.Host + " sni=" + sni))
	})
	srv := httptest.NewServer(h)
	defer srv.Close()
	r := testRunner()
	base := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	if res := one(t, r, def(TypeKeyword, base+"/", HTTPParams{Keyword: "host=vhost.test ", Headers: map[string]string{"host": "vhost.test"}})); res.Status != Up {
		t.Fatalf("host header: %+v", res)
	}
	tsrv := httptest.NewTLSServer(h)
	defer tsrv.Close()
	tbase := strings.Replace(tsrv.URL, "127.0.0.1", "localhost", 1)
	if res := one(t, r, def(TypeKeyword, tbase+"/", HTTPParams{InsecureTLS: true, Keyword: "host=example.com:8443 sni=example.com", Headers: map[string]string{"Host": "example.com:8443"}})); res.Status != Up {
		t.Fatalf("host header tls: %+v", res)
	}
	// Zertifikatspruefung gegen den Host-Kopf (Kette des httptest-Zertifikats unbekannt)
	if res := one(t, r, def(TypeHTTP, tbase+"/", HTTPParams{Headers: map[string]string{"Host": "example.com"}})); res.Reason != ReasonTLSFailed {
		t.Fatalf("host header tls verify: %+v", res)
	}
}

func TestPingTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if got := pingTimeout(ctx, 5*time.Second); got > 4600*time.Millisecond || got < 4*time.Second {
		t.Fatalf("ping timeout must end before context: %v", got)
	}
	if got := pingTimeout(context.Background(), 300*time.Millisecond); got != 200*time.Millisecond {
		t.Fatalf("short: %v", got)
	}
}
