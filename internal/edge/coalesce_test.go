package edge

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
	"strconv"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/dns64/localnet"
)

// #132: HTTP/2 legt Verbindungen fuer alle Namen zusammen, die das Zertifikat abdeckt (Safari mit Wildcard-Zertifikat).
// Anfragen mit anderem Host als SNI werden nach dem Host beantwortet, wenn das Zertifikat der Verbindung ihn abdeckt;
// sonst bleibt es bei 421.
func TestCoalescedHost(t *testing.T) {
	hp, hsp := freePort(t), freePort(t)
	for hsp == hp {
		hsp = freePort(t)
	}
	cfg := Config{Bind: "127.0.0.1", HTTPPort: hp, HTTPSPort: hsp, Default: DefaultNotFound}
	wild := selfSigned(t, "*.example.test")
	other := selfSigned(t, "other.test")
	certs := fakeCerts{crt: map[string]*tls.Certificate{"router.example.test": wild, "vscode.example.test": wild, "strict.example.test": wild,
		"h1.example.test": wild, "other.test": other}}
	e, err := New(cfg, certs, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close(context.Background()) })
	answer := func(s string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, s) })
	}
	if err := e.Set("cdn64", []Route{{Names: []string{"router.example.test"}, Handler: answer("router")},
		{Names: []string{"vscode.example.test"}, Handler: answer("vscode")},
		{Names: []string{"strict.example.test"}, Handler: answer("strict"), MinTLS: tls.VersionTLS13},
		{Names: []string{"h1.example.test"}, Handler: answer("h1"), NoHTTP2: true},
		{Names: []string{"other.test"}, Handler: answer("other")}}); err != nil {
		t.Fatal(err)
	}
	// Verbindung mit SNI router.example.test, Anfrage mit anderem Host (wie curl --resolve ... -H 'Host: ...')
	do := func(host string, maxTLS uint16) (int, string, string) {
		t.Helper()
		tr := &http.Transport{TLSClientConfig: &tls.Config{ServerName: "router.example.test", InsecureSkipVerify: true, MaxVersion: maxTLS}, //nolint:gosec // Test
			ForceAttemptHTTP2: true, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:"+strconv.Itoa(cfg.HTTPSPort))
			}}
		defer tr.CloseIdleConnections()
		c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
		req, _ := http.NewRequest(http.MethodGet, "https://router.example.test/", nil)
		req.Host = host
		resp, err := c.Do(req)
		if err != nil {
			return 0, err.Error(), ""
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), resp.Proto
	}
	if code, body, proto := do("vscode.example.test", 0); code != 200 || body != "vscode" || proto != "HTTP/2.0" {
		t.Fatalf("coalesced host: %d %q %s", code, body, proto)
	}
	if code, body, _ := do("router.example.test", 0); code != 200 || body != "router" {
		t.Fatalf("same host: %d %q", code, body)
	}
	if code, _, _ := do("other.test", 0); code != http.StatusMisdirectedRequest { // Zertifikat deckt den Host nicht ab
		t.Fatalf("other cert: %d", code)
	}
	if code, _, _ := do("strict.example.test", tls.VersionTLS12); code != http.StatusMisdirectedRequest { // verlangt TLS 1.3
		t.Fatalf("min tls: %d", code)
	}
	if code, body, _ := do("strict.example.test", 0); code != 200 || body != "strict" { // TLS 1.3 erfuellt
		t.Fatalf("min tls ok: %d %q", code, body)
	}
	if code, _, _ := do("h1.example.test", 0); code != http.StatusMisdirectedRequest { // nur HTTP/1.1, Verbindung ist h2
		t.Fatalf("no http2: %d", code)
	}
	if code, _, _ := do("unknown.example.test", 0); code != http.StatusMisdirectedRequest { // unbekannter Name
		t.Fatalf("unknown: %d", code)
	}
}

// TLS ohne SNI bekommt die Ersatz-Konfiguration; eine Anfrage fuer einen Namen muss trotzdem dessen TLS-Vorgaben
// erfuellen (hier mindestens TLS 1.3), sonst 421.
func TestNoSNITLSRules(t *testing.T) {
	hp, hsp := freePort(t), freePort(t)
	for hsp == hp {
		hsp = freePort(t)
	}
	cfg := Config{Bind: "127.0.0.1", HTTPPort: hp, HTTPSPort: hsp, Default: DefaultNotFound}
	crt := selfSigned(t, "strict.example.test", "plain.example.test")
	e, err := New(cfg, fakeCerts{crt: map[string]*tls.Certificate{"strict.example.test": crt, "plain.example.test": crt}}, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close(context.Background()) })
	answer := func(s string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, s) })
	}
	if err := e.Set("cdn64", []Route{{Names: []string{"strict.example.test"}, Handler: answer("strict"), MinTLS: tls.VersionTLS13},
		{Names: []string{"plain.example.test"}, Handler: answer("plain")}}); err != nil {
		t.Fatal(err)
	}
	do := func(host string, maxTLS uint16) int {
		t.Helper()
		// Ziel per IP: der Client schickt kein SNI
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MaxVersion: maxTLS}} //nolint:gosec // Test
		defer tr.CloseIdleConnections()
		c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
		req, _ := http.NewRequest(http.MethodGet, "https://127.0.0.1:"+strconv.Itoa(cfg.HTTPSPort)+"/", nil)
		req.Host = host
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := do("strict.example.test", tls.VersionTLS12); code != http.StatusMisdirectedRequest {
		t.Fatalf("no SNI, TLS 1.2, MinTLS 1.3 host: %d", code)
	}
	if code := do("strict.example.test", tls.VersionTLS13); code != 200 {
		t.Fatalf("no SNI, TLS 1.3: %d", code)
	}
	if code := do("plain.example.test", tls.VersionTLS12); code != 200 {
		t.Fatalf("no SNI, host without rules: %d", code)
	}
}

// WE-3: Im Docker-Bridge-Netz ist die Adresse des Gateways keine Herkunft. Allow der Route bekommt trotzdem die echte
// Adresse und wertet sie selbst (z. B. "nur Heimnetz" der Oberflaeche lehnt per localnet.Origin ab), damit
// ausdrueckliche Freigaben des Gateways wirken (DoH mit "weitere erlaubte Client-Netze", Laendersperre).
func TestAllowMaskedGateway(t *testing.T) {
	e, _ := newEdge(t, nil)
	var got []netip.Addr
	lan := func(ip netip.Addr) bool {
		got = append(got, ip)
		ip = localnet.Origin(ip)
		return ip.IsLoopback() || ip.IsPrivate()
	}
	explicit := func(ip netip.Addr) bool { return ip == netip.MustParseAddr("172.17.0.1") } // Gateway freigegeben
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	if err := e.Set("ui", []Route{{Names: []string{"app.test"}, Handler: ok, Allow: lan}}); err != nil {
		t.Fatal(err)
	}
	if err := e.Set("dns64", []Route{{Names: []string{"dns.test"}, Handler: ok, Allow: explicit}}); err != nil {
		t.Fatal(err)
	}
	do := func(host string) int {
		req := httptest.NewRequest(http.MethodGet, "https://"+host+"/", nil)
		req.RemoteAddr = "172.17.0.1:40000"
		rec := httptest.NewRecorder()
		e.serveHTTPS(rec, req)
		return rec.Code
	}
	restore := localnet.OriginForTest(false, netip.MustParseAddr("172.17.0.1")) // der Test selbst kann im Bridge-Netz laufen
	if code := do("app.test"); code != 200 {
		t.Fatalf("private address without bridge: %d", code)
	}
	restore()
	restore = localnet.OriginForTest(true, netip.MustParseAddr("172.17.0.1"))
	defer restore()
	if code := do("app.test"); code == 200 {
		t.Fatalf("docker gateway counted as home network: %d", code)
	}
	if last := got[len(got)-1]; last != netip.MustParseAddr("172.17.0.1") {
		t.Fatalf("allow got %v, want the real gateway address", last)
	}
	if code := do("dns.test"); code != 200 {
		t.Fatalf("explicitly allowed gateway: %d", code)
	}
}

// Verbindung aus dem Tunnel fuer einen Namen (Modus 1, Port 443): auch wenn das Zertifikat der Verbindung einen anderen
// Host abdeckt (Wildcard), gilt sie nur fuer ihren Namen - Host-Kopf mit anderem Namen bekommt 421.
func TestRoutedTLSNoCoalescing(t *testing.T) {
	hp, hsp := freePort(t), freePort(t)
	for hsp == hp {
		hsp = freePort(t)
	}
	cfg := Config{Bind: "127.0.0.1", HTTPPort: hp, HTTPSPort: hsp, Default: DefaultNotFound}
	wild := selfSigned(t, "*.example.test")
	e, err := New(cfg, fakeCerts{crt: map[string]*tls.Certificate{"cloud.example.test": wild, "intern.example.test": wild}}, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close(context.Background()) })
	answer := func(s string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, s) })
	}
	if err := e.Set("cdn64", []Route{{Names: []string{"cloud.example.test"}, Handler: answer("cloud")},
		{Names: []string{"intern.example.test"}, Handler: answer("intern")}}); err != nil {
		t.Fatal(err)
	}
	do := func(host string) int {
		t.Helper()
		served, cl := pair(t, "203.0.113.20:7000")
		e.ServeConnFor(served, 443, "cloud.example.test")
		tc := tls.Client(cl, &tls.Config{ServerName: "cloud.example.test", InsecureSkipVerify: true}) //nolint:gosec // Test
		defer tc.Close()
		_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.WriteString(tc, "GET / HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := do("cloud.example.test"); code != 200 {
		t.Fatalf("routed name: %d", code)
	}
	if code := do("intern.example.test"); code != http.StatusMisdirectedRequest {
		t.Fatalf("other host on routed TLS connection: %d", code)
	}
}
