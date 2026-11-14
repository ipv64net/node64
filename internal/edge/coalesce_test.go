package edge

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
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
