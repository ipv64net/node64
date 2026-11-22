package edge

import (
	"bufio"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// ACMEChallenge: nur GET/HEAD ueber HTTP auf /.well-known/acme-challenge/<token>, Token aus Base64url-Zeichen.
func TestACMEChallenge(t *testing.T) {
	for u, want := range map[string]bool{
		"http://a.test/.well-known/acme-challenge/Abc-123_xyz":    true,
		"http://a.test/.well-known/acme-challenge/":               false,
		"http://a.test/.well-known/acme-challenge/a/b":            false,
		"http://a.test/.well-known/acme-challenge/../admin":       false,
		"http://a.test/.well-known/acme-challenge/%2e%2e%2fadmin": false,
		"http://a.test/.well-known/acme-challenge/a.b":            false,
		"http://a.test/.well-known/acme-challengeX":               false,
		"http://a.test/admin":                                     false,
		"https://a.test/.well-known/acme-challenge/Abc":           false, // nur HTTP
	} {
		if got := ACMEChallenge(httptest.NewRequest(http.MethodGet, u, nil)); got != want {
			t.Errorf("%s: %v", u, got)
		}
	}
	if !ACMEChallenge(httptest.NewRequest(http.MethodHead, "http://a.test/.well-known/acme-challenge/tok", nil)) ||
		ACMEChallenge(httptest.NewRequest(http.MethodPost, "http://a.test/.well-known/acme-challenge/tok", nil)) {
		t.Fatal("methods: only GET and HEAD")
	}
}

// Port 80 mit SetHTTPBlocker: conn trennt beim Annehmen, guard weist je Anfrage ab - ausser Let's-Encrypt-Pruefungen
// (an die Route bzw. eigene Tokens). Port 443 bleibt bei SetBlocker; ohne SetHTTPBlocker gilt SetBlocker auch fuer 80.
func TestHTTPBlocker(t *testing.T) {
	e, _ := newEdge(t, nil)
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "app "+r.URL.Path) })
	if err := e.Set("cdn64", []Route{{Names: []string{"app.test"}, Handler: app, HTTP: app}}); err != nil {
		t.Fatal(err)
	}
	release, err := e.Present("owntoken", "owntoken.key")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	bad := func(a netip.Addr) bool { return a.String() == "198.51.100.1" }
	e.SetBlocker(bad)
	e.SetHTTPBlocker(nil, func(w http.ResponseWriter, r *http.Request) bool {
		if !bad(peerIP(r)) {
			return false
		}
		w.WriteHeader(http.StatusForbidden)
		return true
	})
	get := func(method, path string) (int, string, error) {
		served, cl := pair(t, "198.51.100.1:1")
		defer cl.Close()
		e.ServeConn(served, 80)
		_ = cl.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(cl, method+" "+path+" HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n"); err != nil {
			return 0, "", err
		}
		resp, err := http.ReadResponse(bufio.NewReader(cl), nil)
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), nil
	}
	const tok = "/.well-known/acme-challenge/Abc-123"
	if code, body, err := get("GET", tok); err != nil || code != http.StatusOK || body != "app "+tok {
		t.Fatalf("acme for the route: %d %q %v", code, body, err)
	}
	if code, body, err := get("GET", "/.well-known/acme-challenge/owntoken"); err != nil || code != http.StatusOK || body != "owntoken.key" {
		t.Fatalf("own token: %d %q %v", code, body, err)
	}
	for _, c := range [][2]string{{"GET", "/"}, {"POST", tok}, {"GET", "/.well-known/acme-challenge/a/../b"}, {"POST", "/.well-known/acme-challenge/owntoken"}} {
		if code, _, err := get(c[0], c[1]); err != nil || code != http.StatusForbidden {
			t.Fatalf("%s %s: %d %v", c[0], c[1], code, err)
		}
	}
	// HTTPS: weiter beim Annehmen getrennt
	served, cl := pair(t, "198.51.100.1:1")
	e.ServeConn(served, 443)
	tc := tls.Client(cl, &tls.Config{ServerName: "app.test", InsecureSkipVerify: true}) //nolint:gosec // Test
	_ = tc.SetDeadline(time.Now().Add(2 * time.Second))
	if err := tc.Handshake(); err == nil {
		t.Fatal("https must still be cut off at accept")
	}
	tc.Close()
	// conn: auf Port 80 sofort getrennt, auch die Pruefung
	e.SetHTTPBlocker(bad, nil)
	if _, _, err := get("GET", tok); err == nil {
		t.Fatal("conn blocker must cut off port 80")
	}
	// ohne SetHTTPBlocker: Port 80 wie die anderen (SetBlocker beim Annehmen)
	e.SetHTTPBlocker(nil, nil)
	if _, _, err := get("GET", tok); err == nil {
		t.Fatal("without http blocker the general blocker applies to port 80")
	}
	e.SetBlocker(nil)
	if code, body, err := get("GET", "/"); err != nil || code != http.StatusOK || !strings.HasPrefix(body, "app") {
		t.Fatalf("unblocked: %d %q %v", code, body, err)
	}
}
