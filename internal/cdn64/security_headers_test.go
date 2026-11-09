package cdn64

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

// Kopfzeilen aus Erweitert und HSTS auch auf Antworten der Node selbst (Forum 5083); HSTS des Ziels wird ersetzt, nicht
// verdoppelt; was eine Location entfernt, setzt der Host dort nicht wieder.
func TestHostHeadersOnAllResponses(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=1")
		w.Header().Set("Server", "app/1.0")
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)
	bport, _ := strconv.Atoi(bu.Port())
	certPEM, keyPEM := selfSigned(t, "sec.test")
	if _, err := e.crt.Upload(ctx, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort = []string{"sec.test"}, "127.0.0.1", bport
	h.BlockExploits, h.ForceSSL, h.HSTS = true, true, true
	h.Advanced.ResponseHeaders = []Header{{Name: "X-Frame-Options", Value: "SAMEORIGIN"}, {Name: "Referrer-Policy", Value: "no-referrer"}}
	h.Advanced.ResponseRemove = []string{"Server"}
	h.Locations = []Location{{Path: "/embed", TargetHost: "127.0.0.1", TargetPort: bport, Advanced: &LocationAdvanced{ResponseRemove: []string{"X-Frame-Options"}}}}
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	c := e.client(true)
	check := func(what string, hdr http.Header, frame string) {
		t.Helper()
		if v := hdr.Values("Strict-Transport-Security"); len(v) != 1 || v[0] != "max-age=63072000" {
			t.Errorf("%s: hsts %q", what, v)
		}
		if hdr.Get("X-Frame-Options") != frame || hdr.Get("Referrer-Policy") != "no-referrer" || hdr.Get("Server") != "" {
			t.Errorf("%s: %v", what, hdr)
		}
	}
	code, _, hdr := do(t, c, "GET", "https://sec.test/")
	if code != 200 {
		t.Fatalf("proxied: %d", code)
	}
	check("proxied", hdr, "SAMEORIGIN")
	code, _, hdr = do(t, c, "GET", "https://sec.test/.env") // Exploit-Sperre: Antwort der Node
	if code != 403 {
		t.Fatalf("exploit: %d", code)
	}
	check("exploit 403", hdr, "SAMEORIGIN")
	code, _, hdr = do(t, c, "GET", "https://sec.test/embed/x")
	if code != 200 {
		t.Fatalf("location: %d", code)
	}
	check("location", hdr, "")
	backend.Close() // Ziel weg: Fehlerseite der Node
	code, _, hdr = do(t, c, "GET", "https://sec.test/")
	if code != http.StatusBadGateway {
		t.Fatalf("down: %d", code)
	}
	check("502", hdr, "SAMEORIGIN")
}
