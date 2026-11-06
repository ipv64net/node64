package web

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Resolver der DNS-01-Pruefung und Weg "auto" ueber die API (wie die Seite).
func TestAPICertsDNSCheckAndAuto(t *testing.T) {
	ctx := context.Background()
	a, mgr := newCertsApp(t)
	u, _ := a.store.UserByName(ctx, "admin")
	apiKey, _, err := a.store.NewAPIKey(ctx, u.ID, "nas")
	if err != nil {
		t.Fatal(err)
	}
	api := func(method, path, body string) (int, string) {
		req, _ := http.NewRequest(method, a.srv.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+apiKey)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := api("GET", "/api/certs/dns-check", ""); code != 200 || !strings.Contains(body, `"resolvers":[]`) {
		t.Fatalf("get: %d %s", code, body)
	}
	if code, body := api("PUT", "/api/certs/dns-check", `{"resolvers":["dns.example"]}`); code != 422 || !strings.Contains(body, `"field":"resolvers"`) {
		t.Fatalf("bad: %d %s", code, body)
	}
	code, body := api("PUT", "/api/certs/dns-check", `{"resolvers":["192.0.2.53","https://dns.quad9.net/dns-query"]}`)
	if code != 200 || !strings.Contains(body, `"192.0.2.53:53"`) {
		t.Fatalf("put: %d %s", code, body)
	}
	if got := mgr.CheckResolvers(ctx); strings.Join(got, "|") != "192.0.2.53:53|https://dns.quad9.net/dns-query" {
		t.Fatalf("saved: %v", got)
	}
	if code, _ := api("PUT", "/api/certs/dns-check", `{"resolvers":[]}`); code != 200 || len(mgr.CheckResolvers(ctx)) != 0 {
		t.Fatalf("clear: %d", code)
	}
	// ohne Weg: wie die Seite automatisch gewaehlt (ohne API-Key HTTP-01, hier ohne Port 80 nicht verfuegbar)
	for _, b := range []string{`{"names":["files.example.org"]}`, `{"names":["files.example.org"],"source":"auto"}`} {
		if code, body := api("POST", "/api/certs", b); code != 422 || !strings.Contains(body, "http-01") {
			t.Fatalf("auto %s: %d %s", b, code, body)
		}
	}
}
