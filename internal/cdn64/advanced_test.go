package cdn64

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// X-Forwarded-For und X-Real-IP setzt PROXY64 selbst (echte Client-Adresse, /mcp prueft sie): Erweitert darf sie
// weder setzen noch entfernen - auch nicht mit aelteren gespeicherten Einstellungen.
func TestAdvancedClientHeadersFixed(t *testing.T) {
	for _, a := range []Advanced{
		{RequestHeaders: []Header{{Name: "X-Forwarded-For", Value: "10.0.0.1"}}},
		{RequestHeaders: []Header{{Name: "x-real-ip", Value: "10.0.0.1"}}},
		{RequestRemove: []string{"X-Forwarded-For"}},
		{RequestRemove: []string{"X-Real-IP"}},
	} {
		if err := a.normalize(); err == nil {
			t.Errorf("%+v must be rejected", a)
		}
	}
	if a := (Advanced{RequestRemove: []string{"Cookie"}, ResponseRemove: []string{"X-Real-IP"}}); a.normalize() != nil {
		t.Error("other headers must stay allowed")
	}
	var xff, real string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xff, real = r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP")
	}))
	defer up.Close()
	port, _ := strconv.Atoi(up.URL[strings.LastIndex(up.URL, ":")+1:])
	m := &Module{log: slog.New(slog.NewTextHandler(io.Discard, nil)), trInsecure: http.DefaultTransport.(*http.Transport).Clone(), cache: newAssetCache(1 << 20)}
	h := newHost()
	h.ID, h.Names, h.TargetHost, h.TargetPort = 1, []string{"app.test"}, "127.0.0.1", port
	h.Advanced = Advanced{RequestRemove: []string{"X-Real-IP"}, RequestHeaders: []Header{{Name: "X-Forwarded-For", Value: "10.0.0.1"}}} // ohne normalize
	req := httptest.NewRequest("GET", "http://app.test/", nil)
	req.RemoteAddr = "203.0.113.7:4242"
	m.proxyHandler(h, &hostStats{}).ServeHTTP(httptest.NewRecorder(), req)
	if xff != "203.0.113.7" || real != "203.0.113.7" {
		t.Fatalf("client address: xff %q real %q", xff, real)
	}
}

// CF-Connecting-IP gilt nur von Cloudflare selbst; X-Forwarded-For ueber alle Zeilen von rechts.
func TestClientIPTrusted(t *testing.T) {
	a := &Advanced{TrustedProxies: []string{"10.0.0.0/8", "172.64.0.0/13"}}
	a.prepare()
	for _, c := range []struct {
		peer string
		hdr  [][2]string
		want string
	}{
		{"10.0.0.5:1", [][2]string{{"CF-Connecting-IP", "198.51.100.1"}}, "10.0.0.5"},       // LAN-Proxy reicht den Kopf nur durch
		{"172.64.1.2:1", [][2]string{{"CF-Connecting-IP", "198.51.100.1"}}, "198.51.100.1"}, // Cloudflare
		{"10.0.0.5:1", [][2]string{{"X-Forwarded-For", "198.51.100.9"}, {"X-Forwarded-For", "203.0.113.4, 10.0.0.7"}}, "203.0.113.4"},
		{"203.0.113.50:1", [][2]string{{"X-Forwarded-For", "198.51.100.9"}}, "203.0.113.50"}, // nicht vertrauenswuerdig
	} {
		r := httptest.NewRequest("GET", "http://x.test/", nil)
		r.RemoteAddr = c.peer
		for _, h := range c.hdr {
			r.Header.Add(h[0], h[1])
		}
		if got := a.clientIP(r).String(); got != c.want {
			t.Errorf("%s %v: %s, want %s", c.peer, c.hdr, got, c.want)
		}
	}
}
