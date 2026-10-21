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
