package cdn64

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// Datenverkehr getrennt nach Richtung (Sicht des Besuchers): Upload = Request-Body bzw. WebSocket vom Besucher,
// Download = Antwort bzw. WebSocket zum Besucher (jeweils so, wie es ueber die Leitung geht, also nach der Komprimierung).
func TestStatsUploadDownload(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.m.SetDataDir(t.TempDir())
	e.enable(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" {
			c, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer c.CloseNow()
			for {
				typ, b, err := c.Read(r.Context())
				if err != nil {
					return
				}
				_ = c.Write(r.Context(), typ, append(b, b...)) // doppelt zurueck
			}
		}
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write(bytes.Repeat([]byte("d"), 2000))
	}))
	t.Cleanup(srv.Close)
	h := newHost()
	h.Advanced.Gzip = false // gezaehlt wird, was ueber die Leitung geht (komprimiert waeren 2000 gleiche Zeichen nur ~40 Bytes)
	h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"up.test"}, "127.0.0.1", srv.Listener.Addr().(*net.TCPAddr).Port, CertNone
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	c := e.client(false)
	resp, err := c.Post("http://up.test/data", "application/octet-stream", bytes.NewReader(make([]byte, 5000)))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	conn, _, err := websocket.Dial(ctx, "ws://up.test/ws", &websocket.DialOptions{HTTPClient: c})
	if err != nil {
		t.Fatalf("websocket: %v", err)
	}
	if err := conn.Write(ctx, websocket.MessageBinary, make([]byte, 1000)); err != nil {
		t.Fatal(err)
	}
	if _, b, err := conn.Read(ctx); err != nil || len(b) != 2000 {
		t.Fatalf("websocket echo: %d %v", len(b), err)
	}
	conn.Close(websocket.StatusNormalClosure, "")
	sdb := e.m.stats2.Load()
	var s HostStat
	for i := 0; i < 50; i++ {
		sums, _ := sdb.sums(ctx, time.Now().Add(-2*time.Hour))
		if s = sums[h.ID]; s.Requests == 2 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	// POST: 5000 hoch, 2000 runter; WebSocket: >= 1000 hoch, >= 2000 runter (dazu Rahmen und Schliessen)
	if s.Requests != 2 || s.S2 != 2 || s.S4 != 0 || s.BytesIn < 6000 || s.BytesIn > 6200 || s.Bytes < 4000 || s.Bytes > 4200 { // WebSocket zaehlt als 101, nicht 4xx
		t.Fatalf("traffic: %+v", s)
	}
}

// Wartungsmodus: Seite statt Ziel (503, Retry-After, no-store), Stile und eigenes HTML; zaehlt weder als abgewiesen
// noch als Fehler; nur Proxy-Hosts; eigenes HTML Pflicht und begrenzt.
func TestMaintenanceMode(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.m.SetDataDir(t.TempDir())
	e.enable(t)
	port, _ := echoBackend(t, "ziel")
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"wartung.test"}, "127.0.0.1", port, CertNone
	h.Advanced.Maintenance = true
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if h.Advanced.MaintenanceStyle != MaintMatrix {
		t.Fatalf("default style: %q", h.Advanced.MaintenanceStyle)
	}
	c := e.client(false)
	code, body, hdr := do(t, c, "GET", "http://wartung.test/irgendwas")
	if code != 503 || hdr.Get("Retry-After") == "" || hdr.Get("Cache-Control") != "no-store" || !strings.Contains(body, "MAINTENANCE") || !strings.Contains(body, "wartung.test") || strings.Contains(body, "ziel") {
		t.Fatalf("matrix: %d %v %.200s", code, hdr, body)
	}
	h.Advanced.MaintenanceStyle = MaintGear
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if code, body, _ = do(t, c, "GET", "http://wartung.test/"); code != 503 || !strings.Contains(body, "Wartungsarbeiten") {
		t.Fatalf("gear: %d %.200s", code, body)
	}
	h.Advanced.MaintenanceStyle, h.Advanced.MaintenanceHTML = MaintCustom, ""
	if err := e.m.saveHost(ctx, h); err == nil {
		t.Fatal("custom without HTML accepted")
	}
	h.Advanced.MaintenanceHTML = strings.Repeat("x", maintMaxHTML+1)
	if err := e.m.saveHost(ctx, h); err == nil {
		t.Fatal("too large HTML accepted")
	}
	h.Advanced.MaintenanceHTML = "<h1>Bald wieder da</h1>"
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if code, body, _ = do(t, c, "GET", "http://wartung.test/"); code != 503 || body != "<h1>Bald wieder da</h1>" {
		t.Fatalf("custom: %d %q", code, body)
	}
	h.Advanced.Maintenance = false
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if code, body, _ = do(t, c, "GET", "http://wartung.test/"); code != 200 || !strings.Contains(body, "ziel") {
		t.Fatalf("off: %d %.100s", code, body)
	}
	sdb := e.m.stats2.Load()
	var s HostStat
	for i := 0; i < 50; i++ {
		sums, _ := sdb.sums(ctx, time.Now().Add(-2*time.Hour))
		if s = sums[h.ID]; s.Requests == 4 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if s.Requests != 4 || s.Blocked != 0 || s.S5 != 0 || s.S2 != 1 {
		t.Fatalf("stats: %+v", s)
	}
	// nur Proxy-Hosts
	r := newHostKind(KindRedirect)
	r.Names, r.RedirectTarget, r.Advanced.Maintenance = []string{"weiter.test"}, "example.com", true
	if err := e.m.saveHost(ctx, r); err != nil || r.Advanced.Maintenance {
		t.Fatalf("redirect: %v %v", err, r.Advanced.Maintenance)
	}
}
