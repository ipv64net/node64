package cdn64

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// Wartungsmodus hinter der Zugriffsliste (#33): eigenes HTML nur nach Anmeldung, auch fuer eine Location mit eigener
// Liste; die Anmeldeseite (/.node64/login) geht im Wartungsmodus weiter.
func TestMaintenanceBehindAccessList(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	port, _ := echoBackend(t, "ziel")
	a := &AccessList{Name: "Familie"}
	if err := e.m.saveAccessList(ctx, a, []UserInput{{Username: "anna", Password: "geheim123"}}); err != nil {
		t.Fatal(err)
	}
	b := &AccessList{Name: "Admin", LoginPage: true}
	if err := e.m.saveAccessList(ctx, b, []UserInput{{Username: "bert", Password: "geheim456"}}); err != nil {
		t.Fatal(err)
	}
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID, h.AccessListID = []string{"wartung-acl.test"}, "127.0.0.1", port, CertNone, a.ID
	h.Locations = []Location{{Path: "/admin", Scheme: "http", TargetHost: "127.0.0.1", TargetPort: port, AccessListID: b.ID}}
	h.Advanced.Maintenance, h.Advanced.MaintenanceStyle, h.Advanced.MaintenanceHTML = true, MaintCustom, "<p>intern: 10.0.0.5</p>"
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	c := e.client(false)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if code, body, hdr := do(t, c, "GET", "http://wartung-acl.test/"); code != 401 || strings.Contains(body, "intern") || hdr.Get("WWW-Authenticate") == "" {
		t.Fatalf("without login: %d %.100s", code, body)
	}
	if code, body, _ := do(t, c, "GET", "http://wartung-acl.test/", "Authorization", basic("anna", "falsch")); code != 401 || strings.Contains(body, "intern") {
		t.Fatalf("wrong password: %d %.100s", code, body)
	}
	if code, body, _ := do(t, c, "GET", "http://wartung-acl.test/", "Authorization", basic("anna", "geheim123")); code != 503 || body != "<p>intern: 10.0.0.5</p>" {
		t.Fatalf("with login: %d %q", code, body)
	}
	// Location mit eigener Liste (Login-Seite): ohne Anmeldung das Formular, nicht die Wartungsseite; die Anmeldung
	// selbst geht im Wartungsmodus weiter, danach die Wartungsseite
	if code, body, _ := do(t, c, "GET", "http://wartung-acl.test/admin/x"); code != 401 || strings.Contains(body, "intern") || !strings.Contains(body, `action="/.node64/login"`) {
		t.Fatalf("location without login: %d %.100s", code, body)
	}
	resp, err := c.PostForm("http://wartung-acl.test/.node64/login", url.Values{"username": {"bert"}, "password": {"geheim456"}, "next": {"/admin/x"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 303 || len(resp.Cookies()) != 1 {
		t.Fatalf("login in maintenance: %d", resp.StatusCode)
	}
	ck := resp.Cookies()[0]
	if code, body, _ := do(t, c, "GET", "http://wartung-acl.test/admin/x", "Cookie", ck.Name+"="+ck.Value); code != 503 || body != "<p>intern: 10.0.0.5</p>" {
		t.Fatalf("location after login: %d %q", code, body)
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
