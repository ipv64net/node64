package cdn64

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fixBackend: Ziel, das Anfrage-URI und Host zurueckgibt, auf Wunsch weiterleitet, 500 oder 404 liefert oder haengt.
func fixBackend(t *testing.T, release chan struct{}) int {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/fwd"): // absolut auf den Namen des Besuchers
			w.Header().Set("Location", "https://"+r.Header.Get("X-Forwarded-Host")+"/rezepte/y")
			w.WriteHeader(http.StatusFound)
			return
		case strings.HasSuffix(r.URL.Path, "/kaputt"):
			w.WriteHeader(http.StatusInternalServerError)
			return
		case strings.HasSuffix(r.URL.Path, "/robots.txt"):
			http.NotFound(w, r)
			return
		case strings.HasSuffix(r.URL.Path, "/slow"):
			<-release
		}
		_, _ = io.WriteString(w, r.RequestURI+" "+r.Host)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	p, _ := strconv.Atoi(u.Port())
	return p
}

// Fund 1: Location mit ForwardPath schreibt Weiterleitungen und Cookie-Pfade nicht um (wie vor 1.4.0).
func TestLocationForwardNoUnpath(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	port, _ := pathBackend(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"graf.test"}, "127.0.0.1", port, CertNone
	h.Locations = []Location{{Path: "/rezepte", TargetHost: "127.0.0.1", TargetPort: port, ForwardPath: "/"}}
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	c := e.client(false)
	if code, _, hd := do(t, c, "GET", "http://graf.test/rezepte/go"); code != http.StatusFound || hd.Get("Location") != "/rezepte/ziel?a=1" {
		t.Fatalf("location redirect rewritten: %d %q", code, hd.Get("Location"))
	}
	if _, _, hd := do(t, c, "GET", "http://graf.test/rezepte/cookie"); hd.Values("Set-Cookie")[0] != "s=1; Path=/rezepte; HttpOnly" {
		t.Fatalf("location cookie rewritten: %q", hd.Values("Set-Cookie"))
	}
}

// Fund 2 und 3: Host des Besuchers (nicht der Host-Kopf zum Ziel) fuer Weiterleitungen und {{HOST}}; Kodierung des
// Pfads bleibt beim Pfad des Hosts erhalten.
func TestTargetPathVisitorHostRawPath(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	port := fixBackend(t, nil)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"rezepte.test"}, "127.0.0.1", port, CertNone
	h.Advanced.TargetPath, h.Advanced.HostHeader = "/rezepte", "intern.lan"
	h.Advanced.ErrorHTML, h.Advanced.ErrorOverride = "<p>{{STATUS}} {{HOST}}</p>", true
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	c := e.client(false)
	if code, _, hd := do(t, c, "GET", "http://rezepte.test/fwd"); code != http.StatusFound || hd.Get("Location") != "https://rezepte.test/y" {
		t.Fatalf("visitor redirect: %d %q", code, hd.Get("Location"))
	}
	if code, body, _ := do(t, c, "GET", "http://rezepte.test/kaputt"); code != 500 || body != "<p>500 rezepte.test</p>" {
		t.Fatalf("error page host: %d %q", code, body)
	}
	for _, x := range []struct{ in, want string }{{"/a%2Fb/c?q=1", "/rezepte/a%2Fb/c?q=1"}, {"//a%2F//b", "/rezepte/a%2F/b"},
		{"/x%20y", "/rezepte/x%20y"}, {"/", "/rezepte/"}} {
		if code, body, _ := do(t, c, "GET", "http://rezepte.test"+x.in); code != 200 || body != x.want+" intern.lan" {
			t.Errorf("%s: %d %q, want %q", x.in, code, body, x.want)
		}
	}
	// HostHeader "target": ausgehend steht kein Host-Kopf, {{HOST}} trotzdem der Name des Besuchers
	h.Advanced.HostHeader = "target"
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if code, body, _ := do(t, c, "GET", "http://rezepte.test/kaputt"); code != 500 || body != "<p>500 rezepte.test</p>" {
		t.Fatalf("error page host (target): %d %q", code, body)
	}
}

// Fund 4: KI-robots.txt auch mit Pfad beim Ziel (eingehender Pfad zaehlt).
func TestAIRobotsTargetPath(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	port := fixBackend(t, nil)
	l, err := parseAIBots(testAIList())
	if err != nil {
		t.Fatal(err)
	}
	e.m.bl.ai.put(l, time.Now())
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"ki.test"}, "127.0.0.1", port, CertNone
	h.Advanced.TargetPath, h.Advanced.AIRobots = "/rezepte", true
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	e.m.handlerFor(h, &hostStats{}).ServeHTTP(rec, httptest.NewRequest("GET", "http://ki.test/robots.txt", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "User-agent: GPTBot") {
		t.Fatalf("robots.txt with target path: %d %q", rec.Code, rec.Body.String())
	}
}

// Fund 5: feste 5xx-Antwort einer Location bleibt beim CDN64-Server erhalten, andere Status ohne Kopf.
func TestFixedResponseKeepPage(t *testing.T) {
	for _, x := range []struct {
		status int
		want   string
	}{{503, "off"}, {200, ""}} {
		rec := httptest.NewRecorder()
		fixedHandler(Location{Action: LocRespond, Status: x.status, Body: "x", ContentType: "text/plain"}).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
		if rec.Code != x.status || rec.Header().Get(keepPage) != x.want {
			t.Errorf("%d: %d %q", x.status, rec.Code, rec.Header().Get(keepPage))
		}
	}
}

// Fund 6: volle Zielplaetze - mit Zugriffsliste die neutrale 503 (eigenes HTML nicht ohne Anmeldung), ohne die eigene.
func TestBusyPageAccessList(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	release := make(chan struct{})
	defer close(release)
	port := fixBackend(t, release)
	old := limQueueWait
	limQueueWait = 100 * time.Millisecond
	defer func() { limQueueWait = old }()
	if err := e.m.limSave(ctx, Limits{Enabled: true, TargetConns: 1}); err != nil {
		t.Fatal(err)
	}
	acl := &AccessList{Name: "lan", Rules: []AccessRule{{Action: "allow", CIDR: "10.0.0.0/8"}}}
	if err := e.m.saveAccessList(ctx, acl, nil); err != nil {
		t.Fatal(err)
	}
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"voll.test"}, "127.0.0.1", port, CertNone
	h.Advanced.ErrorHTML = "<p>eigen</p>"
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	busy := func(acls ...int64) string {
		h.AccessListID = 0
		if len(acls) > 0 {
			h.AccessListID = acls[0]
		}
		hd := e.m.handlerFor(h, &hostStats{})
		started := make(chan struct{})
		done := make(chan struct{})
		go func() { // belegt den einzigen Platz
			req := httptest.NewRequest("GET", "http://voll.test/slow", nil)
			req.RemoteAddr = "10.0.0.5:4242"
			close(started)
			hd.ServeHTTP(httptest.NewRecorder(), req)
			close(done)
		}()
		<-started
		time.Sleep(50 * time.Millisecond)
		req := httptest.NewRequest("GET", "http://voll.test/", nil)
		req.RemoteAddr = "203.0.113.9:4242"
		rec := httptest.NewRecorder()
		hd.ServeHTTP(rec, req)
		release <- struct{}{}
		<-done
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("busy: %d", rec.Code)
		}
		return rec.Body.String()
	}
	if body := busy(); body != "<p>eigen</p>" {
		t.Fatalf("without access list: %q", body)
	}
	if body := busy(acl.ID); strings.Contains(body, "eigen") {
		t.Fatalf("with access list: %q", body)
	}
}

// Fund 7: Entfernen an der Location wirkt auch gegen Kopfzeilen, die der Host setzt.
func TestLocationRemovesHostHeaders(t *testing.T) {
	host := Advanced{RequestHeaders: []Header{{"X-Auth", "1"}, {"X-Keep", "2"}}, ResponseHeaders: []Header{{"X-Frame-Options", "DENY"}, {"X-A", "b"}}}
	l := Location{Advanced: &LocationAdvanced{RequestRemove: []string{"x-auth"}, ResponseRemove: []string{"x-frame-options"}}}
	a := l.effective(&host)
	if len(a.RequestHeaders) != 1 || a.RequestHeaders[0].Name != "X-Keep" || len(a.ResponseHeaders) != 1 || a.ResponseHeaders[0].Name != "X-A" {
		t.Fatalf("effective: %+v %+v", a.RequestHeaders, a.ResponseHeaders)
	}
	if len(host.RequestHeaders) != 2 || len(host.ResponseHeaders) != 2 {
		t.Fatalf("host changed: %+v", host)
	}
	// eigene Kopfzeile der Location mit gleichem Namen gilt weiter
	l.Advanced.ResponseHeaders = []Header{{"X-Frame-Options", "SAMEORIGIN"}}
	if a := l.effective(&host); len(a.ResponseHeaders) != 2 || a.ResponseHeaders[1].Value != "SAMEORIGIN" {
		t.Fatalf("own header: %+v", a.ResponseHeaders)
	}
}

// Fund 8: Upload-Grenze des Hosts ohne eigene Grenze der Locations (schneller Pfad) und mit.
func TestMaxBodyFastPath(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	port := fixBackend(t, nil)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"up.test"}, "127.0.0.1", port, CertNone
	h.Advanced.MaxBodyMB = 1
	h.Locations = []Location{{Path: "/frei", TargetHost: "127.0.0.1", TargetPort: port}}
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	post := func(p string) int {
		rec := httptest.NewRecorder()
		e.m.handlerFor(h, &hostStats{}).ServeHTTP(rec, httptest.NewRequest("POST", "http://up.test"+p, strings.NewReader(strings.Repeat("x", 2<<20))))
		return rec.Code
	}
	if post("/x") != http.StatusRequestEntityTooLarge || post("/frei/x") != http.StatusRequestEntityTooLarge {
		t.Fatal("host limit without location limits")
	}
	h.Locations[0].Advanced = &LocationAdvanced{MaxBodyMB: -1}
	if post("/x") != http.StatusRequestEntityTooLarge || post("/frei/x") != 200 {
		t.Fatal("location without limit")
	}
}

// Rueckschreiben der Location darf keine Adresse auf einen fremden Host erzeugen (CodeQL go/bad-redirect-check).
func TestUnpathNoOpenRedirect(t *testing.T) {
	tu, _ := url.Parse("http://10.0.0.5:8080")
	tg := target{url: tu, forward: "/app"}
	for loc, want := range map[string]string{
		"/app//evil.com/":            "/app//evil.com/",
		"/app/%2Fevil.com/":          "/app/%2Fevil.com/",
		"/app/%2F%2Fevil.com":        "/app/%2F%2Fevil.com",
		"/app/%5Cevil.com":           "/app/%5Cevil.com",
		"/app/x%2Fy":                 "/x%2Fy",
		"/app/suppe":                 "/suppe",
		"/app":                       "/",
		"http://10.0.0.5:8080/app/a": "/a",
	} {
		resp := &http.Response{Header: http.Header{"Location": {loc}}, Request: httptest.NewRequest("GET", "http://rezepte.test/", nil)}
		unpath(resp, tg)
		if got := resp.Header.Get("Location"); got != want {
			t.Errorf("%s -> %s, want %s", loc, got, want)
		}
	}
}

// safeNext des Zugriffslisten-Logins: nur lokale Pfade, auch nach dem Entfernen von Steuerzeichen durch den Browser.
func TestAccessLoginSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"/app?x=1": "/app?x=1", "//evil.com": "/", `/\evil.com`: "/", "/\t/evil.com": "/",
		"/\n/evil.com": "/", "https://evil.com": "/", "/.node64/x": "/", "": "/",
	} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

// Issue 120: bricht der Besucher ab, bevor das Ziel antwortet, steht 499 im Log (4xx) statt 502 - kein Fehler des Ziels.
func TestClientAbortIs499(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.m.SetDataDir(t.TempDir())
	e.enable(t)
	release := make(chan struct{})
	port := fixBackend(t, release)
	t.Cleanup(func() { close(release) }) // vor srv.Close (Cleanups rueckwaerts), sonst wartet das Ziel ewig
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"abbruch.test"}, "127.0.0.1", port, CertNone
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	rctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(rctx, "GET", "http://abbruch.test/slow", nil)
	if resp, err := e.client(false).Do(req); err == nil {
		resp.Body.Close()
		t.Fatal("request must be cancelled")
	}
	sdb := e.m.stats2.Load()
	var s HostStat
	for i := 0; i < 50; i++ {
		sums, _ := sdb.sums(ctx, time.Now().Add(-2*time.Hour))
		if s = sums[h.ID]; s.Requests == 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if s.Requests != 1 || s.S4 != 1 || s.S5 != 0 {
		t.Fatalf("client abort counted: %+v", s)
	}
	if n := e.m.statsOf(h.ID).errors.Load(); n != 0 {
		t.Fatalf("client abort in error counter: %d", n)
	}
}
