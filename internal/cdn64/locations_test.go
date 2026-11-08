package cdn64

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// pathBackend: Ziel fuer die Tests zu Pfad im Ziel, Weiterleitungen, Cookies und langsamen Antworten.
func pathBackend(t *testing.T) (int, string) {
	t.Helper()
	var self string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/go"):
			http.Redirect(w, r, "/rezepte/ziel?a=1", http.StatusFound)
			return
		case strings.HasSuffix(r.URL.Path, "/abs"):
			w.Header().Set("Location", "http://"+self+"/rezepte/x")
			w.WriteHeader(http.StatusFound)
			return
		case strings.HasSuffix(r.URL.Path, "/visitor"):
			w.Header().Set("Location", "https://"+r.Host+"/rezepte/y")
			w.WriteHeader(http.StatusFound)
			return
		case strings.HasSuffix(r.URL.Path, "/other"):
			w.Header().Set("Location", "/anderswo")
			w.WriteHeader(http.StatusFound)
			return
		case strings.HasSuffix(r.URL.Path, "/cookie"):
			w.Header().Add("Set-Cookie", "s=1; Path=/rezepte; HttpOnly")
			w.Header().Add("Set-Cookie", "t=2; Path=/frei")
		case strings.HasSuffix(r.URL.Path, "/slow"):
			time.Sleep(1500 * time.Millisecond)
		}
		if r.Method == http.MethodPost {
			_, _ = io.Copy(io.Discard, r.Body)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"path": r.URL.Path, "query": r.URL.RawQuery, "host": r.Host,
			"hdr": r.Header.Get("X-Loc"), "hosthdr": r.Header.Get("X-Host")})
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	self = u.Host
	p, _ := strconv.Atoi(u.Port())
	return p, u.Host
}

func TestTargetPath(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	port, _ := pathBackend(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"rezepte.test"}, "127.0.0.1", port, CertNone
	h.Advanced.TargetPath = "rezepte/" // wird zu /rezepte
	h.Locations = []Location{{Path: "/api", TargetHost: "127.0.0.1", TargetPort: port, ForwardPath: "/v1"}}
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.m.host(ctx, h.ID); got.Advanced.TargetPath != "/rezepte" {
		t.Fatalf("stored target path: %q", got.Advanced.TargetPath)
	}
	c := e.client(false)
	for _, x := range []struct{ in, want string }{{"/suppe", "/rezepte/suppe"}, {"/", "/rezepte/"}, {"//suppe//x", "/rezepte/suppe/x"},
		{"/suppe/", "/rezepte/suppe/"}, {"/api/u", "/v1/u"}} {
		if _, got, _ := getJSON(t, c, "http://rezepte.test"+x.in+"?q=1"); got["path"] != x.want || got["query"] != "q=1" || got["host"] != "rezepte.test" {
			t.Errorf("%s: %v, want %s", x.in, got, x.want)
		}
	}
	// Weiterleitungen des Ziels: Praefix wieder weg (relativ, absolut auf das Ziel, absolut auf den Namen des Besuchers)
	for _, x := range []struct{ in, want string }{{"/go", "/ziel?a=1"}, {"/abs", "/x"}, {"/visitor", "https://rezepte.test/y"}, {"/other", "/anderswo"}} {
		code, _, hd := do(t, c, "GET", "http://rezepte.test"+x.in)
		if code != http.StatusFound || hd.Get("Location") != x.want {
			t.Errorf("redirect %s: %d %q, want %q", x.in, code, hd.Get("Location"), x.want)
		}
	}
	_, _, hd := do(t, c, "GET", "http://rezepte.test/cookie")
	if cs := hd.Values("Set-Cookie"); len(cs) != 2 || cs[0] != "s=1; Path=/; HttpOnly" || cs[1] != "t=2; Path=/frei" {
		t.Errorf("cookie paths: %q", cs)
	}
	// ungueltige Pfade
	var fe *FieldError
	for _, bad := range []string{"/a/../b", "/a b", "/x?y", `/a\b`} {
		b := newHost()
		b.Names, b.TargetHost, b.TargetPort, b.CertID = []string{"bad.test"}, "127.0.0.1", port, CertNone
		b.Advanced.TargetPath = bad
		if err := e.m.saveHost(ctx, b); !errors.As(err, &fe) || fe.Field != "target_path" {
			t.Errorf("target path %q: %v", bad, err)
		}
	}
	// nur Proxy-Hosts: Weiterleitung verliert den Pfad
	r := newHostKind(KindRedirect)
	r.Names, r.RedirectTarget, r.CertID = []string{"weiter.test"}, "example.com", CertNone
	r.Advanced.TargetPath, r.Advanced.OnlyLocations = "/x", true
	if err := e.m.saveHost(ctx, r); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.m.host(ctx, r.ID); got.Advanced.TargetPath != "" || got.Advanced.OnlyLocations {
		t.Fatalf("redirect keeps proxy-only fields: %+v", got.Advanced)
	}
}

func TestLocationActions(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	port, _ := pathBackend(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"mail.test"}, "127.0.0.1", port, CertNone
	h.Advanced.OnlyLocations = true
	h.Locations = []Location{
		{Path: "/.well-known/mta-sts.txt", Action: LocRespond, Body: "version: STSv1\r\nmode: enforce\r\n", TargetHost: "ignoriert", TargetPort: 1},
		{Path: "/autodiscover", TargetHost: "127.0.0.1", TargetPort: port},
		{Path: "/admin", Action: LocBlock, Status: 404},
		{Path: "/gesperrt", Action: LocBlock},
		{Path: "/json", Action: LocRespond, Status: 201, Body: `{"ok":true}`, ContentType: "application/json"},
	}
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	got, _ := e.m.host(ctx, h.ID)
	if l := got.Locations[0]; l.Status != 200 || l.ContentType != "text/plain; charset=utf-8" || l.TargetHost != "" || l.Body != "version: STSv1\nmode: enforce\n" {
		t.Fatalf("respond normalized: %+v", l)
	}
	if got.Locations[3].Status != 403 {
		t.Fatalf("block default status: %d", got.Locations[3].Status)
	}
	c := e.client(false)
	code, body, hd := do(t, c, "GET", "http://mail.test/.well-known/mta-sts.txt")
	if code != 200 || body != "version: STSv1\nmode: enforce\n" || !strings.HasPrefix(hd.Get("Content-Type"), "text/plain") {
		t.Fatalf("fixed response: %d %q %v", code, body, hd)
	}
	if code, _, hd := do(t, c, "HEAD", "http://mail.test/.well-known/mta-sts.txt"); code != 200 || hd.Get("Content-Length") != strconv.Itoa(len("version: STSv1\nmode: enforce\n")) {
		t.Fatalf("head: %d %v", code, hd)
	}
	if code, body, hd := do(t, c, "GET", "http://mail.test/json"); code != 201 || body != `{"ok":true}` || hd.Get("Content-Type") != "application/json" {
		t.Fatalf("json response: %d %q", code, body)
	}
	if _, got, _ := getJSON(t, c, "http://mail.test/autodiscover/autodiscover.xml"); got["path"] != "/autodiscover/autodiscover.xml" {
		t.Fatalf("proxied location: %v", got)
	}
	for _, x := range []struct {
		path string
		code int
	}{{"/admin/x", 404}, {"/gesperrt", 403}, {"/", 404}, {"/SOGo", 404}, {"/.well-known/mta-sts.txtx", 404}} {
		if code, _, _ := do(t, c, "GET", "http://mail.test"+x.path); code != x.code {
			t.Errorf("%s: %d, want %d", x.path, code, x.code)
		}
	}
	// Pruefungen
	var fe *FieldError
	for _, x := range []struct {
		l   Location
		key string
	}{{Location{Path: "/a", Action: "weg"}, "cdn64.err.location_action"}, {Location{Path: "/a", Action: LocBlock, Status: 200}, "cdn64.err.location_status"},
		{Location{Path: "/a", Action: LocRespond, Status: 700}, "cdn64.err.location_status"},
		{Location{Path: "/a", Action: LocRespond, Body: strings.Repeat("x", maxLocBody+1)}, "cdn64.err.location_body"},
		{Location{Path: "/a", Action: LocRespond, ContentType: "text/plain\r\nX: y"}, "cdn64.err.location_body"}} {
		b := newHost()
		b.Names, b.TargetHost, b.TargetPort, b.CertID = []string{"bad.test"}, "127.0.0.1", port, CertNone
		b.Locations = []Location{x.l}
		if err := e.m.saveHost(ctx, b); !errors.As(err, &fe) || fe.Key != x.key {
			t.Errorf("%+v: %v, want %s", x.l, err, x.key)
		}
	}
	b := newHost()
	b.Names, b.TargetHost, b.TargetPort, b.CertID = []string{"leer.test"}, "127.0.0.1", port, CertNone
	b.Advanced.OnlyLocations = true
	if err := e.m.saveHost(ctx, b); !errors.As(err, &fe) || fe.Key != "cdn64.err.only_locations" {
		t.Fatalf("only locations without locations: %v", err)
	}
}

func TestLocationAdvanced(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	port, _ := pathBackend(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"as.test"}, "127.0.0.1", port, CertNone
	h.Advanced.TimeoutSeconds, h.Advanced.MaxBodyMB = 1, 1
	h.Advanced.RequestHeaders = []Header{{Name: "X-Loc", Value: "host"}, {Name: "X-Host", Value: "h"}}
	h.Locations = []Location{
		{Path: "/Microsoft-Server-ActiveSync", TargetHost: "127.0.0.1", TargetPort: port,
			Advanced: &LocationAdvanced{TimeoutSeconds: 5, MaxBodyMB: -1, Buffering: "off", RequestHeaders: []Header{{Name: "x-loc", Value: "location"}}}},
		{Path: "/upload", TargetHost: "127.0.0.1", TargetPort: port, Advanced: &LocationAdvanced{MaxBodyMB: 3}},
		{Path: "/leer", TargetHost: "127.0.0.1", TargetPort: port, Advanced: &LocationAdvanced{}},
	}
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.m.host(ctx, h.ID); got.Locations[2].Advanced != nil {
		t.Fatalf("empty advanced kept: %+v", got.Locations[2].Advanced)
	}
	c := e.client(false)
	c.Timeout = 10 * time.Second
	// Timeout des Hosts (1 s) bricht ab, die Location (5 s) wartet
	if code, _, _ := do(t, c, "GET", "http://as.test/slow"); code != http.StatusBadGateway {
		t.Fatalf("host timeout: %d", code)
	}
	if _, got, _ := getJSON(t, c, "http://as.test/Microsoft-Server-ActiveSync/slow"); got["path"] != "/Microsoft-Server-ActiveSync/slow" || got["hdr"] != "location" || got["hosthdr"] != "h" {
		t.Fatalf("location timeout/headers: %v", got)
	}
	post := func(p string, n int) int {
		req, _ := http.NewRequest("POST", "http://as.test"+p, strings.NewReader(strings.Repeat("x", n)))
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := post("/x", 2<<20); code != http.StatusRequestEntityTooLarge {
		t.Errorf("host upload limit: %d", code)
	}
	if code := post("/upload", 2<<20); code != 200 {
		t.Errorf("location upload limit 3 MB: %d", code)
	}
	if code := post("/upload", 4<<20); code != http.StatusRequestEntityTooLarge {
		t.Errorf("location upload over limit: %d", code)
	}
	if code := post("/Microsoft-Server-ActiveSync", 3<<20); code != 200 {
		t.Errorf("location without upload limit: %d", code)
	}
	var fe *FieldError
	for _, la := range []*LocationAdvanced{{TimeoutSeconds: -1}, {MaxBodyMB: -2}, {Buffering: "egal"}, {RequestHeaders: []Header{{Name: "Connection", Value: "x"}}}} {
		b := newHost()
		b.Names, b.TargetHost, b.TargetPort, b.CertID = []string{"bad.test"}, "127.0.0.1", port, CertNone
		b.Locations = []Location{{Path: "/a", TargetHost: "127.0.0.1", TargetPort: port, Advanced: la}}
		if err := e.m.saveHost(ctx, b); !errors.As(err, &fe) || fe.Field != "locations" {
			t.Errorf("%+v: %v", la, err)
		}
	}
}

func TestMergeHeaders(t *testing.T) {
	got := mergeHeaders([]Header{{"A", "1"}, {"B", "2"}}, []Header{{"b", "3"}, {"C", "4"}})
	if len(got) != 3 || got[0].Name != "A" || got[1].Value != "3" || got[2].Name != "C" {
		t.Fatalf("merge: %+v", got)
	}
}
