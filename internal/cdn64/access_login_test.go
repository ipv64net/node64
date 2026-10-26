package cdn64

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Login-Seite statt Browser-Dialog: Formular, Sitzungs-Cookie (nie beim Ziel), Fehlversuche, Basic Auth weiter
// moeglich, neues Passwort beendet die Sitzung, nur Pfade dieses Namens als Ziel, Abmelden.
func TestAccessListLoginPage(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ziel "+r.URL.Path+" cookie="+r.Header.Get("Cookie"))
	}))
	t.Cleanup(srv.Close)
	a := &AccessList{Name: "Familie", LoginPage: true}
	if err := e.m.saveAccessList(ctx, a, []UserInput{{Username: "anna", Password: "geheim123"}}); err != nil {
		t.Fatal(err)
	}
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID, h.AccessListID = []string{"login.test"}, "127.0.0.1", srv.Listener.Addr().(*net.TCPAddr).Port, CertNone, a.ID
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	c := e.client(false)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	get := func(path string, hdr ...string) (int, string, http.Header) {
		t.Helper()
		req, _ := http.NewRequest("GET", "http://login.test"+path, nil)
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), resp.Header
	}
	post := func(v url.Values) *http.Response {
		t.Helper()
		resp, err := c.PostForm("http://login.test/.node64/login", v)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp
	}
	code, body, hdr := get("/bilder?x=1", "Accept-Language", "de-DE")
	if code != 401 || hdr.Get("WWW-Authenticate") != "" || !strings.Contains(body, `action="/.node64/login"`) || !strings.Contains(body, `value="/bilder?x=1"`) ||
		!strings.Contains(body, "Anmeldung erforderlich") || !strings.Contains(body, "Familie") {
		t.Fatalf("login page: %d %v %.300s", code, hdr, body)
	}
	if resp := post(url.Values{"username": {"anna"}, "password": {"falsch"}, "next": {"/bilder"}}); resp.StatusCode != 401 || len(resp.Cookies()) != 0 {
		t.Fatalf("wrong password: %d", resp.StatusCode)
	}
	resp := post(url.Values{"username": {"anna"}, "password": {"geheim123"}, "next": {"/bilder?x=1"}})
	if resp.StatusCode != 303 || resp.Header.Get("Location") != "/bilder?x=1" || len(resp.Cookies()) != 1 || !resp.Cookies()[0].HttpOnly {
		t.Fatalf("login: %d %v", resp.StatusCode, resp.Header)
	}
	ck := resp.Cookies()[0]
	code, body, _ = get("/bilder", "Cookie", ck.Name+"="+ck.Value+"; andere=1")
	if code != 200 || !strings.Contains(body, "ziel /bilder") || strings.Contains(body, ck.Name) || !strings.Contains(body, "andere=1") {
		t.Fatalf("session: %d %q", code, body)
	}
	if code, _, _ = get("/", "Cookie", ck.Name+"="+ck.Value+"x"); code != 401 {
		t.Fatalf("tampered cookie: %d", code)
	}
	if code, _, _ = get("/", "Authorization", basic("anna", "geheim123")); code != 200 {
		t.Fatalf("basic auth: %d", code)
	}
	if resp := post(url.Values{"username": {"anna"}, "password": {"geheim123"}, "next": {"//evil.example/"}}); resp.Header.Get("Location") != "/" {
		t.Fatalf("foreign next: %q", resp.Header.Get("Location"))
	}
	// neues Passwort beendet die Sitzung
	if err := e.m.saveAccessList(ctx, a, []UserInput{{Username: "anna", Password: "neu-geheim"}}); err != nil {
		t.Fatal(err)
	}
	if code, _, _ = get("/", "Cookie", ck.Name+"="+ck.Value); code != 401 {
		t.Fatalf("old session after new password: %d", code)
	}
	// Abmelden loescht das Cookie
	if code, _, hdr = get("/.node64/logout"); code != 303 || !strings.Contains(hdr.Get("Set-Cookie"), ck.Name+"=;") {
		t.Fatalf("logout: %d %v", code, hdr)
	}
	// ohne Login-Seite: Browser-Dialog wie bisher, /.node64/ geht ans Ziel
	a.LoginPage = false
	if err := e.m.saveAccessList(ctx, a, []UserInput{{Username: "anna"}}); err != nil {
		t.Fatal(err)
	}
	if code, _, hdr = get("/"); code != 401 || hdr.Get("WWW-Authenticate") == "" {
		t.Fatalf("basic dialog: %d %v", code, hdr)
	}
}
