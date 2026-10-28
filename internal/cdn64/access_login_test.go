package cdn64

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
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
	// Abmelden: GET zeigt nur den Knopf, POST loescht das Cookie
	if code, body, hdr = get("/.node64/logout"); code != 200 || hdr.Get("Set-Cookie") != "" || !strings.Contains(body, `method="post"`) {
		t.Fatalf("logout get: %d %v", code, hdr)
	}
	lo, err := c.Post("http://login.test/.node64/logout", "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatal(err)
	}
	lo.Body.Close()
	if lo.StatusCode != 303 || !strings.Contains(lo.Header.Get("Set-Cookie"), ck.Name+"=;") {
		t.Fatalf("logout: %d %v", lo.StatusCode, lo.Header)
	}
	// Host mit HTTPS: Login nie im Klartext, HTTP geht auf HTTPS
	h2 := newHost()
	h2.Names, h2.TargetHost, h2.TargetPort, h2.AccessListID = []string{"login2.test"}, "127.0.0.1", h.TargetPort, a.ID
	if err := e.m.saveHost(ctx, h2); err != nil {
		t.Fatal(err)
	}
	r2, err := c.Get("http://login2.test/x?y=1")
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if r2.StatusCode != http.StatusPermanentRedirect || r2.Header.Get("Location") != "https://login2.test/x?y=1" {
		t.Fatalf("https redirect: %d %q", r2.StatusCode, r2.Header.Get("Location"))
	}
	// ohne Login-Seite: Browser-Dialog wie bisher, /.node64/ geht ans Ziel
	a.LoginPage = false
	if err := e.m.saveAccessList(ctx, a, []UserInput{{Username: "anna"}}); err != nil {
		t.Fatal(err)
	}
	if code, _, hdr = get("/"); code != 401 || hdr.Get("WWW-Authenticate") == "" {
		t.Fatalf("basic dialog: %d %v", code, hdr)
	}
	// ohne Login-Liste: /.node64/login geht trotzdem nie ans Ziel (Anmeldedaten)
	if resp := post(url.Values{"username": {"anna"}, "password": {"geheim123"}}); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("login path without login list: %d", resp.StatusCode)
	}
}

// Login-Seite an einer Location: das Formular geht an PROXY64 (nicht an das Ziel des Hosts), die Liste kommt aus dem
// Formular; das Sitzungs-Cookie geht an kein Ziel, auch nicht an das offene des Hosts.
func TestAccessListLoginLocation(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	var leaked atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/.node64/") {
			leaked.Add(1)
		}
		_, _ = io.WriteString(w, "ziel "+r.URL.Path+" cookie="+r.Header.Get("Cookie"))
	}))
	t.Cleanup(srv.Close)
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	a := &AccessList{Name: "Admin", LoginPage: true}
	if err := e.m.saveAccessList(ctx, a, []UserInput{{Username: "anna", Password: "geheim123"}}); err != nil {
		t.Fatal(err)
	}
	b := &AccessList{Name: "Fotos", LoginPage: true}
	if err := e.m.saveAccessList(ctx, b, []UserInput{{Username: "ben", Password: "geheim456"}}); err != nil {
		t.Fatal(err)
	}
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"loc-login.test"}, "127.0.0.1", port, CertNone
	h.Locations = []Location{{Path: "/admin", TargetHost: "127.0.0.1", TargetPort: port, AccessListID: a.ID},
		{Path: "/fotos", TargetHost: "127.0.0.1", TargetPort: port, AccessListID: b.ID}}
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	c := e.client(false)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	code, body, _ := do(t, c, "GET", "http://loc-login.test/admin/x")
	if code != 401 || !strings.Contains(body, `name="list" value="`+strconv.FormatInt(a.ID, 10)+`"`) {
		t.Fatalf("login page of the location: %d %.200s", code, body)
	}
	resp, err := c.PostForm("http://loc-login.test/.node64/login", url.Values{"list": {strconv.FormatInt(a.ID, 10)}, "username": {"anna"},
		"password": {"geheim123"}, "next": {"/admin/x"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 303 || len(resp.Cookies()) != 1 || resp.Cookies()[0].Name != loginCookieName(a.ID) {
		t.Fatalf("login at location: %d %v", resp.StatusCode, resp.Header)
	}
	ck := resp.Cookies()[0]
	if code, body, _ = do(t, c, "GET", "http://loc-login.test/admin/x", "Cookie", ck.Name+"="+ck.Value+`; q="a b"`); code != 200 ||
		strings.Contains(body, ck.Name) || !strings.Contains(body, `q="a b"`) {
		t.Fatalf("session at location: %d %q", code, body)
	}
	if code, body, _ = do(t, c, "GET", "http://loc-login.test/offen", "Cookie", ck.Name+"="+ck.Value); code != 200 || strings.Contains(body, ck.Name) {
		t.Fatalf("cookie must not reach the open host target: %d %q", code, body)
	}
	if code, _, _ = do(t, c, "GET", "http://loc-login.test/fotos/", "Cookie", ck.Name+"="+ck.Value); code != 401 {
		t.Fatalf("other list must not accept the session: %d", code)
	}
	// fremde oder fehlende Liste bei mehreren Login-Listen: abgelehnt, nie ans Ziel
	if resp, err = c.PostForm("http://loc-login.test/.node64/login", url.Values{"list": {"999"}, "username": {"anna"}, "password": {"geheim123"}}); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown list: %d", resp.StatusCode)
	}
	if n := leaked.Load(); n != 0 {
		t.Fatalf("login request reached the target %d times", n)
	}
}

// Nur das Sitzungs-Cookie faellt heraus, die uebrigen Cookies bleiben Wort fuer Wort (auch in mehreren Zeilen).
func TestStripLoginCookieRaw(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Add("Cookie", `a="x y"; n64_auth_7=tok; b=1`)
	r.Header.Add("Cookie", "c=@{bad}; n64_auth_8=other")
	stripLoginCookie(r, 7)
	if got := r.Header.Values("Cookie"); len(got) != 1 || got[0] != `a="x y"; b=1; c=@{bad}; n64_auth_8=other` {
		t.Fatalf("cookie: %q", got)
	}
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", "n64_auth_7=tok")
	stripLoginCookie(r, 7)
	if _, ok := r.Header["Cookie"]; ok {
		t.Fatal("empty cookie header must be removed")
	}
}
