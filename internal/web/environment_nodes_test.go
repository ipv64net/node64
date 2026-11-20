package web

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/environment"
	"github.com/ipv64net/node64/internal/peer"
	"github.com/ipv64net/node64/internal/store"
)

// keyNode ist eine Node ohne Cluster fuer den Test der hinzugefuegten Nodes; tls ist dieselbe Oberflaeche per HTTPS
// (die gebundenen Endpunkte sprechen nur TLS).
type keyNode struct {
	app *testApp
	env *environment.Service
	tls *httptest.Server
}

func newKeyNode(t *testing.T, id, name string, ttl time.Duration) *keyNode {
	t.Helper()
	ctx := context.Background()
	n := &keyNode{}
	n.app = newTestAppDeps(t, func(d *Deps) {
		for scope, f := range map[string]func() ([]store.Migration, error){"peer": peer.Migrations, environment.Name: environment.Migrations} {
			ms, _ := f()
			if err := d.Store.Migrate(ctx, scope, ms); err != nil {
				t.Fatal(err)
			}
		}
		pm, err := peer.New(ctx, peer.Deps{Core: d.Store, Log: d.Log.Slog(), Version: "test",
			NodeID: func() string { return id }, NodeName: func() string { return name }, AccountID: func() int64 { return 0 }})
		if err != nil {
			t.Fatal(err)
		}
		d.Peer = pm
		n.env = environment.New(environment.Deps{Store: d.Store, Version: "test", NodeName: func() string { return name },
			NodeID: pm.NodeID, PublicKey: pm.PublicKey, StatusTTL: ttl})
		d.Env = n.env
	})
	n.tls = httptest.NewTLSServer(n.app.srv.Config.Handler)
	t.Cleanup(n.tls.Close)
	return n
}

// browser ist ein eigener Browser fuer die andere Node (Cookies, selbst signiertes Zertifikat, ohne Weiterleitungen).
func browser(t *testing.T) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // Test
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

var (
	envKeyRe     = regexp.MustCompile(`n64env1\.[A-Za-z0-9_.-]+`)
	envTicketRe2 = regexp.MustCompile(`name="ticket" value="([^"]+)"`)
)

// enterWith loest ein Ticket im Browser bei B ein (Formular kommt von A: Origin = A) und liefert Antwort und Seite.
func enterWith(t *testing.T, c *http.Client, b *keyNode, origin, ticket string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, b.tls.URL+envEnterPath, strings.NewReader(url.Values{"ticket": {ticket}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", origin)
	return envBrowser(t, c, req)
}

// enterConfirmed loest ein Ticket ein, fuer das B eine Bestaetigung verlangt (Rueckweg nicht als Adresse von A
// bekannt), und bestaetigt auf B (Formular von B mit dessen CSRF-Token).
func enterConfirmed(t *testing.T, c *http.Client, b *keyNode, origin, ticket string) *http.Response {
	t.Helper()
	resp, page := enterWith(t, c, b, origin, ticket)
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, `id="env-confirm"`) || !strings.Contains(page, `action="/environment/confirm"`) {
		t.Fatalf("confirmation page: %d", resp.StatusCode)
	}
	resp, err := c.PostForm(b.tls.URL+"/environment/confirm", url.Values{"_csrf": {csrfOf(t, page)}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func getWith(t *testing.T, c *http.Client, u string) string {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 32<<10)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return sb.String()
}

// Hinzugefuegte Node mit Zugangsschluessel: Zugang auf B, Eintrag auf A, Status und Anmeldung ueber die gebundenen
// Endpunkte; Rolle begrenzt; gesperrter Benutzer, Mittelsmann und widerrufener Schluessel fuehren zur Anmeldeseite;
// Fehlversuche werden gebremst.
func TestEnvironmentAddedNodes(t *testing.T) {
	ctx := context.Background()
	a, b := newKeyNode(t, "node-a-000001", "Node A", -1), newKeyNode(t, "node-b-000001", "Node B", -1)
	me := loginAs(t, a.app, "admin", "sehr geheimes passwort")
	bAdmin := loginAs(t, b.app, "admin", "sehr geheimes passwort")

	// nur TLS
	if resp, _ := b.app.post(t, environment.PathTicket, url.Values{}); resp.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("plain http: %d", resp.StatusCode)
	}

	// Zugang auf B (Schluessel nur einmal sichtbar, gespeichert nur der Pruefwert)
	_, page := b.app.get(t, "/environment/access")
	resp, page := b.app.post(t, "/environment/access", url.Values{"_csrf": {csrfOf(t, page)}, "name": {"von Node A"}, "user": {bAdmin.UID}})
	key := envKeyRe.FindString(page)
	if resp.StatusCode != http.StatusOK || key == "" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("create access: %d %q", resp.StatusCode, key)
	}
	if _, page := b.app.get(t, "/environment/access"); strings.Contains(page, key) || !strings.Contains(page, "von Node A") || strings.Contains(page, "environment.") {
		t.Fatal("key shown again or access missing")
	}

	// Eintrag auf A
	_, page = a.app.get(t, "/environment/nodes/new")
	if strings.Contains(page, "environment.") || !strings.Contains(page, "Zugangsschlüssel (optional)") {
		t.Fatal("node form")
	}
	if resp, _ := a.app.post(t, "/environment/nodes", url.Values{"_csrf": {csrfOf(t, page)}, "url": {b.tls.URL}, "key": {key}, "description": {"Büro"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("add node: %d", resp.StatusCode)
	}
	list, _ := a.env.AddedNodes(ctx)
	if len(list) != 1 || !list[0].HasKey || list[0].OwnerUID != me.UID {
		t.Fatalf("added: %+v", list)
	}
	uid := list[0].UID
	_, page = a.app.get(t, "/environment")
	for _, want := range []string{"Node B", "Hinzugefügt", "mit meinem Benutzer", `action="/environment/nodes/` + uid + `/open"`, "Büro", `href="/environment/nodes/` + uid + `"`} {
		if !strings.Contains(page, want) {
			t.Fatalf("environment page misses %q", want)
		}
	}
	if strings.Contains(page, "environment.") {
		t.Fatal("untranslated key")
	}

	// Oeffnen: Ticket, Formular an B, Anmeldung als Benutzer des Zugangs
	open := func() (string, string) {
		_, page := a.app.get(t, "/environment")
		resp, body := a.app.post(t, "/environment/nodes/"+uid+"/open", url.Values{"_csrf": {csrfOf(t, page)}})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("open: %d", resp.StatusCode)
		}
		if m := envTicketRe2.FindStringSubmatch(body); m != nil {
			return m[1], body
		}
		return "", body
	}
	tok, body := open()
	if tok == "" || !strings.Contains(body, `action="`+b.tls.URL+`/environment/enter"`) {
		t.Fatal("no ticket via access key")
	}
	bb := browser(t)
	// ohne Bestaetigung keine Sitzung (B kennt die Adresse von A nicht)
	if _, page := enterWith(t, browser(t), b, a.app.srv.URL, tok); !strings.Contains(page, "Als „admin“ anmelden?") || !strings.Contains(page, "Node A") {
		t.Fatal("confirmation text")
	}
	tok, _ = open()
	if resp := enterConfirmed(t, bb, b, a.app.srv.URL, tok); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("enter: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if page := getWith(t, bb, b.tls.URL+"/"); !strings.Contains(page, "Geöffnet über Environment von Node A") {
		t.Fatal("banner on B missing")
	}
	// zweites Oeffnen, solange die Sitzung vom ersten lebt: das Formular von A kommt ohne die Cookies von B, die
	// Bestaetigung (mit Cookies) passt trotzdem zum CSRF-Token
	tok, _ = open()
	if resp := enterConfirmed(t, bb, b, a.app.srv.URL, tok); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("second open: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if acc, _ := b.env.Accesses(ctx); len(acc) != 1 || acc[0].LastFromName != "Node A" {
		t.Fatalf("last use: %+v", acc)
	}

	// „nur lesen“ auf A: Sitzung auf B nur lesen, obwohl der Benutzer dort Administrator ist
	_ = a.app.store.UpdateUserAdmin(ctx, me.ID, store.UserAdmin{Role: store.RoleRead})
	tok, _ = open()
	bb2 := browser(t)
	enterConfirmed(t, bb2, b, a.app.srv.URL, tok)
	if page := getWith(t, bb2, b.tls.URL+"/settings"); !strings.Contains(page, "nur lesen") {
		t.Fatal("read-only session on B")
	}
	resp2, err := bb2.Get(b.tls.URL + userAdminPath)
	if err != nil || resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("admin page in read-only session: %v", resp2.StatusCode)
	}
	resp2.Body.Close()
	_ = a.app.store.UpdateUserAdmin(ctx, me.ID, store.UserAdmin{Role: store.RoleAdmin})

	// gesperrter Benutzer auf B: Liste zeigt den abgelehnten Schluessel, Oeffnen fuehrt zur Anmeldeseite
	_ = b.app.store.UpdateUserAdmin(ctx, bAdmin.ID, store.UserAdmin{Role: store.RoleAdmin, Disabled: true})
	_, page = a.app.get(t, "/environment")
	if !strings.Contains(page, "Zugangsschlüssel abgelehnt") || strings.Contains(page, `action="/environment/nodes/`+uid+`/open"`) {
		t.Fatal("locked user on B")
	}
	if tok, body := open(); tok != "" || !strings.Contains(body, b.tls.URL+"/login?env=1") {
		t.Fatal("ticket for locked user")
	}
	_ = b.app.store.UpdateUserAdmin(ctx, bAdmin.ID, store.UserAdmin{Role: store.RoleAdmin})

	// Mittelsmann, der TLS terminiert: B lehnt ab, A erkennt die Antwort nicht an
	target, _ := url.Parse(b.tls.URL)
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // Test
	mitm := httptest.NewTLSServer(rp)
	defer mitm.Close()
	k, _ := environment.ParseAccessKey(key)
	n2, err := a.env.AddNode(ctx, environment.NodeInput{URL: mitm.URL, Key: key, Name: "Mitte"}, me.UID)
	if err != nil {
		t.Fatal(err)
	}
	st := a.env.Status(ctx, n2)
	if st.KeyOK || !strings.Contains(st.KeyErr, "proxy") {
		t.Fatalf("mitm status: %+v", st)
	}
	if _, err := a.env.RequestRemoteTicket(ctx, n2, me.UID, store.RoleAdmin, a.app.srv.URL+"/environment"); err == nil {
		t.Fatal("ticket through a proxy")
	}
	_, _ = a.env.RemoveNode(ctx, n2.UID)
	if k.NodeID != "node-b-000001" {
		t.Fatalf("key node id: %s", k.NodeID)
	}

	// widerrufen: Oeffnen fuehrt zur Anmeldeseite
	acc, _ := b.env.Accesses(ctx)
	_, page = b.app.get(t, "/environment/access")
	if resp, _ := b.app.post(t, "/environment/access/"+itoa(acc[0].ID)+"/delete", url.Values{"_csrf": {csrfOf(t, page)}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	if tok, _ := open(); tok != "" {
		t.Fatal("ticket after revoke")
	}
	// ... und beendet die ueber den Zugang geoeffneten Sitzungen
	for _, c := range []*http.Client{bb, bb2} {
		resp, err := c.Get(b.tls.URL + "/settings")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/login") {
			t.Fatalf("session after revoke: %d %s", resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	// Fehlversuche (Mittelsmann, widerrufen) bremsen: nach fuenf antwortet B mit 429
	for range 3 {
		a.env.Status(ctx, &list[0])
	}
	if st := a.env.Status(ctx, &list[0]); !strings.Contains(st.KeyErr, "too many") {
		t.Fatalf("rate limit: %+v", st)
	}

	// Audit auf beiden Seiten
	entries, _ := b.app.store.AuditList(ctx, 100, 0)
	var created, revoked, login, denied bool
	for _, e := range entries {
		created = created || e.Action == "environment.access_create" && e.Target == "von Node A"
		revoked = revoked || e.Action == "environment.access_revoke"
		login = login || e.Action == "login.environment" && e.Target == "Node A"
		denied = denied || e.Action == "environment.ticket_denied"
	}
	if !created || !revoked || !login || !denied {
		t.Fatalf("audit on B: %v %v %v %v", created, revoked, login, denied)
	}
	entries, _ = a.app.store.AuditList(ctx, 100, 0)
	var added, opened bool
	for _, e := range entries {
		added = added || e.Action == "environment.node_add"
		opened = opened || e.Action == "environment.open" && e.Details == "ticket (access key)"
	}
	if !added || !opened {
		t.Fatalf("audit on A: %v %v", added, opened)
	}

	// Bearbeiten und Entfernen
	_, page = a.app.get(t, "/environment/nodes/"+uid)
	if !strings.Contains(page, "Ein Schlüssel ist hinterlegt") || strings.Contains(page, key) {
		t.Fatal("edit form")
	}
	if resp, _ := a.app.post(t, "/environment/nodes/"+uid, url.Values{"_csrf": {csrfOf(t, page)}, "url": {"ftp://x"}}); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("invalid url: %d", resp.StatusCode)
	}
	if resp, _ := a.app.post(t, "/environment/nodes/"+uid+"/delete", url.Values{"_csrf": {csrfOf(t, page)}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if list, _ := a.env.AddedNodes(ctx); len(list) != 0 {
		t.Fatal("not removed")
	}
}

// Hinzugefuegte Node ohne Schluessel, API und Rechte: „Nur lesen“ sieht die Liste und darf oeffnen, aber nichts
// anlegen und keine Zugaenge sehen.
func TestEnvironmentAddedNodesAPI(t *testing.T) {
	ctx := context.Background()
	a, b := newKeyNode(t, "node-a-000001", "Node A", -1), newKeyNode(t, "node-b-000001", "Node B", -1)
	me := loginAs(t, a.app, "admin", "sehr geheimes passwort")
	key, _, err := a.app.store.NewAPIKey(ctx, me.ID, "test")
	if err != nil {
		t.Fatal(err)
	}
	api := func(method, path, body string) (int, string) {
		req, _ := http.NewRequest(method, a.app.srv.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var sb strings.Builder
		buf := make([]byte, 16<<10)
		for {
			n, err := resp.Body.Read(buf)
			sb.Write(buf[:n])
			if err != nil {
				break
			}
		}
		return resp.StatusCode, sb.String()
	}
	if st, body := api("POST", "/api/environment/nodes", `{"url":"`+b.tls.URL+`","name":"B ohne Schlüssel"}`); st != 201 || !strings.Contains(body, `"has_key":false`) {
		t.Fatalf("create: %d %s", st, body)
	}
	if st, _ := api("POST", "/api/environment/nodes", `{"url":"`+b.tls.URL+`","key":"n64env1.x"}`); st != 422 {
		t.Fatalf("invalid key: %d", st)
	}
	st, body := api("GET", "/api/environment", "")
	if st != 200 || !strings.Contains(body, `"origin":"self"`) || !strings.Contains(body, `"origin":"added"`) || !strings.Contains(body, `"online":true,"version":"test"`) {
		t.Fatalf("list: %d %s", st, body)
	}
	list, _ := a.env.AddedNodes(ctx)
	if st, _ := api("PUT", "/api/environment/nodes/"+list[0].UID, `{"url":"`+b.tls.URL+`","name":"B"}`); st != 200 {
		t.Fatalf("update: %d", st)
	}
	if st, body := api("POST", "/api/environment/access", `{"name":"von C"}`); st != 201 || !envKeyRe.MatchString(body) || !strings.Contains(body, `"username":"admin"`) {
		t.Fatalf("access create: %d %s", st, body)
	}
	if st, body := api("GET", "/api/environment/access", ""); st != 200 || !strings.Contains(body, "von C") || envKeyRe.MatchString(body) {
		t.Fatalf("access list: %d %s", st, body)
	}
	acc, _ := a.env.Accesses(ctx)
	if st, _ := api("DELETE", "/api/environment/access/"+itoa(acc[0].ID), ""); st != 204 {
		t.Fatalf("access revoke: %d", st)
	}

	// „Nur lesen“: Liste und Oeffnen (zur Anmeldeseite) ja, Anlegen und Zugaenge nein
	_ = a.app.store.UpdateUserAdmin(ctx, me.ID, store.UserAdmin{Role: store.RoleRead})
	_, page := a.app.get(t, "/environment")
	if !strings.Contains(page, "B") || strings.Contains(page, "/environment/nodes/new") || strings.Contains(page, `href="/environment/nodes/`+list[0].UID+`"`) {
		t.Fatal("read-only list")
	}
	if resp, body := a.app.post(t, "/environment/nodes/"+list[0].UID+"/open", url.Values{"_csrf": {csrfOf(t, page)}}); resp.StatusCode != 200 || !strings.Contains(body, b.tls.URL+"/login?env=1") {
		t.Fatalf("read-only open: %d", resp.StatusCode)
	}
	for _, p := range []string{"/environment/access", "/environment/nodes/new", "/environment/nodes/" + list[0].UID} {
		if resp, _ := a.app.get(t, p); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("read-only GET %s: %d", p, resp.StatusCode)
		}
	}
	if resp, _ := a.app.post(t, "/environment/nodes", url.Values{"_csrf": {csrfOf(t, page)}, "url": {"x.lan"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("read-only add: %d", resp.StatusCode)
	}
	if st, _ := api("GET", "/api/environment/access", ""); st != 403 {
		t.Fatalf("read-only access list: %d", st)
	}
	if st, _ := api("DELETE", "/api/environment/nodes/"+list[0].UID, ""); st != 403 {
		t.Fatalf("read-only delete: %d", st)
	}
}

// Fehlermeldungen beim Anlegen eines Zugangs sind uebersetzt (kein roher englischer Fehlertext).
func TestEnvironmentAccessErrorTranslated(t *testing.T) {
	b := newKeyNode(t, "node-b-000001", "Node B", -1)
	loginAs(t, b.app, "admin", "sehr geheimes passwort")
	_, page := b.app.get(t, "/environment/access")
	resp, page := b.app.post(t, "/environment/access", url.Values{"_csrf": {csrfOf(t, page)}, "name": {"  "}})
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(page, "Bitte einen Namen angeben.") || strings.Contains(page, "name missing") {
		t.Fatalf("access without name: %d", resp.StatusCode)
	}
}
