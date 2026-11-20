package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/environment"
	"github.com/ipv64net/node64/internal/peer"
	"github.com/ipv64net/node64/internal/store"
)

// envNode ist eine Node fuer den Test mit zwei Nodes: Cluster-Funktionen von Hand, die Ticket-Anfrage geht direkt an
// den Dienst der anderen Node (wie ueber /peer/v2/call).
type envNode struct {
	app   *testApp
	env   *environment.Service
	other *envNode
	id    string
	name  string
	areas map[string]bool // Bereiche, die hier und bei der anderen Node an sind
}

func newEnvNode(t *testing.T, id, name string) *envNode {
	t.Helper()
	ctx := context.Background()
	n := &envNode{id: id, name: name, areas: map[string]bool{"users/accounts": true, "environment/login": true}}
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
		members := func(context.Context) ([]peer.Member, error) {
			o := n.other
			return []peer.Member{{NodeID: o.id, Name: o.name, URL: o.app.srv.URL, Version: "test"}}, nil
		}
		n.env = environment.New(environment.Deps{Store: d.Store, Members: members,
			AreaOn: func(ctx context.Context, module, item string) []peer.Member {
				if !n.areas[module+"/"+item] {
					return nil
				}
				list, _ := members(ctx)
				return list
			},
			Call: func(ctx context.Context, nodeID string, in environment.TicketRequest, out *environment.TicketResponse) error {
				b, _ := json.Marshal(in)
				res, err := n.other.env.HandleTicket(ctx, n.id, b)
				if err != nil {
					return err
				}
				*out = res.(environment.TicketResponse)
				return nil
			}})
		d.Env = n.env
	})
	return n
}

var envTicketRe = regexp.MustCompile(`name="ticket" value="([^"]+)"`)

// openB oeffnet auf A die Node B und liefert Antwort und Ticket ("" = Anmeldeseite).
func openB(t *testing.T, a, b *envNode) (*http.Response, string, string) {
	t.Helper()
	_, page := a.app.get(t, "/environment")
	resp, body := a.app.post(t, "/environment/open/"+b.id, url.Values{"_csrf": {csrfOf(t, page)}})
	if m := envTicketRe.FindStringSubmatch(body); m != nil {
		return resp, body, m[1]
	}
	return resp, body, ""
}

// Zwei Nodes: Oeffnen mit gleicher uid meldet auf B an (Hinweis mit Rueckweg, Audit), das Ticket gilt nur einmal;
// ohne gleiche uid bzw. ohne Benutzer-Abgleich geht es zur Anmeldeseite von B; „nur lesen“ auf A begrenzt die Sitzung
// auf B.
func TestEnvironmentTwoNodes(t *testing.T) {
	ctx := context.Background()
	a, b := newEnvNode(t, "node-a", "Node A"), newEnvNode(t, "node-b", "Node B")
	a.other, b.other = b, a
	me := loginAs(t, a.app, "admin", "sehr geheimes passwort")

	// B ohne Benutzer mit dieser uid (gleicher Name zaehlt nicht): Anmeldeseite
	if _, err := b.app.store.CreateUserWith(ctx, store.NewUser{Username: "admin", PasswordHash: "x", Lang: "de", Timezone: "UTC"}); err != nil {
		t.Fatal(err)
	}
	resp, page := a.app.get(t, "/environment")
	for _, want := range []string{`href="/environment"`, "Node B", b.app.srv.URL, "Diese Node", "mit meinem Benutzer", `action="/environment/open/node-b"`, `href="https://node64.de/docs/cluster/#environment"`} {
		if !strings.Contains(page, want) {
			t.Fatalf("environment page misses %q", want)
		}
	}
	if resp.StatusCode != 200 || strings.Contains(page, "environment.") {
		t.Fatalf("environment page: %d or untranslated key", resp.StatusCode)
	}
	resp, body, tok := openB(t, a, b)
	if resp.StatusCode != 200 || tok != "" || !strings.Contains(body, `id="env-login"`) || !strings.Contains(body, b.app.srv.URL+"/login?env=1") {
		t.Fatalf("open without same uid: %d %q", resp.StatusCode, tok)
	}
	if _, body := b.app.get(t, "/login?env=1"); !strings.Contains(body, "Über Environment ist hier keine Anmeldung") {
		t.Fatal("login hint on B missing")
	}

	// gleiche uid auf B: Ticket, Formular direkt an B (form-action nur dafuer erlaubt)
	if _, err := b.app.store.CreateUserWith(ctx, store.NewUser{UID: me.UID, Username: "dennis", PasswordHash: "x", Lang: "de", Timezone: "UTC"}); err != nil {
		t.Fatal(err)
	}
	resp, body, tok = openB(t, a, b)
	if tok == "" || !strings.Contains(body, `action="`+b.app.srv.URL+`/environment/enter"`) || !strings.Contains(body, "/static/js/environment.js") {
		t.Fatalf("open with same uid: %d", resp.StatusCode)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' "+b.app.srv.URL) {
		t.Fatalf("csp: %s", csp)
	}
	resp = enter(t, b.app.client, b, tok, a.app.srv.URL) // ohne CSRF: kommt von A (Origin)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("enter: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	_, body = b.app.get(t, "/")
	if !strings.Contains(body, `id="env-from"`) || !strings.Contains(body, "Geöffnet über Environment von Node A") || !strings.Contains(body, a.app.srv.URL+"/environment") ||
		strings.Contains(body, "nur lesen") {
		t.Fatal("banner on B missing")
	}
	// Administrator: Aenderungen und Admin-Bereich erlaubt
	if resp, _ := b.app.get(t, userAdminPath); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin page in admin session: %d", resp.StatusCode)
	}
	_, page = b.app.get(t, "/settings")
	if resp, _ := b.app.post(t, "/settings/node", url.Values{"_csrf": {csrfOf(t, page)}, "node_name": {"Node B"}}); resp.StatusCode == http.StatusForbidden {
		t.Fatal("admin session denied")
	}
	// einmal verwendbar
	b2 := newClient(t)
	if resp := enter(t, b2, b, tok, a.app.srv.URL); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login?env=1" {
		t.Fatalf("ticket reused: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	entries, _ := b.app.store.AuditList(ctx, 50, 0)
	var ok, failed, denied bool
	for _, e := range entries {
		ok = ok || e.Action == "login.environment" && e.Actor == "dennis" && e.Target == "Node A" && e.Details == "role admin"
		failed = failed || e.Action == "login.environment_failed"
		denied = denied || e.Action == "environment.ticket_denied"
	}
	if !ok || !failed || !denied {
		t.Fatalf("audit on B: ok=%v failed=%v denied=%v", ok, failed, denied)
	}
	entries, _ = a.app.store.AuditList(ctx, 50, 0)
	ok = false
	for _, e := range entries {
		ok = ok || e.Action == "environment.open" && e.Target == "Node B" && e.Details == "ticket"
	}
	if !ok {
		t.Fatal("audit environment.open on A missing")
	}

	// „nur lesen“ auf A: Sitzung auf B nur lesen, obwohl der Benutzer dort Administrator ist
	if err := a.app.store.UpdateUserAdmin(ctx, me.ID, store.UserAdmin{Role: store.RoleRead}); err != nil {
		t.Fatal(err)
	}
	_, _, tok = openB(t, a, b)
	if tok == "" {
		t.Fatal("no ticket for read-only user")
	}
	enter(t, b.app.client, b, tok, a.app.srv.URL)
	_, body = b.app.get(t, "/settings")
	if !strings.Contains(body, "nur lesen") {
		t.Fatal("read-only badge missing")
	}
	if resp, body := b.app.post(t, "/settings/node", url.Values{"_csrf": {csrfOf(t, body)}, "node_name": {"Boese"}}); resp.StatusCode != http.StatusForbidden ||
		!strings.Contains(body, "Nur lesen") {
		t.Fatalf("read-only session may change: %d", resp.StatusCode)
	}
	if got := b.app.store.SettingOr(ctx, SettingNodeName, ""); got == "Boese" {
		t.Fatal("setting changed")
	}
	// auch Admin-Bereiche beim Lesen gesperrt (Rechtepruefung sieht die begrenzte Rolle)
	if resp, _ := b.app.get(t, userAdminPath); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("admin page in read-only session: %d", resp.StatusCode)
	}
	// Abmelden geht
	_, body = b.app.get(t, "/settings")
	if resp, _ := b.app.post(t, "/logout", url.Values{"_csrf": {csrfOf(t, body)}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout: %d", resp.StatusCode)
	}

	// Benutzer-Abgleich aus: Liste zeigt die Anmeldeseite, Oeffnen holt kein Ticket
	_ = a.app.store.UpdateUserAdmin(ctx, me.ID, store.UserAdmin{Role: store.RoleAdmin})
	delete(a.areas, "users/accounts")
	_, page = a.app.get(t, "/environment")
	if !strings.Contains(page, "Anmeldeseite") || strings.Contains(page, `action="/environment/open/node-b"`) || !strings.Contains(page, `href="`+b.app.srv.URL+`/"`) {
		t.Fatal("list without user sync")
	}
	if _, _, tok = openB(t, a, b); tok != "" {
		t.Fatal("ticket without user sync")
	}
	// B lehnt auch selbst ab, wenn dort der Abgleich aus ist
	a.areas["users/accounts"] = true
	delete(b.areas, "users/accounts")
	if _, _, tok = openB(t, a, b); tok != "" {
		t.Fatal("ticket although user sync is off on B")
	}
	// unbekanntes Mitglied
	_, page = a.app.get(t, "/environment")
	if resp, _ := a.app.post(t, "/environment/open/node-x", url.Values{"_csrf": {csrfOf(t, page)}}); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown member: %d", resp.StatusCode)
	}
}

func newClient(t *testing.T) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// enter schickt ein Ticket an /environment/enter von B, wie der Browser von der Seite mit Ursprung origin ("" = ohne
// Origin und Referer): cross-site ohne die Cookies von B, danach der zweite Schritt (envBrowser).
func enter(t *testing.T, c *http.Client, b *envNode, tok, origin string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, b.app.srv.URL+envEnterPath, strings.NewReader(url.Values{"ticket": {tok}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, _ := envBrowser(t, c, req)
	return resp
}

// Login-CSRF: Ein Ticket gilt nur, wenn das Formular von der oeffnenden Node kommt (Origin, ersatzweise Referer), und
// ersetzt keine bestehende Anmeldung eines anderen Benutzers.
func TestEnvironmentEnterOrigin(t *testing.T) {
	ctx := context.Background()
	a, b := newEnvNode(t, "node-a", "Node A"), newEnvNode(t, "node-b", "Node B")
	a.other, b.other = b, a
	me := loginAs(t, a.app, "admin", "sehr geheimes passwort")
	if _, err := b.app.store.CreateUserWith(ctx, store.NewUser{UID: me.UID, Username: "dennis", PasswordHash: "x", Lang: "de", Timezone: "UTC"}); err != nil {
		t.Fatal(err)
	}
	ticket := func() string {
		t.Helper()
		_, _, tok := openB(t, a, b)
		if tok == "" {
			t.Fatal("no ticket")
		}
		return tok
	}
	denied := func(resp *http.Response) bool { return resp.Header.Get("Location") == "/login?env=1" }

	// von einer fremden Seite: abgelehnt, das Ticket ist danach verbraucht
	tok := ticket()
	if resp := enter(t, newClient(t), b, tok, "https://evil.example"); !denied(resp) {
		t.Fatalf("foreign origin: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp := enter(t, newClient(t), b, tok, a.app.srv.URL); !denied(resp) {
		t.Fatal("ticket usable after foreign attempt")
	}
	// ohne Origin und Referer: abgelehnt
	if resp := enter(t, newClient(t), b, ticket(), ""); !denied(resp) {
		t.Fatal("no origin accepted")
	}
	// Origin "null", Referer mit dem Ursprung von A: angenommen
	req, _ := http.NewRequest(http.MethodPost, b.app.srv.URL+envEnterPath, strings.NewReader(url.Values{"ticket": {ticket()}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "null")
	req.Header.Set("Referer", a.app.srv.URL+"/")
	resp, _ := envBrowser(t, newClient(t), req)
	if resp.Header.Get("Location") != "/" {
		t.Fatalf("referer fallback: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	// Seite zum Oeffnen schickt nur den Ursprung als Referer (nicht no-referrer, sonst Origin "null")
	resp, _, _ = openB(t, a, b)
	if p := resp.Header.Get("Referrer-Policy"); p != "origin" {
		t.Fatalf("referrer policy: %q", p)
	}

	// auf B ist schon ein anderer Benutzer angemeldet: bleibt angemeldet, Hinweis, Audit
	loginAs(t, b.app, "anna", "auch ein geheimes passwort")
	if resp := enter(t, b.app.client, b, ticket(), a.app.srv.URL); resp.Header.Get("Location") != "/" {
		t.Fatalf("other user: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	_, body := b.app.get(t, "/")
	if strings.Contains(body, `id="env-from"`) || !strings.Contains(body, "schon ein anderer Benutzer angemeldet") {
		t.Fatal("session of other user replaced or hint missing")
	}
	if _, body = b.app.get(t, "/settings"); !strings.Contains(body, "anna") {
		t.Fatal("anna no longer signed in")
	}
	entries, _ := b.app.store.AuditList(ctx, 50, 0)
	ok := false
	for _, e := range entries {
		ok = ok || e.Action == "login.environment_failed" && e.Actor == "anna" && strings.Contains(e.Details, "other user")
	}
	if !ok {
		t.Fatal("audit for other user missing")
	}
}

// /environment/enter geht ohne Anmeldung: ungueltige Tickets landen nach einigen Fehlversuchen je Adresse nicht mehr
// im Audit-Log (sonst liesse es sich fluten); abgelehnt werden sie weiter.
func TestEnvironmentEnterAuditThrottled(t *testing.T) {
	ctx := context.Background()
	a, b := newEnvNode(t, "node-a", "Node A"), newEnvNode(t, "node-b", "Node B")
	a.other, b.other = b, a
	for i := range 20 {
		if resp := enter(t, newClient(t), b, "ungueltig-"+itoa(int64(i)), a.app.srv.URL); resp.Header.Get("Location") != "/login?env=1" {
			t.Fatalf("invalid ticket: %d %s", resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	entries, _ := b.app.store.AuditList(ctx, 100, 0)
	n := 0
	for _, e := range entries {
		if e.Action == "login.environment_failed" {
			n++
		}
	}
	if n == 0 || n > 5 {
		t.Fatalf("audit entries for 20 invalid tickets: %d", n)
	}
}
