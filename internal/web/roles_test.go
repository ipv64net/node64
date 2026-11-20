package web

import (
	"context"
	"crypto/rand"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/cdn64"
	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/dns64"
	"github.com/ipv64net/node64/internal/dyndns"
	"github.com/ipv64net/node64/internal/healthchecks"
	"github.com/ipv64net/node64/internal/honeypot"
	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/monitor64"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/peer"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/sonar64"
	"github.com/ipv64net/node64/internal/store"
)

// Rechte-Matrix der Benutzerverwaltung: alle registrierten Routen (Kern, Zertifikate, Module) aus dem Quelltext lesen
// und mit einem Nur-lesen-Benutzer (Sitzung und API-Key) und einem Administrator abklopfen.

// scanRoutes liest die Muster aller mux.Handle/HandleFunc-Aufrufe der Go-Dateien eines Ordners (ohne Tests).
func scanRoutes(t *testing.T, dir string) []string {
	t.Helper()
	fset := token.NewFileSet()
	files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
	consts := map[string]string{}
	var parsed []*ast.File
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, af)
	}
	// eval: moegliche Werte eines Ausdrucks (mehrere bei range ueber eine Liste von Texten)
	var eval func(e ast.Expr, local map[string][]string) []string
	eval = func(e ast.Expr, local map[string][]string) []string {
		switch x := e.(type) {
		case *ast.BasicLit:
			if x.Kind == token.STRING {
				if s, err := strconv.Unquote(x.Value); err == nil {
					return []string{s}
				}
			}
		case *ast.BinaryExpr:
			if x.Op == token.ADD {
				var out []string
				for _, a := range eval(x.X, local) {
					for _, b := range eval(x.Y, local) {
						out = append(out, a+b)
					}
				}
				return out
			}
		case *ast.Ident:
			if v, ok := local[x.Name]; ok {
				return v
			}
			if v, ok := consts[x.Name]; ok {
				return []string{v}
			}
		case *ast.ParenExpr:
			return eval(x.X, local)
		}
		return nil
	}
	values := func(specs []ast.Spec, local map[string][]string, set func(string, []string)) {
		for _, sp := range specs {
			if vs, ok := sp.(*ast.ValueSpec); ok {
				for i, n := range vs.Names {
					if i < len(vs.Values) {
						if v := eval(vs.Values[i], local); v != nil {
							set(n.Name, v)
						}
					}
				}
			}
		}
	}
	// Konstanten und Variablen auf Paketebene (mehrere Runden fuer Verweise untereinander)
	for range 3 {
		for _, af := range parsed {
			for _, d := range af.Decls {
				if gd, ok := d.(*ast.GenDecl); ok {
					values(gd.Specs, nil, func(n string, v []string) {
						if len(v) == 1 {
							consts[n] = v[0]
						}
					})
				}
			}
		}
	}
	var out []string
	for _, af := range parsed {
		for _, d := range af.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			local := map[string][]string{}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.DeclStmt:
					if gd, ok := x.Decl.(*ast.GenDecl); ok {
						values(gd.Specs, local, func(n string, v []string) { local[n] = v })
					}
				case *ast.AssignStmt:
					for i, l := range x.Lhs {
						if id, ok := l.(*ast.Ident); ok && i < len(x.Rhs) {
							if v := eval(x.Rhs[i], local); v != nil {
								local[id.Name] = v
							}
						}
					}
				case *ast.RangeStmt: // for _, p := range []string{"a", "b"}
					if id, ok := x.Value.(*ast.Ident); ok {
						if cl, ok := x.X.(*ast.CompositeLit); ok {
							var vs []string
							for _, el := range cl.Elts {
								vs = append(vs, eval(el, local)...)
							}
							local[id.Name] = vs
						}
					}
				case *ast.CallExpr:
					sel, ok := x.Fun.(*ast.SelectorExpr)
					if !ok || (sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc") || len(x.Args) < 2 {
						return true
					}
					recv := ""
					switch r := sel.X.(type) {
					case *ast.Ident:
						recv = r.Name
					case *ast.SelectorExpr:
						recv = r.Sel.Name
					}
					if recv != "mux" {
						return true
					}
					p := eval(x.Args[0], local)
					if p == nil {
						t.Errorf("%s: route pattern not resolvable", fset.Position(x.Pos()))
						return true
					}
					out = append(out, p...)
				}
				return true
			})
		}
	}
	return out
}

var wildcardRe = regexp.MustCompile(`\{[^}]*\}`)

// routeRequest: Methode und Pfad zu einem Muster ({x} = 1, {x...} = a/b, {$} = nichts); ohne Methode GET und POST.
func routeRequests(pattern string) (methods []string, path string) {
	m, p, ok := strings.Cut(pattern, " ")
	if !ok {
		m, p = "", pattern
	}
	path = wildcardRe.ReplaceAllStringFunc(p, func(w string) string {
		switch {
		case w == "{$}":
			return ""
		case strings.HasSuffix(w, "...}"):
			return "a/b"
		}
		return "1"
	})
	if m == "" {
		return []string{http.MethodGet, http.MethodPost}, path
	}
	return []string{m}, path
}

// publicRoute: ohne Benutzer-Anmeldung (Login, Setup, Push, Statusseiten, Agent-Download, MCP mit eigenem Schluessel).
func publicRoute(path string) bool {
	for _, p := range []string{"/api/health", "/setup", "/login", "/logout", "/mcp", "/static/", "/api/push/", "/status/", "/monitor64/agent/", "/peer/"} {
		if path == p || strings.HasPrefix(path, strings.TrimSuffix(p, "/")+"/") {
			return path != "/login/password" // Passwort beim ersten Anmelden: mit Sitzung
		}
	}
	return path == "/"
}

// adminGets: GETs, die auch beim Lesen nur Administratoren sehen.
var adminGets = map[string]bool{
	"GET /api/backup": true, "GET /settings/backup": true,
	"GET " + userAdminPath: true, "GET /api/users": true, "GET /api/users/{id}": true,
	"GET /api/groups": true, "GET /api/groups/{id}": true, "GET /api/auth/2fa-required": true,
	"GET /api/dns64/zones/{id}/tsig":        true,
	"GET /healthchecks/{token}/edit":        true,
	"GET /healthchecks/online/{token}/edit": true,
}

// fullApp: Testserver mit Zertifikaten, Benachrichtigungen, ipv64-Key (nicht erreichbar) und Cluster, damit
// moeglichst alle Routen des Kerns registriert sind; angemeldet als admin.
func fullApp(t *testing.T) *testApp {
	t.Helper()
	ctx := context.Background()
	a := newTestAppDeps(t, func(d *Deps) {
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		box, _ := secrets.New(key)
		for name, ms := range map[string]func() ([]store.Migration, error){"certs": certs.Migrations, "notify": notify.Migrations, "peer": peer.Migrations} {
			list, _ := ms()
			if err := d.Store.Migrate(ctx, name, list); err != nil {
				t.Fatal(err)
			}
		}
		m, err := certs.New(ctx, certs.Deps{Store: d.Store, Box: box})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(m.Close)
		d.Certs, d.Box = m, box
		d.Notify = notify.NewStore(d.Store, box)
		d.IPv64 = ipv64api.NewKey(d.Store, nil, ipv64api.NewClient("http://127.0.0.1:1", "test"), slog.New(slog.NewTextHandler(io.Discard, nil)))
		pm, err := peer.New(ctx, peer.Deps{Core: d.Store, Log: d.Log.Slog(), Version: "test",
			NodeID: func() string { return "node-a" }, NodeName: func() string { return "Node A" }, AccountID: func() int64 { return 0 }})
		if err != nil {
			t.Fatal(err)
		}
		d.Peer = pm
	})
	loginAs(t, a, "admin", "sehr geheimes passwort")
	return a
}

// roleApp: fullApp mit einem Administrator und einem Nur-lesen-Benutzer (angemeldet als leser).
func roleApp(t *testing.T) (a *testApp, admin, reader *store.User) {
	t.Helper()
	a = fullApp(t)
	ctx := context.Background()
	admin, _ = a.store.UserByName(ctx, "admin")
	reader = createUser(t, a, "leser", store.RoleRead)
	a.client.Jar, _ = cookiejar.New(nil) // neue Sitzung als leser
	if resp := login(t, a, "leser", "sehr geheimes passwort"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login leser: %d", resp.StatusCode)
	}
	return a, admin, reader
}

func createUser(t *testing.T, a *testApp, name, role string) *store.User {
	t.Helper()
	hash, _ := HashPassword("sehr geheimes passwort")
	u, err := a.store.CreateUserWith(context.Background(), store.NewUser{Username: name, PasswordHash: hash, Role: role})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func login(t *testing.T, a *testApp, name, pw string) *http.Response {
	t.Helper()
	_, body := a.get(t, "/login")
	resp, _ := a.post(t, "/login", url.Values{"_csrf": {csrfOf(t, body)}, "username": {name}, "password": {pw}})
	return resp
}

// sessionOf: Cookies der angemeldeten Sitzung und der CSRF-Token fuer direkte Aufrufe des Handlers.
func sessionOf(t *testing.T, a *testApp) ([]*http.Cookie, string) {
	t.Helper()
	u, _ := url.Parse(a.srv.URL)
	cookies := a.client.Jar.Cookies(u)
	_, body := a.get(t, "/settings")
	return cookies, csrfOf(t, body)
}

// call fuehrt eine Anfrage direkt am Handler aus (mit Zeitlimit, z. B. fuer Streams).
func call(h http.Handler, method, path string, cookies []*http.Cookie, csrf, bearer string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req := httptest.NewRequestWithContext(ctx, method, path, nil)
	req.RemoteAddr = "192.0.2.10:1234"
	for _, c := range cookies {
		req.AddCookie(c)
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

type routeSet struct {
	name     string
	handler  http.Handler
	mux      *http.ServeMux
	patterns []string
}

// routeSets: Kern und Zertifikate am fertigen Handler; Module an einem eigenen Router mit denselben Guards (Enabled
// laesst durch, damit die Module nicht laufen muessen).
func routeSets(t *testing.T, a *testApp) []routeSet {
	t.Helper()
	core := append(scanRoutes(t, "."), scanRoutes(t, "../certsui")...)
	sets := []routeSet{{name: "core", handler: a.s.Handler(), mux: a.s.mux, patterns: core}}
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	box, _ := secrets.New(key)
	mods := map[string]module.Module{
		"healthchecks": healthchecks.New(a.store, log, nil, nil, "test"),
		"dns64":        dns64.New(a.store, log, dir, "test"),
		"monitor64":    monitor64.New(a.store, log, box, dir, "test"),
		"cdn64":        cdn64.New(a.store, log, nil, nil, "test"),
		"dyndns":       dyndns.New(a.store, log, box, nil, "test"),
		"honeypot":     honeypot.New(a.store, log, dir, "test"),
		"sonar64":      sonar64.New(a.store, log, box, dir, "test"),
	}
	names := make([]string, 0, len(mods))
	for n := range mods {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		mux := http.NewServeMux()
		g := a.s.guards()
		g.Enabled = func(h http.Handler) http.Handler { return h }
		mods[n].Routes(mux, g)
		sets = append(sets, routeSet{name: n, handler: a.s.recoverer(a.s.session(mux)), mux: mux, patterns: scanRoutes(t, "../"+n)})
	}
	return sets
}

// registered: Muster ist in diesem Aufbau wirklich registriert (sonst z. B. ohne Cluster/Benachrichtigungen).
func registered(mux *http.ServeMux, method, path, pattern string) bool {
	req := httptest.NewRequest(method, path, nil)
	_, pat := mux.Handler(req)
	return pat == pattern
}

func TestReadOnlyRouteMatrix(t *testing.T) {
	if _, err := os.Stat("../certsui"); err != nil {
		t.Skip("source tree not available")
	}
	a, admin, reader := roleApp(t)
	// Key 1 gehoert dem Administrator: die Selbstbedienung DELETE /api/keys/1 des Lesers trifft ihn nicht
	if _, _, err := a.store.NewAPIKey(context.Background(), admin.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	a.s.ipLimit = newIPLimiter(1e6, 1e6) // viele Anfragen von einer Adresse
	cookies, csrf := sessionOf(t, a)
	apiKey, _, err := a.store.NewAPIKey(context.Background(), reader.ID, "lesen")
	if err != nil {
		t.Fatal(err)
	}
	checked, skipped := 0, 0
	for _, set := range routeSets(t, a) {
		for _, pattern := range set.patterns {
			methods, path := routeRequests(pattern)
			if publicRoute(path) {
				continue
			}
			for _, m := range methods {
				if !registered(set.mux, m, path, pattern) {
					skipped++
					t.Logf("not registered here: %s %s", set.name, pattern)
					continue
				}
				checked++
				req := httptest.NewRequest(m, path, nil)
				want403 := (changes(m) && !readOnlyAllowed(req)) || adminGets[pattern] || adminPath(path)
				got := call(set.handler, m, path, cookies, csrf, "")
				if want403 != (got == http.StatusForbidden) {
					t.Errorf("%s %s (session, read-only): got %d, want 403=%v", set.name, pattern, got, want403)
				}
				if strings.HasPrefix(path, "/api/") {
					got := call(set.handler, m, path, nil, "", apiKey)
					if want403 != (got == http.StatusForbidden) {
						t.Errorf("%s %s (api key, read-only): got %d, want 403=%v", set.name, pattern, got, want403)
					}
				}
			}
		}
	}
	if checked < 700 {
		t.Fatalf("only %d routes checked (%d not registered in this setup)", checked, skipped)
	}
	t.Logf("%d route requests checked, %d not registered in this setup", checked, skipped)
}

// Administrator: alle GETs wie bisher (nie 403).
func TestAdminRouteMatrixGets(t *testing.T) {
	if _, err := os.Stat("../certsui"); err != nil {
		t.Skip("source tree not available")
	}
	a := fullApp(t)
	a.s.ipLimit = newIPLimiter(1e6, 1e6)
	cookies, csrf := sessionOf(t, a)
	for _, set := range routeSets(t, a) {
		for _, pattern := range set.patterns {
			methods, path := routeRequests(pattern)
			if publicRoute(path) || methods[0] != http.MethodGet || !registered(set.mux, http.MethodGet, path, pattern) {
				continue
			}
			if got := call(set.handler, http.MethodGet, path, cookies, csrf, ""); got == http.StatusForbidden {
				t.Errorf("%s %s (admin): 403", set.name, pattern)
			}
		}
	}
}

// app.js graut fuer „Nur lesen“ alle POST-Formulare aus, ausser denen, die der Server erlaubt (selfService): die
// Liste own muss jede erlaubte Formular-Route enthalten (auch Environment), Formulare an andere Nodes bleiben frei.
func TestReadOnlyFormsMatchSelfService(t *testing.T) {
	js, err := staticFS.ReadFile("static/js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`var own = /(.+)/;`).FindSubmatch(js)
	if m == nil {
		t.Fatal("own not found in app.js")
	}
	own := regexp.MustCompile(string(m[1]))
	for _, p := range []string{"/settings/user", "/settings/password", "/login/password", "/settings/2fa/enable", "/settings/2fa/disable",
		"/settings/api-keys", "/settings/api-keys/3/delete", "/settings/login/passkeys/begin", "/settings/login/passkeys/7/delete",
		"/settings/login/oidc/link", "/settings/login/identities/2/delete", "/settings/mcp/keys", "/settings/mcp/keys/4/delete",
		"/environment/open/node-b", "/environment/nodes/abc123/open"} {
		if _, pat := selfService.Handler(httptest.NewRequest(http.MethodPost, p, nil)); pat == "" {
			t.Fatalf("%s is not self service", p)
		}
		if !own.MatchString(p) {
			t.Errorf("app.js disables the allowed form %s", p)
		}
	}
	for _, p := range []string{"/settings/node", "/environment/nodes", "/environment/access", "/settings/users"} {
		if own.MatchString(p) {
			t.Errorf("app.js leaves %s enabled", p)
		}
	}
}
