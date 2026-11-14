package dns64

import (
	"context"
	"encoding/json"
	"html/template"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/ipv64net/node64/internal/dns64/filter"
	"github.com/ipv64net/node64/internal/dns64/groups"
)

// rulesMux: lokale API samt Listen-Routen (Regeln, Suche) und den Einzelfeldern Freigeben/Sperren.
func rulesMux(m *Module) *http.ServeMux {
	mux := listsMux(m)
	m.g.Actor = func(*http.Request) string { return "test" } // Einzelfelder schreiben den Namen ins Log
	m.apiRoutes(mux, m.g)
	return mux
}

// Forum 5162: AdGuard-Regeln in den Einzelfeldern und im Textfeld "Eigene Filterregeln"; die Regeln wirken sofort
// im DNS (auch eine Freigabe gegen die eigene Sperre der Elterndomain), $client wird mit Hinweis abgelehnt.
func TestAPIRules(t *testing.T) {
	m, port := testModule(t)
	port = startUp(t, m, port)
	mux := rulesMux(m)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	if w := apiDo(mux, "POST", "/api/dns64/allowlist", `{"domain":"@@||frei.example^"}`); w.Code != 200 || !strings.Contains(w.Body.String(), `"frei.example"`) {
		t.Fatalf("allow field with @@ rule: %d %s", w.Code, w.Body)
	}
	if w := apiDo(mux, "POST", "/api/dns64/denylist", `{"domain":"||werbung.example^"}`); w.Code != 200 {
		t.Fatalf("deny field with || rule: %d %s", w.Code, w.Body)
	}
	if w := apiDo(mux, "POST", "/api/dns64/allowlist", `{"domain":"@@||x.example^$client='192.168.0.100'"}`); w.Code != 400 || !strings.Contains(w.Body.String(), "dns64.rules.err_client") {
		t.Fatalf("$client: %d %s", w.Code, w.Body)
	}
	if w := apiDo(mux, "POST", "/api/dns64/denylist", `{"domain":"@@||x.example^"}`); w.Code != 400 || !strings.Contains(w.Body.String(), "dns64.rules.err_allow") {
		t.Fatalf("@@ in deny field: %d %s", w.Code, w.Body)
	}

	w := apiDo(mux, "PUT", "/api/dns64/rules", `{"rules":["# Werbung","||tracker.example^","@@||ok.tracker.example^","@@||kind.example^$client=192.168.0.100","kaputt!"]}`)
	var res filter.RulesResult
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if w.Code != 200 || res.Deny != 1 || res.Allow != 1 || res.Client != 1 || len(res.Invalid) != 2 || res.Removed != 2 {
		t.Fatalf("replace rules: %d %s", w.Code, w.Body)
	}
	w = apiDo(mux, "GET", "/api/dns64/rules", "")
	if !strings.Contains(w.Body.String(), `"||tracker.example^\n@@||ok.tracker.example^"`) {
		t.Fatalf("get rules: %s", w.Body)
	}
	if w := apiDo(mux, "PUT", "/api/dns64/rules", `{"rules":["kaputt!"]}`); w.Code != 422 {
		t.Fatalf("only invalid: %d %s", w.Code, w.Body)
	}

	r, err := query(addr, "ads.tracker.example")
	if err != nil || len(r.Answer) != 1 || !r.Answer[0].(*dns.A).A.IsUnspecified() {
		t.Fatalf("rule ||tracker.example^ does not block: %v %v", r, err)
	}
	if blocked, _ := m.running().lists.Check("cdn.ok.tracker.example"); blocked {
		t.Fatal("@@||ok.tracker.example^ does not beat the parent block")
	}
}

// Issue #122: Suche "In welcher Liste steht diese Domain?" - eigene Sperre, eigene Freigabe, Dienste, Gruppenregeln;
// ungueltige Eingabe 400.
func TestAPILookup(t *testing.T) {
	m, port := testModule(t)
	startUp(t, m, port)
	mux := rulesMux(m)
	ctx := context.Background()
	e := m.running()
	if _, err := e.lists.Deny.Add("tiktok.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.lists.Allow.Add("ok.example"); err != nil {
		t.Fatal(err)
	}
	g, err := m.AddGroup(ctx, "Kinder")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []groups.Domain{{GroupID: g.ID, Domain: "spiele.example", Action: groups.ActionBlock}, {GroupID: g.ID, Domain: "schule.example", Action: groups.ActionAllow}} {
		if _, err := m.AddGroupDomain(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	w := apiDo(mux, "GET", "/api/dns64/lookup?domain="+"||www.tiktok.com^", "")
	var out filter.Lookup
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != 200 || out.Domain != "www.tiktok.com" || !out.Blocked || out.Reason != "own:tiktok.com" || out.Own != "tiktok.com" || len(out.Services) != 1 || out.Services[0] != "TikTok" {
		t.Fatalf("lookup tiktok: %d %s", w.Code, w.Body)
	}
	w = apiDo(mux, "GET", "/api/dns64/lookup?domain=a.spiele.example", "")
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.Blocked || len(out.Groups) != 1 || out.Groups[0].Group != "Kinder" || out.Groups[0].Kind != "block" || out.Groups[0].Entry != "spiele.example" {
		t.Fatalf("lookup group: %s", w.Body)
	}
	w = apiDo(mux, "GET", "/api/dns64/lookup?domain=ok.example", "")
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.Allowed != "ok.example" || out.Blocked {
		t.Fatalf("lookup allowed: %s", w.Body)
	}
	if w := apiDo(mux, "GET", "/api/dns64/lookup?domain=kaputt!", ""); w.Code != 400 {
		t.Fatalf("invalid: %d", w.Code)
	}
}

// Seite Blocklisten: Textfeld "Eigene Filterregeln" mit den Regeln und die Suche "Domain pruefen" (nur mit Dienst).
func TestListsPageRulesRender(t *testing.T) {
	tpl, err := template.New("lists").ParseFS(templateFS, "templates/pages/lists.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, running := range []bool{true, false} {
		var sb strings.Builder
		v := listsView{tview{CSRF: "c", Data: pageData{Running: running, Rules: "||ads.example^\n@@||ok.example^"}}}
		if err := tpl.ExecuteTemplate(&sb, "content", v); err != nil {
			t.Fatal(err)
		}
		out := sb.String()
		if !strings.Contains(out, `action="/dns64/rules/save"`) || !strings.Contains(out, "||ads.example^\n@@||ok.example^</textarea>") || !strings.Contains(out, `id="domain-pruefen"`) {
			t.Fatalf("running=%v:\n%s", running, out)
		}
		if strings.Contains(out, `id="lookup-form"`) != running {
			t.Fatalf("running=%v: lookup form", running)
		}
	}
}

// listsView: wie tview, dazu Version fuer den Skript-Block.
type listsView struct{ tview }

func (listsView) Version() string { return "test" }
