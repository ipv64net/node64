package dns64

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/dns64/filter"
	"github.com/ipv64net/node64/internal/dns64/groups"
	"github.com/ipv64net/node64/internal/module"
)

// Alle Routen des Moduls lassen sich zusammen eintragen (net/http meldet sich ueberschneidende Muster mit panic).
func TestRoutesRegister(t *testing.T) {
	m, _ := testModule(t)
	pass := func(h http.Handler) http.Handler { return h }
	m.Routes(http.NewServeMux(), module.Guards{Enabled: pass, Auth: pass, T: func(_ *http.Request, key string, _ ...any) string { return key }})
}

// listsMux: wie apiMux, dazu die Routen fuer Listen, Sperrliste, Dienste und Mitglieder.
func listsMux(m *Module) *http.ServeMux {
	mux := apiMux(m)
	m.apiMoreRoutes(mux, m.g)
	return mux
}

// Mehrere Listen auf einmal: Name davor, Doppelte (auch im Text), ungueltige Zeilen und Kommentare.
func TestAddListsBulk(t *testing.T) {
	m, _ := testModule(t)
	c := m.loadConfig(context.Background())
	n := len(c.Lists)
	res := c.addListsBulk([]string{
		"# meine Listen", "",
		"https://lists.example/hosts/ads.txt",
		"Meine Liste | https://b.example/block.txt",
		"https://lists.example/hosts/ads.txt",
		"ftp://kaputt.example/x",
		c.Lists[0].URL,
	}, false)
	if len(res.Added) != 2 || len(res.Duplicates) != 2 || len(res.Invalid) != 1 || res.Invalid[0] != "ftp://kaputt.example/x" {
		t.Fatalf("bulk: %+v", res)
	}
	if len(c.Lists) != n+2 || c.Lists[n].Name != "lists.example · ads.txt" || c.Lists[n+1].Name != "Meine Liste" || !c.Lists[n].Enabled {
		t.Fatalf("lists: %+v", c.Lists[n:])
	}

	res = c.addListsBulk([]string{"https://allow.example/ok.txt", "Fehlalarme https://allow.example/fp.txt"}, true)
	if len(res.Added) != 2 || len(c.AllowLst) != 2 || c.AllowLst[1].Name != "Fehlalarme" || len(c.Lists) != n+2 {
		t.Fatalf("allow bulk: %+v %+v", res, c.AllowLst)
	}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
}

// Freigabe-Listen ueber die API: anlegen (einzeln und mehrere), Stand abrufen, abschalten per Einstellungen,
// entfernen; die Einstellungen ueberstehen das Neuladen.
func TestAPIAllowLists(t *testing.T) {
	m, _ := testModule(t)
	mux := listsMux(m)
	if w := apiDo(mux, "POST", "/api/dns64/allowlists", `{"url":"https://allow.example/ok.txt"}`); w.Code != 201 || !strings.Contains(w.Body.String(), `"allow_lists":[{`) {
		t.Fatalf("add: %d %s", w.Code, w.Body)
	}
	if w := apiDo(mux, "POST", "/api/dns64/allowlists", `{"url":"https://allow.example/ok.txt"}`); w.Code != 400 {
		t.Fatalf("dup: %d %s", w.Code, w.Body)
	}
	if w := apiDo(mux, "POST", "/api/dns64/allowlists", `{"urls":["https://allow.example/ok.txt","kaputt"]}`); w.Code != 422 {
		t.Fatalf("bulk none: %d %s", w.Code, w.Body)
	}
	w := apiDo(mux, "POST", "/api/dns64/allowlists", `{"urls":["FP | https://allow.example/fp.txt","https://allow.example/ok.txt"]}`)
	var bulk BulkResult
	_ = json.Unmarshal(w.Body.Bytes(), &bulk)
	if w.Code != 201 || len(bulk.Added) != 1 || len(bulk.Duplicates) != 1 {
		t.Fatalf("bulk: %d %s", w.Code, w.Body)
	}
	w = apiDo(mux, "GET", "/api/dns64/allowlists", "")
	var rows []struct {
		Name    string `json:"name"`
		URL     string `json:"url"`
		Enabled bool   `json:"enabled"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &rows)
	if w.Code != 200 || len(rows) != 2 || rows[1].Name != "FP" || !rows[1].Enabled {
		t.Fatalf("get: %d %s", w.Code, w.Body)
	}
	ctx := context.Background()
	c := m.loadConfig(ctx)
	c.AllowLst[0].Enabled = false
	if err := m.saveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	if a := m.loadConfig(ctx).activeAllowLists(); len(a) != 1 || a[0].URL != "https://allow.example/fp.txt" {
		t.Fatalf("active: %+v", a)
	}
	if w := apiDo(mux, "DELETE", "/api/dns64/allowlists?url=https://allow.example/ok.txt", ""); w.Code != 200 {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	if w := apiDo(mux, "DELETE", "/api/dns64/allowlists?url=https://allow.example/ok.txt", ""); w.Code != 404 {
		t.Fatalf("delete again: %d", w.Code)
	}
	if l := m.loadConfig(ctx).AllowLst; len(l) != 1 {
		t.Fatalf("after delete: %+v", l)
	}

	// Blocklisten nehmen ebenfalls mehrere URLs
	if w := apiDo(mux, "POST", "/api/dns64/lists", `{"urls":["https://block.example/a.txt","https://block.example/b.txt"]}`); w.Code != 201 || !strings.Contains(w.Body.String(), `"added":["https://block.example/a.txt","https://block.example/b.txt"]`) {
		t.Fatalf("lists bulk: %d %s", w.Code, w.Body)
	}
}

// Eigene Sperrliste als Text ersetzen; nur ungueltige Zeilen lassen sie stehen.
func TestAPIDenyReplace(t *testing.T) {
	m, _ := testModule(t)
	mux := listsMux(m)
	w := apiDo(mux, "PUT", "/api/dns64/denylist", `{"domains":["# Werbung","ads.example","*.tracker.example","ads.example","nicht gueltig!"]}`)
	var res filter.ReplaceResult
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if w.Code != 200 || res.Total != 2 || res.Duplicates != 1 || len(res.Invalid) != 1 {
		t.Fatalf("replace: %d %s", w.Code, w.Body)
	}
	if w := apiDo(mux, "PUT", "/api/dns64/denylist", `{"domains":["kaputt"]}`); w.Code != 422 {
		t.Fatalf("all invalid: %d %s", w.Code, w.Body)
	}
	if w := apiDo(mux, "PUT", "/api/dns64/denylist", `{}`); w.Code != 400 {
		t.Fatalf("missing domains: %d", w.Code)
	}
	dl, _ := m.denylist()
	if dl.Text() != "ads.example\ntracker.example" {
		t.Fatalf("text: %q", dl.Text())
	}
}

// Dienste: Liste fuer die API, Sperre je Gruppe ueber die Kategorien (unbekannte fallen weg).
func TestAPIServicesRules(t *testing.T) {
	m, _ := testModule(t)
	mux := listsMux(m)
	w := apiDo(mux, "GET", "/api/dns64/services", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"key":"svc:tiktok"`) || !strings.Contains(w.Body.String(), `"groups":["ai",`) {
		t.Fatalf("services: %d %.200s", w.Code, w.Body)
	}
	ctx := context.Background()
	g, err := m.AddGroup(ctx, "Kinder")
	if err != nil {
		t.Fatal(err)
	}
	body := `{"lists_mode":"global","categories":["svc:tiktok","svc:gibtsnicht","games","svc:discord"]}`
	if w := apiDo(mux, "PUT", "/api/dns64/groups/"+strconv.FormatInt(g.ID, 10)+"/rules", body); w.Code >= 300 {
		t.Fatalf("rules: %d %s", w.Code, w.Body)
	}
	gl, _ := m.Groups(ctx)
	if got := strings.Join(gl[0].Cats, ","); got != "games,svc:tiktok,svc:discord" {
		t.Fatalf("cats: %s", got)
	}
	if got := strings.Join(gl[0].ServiceNames(), ","); got != "TikTok,Discord" || strings.Join(gl[0].CatKeys(), ",") != "games" {
		t.Fatalf("names: %s / %v", got, gl[0].CatKeys())
	}
}

// Tags je Geraet: beim Anlegen, Aendern ueber die API (fehlende Felder bleiben), Grenzen.
func TestAPIMemberTags(t *testing.T) {
	m, _ := testModule(t)
	mux := listsMux(m)
	ctx := context.Background()
	g, _ := m.AddGroup(ctx, "IoT")
	x, err := m.AddMember(ctx, groups.Member{GroupID: g.ID, Kind: groups.KindIP, Value: "192.168.1.60", Label: "Steckdose", Tags: groups.SplitTags("Küche, MQTT, küche")})
	if err != nil {
		t.Fatal(err)
	}
	gl, _ := m.Groups(ctx)
	if got := gl[0].Members[0].Tags; !slices.Equal(got, []string{"Küche", "MQTT"}) {
		t.Fatalf("tags after add: %v", got)
	}
	id := "/api/dns64/groups/members/" + strconv.FormatInt(x.ID, 10)
	if w := apiDo(mux, "PATCH", id, `{"tags":["Wohnzimmer"," Licht "]}`); w.Code != 200 || !strings.Contains(w.Body.String(), `"tags":["Wohnzimmer","Licht"]`) {
		t.Fatalf("update tags: %d %s", w.Code, w.Body)
	}
	if w := apiDo(mux, "PATCH", id, `{"label":"Lampe"}`); w.Code != 200 {
		t.Fatalf("update label: %d %s", w.Code, w.Body)
	}
	gl, _ = m.Groups(ctx)
	if mb := gl[0].Members[0]; mb.Label != "Lampe" || !slices.Equal(mb.Tags, []string{"Wohnzimmer", "Licht"}) || mb.TagAttr() != "wohnzimmer|licht" {
		t.Fatalf("member: %+v", mb)
	}
	if w := apiDo(mux, "PATCH", id, `{"tags":["`+strings.Repeat("x", groups.MaxTagLen+1)+`"]}`); w.Code != 422 {
		t.Fatalf("long tag: %d", w.Code)
	}
	many := `{"tags":["a","b","c","d","e","f","g","h","i","j","k"]}`
	if w := apiDo(mux, "PATCH", id, many); w.Code != 422 {
		t.Fatalf("too many tags: %d", w.Code)
	}
	if w := apiDo(mux, "PATCH", "/api/dns64/groups/members/9999", `{"label":"x"}`); w.Code != 404 {
		t.Fatalf("unknown: %d", w.Code)
	}
	if w := apiDo(mux, "PATCH", id, `{"tags":[]}`); w.Code != 200 || !strings.Contains(w.Body.String(), `"tags":[]`) {
		t.Fatalf("clear tags: %d %s", w.Code, w.Body)
	}
}

// Cluster: Tags und Dienste kommen beim Partner an; ohne Tags bleibt das Mitglied-JSON wie bisher.
func TestClusterTagsServices(t *testing.T) {
	a, _ := testModule(t)
	b, _ := testModule(t)
	ctx := context.Background()
	var la clLog
	a.SetCluster(la.hook)
	g, _ := a.AddGroup(ctx, "Kinder")
	if err := a.SetGroupRules(ctx, g.ID, groups.Rules{ListsMode: groups.ListsGlobal, Cats: []string{"svc:tiktok", "social"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddMember(ctx, groups.Member{GroupID: g.ID, Kind: groups.KindIP, Value: "192.168.1.70", Label: "Tablet", Tags: []string{"Kind 1"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddMember(ctx, groups.Member{GroupID: g.ID, Kind: groups.KindIP, Value: "192.168.1.71"}); err != nil {
		t.Fatal(err)
	}
	c := a.loadConfig(ctx)
	if err := c.addAllowList("", "https://allow.example/ok.txt"); err != nil {
		t.Fatal(err)
	}
	if err := a.saveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	cur, err := a.clCurrent(ctx, ItemMembers)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range cur {
		if strings.Count(v, `"tags"`) != 1 {
			t.Fatalf("members json: %s", v)
		}
	}
	clSync(t, a, b, la.take())
	gl, _ := b.Groups(ctx)
	if len(gl) != 1 || strings.Join(gl[0].Cats, ",") != "social,svc:tiktok" || len(gl[0].Members) != 2 {
		t.Fatalf("group on b: %+v", gl)
	}
	for _, x := range gl[0].Members {
		if x.Value == "192.168.1.70" && !slices.Equal(x.Tags, []string{"Kind 1"}) {
			t.Fatalf("tags on b: %+v", x)
		}
	}
	if l := b.loadConfig(ctx).AllowLst; len(l) != 1 || l[0].URL != "https://allow.example/ok.txt" {
		t.Fatalf("allow lists on b: %+v", l)
	}
}
