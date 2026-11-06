package dns64

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/dns64/groups"
	"github.com/ipv64net/node64/internal/module"
)

func apiMux(m *Module) *http.ServeMux {
	pass := func(h http.Handler) http.Handler { return h }
	g := module.Guards{Enabled: pass, Auth: pass, T: func(_ *http.Request, key string, _ ...any) string { return key }}
	m.g = g
	mux := http.NewServeMux()
	m.zoneRoutes(mux, g)
	m.groupRoutes(mux, g)
	return mux
}

func apiDo(mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

// Zone ueber die API: dynamische Updates einschalten (erzeugt Schluessel), Schluessel abrufen und erneuern; in
// der Liste steht das Secret nie. Ohne Feld dynamic bleibt der Schalter.
func TestAPIZoneDynamic(t *testing.T) {
	m, _ := testModule(t)
	mux := apiMux(m)
	w := apiDo(mux, "POST", "/api/dns64/zones", `{"name":"home.lan"}`)
	if w.Code != 201 || !strings.Contains(w.Body.String(), `"dynamic":false`) {
		t.Fatalf("add: %d %s", w.Code, w.Body)
	}
	var z Zone
	_ = json.Unmarshal(w.Body.Bytes(), &z)
	id := "/api/dns64/zones/" + strconv.FormatInt(z.ID, 10)
	if w := apiDo(mux, "PUT", id, `{"name":"home.lan","dynamic":true}`); w.Code != 200 || !strings.Contains(w.Body.String(), `"dynamic":true`) || !strings.Contains(w.Body.String(), `"tsig_name":"node64-home.lan"`) {
		t.Fatalf("on: %d %s", w.Code, w.Body)
	}
	w = apiDo(mux, "GET", id+"/tsig", "")
	var k struct {
		Name    string `json:"tsig_name"`
		Secret  string `json:"tsig_secret"`
		Dynamic bool   `json:"dynamic"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &k)
	if w.Code != 200 || k.Name != "node64-home.lan" || len(k.Secret) < 40 || !k.Dynamic {
		t.Fatalf("get tsig: %d %s", w.Code, w.Body)
	}
	if w := apiDo(mux, "GET", "/api/dns64/zones", ""); strings.Contains(w.Body.String(), k.Secret) || strings.Contains(w.Body.String(), "tsig_secret") {
		t.Fatalf("secret in list: %s", w.Body)
	}
	// ohne Feld: Schalter und Schluessel bleiben
	if w := apiDo(mux, "PUT", id, `{"name":"home.lan","comment":"x"}`); w.Code != 200 || !strings.Contains(w.Body.String(), `"dynamic":true`) {
		t.Fatalf("keep: %d %s", w.Code, w.Body)
	}
	w = apiDo(mux, "POST", id+"/tsig", "")
	var k2 struct {
		Secret string `json:"tsig_secret"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &k2)
	if w.Code != 200 || k2.Secret == "" || k2.Secret == k.Secret {
		t.Fatalf("renew: %d %s", w.Code, w.Body)
	}
	if w := apiDo(mux, "PUT", id, `{"name":"home.lan","dynamic":false}`); w.Code != 200 || !strings.Contains(w.Body.String(), `"dynamic":false`) {
		t.Fatalf("off: %d %s", w.Code, w.Body)
	}
	for _, p := range []string{"GET", "POST"} {
		if w := apiDo(mux, p, "/api/dns64/zones/999/tsig", ""); w.Code != 404 {
			t.Fatalf("%s unknown zone: %d", p, w.Code)
		}
	}
}

// Geraet per MAC oder IP aus seiner Gruppe nehmen (wie "Keine Gruppe" auf der Seite).
func TestAPIUnassign(t *testing.T) {
	m, _ := testModule(t)
	mux := apiMux(m)
	ctx := context.Background()
	g, err := m.AddGroup(ctx, "Kinder")
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range []groups.Member{{GroupID: g.ID, Kind: groups.KindMAC, Value: "aa:bb:cc:dd:ee:ff"}, {GroupID: g.ID, Kind: groups.KindIP, Value: "192.168.1.20"}} {
		if _, err := m.AddMember(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	if w := apiDo(mux, "POST", "/api/dns64/groups/unassign", `{}`); w.Code != 400 {
		t.Fatalf("empty: %d", w.Code)
	}
	if w := apiDo(mux, "POST", "/api/dns64/groups/unassign", `{"mac":"AA-BB-CC-DD-EE-FF"}`); w.Code != 204 {
		t.Fatalf("mac: %d %s", w.Code, w.Body)
	}
	if w := apiDo(mux, "POST", "/api/dns64/groups/unassign", `{"ip":"192.168.1.20"}`); w.Code != 204 {
		t.Fatalf("ip: %d %s", w.Code, w.Body)
	}
	list, _ := m.Groups(ctx)
	for _, x := range list {
		if x.ID == g.ID && len(x.Members) != 0 {
			t.Fatalf("members left: %+v", x.Members)
		}
	}
}
