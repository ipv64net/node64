package monitor64

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/module"
)

// Die lokale API von Monitor64 steht in der OpenAPI-Beschreibung des Kerns (Tag "Monitor64", Pfade ohne /api).
// Der Test gleicht die registrierten Routen mit den beschriebenen ab: jede Route beschrieben, nichts beschrieben,
// was es nicht gibt.

const openAPIPath = "../web/static/openapi.json"

// reAPIRoute findet die Muster der JSON-API in den Quelltexten (mux.Handle("GET /api/monitor64/...", ...)).
var reAPIRoute = regexp.MustCompile(`"((?:GET|POST|PUT|DELETE|PATCH) /api/monitor64(?:/[^"]*)?)"`)

// sourceRoutes liest alle Muster "/api/monitor64/..." aus den Quelltexten des Pakets (ohne Tests).
func sourceRoutes(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range reAPIRoute.FindAllStringSubmatch(string(b), -1) {
			out[m[1]] = true
		}
	}
	return out
}

// routeMux registriert die Routen wie im Betrieb (Guards ohne Wirkung).
func routeMux() *http.ServeMux {
	pass := func(h http.Handler) http.Handler { return h }
	mux := http.NewServeMux()
	(&Module{}).uiRoutes(mux, module.Guards{Enabled: pass, Auth: pass})
	return mux
}

var rePathVar = regexp.MustCompile(`\{([A-Za-z0-9_]+)\}`)

// muxPattern liefert das Muster, das der Mux fuer Methode und Pfad (Platzhalter mit Beispielwert) waehlt.
func muxPattern(mux *http.ServeMux, method, path string) string {
	req := httptest.NewRequest(method, rePathVar.ReplaceAllString(path, "abcdefgh12"), nil)
	_, pat := mux.Handler(req)
	return pat
}

type openAPIDoc struct {
	Tags       []map[string]any                      `json:"tags"`
	RawPaths   map[string]map[string]json.RawMessage `json:"paths"`
	Components struct {
		Schemas map[string]json.RawMessage `json:"schemas"`
	} `json:"components"`
}

// loadOpenAPI liest openapi.json (ungueltiges JSON laesst den Test scheitern).
func loadOpenAPI(t *testing.T) openAPIDoc {
	t.Helper()
	b, err := os.ReadFile(openAPIPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc openAPIDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("openapi.json ist kein gueltiges JSON: %v", err)
	}
	return doc
}

var httpMethods = map[string]bool{"get": true, "put": true, "post": true, "delete": true, "patch": true}

func TestOpenAPIMonitor64Routes(t *testing.T) {
	doc := loadOpenAPI(t)
	mux := routeMux()

	registered := sourceRoutes(t)
	if len(registered) < 60 {
		t.Fatalf("nur %d Routen in den Quelltexten gefunden - Muster passt nicht mehr?", len(registered))
	}
	// Gegenprobe mit dem Mux: jedes gefundene Muster ist genau so registriert
	for r := range registered {
		method, path, _ := strings.Cut(r, " ")
		if got := muxPattern(mux, method, path); got != r {
			t.Errorf("Route %q: der Mux waehlt %q", r, got)
		}
	}

	documented := map[string]bool{}
	for path, item := range doc.RawPaths {
		if path != "/monitor64" && !strings.HasPrefix(path, "/monitor64/") {
			continue
		}
		var pathParams []map[string]any
		if raw, ok := item["parameters"]; ok {
			_ = json.Unmarshal(raw, &pathParams)
		}
		for method, raw := range item {
			if !httpMethods[method] {
				continue
			}
			route := strings.ToUpper(method) + " /api" + path
			documented[route] = true
			var op struct {
				Tags       []string         `json:"tags"`
				Summary    string           `json:"summary"`
				Parameters []map[string]any `json:"parameters"`
				Responses  map[string]any   `json:"responses"`
			}
			if err := json.Unmarshal(raw, &op); err != nil {
				t.Errorf("%s: %v", route, err)
				continue
			}
			if len(op.Tags) == 0 || op.Tags[0] != "Monitor64" {
				t.Errorf("%s: Tag Monitor64 fehlt", route)
			}
			if op.Summary == "" || len(op.Responses) == 0 {
				t.Errorf("%s: summary bzw. responses fehlen", route)
			}
			// jeder Platzhalter im Pfad ist als Pfad-Parameter beschrieben
			for _, m := range rePathVar.FindAllStringSubmatch(path, -1) {
				found := false
				for _, p := range append(pathParams, op.Parameters...) {
					if p["in"] == "path" && p["name"] == m[1] {
						found = true
					}
				}
				if !found {
					t.Errorf("%s: Pfad-Parameter %q nicht beschrieben", route, m[1])
				}
			}
			if !registered[route] && muxPattern(mux, strings.ToUpper(method), "/api"+path) != route {
				t.Errorf("%s steht in openapi.json, ist aber nicht registriert", route)
			}
		}
	}

	var missing []string
	for r := range registered {
		if !documented[r] {
			missing = append(missing, r)
		}
	}
	sort.Strings(missing)
	for _, r := range missing {
		t.Errorf("Route %s fehlt in openapi.json (Tag Monitor64, Pfad ohne /api)", r)
	}

	hasTag := false
	for _, tg := range doc.Tags {
		if tg["name"] == "Monitor64" {
			hasTag = true
		}
	}
	if !hasTag {
		t.Error("Tag Monitor64 fehlt in openapi.json")
	}
}

// TestOpenAPIMonitor64Refs: alle Verweise der Monitor64-Pfade und -Schemas zeigen auf vorhandene Schemas.
func TestOpenAPIMonitor64Refs(t *testing.T) {
	doc := loadOpenAPI(t)
	reRef := regexp.MustCompile(`"\$ref":\s*"#/components/schemas/([^"]+)"`)
	check := func(where string, raw []byte) {
		for _, m := range reRef.FindAllSubmatch(raw, -1) {
			if _, ok := doc.Components.Schemas[string(m[1])]; !ok {
				t.Errorf("%s: Verweis auf unbekanntes Schema %q", where, m[1])
			}
		}
	}
	n := 0
	for path, item := range doc.RawPaths {
		if !strings.HasPrefix(path, "/monitor64/") {
			continue
		}
		for method, raw := range item {
			check(strings.ToUpper(method)+" "+path, raw)
		}
	}
	for name, raw := range doc.Components.Schemas {
		if strings.HasPrefix(name, "Monitor64") {
			n++
			check("Schema "+name, raw)
		}
	}
	if n == 0 {
		t.Error("keine Monitor64-Schemas in openapi.json")
	}
}
