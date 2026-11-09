package apis

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/proxmox"
)

// Testgeheimnis: darf in keinem Fehlertext auftauchen.
const testSecret = "8f2b7c1e-5a4d-4e3b-9c2a-1d0e6f7a8b9c"

// fakeAPI ist ein Proxmox-API-Server mit aufgezeichneten Antworten (data-Teil; der Server haengt {"data":…} an).
type fakeAPI struct {
	t      *testing.T
	mu     sync.Mutex
	routes map[string]fakeResp
	hits   map[string]int
	auth   int // Anfragen mit Authorization-Kopf
}

type fakeResp struct {
	status int
	body   string
}

func newFakeAPI(t *testing.T) *fakeAPI {
	return &fakeAPI{t: t, routes: map[string]fakeResp{}, hits: map[string]int{}}
}

// set legt eine Antwort fest (body: Datei aus testdata, wenn er mit "@" beginnt, sonst JSON bzw. Fehlertext).
func (f *fakeAPI) set(path string, status int, body string) {
	f.t.Helper()
	if strings.HasPrefix(body, "@") {
		body = fixture(f.t, body[1:])
	}
	f.mu.Lock()
	f.routes[path] = fakeResp{status: status, body: body}
	f.mu.Unlock()
}

func (f *fakeAPI) ok(path, body string) { f.set(path, http.StatusOK, body) }

func (f *fakeAPI) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/api2/json")
	if r.URL.RawQuery != "" {
		q, _ := url.QueryUnescape(r.URL.RawQuery)
		p += "?" + q
	}
	f.mu.Lock()
	f.hits[p]++
	if r.Header.Get("Authorization") != "" {
		f.auth++
	}
	resp, ok := f.routes[p]
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"data":null,"message":"Path '/api2/json` + p + `' not found."}`))
		return
	}
	if resp.status != http.StatusOK {
		w.WriteHeader(resp.status)
		b, _ := json.Marshal(map[string]any{"data": nil, "message": resp.body})
		_, _ = w.Write(b)
		return
	}
	_, _ = w.Write([]byte(`{"data":` + resp.body + `}`))
}

// tlsServer startet den Server mit TLS und liefert Adresse und Pin.
func tlsServer(t *testing.T, h http.Handler) (string, string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // Zertifikat-Abruf im Test bricht den Handshake ab
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL, proxmox.CertFingerprint(srv.Certificate().Raw)
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func svcByKey(t *testing.T, l []model.Service, key string) model.Service {
	t.Helper()
	for _, s := range l {
		if s.Key == key {
			return s
		}
	}
	keys := make([]string, 0, len(l))
	for _, s := range l {
		keys = append(keys, s.Key)
	}
	t.Fatalf("Dienst %q fehlt (vorhanden: %s)", key, strings.Join(keys, ", "))
	return model.Service{}
}

func hasSvc(l []model.Service, key string) bool {
	for _, s := range l {
		if s.Key == key {
			return true
		}
	}
	return false
}

func metric(s model.Service, name string) (model.Metric, bool) {
	for _, m := range s.Metrics {
		if m.Name == name {
			return m, true
		}
	}
	return model.Metric{}, false
}

func mustMetric(t *testing.T, s model.Service, name string) model.Metric {
	t.Helper()
	m, ok := metric(s, name)
	if !ok {
		t.Fatalf("%s: Messgroesse %q fehlt (%+v)", s.Key, name, s.Metrics)
	}
	return m
}

func hasFact(s model.Service, code string) bool {
	for _, f := range s.Facts {
		if f.Code == code {
			return true
		}
	}
	return false
}

func near(a, b float64) bool {
	d := a - b
	return d < 0.01 && d > -0.01
}
