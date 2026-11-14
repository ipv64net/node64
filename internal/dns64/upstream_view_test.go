package dns64

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/dns64/upstream"
	"github.com/ipv64net/node64/internal/module"
)

// Forum 5151: ein eigener klassischer Upstream (z. B. lokaler Unbound, 192.168.1.5:5335) hat keine Bootstrap-IPs.
// Die Uebersicht zeigt ihn trotzdem: "ips" ist in der API eine leere Liste, nie null (dns64.js ruft ips.join auf).
func TestUpstreamsPlainHasIPList(t *testing.T) {
	m, port := testModule(t)
	ctx := context.Background()
	c := m.loadConfig(ctx)
	s := upstream.Server{Name: "Unbound", URL: "127.0.0.1:5335"}
	if err := checkUpstream(&s); err != nil {
		t.Fatal(err)
	}
	if err := c.addUpstream(s); err != nil {
		t.Fatal(err)
	}
	if err := m.saveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	startUp(t, m, port)
	defer m.Stop(ctx)

	pass := func(h http.Handler) http.Handler { return h }
	mux := http.NewServeMux()
	m.apiRoutes(mux, module.Guards{Enabled: pass, Auth: pass, T: func(_ *http.Request, key string, _ ...any) string { return key }})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/dns64/upstreams", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var out struct {
		Servers []map[string]json.RawMessage `json:"servers"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, srv := range out.Servers {
		if strings.Contains(string(srv["url"]), "dns://127.0.0.1:5335") {
			found = true
			if string(srv["ips"]) == "null" {
				t.Fatalf("plain upstream: ips = null (Uebersicht bricht ab): %s", w.Body)
			}
		}
	}
	if !found {
		t.Fatalf("plain upstream missing: %s", w.Body)
	}
}
