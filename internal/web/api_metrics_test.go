package web

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/metrics"
)

type metricsModule struct{ pingModule }

func (metricsModule) Metrics(_ context.Context, w *metrics.Writer) {
	w.Gauge("node64_ping_answers", "Test", 42)
}

func TestAPIMetrics(t *testing.T) {
	a := newTestAppWith(t, metricsModule{})
	ctx := context.Background()
	_ = a.store.SetModuleEnabled(ctx, "ping", true)
	a.registry.StartEnabled(ctx)
	hash, _ := HashPassword("sehr geheimes passwort")
	u, _ := a.store.CreateUser(ctx, "admin", hash, "de", "UTC")
	key, _, err := a.store.NewAPIKey(ctx, u.ID, "prometheus")
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := a.get(t, "/api/metrics")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no auth: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest("GET", a.srv.URL+"/api/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err = a.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	body := string(b)
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain; version=0.0.4") {
		t.Fatalf("status %d, type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	for _, want := range []string{
		"# TYPE node64_info gauge\nnode64_info{version=",
		`node64_module_running{module="ping"} 1`,
		`node64_module_enabled{module="ping"} 1`,
		"node64_database_bytes ",
		"node64_ping_answers 42",
		"node64_scrape_duration_seconds ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in\n%s", want, body)
		}
	}
	// gestoppte Module liefern nichts
	_ = a.registry.Disable(ctx, "ping")
	resp, _ = a.client.Do(req)
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(b), "node64_ping_answers") || !strings.Contains(string(b), `node64_module_running{module="ping"} 0`) {
		t.Fatalf("disabled module:\n%s", b)
	}
}
