package healthchecks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/metrics"
)

func TestMetrics(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("fine")) }))
	defer target.Close()
	m, srv := newTestModule(t)
	code, b := call(t, srv, "POST", "/api/checks", map[string]any{"name": "Shop \"Web\"", "type": "http", "target": target.URL, "interval_seconds": 20, "group": "Kunden"})
	if code != 201 {
		t.Fatalf("create: %d %s", code, b)
	}
	var c checkJSON
	_ = json.Unmarshal(b, &c)
	_, _ = call(t, srv, "POST", "/api/checks", map[string]any{"name": "Pausiert", "type": "http", "target": target.URL, "interval_seconds": 20, "paused": true})

	var out string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		w := metrics.New()
		m.Metrics(context.Background(), w)
		var sb strings.Builder
		_, _ = w.WriteTo(&sb)
		if out = sb.String(); strings.Contains(out, "node64_hc_check_up{") {
			break
		}
	}
	l := `token="` + c.Token + `",check="Shop \"Web\"",type="http",group="Kunden"`
	for _, want := range []string{
		"node64_hc_check_state{" + l + `,state="up"} 1`,
		"node64_hc_check_up{" + l + "} 1",
		"node64_hc_check_latency_seconds{" + l + "} ",
		"node64_hc_check_interval_seconds{" + l + "} 20",
		`node64_hc_checks{state="up"} 1`,
		`node64_hc_checks{state="paused"} 1`,
		"node64_hc_incidents_open 0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Count(out, "node64_hc_check_up{") != 1 { // pausierte Checks haben kein _up
		t.Errorf("paused check has _up:\n%s", out)
	}
}
