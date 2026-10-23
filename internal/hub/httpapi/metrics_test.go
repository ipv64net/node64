package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/hub/store"
)

// Eigener Port fuer Prometheus: nur fuer die eingetragenen Absender, mit Laufzeit-Werten.
func TestServeMetrics(t *testing.T) {
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := New("127.0.0.1:0", lg, store.NewMetrics(), func() map[string]any { return map[string]any{"connections": 7} })
	get := func(allow []netip.Prefix) (int, string) {
		ms, err := s.ServeMetrics("127.0.0.1:0", allow)
		if err != nil {
			t.Fatal(err)
		}
		defer ms.Shutdown(time.Second)
		resp, err := http.Get("http://" + ms.Addr() + "/metrics")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	code, body := get([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	for _, want := range []string{"hub_measurements_total 0", "hub_goroutines ", "hub_gateway_connections 7", "hub_db_ok 1"} {
		if code != 200 || !strings.Contains(body, want) {
			t.Fatalf("metrics ohne %q: %d %s", want, code, body)
		}
	}
	if code, _ = get([]netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")}); code != http.StatusForbidden {
		t.Fatalf("fremder absender: %d", code)
	}
}
