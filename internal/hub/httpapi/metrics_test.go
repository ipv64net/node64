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

// Werte je Check-Typ: Anzahl, Laeufe nach Ergebnis, Dauer, Ping-Pakete.
func TestDetailMetrics(t *testing.T) {
	m := store.NewMetrics()
	m.SetTypes(map[string]int{"icmp": 2, "http": 1})
	m.ObserveRun("icmp", true, 2*time.Second, 6, 0)
	m.ObserveRun("icmp", false, time.Second, 3, 2)
	m.ObserveRun("http", true, 500*time.Millisecond, 0, 0)
	s := New("127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)), m, nil)
	var sb strings.Builder
	s.detailMetrics(&sb)
	body := sb.String()
	for _, want := range []string{`hub_checks_by_type{type="icmp"} 2`, `hub_checks_by_type{type="http"} 1`,
		`hub_check_runs_total{type="icmp",result="ok"} 1`, `hub_check_runs_total{type="icmp",result="fail"} 1`,
		`hub_check_duration_seconds_sum{type="icmp"} 3`, `hub_check_duration_seconds_count{type="icmp"} 2`,
		`hub_ping_packets_sent_total 9`, `hub_ping_packets_lost_total 2`, "hub_cleanup_last_success_timestamp_seconds 0"} {
		if !strings.Contains(body, want) {
			t.Fatalf("ohne %q:\n%s", want, body)
		}
	}
}
