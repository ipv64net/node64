package dns64

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/metrics"
)

func TestMetrics(t *testing.T) {
	m, port := testModule(t)
	out := func() string {
		w := metrics.New()
		m.Metrics(context.Background(), w)
		var sb strings.Builder
		_, _ = w.WriteTo(&sb)
		return sb.String()
	}
	if s := out(); !strings.Contains(s, "node64_dns64_up 0") || strings.Contains(s, "queries_total") {
		t.Fatalf("stopped:\n%s", s)
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for i := 0; i < 2; i++ {
		if _, err := query(addr, "nas"); err != nil {
			t.Fatal(err)
		}
	}
	s := out()
	for _, want := range []string{
		"node64_dns64_up 1",
		`node64_dns64_queries_total{status="local",proto="udp"} 2`,
		"node64_dns64_query_duration_seconds_count 2",
		"node64_dns64_blocking_paused 0",
		"# TYPE node64_dns64_cache_hits_total counter",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
}
