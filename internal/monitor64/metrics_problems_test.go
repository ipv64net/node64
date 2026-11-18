package monitor64

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/metrics"
)

// Offene Probleme als Metrik: nur die, die diese Node fuehrt (im Cluster sonst doppelt), ohne geschlossene und geloeschte.
func TestMetricsProblemCounts(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	self := e.m.nodeID()
	for i, p := range []struct{ uid, node, closed, ack string }{
		{"p1", self, "", ""},
		{"p2", self, "", "dennis"},
		{"p3", self, tsNow(), ""},
		{"p4", "andere-node", "", ""},
	} {
		if _, err := e.m.st.Writer().Exec(`INSERT INTO m64_problems (uid, node_id, host_uid, service_key, state, worst, opened_at, closed_at, ack, updated_at) VALUES (?, ?, 'h1', ?, 'warn', 'warn', ?, ?, ?, ?)`,
			p.uid, p.node, fmt.Sprintf("svc%d", i), tsNow(), p.closed, p.ack, tsNow()); err != nil {
			t.Fatal(err)
		}
	}
	w := metrics.New()
	e.m.Metrics(ctx, w)
	var b bytes.Buffer
	_, _ = w.WriteTo(&b)
	for _, want := range []string{"node64_monitor_problems_open 2\n", "node64_monitor_problems_unacked 1\n"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in\n%s", want, b.String())
		}
	}
}
