package cdnedge

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/metrics"
	"github.com/ipv64net/node64/internal/tunnel"
)

func TestLinkMetrics(t *testing.T) {
	s := &Server{}
	lbl := func(kv ...string) []string { return append([]string{"server", "srvT"}, kv...) }
	links := []tunnelLink{
		{Tunnel: "tn_ok", Slot: 0, Rep: tunnel.LinkReport{RTT: 20 * time.Millisecond, NodeRTT: 21 * time.Millisecond, EdgeToNode: 0, NodeToEdge: 0.001}},
		{Tunnel: "tn_bad", Slot: 1, Rep: tunnel.LinkReport{RTT: 35 * time.Millisecond, EdgeToNode: -1, NodeToEdge: 0.03}}, // Upload unbekannt
		{Tunnel: "tn_old", Slot: 0, Rep: tunnel.LinkReport{RTT: 10 * time.Millisecond, EdgeToNode: 0.02, NodeToEdge: -1}}, // aeltere Node
	}
	for i := 0; i < linkMetricsMax+5; i++ { // mehr als die Grenze: nur die mit Verlust sicher dabei
		links = append(links, tunnelLink{Tunnel: "tn_" + strconv.Itoa(1000+i), Rep: tunnel.LinkReport{RTT: time.Millisecond, EdgeToNode: -1, NodeToEdge: -1}})
	}
	w := metrics.New()
	s.linkMetrics(w, lbl, links)
	var b strings.Builder
	_, _ = w.WriteTo(&b)
	out := b.String()
	for _, want := range []string{
		`cdn64_edge_tunnel_lossy_connections{server="srvT",direction="node_to_edge"} 1`,
		`cdn64_edge_tunnel_lossy_connections{server="srvT",direction="edge_to_node"} 1`,
		`cdn64_edge_tunnel_loss_ratio{server="srvT",tunnel="tn_bad",slot="1",account_id="0",direction="node_to_edge"} 0.03`,
		`cdn64_edge_tunnel_loss_ratio{server="srvT",tunnel="tn_old",slot="0",account_id="0",direction="edge_to_node"} 0.02`,
		`cdn64_edge_tunnel_loss_ratio{server="srvT",tunnel="tn_ok",slot="0",account_id="0",direction="edge_to_node"} 0`,
		`cdn64_edge_tunnel_rtt_seconds{server="srvT",tunnel="tn_bad",slot="1",account_id="0"} 0.035`,
		`cdn64_edge_tunnel_node_rtt_seconds{server="srvT",tunnel="tn_ok",slot="0",account_id="0"} 0.021`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(out, `tunnel="tn_bad",slot="1",account_id="0",direction="edge_to_node"`) || strings.Contains(out, `cdn64_edge_tunnel_node_rtt_seconds{server="srvT",tunnel="tn_old"`) {
		t.Error("unknown values must not be exported")
	}
	if n := strings.Count(out, "cdn64_edge_tunnel_rtt_seconds{"); n != linkMetricsMax {
		t.Errorf("rtt rows: %d", n)
	}
	if strings.Count(out, "# TYPE cdn64_edge_tunnel_loss_ratio") != 1 {
		t.Error("family not grouped")
	}
	if t.Failed() {
		t.Log(out[:min(len(out), 3000)])
	}
}
