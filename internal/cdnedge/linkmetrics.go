package cdnedge

import (
	"sort"
	"strconv"

	"github.com/ipv64net/node64/internal/metrics"
	"github.com/ipv64net/node64/internal/tunnel"
)

// Verlust und RTT je Tunnel-Verbindung (tunnel/linkstats.go): zeigt bei einer Kundenmeldung, ob Paketverlust auf
// der Leitung der Node bremst. node_to_edge = Download der Besucher (meldet die Node), edge_to_node = Upload.

// linkMetricsMax: hoechstens so viele Verbindungen einzeln (Kardinalitaet), die mit dem meisten Verlust zuerst.
const linkMetricsMax = 300

// lossyRatio: ab diesem Anteil zaehlt eine Verbindung als verlustreich (Sammelwert).
const lossyRatio = 0.01

type tunnelLink struct {
	Tunnel string
	Slot   int
	Rep    tunnel.LinkReport
	p      *tunnel.Peer
}

func (s *Server) linkMetrics(w *metrics.Writer, lbl func(kv ...string) []string, links []tunnelLink) {
	acc := map[string]int{} // Tunnel -> Account (aus den Namen)
	if rs := s.routes.Load(); rs != nil {
		for _, e := range rs.exact {
			for _, t := range e.Tunnels {
				acc[t] = e.UserID
			}
		}
	}
	worst := func(r tunnel.LinkReport) float64 { return max(r.NodeToEdge, r.EdgeToNode) }
	lossy := map[string]int{"node_to_edge": 0, "edge_to_node": 0}
	for _, l := range links {
		if l.Rep.NodeToEdge >= lossyRatio {
			lossy["node_to_edge"]++
		}
		if l.Rep.EdgeToNode >= lossyRatio {
			lossy["edge_to_node"]++
		}
	}
	for _, d := range []string{"edge_to_node", "node_to_edge"} {
		w.Gauge("cdn64_edge_tunnel_lossy_connections", "Tunnel connections with at least 1 % packet loss in the last interval", float64(lossy[d]), lbl("direction", d)...)
	}
	sort.Slice(links, func(i, j int) bool {
		if a, b := worst(links[i].Rep), worst(links[j].Rep); a != b {
			return a > b
		}
		if links[i].Tunnel != links[j].Tunnel {
			return links[i].Tunnel < links[j].Tunnel
		}
		return links[i].Slot < links[j].Slot
	})
	if len(links) > linkMetricsMax {
		links = links[:linkMetricsMax]
	}
	for _, l := range links {
		base := []string{"tunnel", l.Tunnel, "slot", strconv.Itoa(l.Slot), "account_id", strconv.Itoa(acc[l.Tunnel])}
		w.Gauge("cdn64_edge_tunnel_rtt_seconds", "Round trip time of a tunnel connection (server view)", l.Rep.RTT.Seconds(), lbl(base...)...)
		if l.Rep.NodeRTT > 0 {
			w.Gauge("cdn64_edge_tunnel_node_rtt_seconds", "Round trip time of a tunnel connection as reported by the node", l.Rep.NodeRTT.Seconds(), lbl(base...)...)
		}
		for _, x := range []struct {
			d string
			v float64
		}{{"edge_to_node", l.Rep.EdgeToNode}, {"node_to_edge", l.Rep.NodeToEdge}} {
			if x.v >= 0 { // -1 = unbekannt (TCP, zu wenig Pakete, aeltere Node)
				w.Gauge("cdn64_edge_tunnel_loss_ratio", "Share of lost packets of a tunnel connection in the last interval (node_to_edge = visitor downloads)", x.v,
					lbl(append(append([]string{}, base...), "direction", x.d)...)...)
			}
		}
	}
}
