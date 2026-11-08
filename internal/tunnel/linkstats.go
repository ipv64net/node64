package tunnel

import (
	"context"
	"time"
)

// Verlust und RTT je Tunnel-Verbindung, fuer beide Richtungen: Die Node kennt die Verluste ihrer Senderichtung
// (Download der Besucher) und meldet sie alle statsEvery per Control "stats"; der Server misst seine Senderichtung
// (Upload der Besucher) selbst. Verlust = Anteil verlorener Pakete im letzten Intervall, nicht seit dem Start.

// statsEvery: Abstand der Messungen (Tests kuerzer).
var statsEvery = 30 * time.Second

// minLossPackets: darunter ist der Anteil verlorener Pakete im Intervall zu ungenau (ruhige Verbindung).
const minLossPackets = 200

// lossRatio: Anteil verlorener Pakete zwischen zwei Messungen; -1 = zu wenig Pakete bzw. neue Zaehlung.
// PacketsLost von quic-go kann sinken (spaeter doch angekommen): dann 0.
func lossRatio(sent, lost, lastSent, lastLost uint64) float64 {
	if sent < lastSent || sent-lastSent < minLossPackets {
		return -1
	}
	dl := int64(lost) - int64(lastLost)
	if dl < 0 {
		dl = 0
	}
	return min(float64(dl)/float64(sent-lastSent), 1)
}

// LinkReport: letzter Stand einer Tunnel-Verbindung (Server-Seite).
type LinkReport struct {
	RTT        time.Duration // RTT aus Sicht des Servers
	NodeRTT    time.Duration // RTT aus Sicht der Node (0 = keine Meldung, aeltere Node)
	EdgeToNode float64       // Verlust Server -> Node im letzten Intervall (-1 = unbekannt)
	NodeToEdge float64       // Verlust Node -> Server laut Node (-1 = unbekannt)
	At         time.Time     // letzte eigene Messung (Null = noch keine)
	NodeAt     time.Time     // letzte Meldung der Node
}

type linkState struct {
	rep                LinkReport
	ownSent, ownLost   uint64
	nodeSent, nodeLost uint64
}

// Link liefert den letzten Stand der Verbindung.
func (p *Peer) Link() LinkReport {
	p.lmu.Lock()
	defer p.lmu.Unlock()
	r := p.link.rep
	if r.At.IsZero() { // noch keine Messung
		r.RTT, r.EdgeToNode = p.Session.RTT(), -1
		if r.NodeAt.IsZero() {
			r.NodeToEdge = -1
		}
	}
	return r
}

// sampleOwn misst die Senderichtung des Servers.
func (p *Peer) sampleOwn() {
	st := p.Session.Stats()
	p.lmu.Lock()
	defer p.lmu.Unlock()
	l := &p.link
	l.rep.RTT, l.rep.At, l.rep.EdgeToNode = st.RTT, time.Now(), -1
	if st.HasLoss {
		l.rep.EdgeToNode = lossRatio(st.Sent, st.Lost, l.ownSent, l.ownLost)
		l.ownSent, l.ownLost = st.Sent, st.Lost
	}
	if l.rep.NodeAt.IsZero() {
		l.rep.NodeToEdge = -1
	}
}

// nodeStats: Meldung der Node (Control "stats").
func (p *Peer) nodeStats(m Control) {
	p.lmu.Lock()
	defer p.lmu.Unlock()
	l := &p.link
	l.rep.NodeRTT, l.rep.NodeAt, l.rep.NodeToEdge = time.Duration(m.RTTms*float64(time.Millisecond)), time.Now(), -1
	if m.Loss {
		l.rep.NodeToEdge = lossRatio(m.Sent, m.Lost, l.nodeSent, l.nodeLost)
		l.nodeSent, l.nodeLost = m.Sent, m.Lost
	}
}

// measureLink (Server): eigene Messung alle statsEvery, bis die Verbindung endet.
func (p *Peer) measureLink() {
	t := time.NewTicker(statsEvery)
	defer t.Stop()
	for {
		select {
		case <-p.Session.Done():
			return
		case <-t.C:
			p.sampleOwn()
		}
	}
}

// reportLink (Node): alle statsEvery die eigene Senderichtung messen, an den Server melden und fuer die Anzeige
// merken, bis die Verbindung endet. ctx traegt den Zustand des Slots (update).
func (c *Client) reportLink(ctx context.Context, sess Session, ctrl Stream, edge string, slot int) {
	t := time.NewTicker(statsEvery)
	defer t.Stop()
	var lastSent, lastLost uint64
	for {
		select {
		case <-sess.Done():
			return
		case <-t.C:
		}
		st := sess.Stats()
		_ = ctrl.SetWriteDeadline(time.Now().Add(5 * time.Second))
		err := writeMsg(ctrl, Control{Type: "stats", RTTms: float64(st.RTT.Microseconds()) / 1000, Sent: st.Sent, Lost: st.Lost, Loss: st.HasLoss})
		_ = ctrl.SetWriteDeadline(time.Time{})
		var ds, dl uint64
		if st.HasLoss && st.Sent >= lastSent {
			ds = st.Sent - lastSent
			if st.Lost > lastLost {
				dl = st.Lost - lastLost
			}
		}
		lastSent, lastLost = st.Sent, st.Lost
		c.update(ctx, edge, slot, func(s *edgeState) { s.dSent, s.dLost = ds, dl })
		if err != nil {
			return
		}
	}
}
