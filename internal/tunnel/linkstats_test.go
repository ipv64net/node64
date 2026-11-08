package tunnel

import (
	"bytes"
	"context"
	"io"
	"math"
	"testing"
	"time"
)

func TestLossRatio(t *testing.T) {
	for _, c := range []struct {
		sent, lost, ls, ll uint64
		want               float64
	}{
		{1000, 10, 0, 0, 0.01},     // erste Messung: seit Beginn
		{2000, 30, 1000, 10, 0.02}, // Intervall: 20 von 1000
		{1100, 50, 1000, 10, -1},   // zu wenig Pakete
		{500, 0, 1000, 0, -1},      // neue Zaehlung
		{3000, 5, 2000, 30, 0},     // PacketsLost gesunken
		{1200, 2000, 1000, 0, 1},   // genau 200 Pakete zaehlen, Anteil hoechstens 1
	} {
		got := lossRatio(c.sent, c.lost, c.ls, c.ll)
		if math.Abs(got-c.want) > 1e-9 {
			t.Fatalf("%+v: got %v want %v", c, got, c.want)
		}
	}
}

// fakeSess: nur Stats/RTT/Done fuer die Auswertung des Servers.
type fakeSess struct {
	Session
	st   LinkStats
	done chan struct{}
}

func (f *fakeSess) Stats() LinkStats      { return f.st }
func (f *fakeSess) RTT() time.Duration    { return f.st.RTT }
func (f *fakeSess) Done() <-chan struct{} { return f.done }

func TestPeerLink(t *testing.T) {
	fs := &fakeSess{st: LinkStats{RTT: 20 * time.Millisecond, Sent: 0, HasLoss: true}, done: make(chan struct{})}
	p := &Peer{Session: fs}
	if r := p.Link(); r.EdgeToNode != -1 || r.NodeToEdge != -1 || r.RTT != 20*time.Millisecond {
		t.Fatalf("vor der Messung: %+v", r)
	}
	fs.st.Sent, fs.st.Lost = 5000, 50
	p.sampleOwn()
	p.nodeStats(Control{Type: "stats", RTTms: 21.5, Sent: 10000, Lost: 300, Loss: true})
	r := p.Link()
	if math.Abs(r.EdgeToNode-0.01) > 1e-9 || math.Abs(r.NodeToEdge-0.03) > 1e-9 || r.NodeRTT != 21500*time.Microsecond || r.At.IsZero() || r.NodeAt.IsZero() {
		t.Fatalf("erste Messung: %+v", r)
	}
	fs.st.Sent, fs.st.Lost = 6000, 50 // Intervall ohne Verlust
	p.sampleOwn()
	p.nodeStats(Control{Type: "stats", RTTms: 22, Sent: 10100, Lost: 300, Loss: true}) // zu wenig Pakete
	if r := p.Link(); r.EdgeToNode != 0 || r.NodeToEdge != -1 {
		t.Fatalf("zweite Messung: %+v", r)
	}
	p.nodeStats(Control{Type: "stats", RTTms: 22}) // TCP-Ausweichweg der Node: nur RTT
	if r := p.Link(); r.NodeToEdge != -1 || r.NodeRTT != 22*time.Millisecond {
		t.Fatalf("tcp: %+v", r)
	}
}

// Echter Tunnel (QUIC und TCP): die Node meldet ihre Messwerte, der Server misst selbst, die Node zeigt ihren Verlust.
func TestLinkStatsEndToEnd(t *testing.T) {
	old := statsEvery
	statsEvery = 100 * time.Millisecond
	defer func() { statsEvery = old }()
	for _, tcp := range []bool{false, true} {
		f := newFixture(t)
		c := f.client("secret", tcp, func(st Stream, h Header) { _, _ = io.Copy(st, st); _ = st.CloseWrite(); _ = st.Close() })
		ctx, cancel := context.WithCancel(context.Background())
		go c.Run(ctx)
		var p *Peer
		select {
		case p = <-f.peers:
		case <-time.After(10 * time.Second):
			t.Fatal("no tunnel")
		}
		// Verkehr in beide Richtungen, damit genug Pakete fuer einen Anteil zusammenkommen
		st, err := OpenStream(ctx, p, Header{Kind: KindTLS, Client: "203.0.113.7:4444", Host: "a.test", Port: 443})
		if err != nil {
			t.Fatal(err)
		}
		payload := bytes.Repeat([]byte("x"), 4<<20)
		go func() { _, _ = st.Write(payload); _ = st.CloseWrite() }()
		if back, err := io.ReadAll(st); err != nil || len(back) != len(payload) {
			t.Fatalf("echo: %d %v", len(back), err)
		}
		waitFor(t, "meldung der node", func() bool { r := p.Link(); return !r.NodeAt.IsZero() && !r.At.IsZero() })
		r := p.Link()
		if tcp {
			if r.NodeToEdge != -1 || r.EdgeToNode != -1 {
				t.Fatalf("tcp: kein Verlust erwartet: %+v", r)
			}
		} else if r.NodeRTT <= 0 || r.RTT <= 0 {
			t.Fatalf("quic rtt: %+v", r)
		}
		s := c.Status()[0]
		if tcp && s.LossPct != -1 {
			t.Fatalf("tcp: loss_pct %v", s.LossPct)
		}
		// Loopback kann bei kleinen UDP-Puffern (CI) Pakete verlieren: nur den Wertebereich pruefen
		if !tcp && (s.LossPct < -1 || s.LossPct > 100) {
			t.Fatalf("quic: loss_pct %v", s.LossPct)
		}
		cancel()
	}
}
