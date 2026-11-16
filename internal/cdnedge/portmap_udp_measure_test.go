package cdnedge

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/ipv64net/node64/internal/tunnel"
)

// Messung UDP-Portmapper Modus 1 (z. B. WireGuard): Besucher -> UDP-Port des Servers -> Tunnel -> Node -> Ziel. Als
// staukontrollierter Verkehr im UDP dient QUIC (wie TCP in WireGuard): Durchsatz je 250 ms in beide Richtungen.
// Laeuft nur mit NODE64_UDPTEST=1; NODE64_DLTEST_LOSS (Prozent) und NODE64_DLTEST_RTT (ms) stellen die Leitung ein,
// NODE64_DLTEST_DIR=up misst den Upload des Besuchers.
func TestUDPPortmapMeasure(t *testing.T) {
	if os.Getenv("NODE64_UDPTEST") == "" {
		t.Skip("Messung: NODE64_UDPTEST=1")
	}
	loss, rtt := 0.0, 30
	if v, err := strconv.ParseFloat(os.Getenv("NODE64_DLTEST_LOSS"), 64); err == nil {
		loss = v
	}
	if v, err := strconv.Atoi(os.Getenv("NODE64_DLTEST_RTT")); err == nil {
		rtt = v
	}
	udpPortmapRun(t, loss, rtt, os.Getenv("NODE64_DLTEST_DIR") == "up", 10*time.Second)
}

// Download durch den UDP-Portmapper (QUIC wie TCP in WireGuard): Der Reflexionsschutz darf den Anlauf nicht
// abwuergen. Vorher verwarf der Server in den ersten 2 s fast alles, der Besucher schickte nichts mehr zurueck und
// der Download kam nie in Gang (0 statt rund 290 Mbit/s; Forum 5110).
func TestUDPPortmapQUICDownload(t *testing.T) {
	if mbit := udpPortmapRun(t, 0, 20, false, 3*time.Second); mbit < 20 {
		t.Fatalf("download through the udp port mapping: %.1f Mbit/s", mbit)
	}
}

// udpPortmapRun misst einen QUIC-Download bzw. -Upload durch den UDP-Portmapper (Modus 1) ueber die simulierte
// Leitung und liefert Mbit/s.
func udpPortmapRun(t *testing.T, loss float64, rtt int, up bool, dur time.Duration) float64 {
	t.Helper()
	cf, kf, pool, _ := testCA(t, "edge.test")
	_, _, qpool, qcrt := testCA(t, "wg.test")
	tok := "node-token"
	cfg := &Config{Name: "B", ListenHTTP: freeAddr(t), TunnelListen: freeAddr(t), TLSCert: cf, TLSKey: kf,
		Tunnels: []TunnelEntry{{ID: "t1", TokenSHA256: sha256hex(tok)}}, DataDir: t.TempDir(), PortRange: "1024-65535"}
	s := startEdge(t, cfg, pool)
	relay := newLossyRelay(t, cfg.TunnelListen, time.Duration(rtt)*time.Millisecond/2, loss/100)

	// Ziel hinter der Node: QUIC-Server, der endlos sendet bzw. alles liest
	tpc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tpc.Close()
	ln, err := quic.Listen(tpc, &tls.Config{Certificates: []tls.Certificate{qcrt}, NextProtos: []string{"m"}}, &quic.Config{MaxIdleTimeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	const slot = 250 * time.Millisecond
	slots := make([]int64, dur/slot)
	var smu sync.Mutex
	var start time.Time
	count := func(n int) bool {
		el := time.Since(start)
		if start.IsZero() || el >= dur {
			return false
		}
		smu.Lock()
		slots[el/slot] += int64(n)
		smu.Unlock()
		return true
	}
	go func() {
		for {
			c, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				st, err := c.AcceptStream(context.Background())
				if err != nil {
					return
				}
				buf := make([]byte, 64<<10)
				if up {
					for {
						n, err := st.Read(buf)
						count(n)
						if err != nil {
							return
						}
					}
				}
				for {
					if _, err := st.Write(buf); err != nil {
						return
					}
				}
			}()
		}
	}()

	// Node: UDP-Stream an das Ziel weiterreichen (wie cdn64 streamUDPTunnel)
	var nodePkts sync.Map // Paketgroessen der Node
	handler := func(st tunnel.Stream, h tunnel.Header) {
		defer st.Close()
		if h.Kind != tunnel.KindUDP {
			return
		}
		u, err := net.Dial("udp", tpc.LocalAddr().String())
		if err != nil {
			return
		}
		defer u.Close()
		var wmu sync.Mutex
		go func() {
			buf := make([]byte, tunnel.MaxDatagram)
			for {
				n, err := u.Read(buf)
				if err != nil {
					return
				}
				nodePkts.Store(n, true)
				wmu.Lock()
				err = tunnel.WriteDatagram(st, buf[:n])
				wmu.Unlock()
				if err != nil {
					return
				}
			}
		}()
		buf := make([]byte, tunnel.MaxDatagram)
		for {
			n, err := tunnel.ReadDatagram(st, buf)
			if err != nil {
				return
			}
			_, _ = u.Write(buf[:n])
		}
	}
	node := tunnel.NewClient(tunnel.ClientConfig{Tunnel: "t1", Token: tok, RootCAs: pool, Caps: []string{tunnel.CapPorts},
		Edges: []tunnel.Edge{{Name: "B", Host: "edge.test", Port: relay.port(), IPs: []string{"127.0.0.1"}}}, Handler: handler})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go node.Run(ctx)
	for i := 0; i < 1200 && s.peer("t1") == nil; i++ {
		time.Sleep(25 * time.Millisecond)
	}
	if s.peer("t1") == nil {
		t.Fatal("node not connected")
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, p, _ := net.SplitHostPort(pc.LocalAddr().String())
	_ = pc.Close()
	uport, _ := strconv.Atoi(p)
	s.applyConfig(&apiConfig{Tunnels: []apiTunnel{{ID: "t1", TokenSHA256: sha256hex(tok), UserID: 1}}, Hosts: []apiHost{
		{ID: 1, Name: "wg.test", Mode: 1, UserID: 1, Tunnels: []string{"t1"}, Mappings: []apiMapping{{Listen: uport, Transport: "udp", Port: 51820}}}}})
	time.Sleep(2 * time.Second)

	dctx, dcancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer dcancel()
	qc, err := quic.DialAddr(dctx, "127.0.0.1:"+strconv.Itoa(uport), &tls.Config{RootCAs: qpool, ServerName: "wg.test", NextProtos: []string{"m"}},
		&quic.Config{MaxIdleTimeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	st, err := qc.OpenStreamSync(dctx)
	if err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	buf := make([]byte, 64<<10)
	if up {
		for time.Since(start) < dur {
			if _, err := st.Write(buf); err != nil {
				break
			}
		}
		time.Sleep(500 * time.Millisecond)
	} else {
		_, _ = st.Write([]byte("go"))
		for {
			n, err := st.Read(buf)
			if !count(n) || err != nil {
				break
			}
		}
	}
	cs := qc.ConnectionStats()
	_ = qc.CloseWithError(0, "")
	var line []string
	var total int64
	smu.Lock()
	for _, b := range slots {
		total += b
		line = append(line, fmt.Sprintf("%.0f", float64(b)*8/slot.Seconds()/1e6))
	}
	smu.Unlock()
	maxPkt := 0
	nodePkts.Range(func(k, _ any) bool { maxPkt = max(maxPkt, k.(int)); return true })
	what := "Download"
	if up {
		what = "Upload"
	}
	t.Logf("UDP-Portmapper Modus 1, RTT %d ms, Verlust %.1f %%: %s %.1f Mbit/s", rtt, loss, what, float64(total)*8/dur.Seconds()/1e6)
	t.Logf("je 250 ms (Mbit/s): %s", strings.Join(line, " "))
	t.Logf("Besucher-QUIC: RTT %v (min %v), gesendet %d, verloren %d; groesstes Paket der Node %d Byte", cs.SmoothedRTT.Round(time.Millisecond),
		cs.MinRTT.Round(time.Millisecond), cs.PacketsSent, cs.PacketsLost, maxPkt)
	return float64(total) * 8 / dur.Seconds() / 1e6
}
