package cdnedge

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/tunnel"
)

// lossyRelay: UDP zwischen Node und Server mit Verzoegerung (je Richtung) und zufaelligem Verlust - wie eine
// Heimleitung. Je Absender der Node (parallele Tunnel-Verbindungen) ein eigener Socket zum Server.
type lossyRelay struct {
	pc    net.PacketConn
	to    *net.UDPAddr
	delay time.Duration
	loss  float64
	mu    sync.Mutex
	ups   map[string]net.PacketConn
	rnd   *rand.Rand
}

func newLossyRelay(t *testing.T, target string, delay time.Duration, loss float64) *lossyRelay {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	to, _ := net.ResolveUDPAddr("udp", target)
	r := &lossyRelay{pc: pc, to: to, delay: delay, loss: loss, ups: map[string]net.PacketConn{}, rnd: rand.New(rand.NewSource(1))}
	t.Cleanup(func() {
		_ = pc.Close()
		r.mu.Lock()
		for _, u := range r.ups {
			_ = u.Close()
		}
		r.mu.Unlock()
	})
	go r.pump(pc, func(a net.Addr) (net.PacketConn, net.Addr) { // Node -> Server
		r.mu.Lock()
		defer r.mu.Unlock()
		up := r.ups[a.String()]
		if up == nil {
			var err error
			if up, err = net.ListenPacket("udp", "127.0.0.1:0"); err != nil {
				return nil, nil
			}
			r.ups[a.String()] = up
			go r.pump(up, func(net.Addr) (net.PacketConn, net.Addr) { return pc, a }) // Server -> Node
		}
		return up, to
	})
	return r
}

func (r *lossyRelay) drop() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rnd.Float64() < r.loss
}

func (r *lossyRelay) pump(in net.PacketConn, out func(net.Addr) (net.PacketConn, net.Addr)) {
	buf := make([]byte, 65535)
	q := make(chan delayed, 1<<16)
	defer close(q)
	go sendDelayed(q)
	for {
		n, a, err := in.ReadFrom(buf)
		if err != nil {
			return
		}
		if r.drop() {
			continue
		}
		pc, dst := out(a)
		if dst == nil {
			continue
		}
		select { // Warteschlange in Reihenfolge (eigene Timer je Paket wuerden umsortieren - QUIC haelt das fuer Verlust)
		case q <- delayed{at: time.Now().Add(r.delay), b: append([]byte(nil), buf[:n]...), pc: pc, dst: dst}:
		default: // voll: verloren
		}
	}
}

type delayed struct {
	at  time.Time
	b   []byte
	pc  net.PacketConn
	dst net.Addr
}

func sendDelayed(q chan delayed) {
	for d := range q {
		if w := time.Until(d.at); w > 0 {
			time.Sleep(w)
		}
		_, _ = d.pc.WriteTo(d.b, d.dst)
	}
}

func (r *lossyRelay) port() int { return r.pc.LocalAddr().(*net.UDPAddr).Port }

// Messung Download ueber HTTP/3 in Modus 1 (Besucher -> Server -> Tunnel -> Node): Durchsatz je 250 ms und wie viele
// Pakete der Node als Datagramm bzw. (zu gross) im Stream durch den Tunnel gingen. Im Stream haelt ein verlorenes
// Tunnel-Paket alle folgenden auf - der Download bricht ein. Laeuft nur mit NODE64_DLTEST=1 (dauert einige Sekunden);
// NODE64_DLTEST_LOSS (Prozent, Standard 1) und NODE64_DLTEST_RTT (ms, Standard 30) stellen die Leitung ein,
// NODE64_DLTEST_PAR parallele Downloads (wie ein Speedtest), NODE64_DLTEST_SESSIONS parallele Tunnel-Verbindungen,
// NODE64_DLTEST_DIR=up misst den Upload des Besuchers (Server -> Node, gezaehlt in der Node), NODE64_DLTEST_SECS die Dauer.
func TestQUICDownloadMeasure(t *testing.T) {
	if os.Getenv("NODE64_DLTEST") == "" {
		t.Skip("Messung: NODE64_DLTEST=1")
	}
	loss, rtt, mode := 1.0, 30, os.Getenv("NODE64_DLTEST_MODE") // h3 (Standard), h3stream (ohne Datagramme), tcp
	if v, err := strconv.ParseFloat(os.Getenv("NODE64_DLTEST_LOSS"), 64); err == nil {
		loss = v
	}
	if v, err := strconv.Atoi(os.Getenv("NODE64_DLTEST_RTT")); err == nil {
		rtt = v
	}
	par, sessions, up := 1, 1, os.Getenv("NODE64_DLTEST_DIR") == "up"
	dur := 8 * time.Second
	if v, err := strconv.Atoi(os.Getenv("NODE64_DLTEST_SECS")); err == nil && v > 0 {
		dur = time.Duration(v) * time.Second
	}
	const slot = 250 * time.Millisecond
	slots := make([]int64, dur/slot)
	var smu sync.Mutex
	var maxGap time.Duration
	var start time.Time
	count := func(n int, last *time.Duration) bool { // false = Messzeit vorbei
		el := time.Since(start)
		if start.IsZero() || el >= dur {
			return !start.IsZero() && el < dur
		}
		smu.Lock()
		defer smu.Unlock()
		if g := el - *last; g > maxGap && *last > 0 {
			maxGap = g
		}
		*last = el
		slots[el/slot] += int64(n)
		return true
	}
	if v, err := strconv.Atoi(os.Getenv("NODE64_DLTEST_PAR")); err == nil && v > 0 {
		par = v
	}
	if v, err := strconv.Atoi(os.Getenv("NODE64_DLTEST_SESSIONS")); err == nil && v > 0 {
		sessions = v
	}
	cf, kf, pool, _ := testCA(t, "edge.test")
	_, _, hpool, crt := testCA(t, "h1.test")
	tok := "node-token"
	cfg := &Config{Name: "B", PublicHost: "edge.test", ListenHTTP: freeAddr(t), ListenHTTPS: freeAddr(t), TunnelListen: freeAddr(t),
		TLSCert: cf, TLSKey: kf, Hosts: []HostEntry{{Name: "h1.test", Tunnel: "t1", Mode: 1}}, HTTP3: true,
		Tunnels: []TunnelEntry{{ID: "t1", TokenSHA256: sha256hex(tok), Sessions: sessions}}, DataDir: t.TempDir()}
	s := startEdge(t, cfg, pool)
	relay := newLossyRelay(t, cfg.TunnelListen, time.Duration(rtt)*time.Millisecond/2, loss/100)

	ne, err := edge.New(edge.Config{Bind: "127.0.0.1", HTTPPort: 0, HTTPSPort: 0, Default: edge.DefaultNotFound}, fixedCerts{&crt}, nil,
		slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer ne.Close(context.Background())
	chunk := make([]byte, 64<<10)
	if err := ne.Set("test", []edge.Route{{Names: []string{"h1.test"}, HTTP3: true, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost { // Upload: in der Node zaehlen
			buf := make([]byte, 256<<10)
			var last time.Duration
			for {
				n, err := r.Body.Read(buf)
				count(n, &last)
				if err != nil {
					return
				}
			}
		}
		for r.Context().Err() == nil { // endloser Download wie beim Speedtest
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	})}}); err != nil {
		t.Fatal(err)
	}
	node := tunnel.NewClient(tunnel.ClientConfig{Tunnel: "t1", Token: tok, RootCAs: pool, Caps: []string{tunnel.CapQUIC}, Sessions: sessions,
		Edges: []tunnel.Edge{{Name: "B", Host: "edge.test", Port: relay.port(), IPs: []string{"127.0.0.1"}}},
		Handler: func(st tunnel.Stream, h tunnel.Header) {
			ap, err := netip.ParseAddrPort(h.Client)
			if err == nil && h.Kind == tunnel.KindTLS {
				ne.ServeConn(&remoteConn{Stream: st, ra: net.TCPAddrFromAddrPort(ap)}, 443)
				return
			}
			if err != nil || h.Kind != tunnel.KindQUIC {
				_ = st.Close()
				return
			}
			var attach func(func([]byte)) *tunnel.DatagramFlow
			if h.Flow != 0 && mode != "h3stream" {
				attach = func(recv func([]byte)) *tunnel.DatagramFlow { return tunnel.AcceptDatagrams(st, h.Flow, recv) }
			}
			ne.ServeQUICFlow(st, ap, "", attach)
		}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go node.Run(ctx)
	for i := 0; i < 1200 && (s.peer("t1") == nil || !node.AllHave(tunnel.CapQUIC)); i++ {
		time.Sleep(25 * time.Millisecond)
	}
	if s.peer("t1") == nil {
		t.Fatal("node not connected")
	}
	time.Sleep(2 * time.Second) // Tunnel: Path-MTU-Discovery wie auf einer laenger laufenden Verbindung

	var qconn *quic.Conn
	h3 := &http.Client{Transport: &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: hpool},
		Dial: func(ctx context.Context, _ string, tc *tls.Config, qc *quic.Config) (*quic.Conn, error) {
			c, err := quic.DialAddr(ctx, cfg.ListenHTTPS, tc, slowQUIC(qc))
			qconn = c
			return c, err
		}}}
	if mode == "tcp" {
		h3 = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: hpool},
			DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, n, cfg.ListenHTTPS)
			}}}
	}
	dctx, dcancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer dcancel()
	before := tunnel.DatagramStats()
	var proto string
	start = time.Now()
	var wg sync.WaitGroup
	for k := 0; k < par; k++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			req, _ := http.NewRequestWithContext(dctx, http.MethodGet, "https://h1.test/download/"+strconv.Itoa(k), nil)
			if up {
				req, _ = http.NewRequestWithContext(dctx, http.MethodPost, "https://h1.test/upload/"+strconv.Itoa(k), &endless{until: start.Add(dur)})
			}
			resp, err := h3.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			defer resp.Body.Close()
			smu.Lock()
			proto = resp.Proto
			smu.Unlock()
			if up {
				return
			}
			buf := make([]byte, 256<<10)
			var last time.Duration
			for {
				n, err := resp.Body.Read(buf)
				if !count(n, &last) || err != nil {
					return
				}
			}
		}(k)
	}
	wg.Wait()
	if up { // Antwort kommt erst nach dem Body: Rest der Messzeit abwarten
		time.Sleep(time.Until(start.Add(dur)))
	}
	after := tunnel.DatagramStats()

	mbit := make([]float64, len(slots))
	var line []string
	var total int64
	for i, b := range slots {
		mbit[i] = float64(b) * 8 / slot.Seconds() / 1e6
		total += b
		line = append(line, fmt.Sprintf("%.0f", mbit[i]))
	}
	sorted := append([]float64(nil), mbit...)
	sort.Float64s(sorted)
	med := sorted[len(sorted)/2]
	dips := 0
	for _, m := range mbit[4:] { // erste Sekunde: Anlauf
		if m < med/4 {
			dips++
		}
	}
	dg, big, drop := after.Sent-before.Sent, after.TooLarge-before.TooLarge, after.Dropped-before.Dropped
	t.Logf("Leitung: RTT %d ms, Verlust %.1f %%, Art %s (%s), %d Downloads, %d Tunnel-Verbindung(en)", rtt, loss, mode, proto, par, sessions)
	if qconn != nil {
		cs := qconn.ConnectionStats()
		t.Logf("Besucher-QUIC: RTT %v (min %v), Pakete empfangen %d, gesendet %d, verloren (gesendet) %d", cs.SmoothedRTT.Round(time.Millisecond),
			cs.MinRTT.Round(time.Millisecond), cs.PacketsReceived, cs.PacketsSent, cs.PacketsLost)
	}
	what := "Download"
	if up {
		what = "Upload"
	}
	t.Logf(what+": %.1f MB in %v = %.1f Mbit/s, Median %.0f Mbit/s, Einbrueche (< 1/4 Median) %d von %d, laengste Pause %v",
		float64(total)/1e6, dur, float64(total)*8/dur.Seconds()/1e6, med, dips, len(mbit)-4, maxGap.Round(time.Millisecond))
	t.Logf("je 250 ms (Mbit/s): %s", strings.Join(line, " "))
	t.Logf("Tunnel: %d Pakete als Datagramm, %d zu gross (Stream) = %.0f %% im Stream, %d zu gross verworfen", dg, big,
		100*float64(big)/float64(max(dg+big, 1)), drop)
}

// endless: Upload-Body aus Nullen bis zur Frist.
type endless struct{ until time.Time }

func (e *endless) Read(p []byte) (int, error) {
	if time.Now().After(e.until) {
		return 0, io.EOF
	}
	clear(p)
	return len(p), nil
}
