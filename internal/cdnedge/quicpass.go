package cdnedge

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/quicsni"
	"github.com/ipv64net/node64/internal/tunnel"
)

// HTTP/3 in Modus 1: vor dem QUIC-Listener auf UDP 443 sitzt eine Weiche. Sie liest aus den Initial-Paketen eines
// neuen Besuchers den Namen (internal/quicsni, ohne TLS zu beenden). Gehoert er zu einem Modus-1-Namen, gehen alle
// Datagramme dieses Besuchers (Adresse:Port) roh durch den Tunnel der Node (Stream "quic", Datagramme mit
// Laengenpraefix) - TLS und HTTP/3 enden erst in der Node, wie bei TCP. Alles andere (HTTP/3 fuer Modus 2/3, der
// Tunnel ueber 443) geht unveraendert an quic-go. Ohne Tunnel hier geht der Stream ueber den Nachbarn.
//
// Die Adresse eines Besuchers kann gefaelscht sein, bis er auf eine Antwort der Node reagiert: sein Paket traegt dann
// die Verbindungs-ID, die die Node gewaehlt hat (Source Connection ID ihrer langen Pakete) - die kennt nur, wer die
// Antwort bekommen hat. Bis dahin zaehlt der Fluss nur im UDP-Budget (guard.admitUDP), die Node darf ihm hoechstens
// qpFree + qpAmp x Eingang schicken (keine Reflexion) und nach qpProveIn ist Schluss. Ruhig ist ein Fluss nach den
// Paketen des Besuchers (die Node haelt ihn nicht offen).

const (
	qpPendMax   = 4096             // Besucher, deren ClientHello gerade gelesen wird
	qpPendPkts  = 8                // so viele Datagramme warten hoechstens auf den Namen
	qpPendAge   = 3 * time.Second  // danach an quic-go
	qpFlowIdle  = 60 * time.Second // ruhiger Fluss: Stream zu
	qpFlowQueue = 512              // Datagramme in Richtung Node, die warten duerfen (hoechstens qpMaxDgram gross)
	qpMaxDgram  = 1500             // groessere Datagramme gibt es bei QUIC praktisch nicht: verwerfen
	qpProveIn   = 10 * time.Second // so lange darf ein Besucher brauchen, um seine Adresse nachzuweisen
	qpMinCID    = 4                // kuerzere IDs der Node taugen nicht als Nachweis
	qpAmp       = 3                // vor dem Nachweis: Node -> Besucher hoechstens qpFree + 3 x Eingang (wie RFC 9000 8.1)
	qpFree      = 1500
)

// quicDemux ist die PacketConn fuer quic-go (ReadFrom ruft nur eine Goroutine von quic-go).
type quicDemux struct {
	s      *Server
	c      *net.UDPConn
	buf    []byte
	ready  []qpkt // freigegeben fuer quic-go (in Reihenfolge)
	pend   map[netip.AddrPort]*qpend
	mu     sync.Mutex
	flows  map[netip.AddrPort]*qflow
	swept  time.Time
	closed atomic.Bool
}

type qpkt struct {
	data []byte
	addr netip.AddrPort
}

type qpend struct {
	pkts  [][]byte
	asm   quicsni.Assembler
	dcid  []byte
	since time.Time
}

type qflow struct {
	d       *quicDemux
	addr    netip.AddrPort
	st      *hostStat
	q       chan []byte
	last    atomic.Int64 // letztes Paket des Besuchers
	born    time.Time
	in, out atomic.Int64           // Bytes vom bzw. zum Besucher
	proven  atomic.Bool            // Adresse nachgewiesen
	scid    atomic.Pointer[[]byte] // Verbindungs-ID der Node (aus ihren langen Paketen)
	mu      sync.Mutex
	rel     func() // Platz: erst im UDP-Budget, nach dem Nachweis im guard
	relDone bool
	once    sync.Once
	done    chan struct{}
}

func newQUICDemux(s *Server, c *net.UDPConn) *quicDemux {
	return &quicDemux{s: s, c: c, buf: make([]byte, 65536), pend: map[netip.AddrPort]*qpend{}, flows: map[netip.AddrPort]*qflow{}}
}

// ReadFrom liefert quic-go das naechste Datagramm, das nicht durchgereicht wird.
func (d *quicDemux) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		if len(d.ready) > 0 {
			pk := d.ready[0]
			d.ready = d.ready[1:]
			return copy(p, pk.data), net.UDPAddrFromAddrPort(pk.addr), nil
		}
		d.sweep()
		n, ap, err := d.c.ReadFromUDPAddrPort(d.buf)
		if err != nil {
			return 0, nil, err
		}
		ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		pkt := d.buf[:n]
		d.mu.Lock()
		f := d.flows[ap]
		d.mu.Unlock()
		if f != nil {
			if n <= qpMaxDgram {
				f.toNode(pkt)
			}
			continue
		}
		if n <= qpMaxDgram && (d.pend[ap] != nil || quicsni.IsInitial(pkt)) {
			d.sniff(ap, append([]byte(nil), pkt...))
			continue
		}
		return copy(p, pkt), net.UDPAddrFromAddrPort(ap), nil
	}
}

// sniff sammelt die ersten Datagramme eines Besuchers, bis der Name feststeht.
func (d *quicDemux) sniff(ap netip.AddrPort, pkt []byte) {
	pe := d.pend[ap]
	if pe == nil {
		if len(d.pend) >= qpPendMax {
			d.ready = append(d.ready, qpkt{pkt, ap})
			return
		}
		pe = &qpend{since: time.Now()}
		d.pend[ap] = pe
	}
	pe.pkts = append(pe.pkts, pkt)
	if quicsni.IsInitial(pkt) {
		dcid, chunks, err := quicsni.Parse(pkt)
		if err != nil || (pe.dcid != nil && !bytes.Equal(dcid, pe.dcid)) {
			d.release(ap)
			return
		}
		pe.dcid = dcid
		if pe.asm.Add(chunks) {
			h, _ := pe.asm.Hello()
			sni, _ := quicsni.ServerName(h)
			d.decide(ap, sni)
			return
		}
	}
	if len(pe.pkts) >= qpPendPkts {
		d.release(ap)
	}
}

// release gibt die gesammelten Datagramme an quic-go.
func (d *quicDemux) release(ap netip.AddrPort) {
	pe := d.pend[ap]
	delete(d.pend, ap)
	if pe == nil {
		return
	}
	for _, p := range pe.pkts {
		d.ready = append(d.ready, qpkt{p, ap})
	}
}

// decide: Modus-1-Name -> durchreichen, sonst quic-go.
func (d *quicDemux) decide(ap netip.AddrPort, sni string) {
	re := d.s.routes.Load().lookup(sni)
	if sni == "" || d.s.isPublicName(sni) || re == nil || re.Mode != 1 {
		d.release(ap)
		return
	}
	pe := d.pend[ap]
	delete(d.pend, ap)
	f := &qflow{d: d, addr: ap, st: d.s.stats.of(re.Name), q: make(chan []byte, qpFlowQueue), born: time.Now(), done: make(chan struct{})}
	f.last.Store(time.Now().UnixNano())
	for _, p := range pe.pkts {
		f.in.Add(int64(len(p)))
		f.q <- p
	}
	d.mu.Lock()
	d.flows[ap] = f
	d.mu.Unlock()
	go f.run(re, sni)
}

// sweep (hoechstens jede Sekunde): wartende Besucher nach qpPendAge an quic-go, ruhige Fluesse zu.
func (d *quicDemux) sweep() {
	now := time.Now()
	if now.Sub(d.swept) < time.Second {
		return
	}
	d.swept = now
	for ap, pe := range d.pend {
		if now.Sub(pe.since) > qpPendAge {
			d.release(ap)
		}
	}
	cut := now.Add(-qpFlowIdle).UnixNano()
	d.mu.Lock()
	var idle []*qflow
	for _, f := range d.flows {
		if f.last.Load() < cut || (!f.proven.Load() && now.Sub(f.born) > qpProveIn) {
			idle = append(idle, f)
		}
	}
	d.mu.Unlock()
	for _, f := range idle {
		f.close()
	}
}

func (f *qflow) toNode(pkt []byte) {
	f.last.Store(time.Now().UnixNano())
	f.in.Add(int64(len(pkt)))
	if !f.proven.Load() && f.answers(pkt) {
		f.prove()
	}
	select {
	case f.q <- append([]byte(nil), pkt...):
	default: // Node kommt nicht hinterher: verwerfen (QUIC wiederholt)
	}
}

// answers: Paket des Besuchers an die Verbindungs-ID, die die Node gewaehlt hat (lang: Destination Connection ID
// genau, kurz: deren Anfang).
func (f *qflow) answers(p []byte) bool {
	idp := f.scid.Load()
	if idp == nil || len(p) < 6 {
		return false
	}
	id := *idp
	if p[0]&0x80 != 0 {
		l := int(p[5])
		return 6+l <= len(p) && bytes.Equal(p[6:6+l], id)
	}
	return len(p) >= 1+len(id) && bytes.Equal(p[1:1+len(id)], id)
}

// prove: Adresse nachgewiesen - der Fluss zaehlt ab jetzt wie eine Verbindung (Grenzen je IP und insgesamt).
func (f *qflow) prove() {
	if f.proven.Swap(true) {
		return
	}
	rel, gs, why := f.d.s.guard.admitG(f.addr.Addr(), f.st)
	if why != "" {
		f.close()
		return
	}
	gs.mark(f.st)
	f.mu.Lock()
	old, done := f.rel, f.relDone
	f.rel = rel
	f.mu.Unlock()
	if old != nil {
		old()
	}
	if done {
		rel()
	}
}

// setRel bzw. dropRel: Platz des Flusses merken bzw. am Ende freigeben.
func (f *qflow) setRel(r func()) {
	f.mu.Lock()
	f.rel = r
	f.mu.Unlock()
}

func (f *qflow) dropRel() {
	f.mu.Lock()
	r := f.rel
	f.rel, f.relDone = nil, true
	f.mu.Unlock()
	if r != nil {
		r()
	}
}

// nodeSCID: Source Connection ID eines langen QUIC-Pakets der Node (nil = keins bzw. Version Negotiation).
func nodeSCID(p []byte) []byte {
	if len(p) < 7 || p[0]&0x80 == 0 || (p[1]|p[2]|p[3]|p[4]) == 0 {
		return nil
	}
	i := 6 + int(p[5])
	if i >= len(p) {
		return nil
	}
	l := int(p[i])
	if l > 20 || i+1+l > len(p) {
		return nil
	}
	return p[i+1 : i+1+l]
}

func (f *qflow) close() {
	f.once.Do(func() {
		close(f.done)
		f.d.mu.Lock()
		if f.d.flows[f.addr] == f {
			delete(f.d.flows, f.addr)
		}
		f.d.mu.Unlock()
	})
}

// run: Stream zur Node (hier oder ueber den Nachbarn), dann Datagramme in beide Richtungen.
func (f *qflow) run(re *route, sni string) {
	defer f.close()
	s := f.d.s
	client := f.addr.String()
	if re.Blocked != "" {
		return
	}
	st := f.st
	if !re.allows(f.addr.Addr()) {
		st.block(bACL, f.addr.Addr())
		return
	}
	release, why := s.guard.admitUDP(f.addr.Addr(), st) // Adresse noch nicht nachgewiesen; Abweisungen beim Namen
	if why != "" {
		return
	}
	f.setRel(release)
	defer f.dropRel()
	var conn net.Conn
	counted := true // gezaehlt und begrenzt wird beim Server mit dem Tunnel
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if p := s.peerFor(re.Tunnels); p != nil && tunnel.HasCap(p.Caps, tunnel.CapQUIC) {
		ts, err := s.openPeer(ctx, p, tunnel.Header{Kind: tunnel.KindQUIC, Client: client, Host: sni, Port: 443})
		if err == nil {
			conn = ts
		}
	} else if p == nil {
		if pc := s.dialPeer(ctx, tunnel.KindQUIC, sni, 443, client, nil); pc != nil {
			conn, counted = pc, false
			st.ViaPeer.Add(1)
		}
	}
	cancel()
	if conn == nil {
		st.NoTunnel.Add(1)
		return
	}
	defer conn.Close()
	defer s.track(re.Name, re.Mode, f.addr.Addr(), f.close)()
	if counted {
		st.conn(f.addr.Addr())
	}
	go func() { // Node -> Besucher
		defer f.close()
		buf := make([]byte, tunnel.MaxDatagram)
		for {
			n, err := tunnel.ReadDatagram(conn, buf)
			if err != nil {
				return
			}
			if !f.proven.Load() { // vor dem Nachweis: ID der Node merken, Antwort begrenzen (gefaelschter Absender)
				if id := nodeSCID(buf[:n]); len(id) >= qpMinCID && (f.scid.Load() == nil || !bytes.Equal(*f.scid.Load(), id)) {
					id = append([]byte(nil), id...)
					f.scid.Store(&id)
				}
				if f.out.Load()+int64(n) > qpFree+qpAmp*f.in.Load() {
					continue
				}
			}
			if _, err := f.d.c.WriteToUDPAddrPort(buf[:n], f.addr); err != nil && errors.Is(err, net.ErrClosed) {
				return
			}
			f.out.Add(int64(n))
			if counted {
				st.BytesOut.Add(int64(n))
				s.bw.take(re.UserID, n)
			}
		}
	}()
	for { // Besucher -> Node
		select {
		case <-f.done:
			return
		case p := <-f.q:
			if err := tunnel.WriteDatagram(conn, p); err != nil {
				return
			}
			if counted {
				st.BytesIn.Add(int64(len(p)))
				s.bw.take(re.UserID, len(p))
			}
		}
	}
}

// open: Anzahl durchgereichter QUIC-Besucher (fuer /health).
func (d *quicDemux) open() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.flows)
}

// --- net.PacketConn fuer quic-go

func (d *quicDemux) WriteTo(p []byte, addr net.Addr) (int, error) { return d.c.WriteTo(p, addr) }
func (d *quicDemux) Close() error {
	d.closed.Store(true)
	d.mu.Lock()
	var all []*qflow
	for _, f := range d.flows {
		all = append(all, f)
	}
	d.mu.Unlock()
	for _, f := range all {
		f.close()
	}
	return d.c.Close()
}
func (d *quicDemux) LocalAddr() net.Addr                { return d.c.LocalAddr() }
func (d *quicDemux) SetDeadline(t time.Time) error      { return d.c.SetDeadline(t) }
func (d *quicDemux) SetReadDeadline(t time.Time) error  { return d.c.SetReadDeadline(t) }
func (d *quicDemux) SetWriteDeadline(t time.Time) error { return d.c.SetWriteDeadline(t) }
func (d *quicDemux) SetReadBuffer(n int) error          { return d.c.SetReadBuffer(n) }
func (d *quicDemux) SetWriteBuffer(n int) error         { return d.c.SetWriteBuffer(n) }
