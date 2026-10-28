package sonar

// Paris-Traceroute: alle Proben einer Traceroute gehoeren zum selben Flow, damit Load-Balancer sie denselben Weg
// schicken. Bei ICMP bleiben Typ, Code und Pruefsumme gleich (die steigende Sequenznummer wird in der Nutzlast
// ausgeglichen), bei UDP bleiben Adressen und Ports gleich. Nur die TTL steigt. Je Probe wird gewartet, bis die
// Antwort da ist oder der Timeout ablaeuft (eine Probe gleichzeitig, Abstand mindestens Gap).
//
// Wege, nach Vorrang: Ping-Socket mit Fehlerwarteschlange (Linux, ohne Rechte), Raw-Socket (cap_net_raw),
// UDP 6464 mit Fehlerwarteschlange (Linux, ohne Rechte; endet am Knoten oder an "Port unerreichbar" vom Ziel).

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// errTraceUnsupported: auf diesem System gibt es den Weg nicht.
var errTraceUnsupported = errors.New("sonar: trace not supported")

// tracer sendet eine Probe mit einer TTL und wartet auf die Antwort.
type tracer interface {
	probe(ttl, k int, timeout time.Duration) traceReply
	close()
}

// traceReply ist die Antwort auf eine Probe.
type traceReply struct {
	addr    netip.Addr    // Antwortender (Router oder Ziel); ungueltig = keine Antwort
	rtt     time.Duration //
	reached bool          // Ziel hat geantwortet (Echo-Antwort, "S64!", unerreichbar vom Ziel selbst)
	stop    bool          // unterwegs unerreichbar: nicht weiter
	err     error         // lokaler Sendefehler
}

// Trace macht eine Paris-Traceroute zu t (Count = Versuche je Hop 1..3, MaxTTL 1..30, 0 = 30).
func (p *prober) Trace(ctx context.Context, t Target, round time.Time) Result {
	res := Result{Round: round, Target: t.ID, Family: t.Family, Method: MethodTrace, At: time.Now().UTC()}
	addr, e := p.checkTarget(t)
	if e != "" {
		res.Error = e
		return res
	}
	maxTTL := t.MaxTTL
	if maxTTL == 0 {
		maxTTL = traceMaxTTL
	}
	if t.Count < 1 || t.Count > traceMaxAttempts || maxTTL < 1 || maxTTL > traceMaxTTL {
		res.Error = probeErrInvalid
		return res
	}
	tr, e := p.newTracer(addr)
	if e != "" {
		res.Error = e
		return res
	}
	defer tr.close()

	var last time.Time
	k, silent := 0, 0
	for ttl := 1; ttl <= maxTTL; ttl++ {
		var r traceReply
		for a := 0; a < t.Count; a++ {
			if wait := p.cfg.Gap - time.Since(last); !last.IsZero() && wait > 0 {
				tm := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					tm.Stop()
				case <-tm.C:
				}
			}
			if ctx.Err() != nil {
				res.Error = probeErrCanceled
				return res
			}
			k++
			last = time.Now()
			r = tr.probe(ttl, k, p.cfg.Timeout)
			if r.err != nil {
				res.Error = probeSendErr(r.err)
				return res
			}
			res.Sent++
			if r.addr.IsValid() {
				break
			}
		}
		hop := Hop{TTL: ttl}
		if r.addr.IsValid() {
			res.Recv++
			hop.Addr = r.addr.String()
			hop.RTTMs = probeRound(probeMs(r.rtt))
			silent = 0
		} else {
			silent++
		}
		res.Hops = append(res.Hops, hop)
		if r.reached {
			ms := probeRound(probeMs(r.rtt))
			res.MinMs, res.AvgMs, res.MaxMs = ms, ms, ms
			break
		}
		if r.stop || silent >= traceMaxSilent {
			break
		}
	}
	return res
}

// newTracer waehlt den Weg fuer die Familie von a.
func (p *prober) newTracer(a netip.Addr) (tracer, string) {
	fi := probeFam(a)
	if p.ping[fi] {
		if tr, err := newDgramTracer(a, true, 0, p.short); err == nil {
			return tr, ""
		}
	}
	if p.raw[fi] {
		if tr, err := newRawTracer(a); err == nil {
			return tr, ""
		}
	}
	tr, err := newDgramTracer(a, false, p.udpPort, p.short)
	switch {
	case err == nil:
		return tr, ""
	case errors.Is(err, errTraceUnsupported):
		return nil, probeErrUnsupported
	}
	return nil, probeSendErr(err)
}

// traceEcho baut eine ICMP-Echo-Anfrage mit Sequenz k. Die Nutzlast gleicht k aus (seq + Ausgleich = 0xff00), so
// bleibt die Pruefsumme bei fester ID fuer alle Proben gleich (Paris). Beim Ping-Socket setzt der Kernel ID und
// Pruefsumme, beide bleiben ebenfalls gleich.
func traceEcho(v6 bool, id, k int) []byte {
	var data [16]byte
	copy(data[:], "S64T")
	binary.BigEndian.PutUint16(data[4:], uint16(0xff00-k))
	var typ icmp.Type = ipv4.ICMPTypeEcho
	if v6 {
		typ = ipv6.ICMPTypeEchoRequest
	}
	m := icmp.Message{Type: typ, Body: &icmp.Echo{ID: id, Seq: k & 0xffff, Data: data[:]}}
	b, _ := m.Marshal(nil) // IPv6: Pruefsumme rechnet der Kernel
	return b
}

// traceQuoted prueft das zitierte Paket in einer ICMP-Fehlermeldung: unsere Echo-Anfrage an dst mit id und seq.
// Ist das Zitat zu kurz fuer ID und Sequenz, zaehlt die Zieladresse allein.
func traceQuoted(v6 bool, q []byte, dst netip.Addr, id, seq int) bool {
	var off int
	if v6 {
		if len(q) < 40 || q[6] != icmpProto6 || netip.AddrFrom16([16]byte(q[24:40])) != dst {
			return false
		}
		off = 40
	} else {
		if len(q) < 20 {
			return false
		}
		ihl := int(q[0]&0x0f) * 4
		if ihl < 20 || len(q) < ihl || q[9] != icmpProto4 || netip.AddrFrom4([4]byte(q[16:20])) != dst {
			return false
		}
		off = ihl
	}
	ic := q[off:]
	if len(ic) < 8 {
		return len(ic) == 0
	}
	want := byte(8)
	if v6 {
		want = 128
	}
	return ic[0] == want && int(binary.BigEndian.Uint16(ic[4:6])) == id && int(binary.BigEndian.Uint16(ic[6:8])) == seq
}

// rawTracer ist der Weg ueber einen Raw-Socket (cap_net_raw): er sieht alle ICMP-Pakete und filtert selbst.
type rawTracer struct {
	c   *icmp.PacketConn
	dst netip.Addr
	to  net.Addr
	v6  bool
	id  int
	buf []byte
}

func newRawTracer(dst netip.Addr) (*rawTracer, error) {
	network, laddr := "ip4:icmp", "0.0.0.0"
	if dst.Is6() {
		network, laddr = "ip6:ipv6-icmp", "::"
	}
	c, err := icmp.ListenPacket(network, laddr)
	if err != nil {
		return nil, err
	}
	t := &rawTracer{c: c, dst: dst, to: icmpDst(dst, true), v6: dst.Is6(), id: icmpRand16(), buf: make([]byte, 1500)}
	if t.v6 {
		var f ipv6.ICMPFilter
		f.SetAll(true)
		f.Accept(ipv6.ICMPTypeEchoReply)
		f.Accept(ipv6.ICMPTypeTimeExceeded)
		f.Accept(ipv6.ICMPTypeDestinationUnreachable)
		_ = c.IPv6PacketConn().SetICMPFilter(&f)
	}
	return t, nil
}

func (t *rawTracer) close() { _ = t.c.Close() }

func (t *rawTracer) probe(ttl, k int, timeout time.Duration) traceReply {
	var err error
	proto := icmpProto4
	if t.v6 {
		proto = icmpProto6
		err = t.c.IPv6PacketConn().SetHopLimit(ttl)
	} else {
		err = t.c.IPv4PacketConn().SetTTL(ttl)
	}
	if err != nil {
		return traceReply{err: err}
	}
	start := time.Now()
	if _, err := t.c.WriteTo(traceEcho(t.v6, t.id, k), t.to); err != nil {
		return traceReply{err: err}
	}
	_ = t.c.SetReadDeadline(start.Add(timeout))
	seq := k & 0xffff
	for {
		n, peer, err := t.c.ReadFrom(t.buf)
		if err != nil {
			return traceReply{} // Zeitablauf
		}
		rtt := time.Since(start)
		from := icmpPeer(peer)
		m, err := icmp.ParseMessage(proto, t.buf[:n])
		if err != nil {
			continue
		}
		switch b := m.Body.(type) {
		case *icmp.Echo:
			if (m.Type == ipv4.ICMPTypeEchoReply || m.Type == ipv6.ICMPTypeEchoReply) &&
				b.ID == t.id && b.Seq == seq && from == t.dst {
				return traceReply{addr: from, rtt: rtt, reached: true}
			}
		case *icmp.TimeExceeded:
			if traceQuoted(t.v6, b.Data, t.dst, t.id, seq) {
				return traceReply{addr: from, rtt: rtt}
			}
		case *icmp.DstUnreach:
			if traceQuoted(t.v6, b.Data, t.dst, t.id, seq) {
				return traceReply{addr: from, rtt: rtt, reached: from == t.dst, stop: true}
			}
		}
	}
}
