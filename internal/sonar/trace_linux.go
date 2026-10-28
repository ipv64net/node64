//go:build linux

package sonar

// Traceroute ohne Rechte (Linux): ein verbundener SOCK_DGRAM-Socket (Ping-Socket fuer ICMP oder UDP) mit
// IP_RECVERR/IPV6_RECVERR. ICMP-Fehler (TTL abgelaufen, unerreichbar) landen in der Fehlerwarteschlange des Sockets
// samt Absender (Router). Der Socket laeuft bewusst ausserhalb des Go-Netpollers (blockierendes recvfrom mit
// SO_RCVTIMEO): ein reines EPOLLERR wuerde dort als Fehler haengen bleiben. Eine Probe gleichzeitig, je Probe
// hoechstens timeout.

import (
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"syscall"
	"time"
)

// Herkunft eines Eintrags der Fehlerwarteschlange (linux/errqueue.h).
const (
	traceOriginICMP  = 2
	traceOriginICMP6 = 3
)

type dgramTracer struct {
	fd    int
	dst   netip.Addr
	v6    bool
	icmp  bool
	short [4]byte // eigene Kurz-ID fuer UDP-Proben
	nonce [8]byte // Nonce der laufenden UDP-Probe
	buf   []byte
	oob   []byte
}

func newDgramTracer(dst netip.Addr, useICMP bool, port int, short [4]byte) (tracer, error) {
	t := &dgramTracer{dst: dst, v6: dst.Is6(), icmp: useICMP, short: short, buf: make([]byte, 1500), oob: make([]byte, 512)}
	domain, proto := syscall.AF_INET, syscall.IPPROTO_UDP
	if t.v6 {
		domain = syscall.AF_INET6
	}
	if useICMP {
		proto = syscall.IPPROTO_ICMP
		if t.v6 {
			proto = syscall.IPPROTO_ICMPV6
		}
	}
	fd, err := syscall.Socket(domain, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, proto)
	if err != nil {
		return nil, err
	}
	t.fd = fd
	if t.v6 {
		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_RECVERR, 1)
	} else {
		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_RECVERR, 1)
	}
	if err == nil {
		var sa syscall.Sockaddr = &syscall.SockaddrInet4{Port: port, Addr: dst.As4()}
		if t.v6 {
			sa = &syscall.SockaddrInet6{Port: port, Addr: dst.As16()}
		}
		err = syscall.Connect(fd, sa) // fester Flow: gleiche Adressen und Ports fuer alle Proben
	}
	if err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	return t, nil
}

func (t *dgramTracer) close() { _ = syscall.Close(t.fd) }

func (t *dgramTracer) probe(ttl, k int, timeout time.Duration) traceReply {
	var err error
	if t.v6 {
		err = syscall.SetsockoptInt(t.fd, syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
	} else {
		err = syscall.SetsockoptInt(t.fd, syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
	}
	if err != nil {
		return traceReply{err: err}
	}
	t.drain()
	var pkt []byte
	if t.icmp {
		pkt = traceEcho(t.v6, 0, k)
	} else {
		_, _ = rand.Read(t.nonce[:])
		pkt = make([]byte, s64PacketLen)
		s64Encode(pkt, s64MagicReq, t.nonce, t.short)
	}
	start := time.Now()
	if _, err := syscall.Write(t.fd, pkt); err != nil {
		if err != syscall.ECONNREFUSED {
			return traceReply{err: err}
		}
		if _, err := syscall.Write(t.fd, pkt); err != nil {
			return traceReply{err: err}
		}
	}
	deadline := start.Add(timeout)
	for {
		rem := time.Until(deadline)
		if rem < time.Millisecond {
			r, _ := t.errQueue(k, start)
			return r
		}
		tv := syscall.NsecToTimeval(rem.Nanoseconds()) // nie 0 (= ohne Ende)
		_ = syscall.SetsockoptTimeval(t.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
		n, _, err := syscall.Recvfrom(t.fd, t.buf, 0)
		if err == nil {
			if t.matchReply(t.buf[:n], k) {
				return traceReply{addr: t.dst, rtt: time.Since(start), reached: true}
			}
			continue
		}
		if err == syscall.EINTR {
			continue
		}
		// Zeitablauf oder gemeldeter ICMP-Fehler (sk_err): Fehlerwarteschlange lesen
		if r, ok := t.errQueue(k, start); ok {
			return r
		}
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			return traceReply{}
		}
	}
}

// matchReply prueft eine direkte Antwort des Ziels (Echo-Antwort bzw. "S64!" mit unserer Nonce).
func (t *dgramTracer) matchReply(b []byte, k int) bool {
	if !t.icmp {
		nonce, _, ok := s64Parse(b, s64MagicResp)
		return ok && nonce == t.nonce
	}
	want := byte(0)
	if t.v6 {
		want = 129
	}
	return len(b) >= 8 && b[0] == want && int(binary.BigEndian.Uint16(b[6:8])) == k&0xffff
}

// errQueue liest die Fehlerwarteschlange und liefert den ersten Eintrag, der zu Probe k gehoert.
func (t *dgramTracer) errQueue(k int, start time.Time) (traceReply, bool) {
	for range 16 {
		n, oobn, _, _, err := syscall.Recvmsg(t.fd, t.buf, t.oob, syscall.MSG_ERRQUEUE|syscall.MSG_DONTWAIT)
		if err != nil {
			return traceReply{}, false
		}
		rtt := time.Since(start)
		typ, from, ok := traceParseErr(t.oob[:oobn], t.v6)
		if !ok || !t.matchQuoted(t.buf[:n], k) {
			continue
		}
		if t.v6 {
			switch typ {
			case 3: // Zeit abgelaufen
				return traceReply{addr: from, rtt: rtt}, true
			case 1: // unerreichbar (Code 4 = Port)
				return traceReply{addr: from, rtt: rtt, reached: from == t.dst, stop: true}, true
			}
		} else {
			switch typ {
			case 11:
				return traceReply{addr: from, rtt: rtt}, true
			case 3:
				return traceReply{addr: from, rtt: rtt, reached: from == t.dst, stop: true}, true
			}
		}
	}
	return traceReply{}, false
}

// matchQuoted prueft das zitierte Paket, soweit vorhanden: bei ICMP Typ und Sequenz, bei UDP die Nonce.
func (t *dgramTracer) matchQuoted(q []byte, k int) bool {
	if t.icmp {
		if len(q) < 8 {
			return true
		}
		want := byte(8)
		if t.v6 {
			want = 128
		}
		return q[0] == want && int(binary.BigEndian.Uint16(q[6:8])) == k&0xffff
	}
	if len(q) < 14 {
		return true // Router zitieren oft nur 8 Byte (UDP-Kopf), der Rest fehlt
	}
	return [8]byte(q[6:14]) == t.nonce
}

// drain leert Fehlerwarteschlange, Empfangspuffer und sk_err vor einer neuen Probe (spaete Antworten).
func (t *dgramTracer) drain() {
	for range 64 {
		if _, _, _, _, err := syscall.Recvmsg(t.fd, t.buf, t.oob, syscall.MSG_ERRQUEUE|syscall.MSG_DONTWAIT); err != nil {
			break
		}
	}
	for range 64 {
		_, _, err := syscall.Recvfrom(t.fd, t.buf, syscall.MSG_DONTWAIT)
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			break
		}
	}
	_, _ = syscall.GetsockoptInt(t.fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
}

// traceParseErr liest sock_extended_err (16 Byte: errno, origin, type, code, pad, info, data) und die
// Absenderadresse (sockaddr dahinter) aus den Steuerdaten.
func traceParseErr(oob []byte, v6 bool) (typ uint8, from netip.Addr, ok bool) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return 0, from, false
	}
	for _, m := range msgs {
		if v6 && (m.Header.Level != syscall.IPPROTO_IPV6 || m.Header.Type != syscall.IPV6_RECVERR) {
			continue
		}
		if !v6 && (m.Header.Level != syscall.IPPROTO_IP || m.Header.Type != syscall.IP_RECVERR) {
			continue
		}
		d := m.Data
		if len(d) < 16+4 {
			continue
		}
		origin := d[4]
		if (v6 && origin != traceOriginICMP6) || (!v6 && origin != traceOriginICMP) {
			continue
		}
		typ = d[5]
		sa := d[16:]
		switch binary.NativeEndian.Uint16(sa[0:2]) {
		case syscall.AF_INET:
			if len(sa) >= 8 {
				from = netip.AddrFrom4([4]byte(sa[4:8]))
			}
		case syscall.AF_INET6:
			if len(sa) >= 24 {
				from = netip.AddrFrom16([16]byte(sa[8:24])).Unmap()
			}
		}
		if from.IsValid() {
			return typ, from, true
		}
	}
	return 0, from, false
}
