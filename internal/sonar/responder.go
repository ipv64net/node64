package sonar

// Antworter auf UDP 6464 (Vertrag Abschnitt 4): beantwortet nur exakt 64 Byte grosse Anfragen im Format "S64?" mit
// einer gleich grossen Antwort "S64!". Grenzen: je Quelle 5 Pakete/s (IPv6 je /64), gesamt 50 Pakete/s, Rest wird
// still verworfen. Keine Antwort an private/reservierte Quellen oder Quellports < 1024 (keine Reflexion auf Dienste).
// Nur wenn der Antworter selbst an Loopback gebunden ist (Tests), beantwortet er Loopback-Quellen.
// An der Wildcard gebunden antwortet er von genau der Adresse, an die die Anfrage ging (IP_PKTINFO/IPV6_PKTINFO):
// sonst waehlt der Kernel die Quelle, und bei mehreren Adressen (IPv6 mit Privacy Extensions, Zusatz-IPs) verwirft
// der verbundene Socket des Messenden die Antwort.

import (
	"bytes"
	"cmp"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Grenzen des Antworters (fest).
const (
	respPerSourceRate = 5    // Pakete/s je Quelle
	respTotalRate     = 50   // Pakete/s gesamt
	respMaxSources    = 4096 // gemerkte Quellen fuer die Ratenbegrenzung
	respMaxSeen       = 1024 // Eintraege (Kurz-ID, Familie) bis zum naechsten Drain
	respSweepEvery    = 100 * time.Millisecond
)

// Responder beantwortet Proben auf UDP 6464 (nur Format "S64?", Antwort nie groesser als die Anfrage, Grenzen je
// Quelle und gesamt, siehe Vertrag).
type Responder struct {
	conn     *net.UDPConn
	short    [4]byte
	loopback bool // an Loopback gebunden: Loopback-Quellen erlaubt (Tests)
	lim      *respLimiter

	// Zieladresse je Paket (nur aus Run benutzt): 0 = aus, 4 = IP_PKTINFO (IPv4-Socket), 6 = IPV6_PKTINFO
	// (Dual-Stack, IPv4 als gemappte Adresse). oob6 ist die Vorlage fuer IPV6_PKTINFO, die Adresse steht ab off6.
	pkt  int
	oob6 []byte
	off6 int

	mu   sync.Mutex
	seen map[respKey]*Inbound

	closeOnce sync.Once
	closeErr  error
}

type respKey struct {
	short [4]byte
	fam   int
}

// NewResponder oeffnet UDP 6464 (IPv4 und IPv6). addr leer = ":6464".
func NewResponder(addr, nodeID string) (*Responder, error) {
	if nodeID == "" {
		return nil, errors.New("sonar: responder needs a node id")
	}
	if addr == "" {
		addr = ":" + strconv.Itoa(Port)
	}
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp", ua) // Wildcard = Dual-Stack (IPv4 als gemappte Adressen)
	if err != nil {
		return nil, err
	}
	r := &Responder{
		conn:     c,
		short:    udpShortID(nodeID),
		loopback: ua.IP != nil && ua.IP.IsLoopback(),
		lim:      newRespLimiter(),
		seen:     map[respKey]*Inbound{},
	}
	if ua.IP == nil || ua.IP.IsUnspecified() {
		r.initPktinfo()
	}
	return r, nil
}

// respMarker ist ein Platzhalter, um die Lage der Adresse in IPV6_PKTINFO zu finden (gemappte Adressen setzt
// golang.org/x/net/ipv6 dort nicht selbst ein).
var respMarker = [16]byte{0xff, 0x0f, 'S', '6', '4', 'p', 'k', 't', 'i', 'n', 'f', 'o', 0x53, 0x36, 0x34, 0x21}

// initPktinfo schaltet die Zieladresse je Paket ein, wenn das System es kann (sonst wie bisher ohne).
func (r *Responder) initPktinfo() {
	la, _ := r.conn.LocalAddr().(*net.UDPAddr)
	if la == nil {
		return
	}
	if la.IP.To4() != nil {
		if ipv4.NewPacketConn(r.conn).SetControlMessage(ipv4.FlagDst, true) == nil {
			r.pkt = 4
		}
		return
	}
	if ipv6.NewPacketConn(r.conn).SetControlMessage(ipv6.FlagDst, true) != nil {
		return
	}
	oob := (&ipv6.ControlMessage{Src: respMarker[:]}).Marshal()
	if off := bytes.Index(oob, respMarker[:]); off >= 0 {
		r.pkt, r.oob6, r.off6 = 6, oob, off
	}
}

// dstOf liest die Zieladresse der Anfrage aus den Steuerdaten (Dual-Stack: IPv4 gemappt).
func (r *Responder) dstOf(oob []byte) (netip.Addr, bool) {
	var ip net.IP
	switch r.pkt {
	case 4:
		var cm ipv4.ControlMessage
		if cm.Parse(oob) != nil {
			return netip.Addr{}, false
		}
		ip = cm.Dst
	case 6:
		var cm ipv6.ControlMessage
		if cm.Parse(oob) != nil {
			return netip.Addr{}, false
		}
		ip = cm.Dst
	}
	a, ok := netip.AddrFromSlice(ip)
	return a, ok && a.IsValid() && !a.IsUnspecified()
}

// reply sendet die Antwort, wenn moeglich von der Zieladresse der Anfrage. Anfragen an Multicast- oder
// Broadcast-Adressen bleiben unbeantwortet. Lehnt der Kernel die Quelladresse ab, antwortet er ohne Vorgabe.
func (r *Responder) reply(out []byte, to netip.AddrPort, oob []byte) {
	if r.pkt != 0 {
		if dst, ok := r.dstOf(oob); ok {
			if u := dst.Unmap(); u.IsMulticast() || u == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
				return
			}
			var cm []byte
			if r.pkt == 6 {
				a := dst.As16()
				copy(r.oob6[r.off6:], a[:])
				cm = r.oob6
			} else {
				cm = (&ipv4.ControlMessage{Src: dst.AsSlice()}).Marshal()
			}
			if _, _, err := r.conn.WriteMsgUDPAddrPort(out, cm, to); err == nil {
				return
			}
		}
	}
	_, _ = r.conn.WriteToUDPAddrPort(out, to)
}

// LocalAddr ist die gebundene Adresse (Log, Tests).
func (r *Responder) LocalAddr() net.Addr { return r.conn.LocalAddr() }

// Close schliesst den Socket (auch ohne Run).
func (r *Responder) Close() error {
	r.closeOnce.Do(func() { r.closeErr = r.conn.Close() })
	return r.closeErr
}

// Run beantwortet bis ctx endet (oder Close) und schliesst danach den Socket.
func (r *Responder) Run(ctx context.Context) error {
	stop := context.AfterFunc(ctx, func() { _ = r.Close() })
	defer stop()
	defer r.Close()
	buf := make([]byte, 2*s64PacketLen) // groessere Pakete fallen durch die Laengenpruefung
	var out [s64PacketLen]byte
	var oob [128]byte
	fails := 0
	for {
		var n, oobn int
		var src netip.AddrPort
		var err error
		if r.pkt != 0 {
			n, oobn, _, src, err = r.conn.ReadMsgUDPAddrPort(buf, oob[:])
		} else {
			n, src, err = r.conn.ReadFromUDPAddrPort(buf)
		}
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			// voruebergehend (z. B. ICMP-Fehler einer frueheren Antwort): kurz bremsen, nie heiss laufen
			if fails++; fails > 10 {
				time.Sleep(10 * time.Millisecond)
			}
			continue
		}
		fails = 0
		if r.answer(buf[:n], src, time.Now(), out[:]) {
			r.reply(out[:], src, oob[:oobn])
		}
	}
}

// answer prueft eine Anfrage, wendet die Grenzen an, merkt sie fuer Drain und baut die Antwort in out.
func (r *Responder) answer(b []byte, src netip.AddrPort, now time.Time, out []byte) bool {
	nonce, sender, ok := s64Parse(b, s64MagicReq)
	if !ok || src.Port() < 1024 {
		return false
	}
	a := src.Addr().Unmap()
	if !probePublic(a) && !(r.loopback && a.IsLoopback()) {
		return false
	}
	if !r.lim.allow(a, now) {
		return false
	}
	s64Encode(out, s64MagicResp, nonce, r.short)
	fam := 6
	if a.Is4() {
		fam = 4
	}
	r.mu.Lock()
	k := respKey{sender, fam}
	if in := r.seen[k]; in != nil {
		in.Count++
		in.At = now.UTC()
	} else if len(r.seen) < respMaxSeen {
		r.seen[k] = &Inbound{From: hex.EncodeToString(sender[:]), Family: fam, At: now.UTC(), Count: 1}
	}
	r.mu.Unlock()
	return true
}

// Drain liefert die seit dem letzten Aufruf beantworteten Proben (zusammengefasst je Quelle und Familie).
func (r *Responder) Drain() []Inbound {
	r.mu.Lock()
	out := make([]Inbound, 0, len(r.seen))
	for _, in := range r.seen {
		out = append(out, *in)
	}
	clear(r.seen)
	r.mu.Unlock()
	slices.SortFunc(out, func(x, y Inbound) int {
		return cmp.Or(cmp.Compare(x.From, y.From), cmp.Compare(x.Family, y.Family))
	})
	return out
}

// respBucket ist ein Token-Bucket (Rate = Tiefe, also hoechstens eine Sekunde Vorrat).
type respBucket struct {
	tokens float64
	last   time.Time
}

func (b *respBucket) take(now time.Time, rate float64) bool {
	if d := now.Sub(b.last).Seconds(); d > 0 {
		b.tokens = min(rate, b.tokens+d*rate)
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// respLimiter begrenzt je Quelle und gesamt, mit begrenztem Speicher. Nur aus Run benutzt (kein Lock noetig).
type respLimiter struct {
	total     respBucket
	src       map[netip.Addr]*respBucket
	lastSweep time.Time
}

func newRespLimiter() *respLimiter {
	return &respLimiter{total: respBucket{tokens: respTotalRate}, src: map[netip.Addr]*respBucket{}}
}

// allow sagt, ob eine Anfrage von a jetzt beantwortet werden darf. Zuerst die Quelle (eine laute Quelle
// verbraucht so nichts vom Gesamtbudget), dann gesamt.
func (l *respLimiter) allow(a netip.Addr, now time.Time) bool {
	key := a
	if a.Is6() {
		p, _ := a.Prefix(64)
		key = p.Addr()
	}
	b := l.src[key]
	if b == nil {
		if len(l.src) >= respMaxSources {
			l.sweep(now)
			if len(l.src) >= respMaxSources {
				return false // Tabelle voll (Flut mit vielen Quellen): neue Quellen verwerfen
			}
		}
		b = &respBucket{tokens: respPerSourceRate, last: now}
		l.src[key] = b
	}
	if !b.take(now, respPerSourceRate) {
		return false
	}
	return l.total.take(now, respTotalRate)
}

// sweep entfernt Quellen, deren Bucket wieder voll ist (eine Sekunde ruhig); hoechstens alle 100 ms.
func (l *respLimiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < respSweepEvery {
		return
	}
	l.lastSweep = now
	for k, b := range l.src {
		if now.Sub(b.last) >= time.Second {
			delete(l.src, k)
		}
	}
}
