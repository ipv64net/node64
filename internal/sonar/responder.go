package sonar

// Antworter auf UDP 6464 (Vertrag Abschnitt 4): beantwortet nur exakt 64 Byte grosse Anfragen im Format "S64?" mit
// einer gleich grossen Antwort "S64!". Grenzen: je Quelle 5 Pakete/s (IPv6 je /64), gesamt 50 Pakete/s, Rest wird
// still verworfen. Keine Antwort an private/reservierte Quellen oder Quellports < 1024 (keine Reflexion auf Dienste).
// Nur wenn der Antworter selbst an Loopback gebunden ist (Tests), beantwortet er Loopback-Quellen.

import (
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
	return &Responder{
		conn:     c,
		short:    udpShortID(nodeID),
		loopback: ua.IP != nil && ua.IP.IsLoopback(),
		lim:      newRespLimiter(),
		seen:     map[respKey]*Inbound{},
	}, nil
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
	fails := 0
	for {
		n, src, err := r.conn.ReadFromUDPAddrPort(buf)
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
			_, _ = r.conn.WriteToUDPAddrPort(out[:], src)
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
