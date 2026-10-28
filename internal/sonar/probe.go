package sonar

// Messen und Antworten (Vertrag docs/SONAR64-VERTRAG.md, Abschnitte 4 und 8). Der Kern nutzt nur Prober und
// Responder. Grenzen je Runde und Tag setzt der Runner davor; der Prober prueft jedes Ziel trotzdem selbst
// (nur oeffentliche Adressen, Count 1..5, Versuche 1..3, MaxTTL 1..30) und misst nie mehr, als er bekommt.
//
// Dateien: probe.go (Prober, Pruefungen, Statistik), icmp.go (ICMP-Echo), udp.go (UDP 6464, Paketformat),
// trace*.go (Paris-Traceroute), responder.go (Antworter auf UDP 6464).

import (
	"context"
	"errors"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"
)

// HTTPDoer ist der HTTP-Client des Kerns (Tests ersetzen ihn).
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Prober misst ein Ziel. Grenzen (Pakete pro Sekunde, Tagesbudget) setzt der Runner davor durch; der Prober misst
// nur, was er bekommt, prueft aber selbst: keine privaten/reservierten Adressen, Count 1..5, MaxTTL 1..30.
type Prober interface {
	// Ping misst per ICMP oder UDP 6464 (t.Method) und liefert die Zusammenfassung (Round/Target/At setzt der Prober).
	Ping(ctx context.Context, t Target, round time.Time) Result
	// Trace macht eine Paris-Traceroute (gleicher Flow je Hop) und liefert Hops.
	Trace(ctx context.Context, t Target, round time.Time) Result
	// ICMPAllowed sagt, ob ICMP-Echo moeglich ist (Raw-Socket mit cap_net_raw oder Linux-Ping-Socket).
	ICMPAllowed() bool
}

// ProbeConfig stellt den Prober ein.
type ProbeConfig struct {
	NodeID  string        // fuer die Kurzform in UDP-Proben (8 Hex = erste 4 Byte von SHA-256(NodeID))
	Timeout time.Duration // je Paket, Standard 1 s
	Gap     time.Duration // Abstand zwischen Paketen einer Messung, Standard 500 ms (= 2 Pakete/s)
}

// Feste Grenzen des Probers (nicht vom Plan aenderbar).
const (
	probeMaxCount    = 5  // Pakete je Ping
	traceMaxAttempts = 3  // Versuche je Hop
	traceMaxTTL      = 30 // hoechste TTL
	traceMaxSilent   = 6  // so viele stumme Hops in Folge beenden die Traceroute

	probeMinGap     = 10 * time.Millisecond
	probeMinTimeout = 100 * time.Millisecond
	probeMaxTimeout = 5 * time.Second
)

// Kennungen in Result.Error (lokale Gruende; reiner Verlust ist kein Fehler, sondern Recv < Sent).
const (
	probeErrInvalid     = "invalid"     // Ziel oder Parameter ungueltig
	probeErrDenied      = "denied"      // privates/reserviertes Ziel oder lokal verboten
	probeErrICMPDenied  = "icmp_denied" // kein Ping-Socket und kein Raw-Socket
	probeErrNoRoute     = "no_route"    // keine lokale Route (z. B. kein IPv6)
	probeErrSocket      = "socket"      // sonstiger Socket-Fehler
	probeErrCanceled    = "canceled"    // abgebrochen (ctx)
	probeErrUnsupported = "unsupported" // auf diesem System nicht moeglich
	probeErrWrongNode   = "wrong_node"  // UDP: Antwort kam von einem anderen Knoten als geplant
)

// prober ist der echte Prober.
type prober struct {
	cfg   ProbeConfig
	short [4]byte // eigene Kurz-ID
	ping  [2]bool // Linux-Ping-Socket je Familie (0 = IPv4, 1 = IPv6)
	raw   [2]bool // Raw-Socket je Familie

	allowLoopback bool // nur Tests: Loopback als Ziel erlauben
	udpPort       int  // Zielport fuer UDP-Proben (Tests aendern ihn)
}

// NewProber liefert den echten Prober.
func NewProber(cfg ProbeConfig) Prober { return newProber(cfg) }

func newProber(cfg ProbeConfig) *prober {
	if cfg.Timeout <= 0 {
		cfg.Timeout = time.Second
	}
	cfg.Timeout = min(max(cfg.Timeout, probeMinTimeout), probeMaxTimeout)
	if cfg.Gap <= 0 {
		cfg.Gap = 500 * time.Millisecond
	}
	cfg.Gap = max(cfg.Gap, probeMinGap)
	p := &prober{cfg: cfg, short: udpShortID(cfg.NodeID), udpPort: Port}
	p.ping[0] = icmpCanListen("udp4", "0.0.0.0")
	p.ping[1] = icmpCanListen("udp6", "::")
	if !p.ping[0] {
		p.raw[0] = icmpCanListen("ip4:icmp", "0.0.0.0")
	}
	if !p.ping[1] {
		p.raw[1] = icmpCanListen("ip6:ipv6-icmp", "::")
	}
	return p
}

// ICMPAllowed sagt, ob ICMP-Echo in mindestens einer Familie moeglich ist.
func (p *prober) ICMPAllowed() bool { return p.ping[0] || p.ping[1] || p.raw[0] || p.raw[1] }

// Ping misst per ICMP-Echo oder UDP 6464.
func (p *prober) Ping(ctx context.Context, t Target, round time.Time) Result {
	res := Result{Round: round, Target: t.ID, Family: t.Family, Method: t.Method, At: time.Now().UTC()}
	addr, e := p.checkTarget(t)
	if e != "" {
		res.Error = e
		return res
	}
	if t.Count < 1 || t.Count > probeMaxCount {
		res.Error = probeErrInvalid
		return res
	}
	switch t.Method {
	case MethodICMP:
		p.icmpPing(ctx, addr, t.Count, &res)
	case MethodUDP:
		p.udpPing(ctx, addr, t.ID, t.Count, &res)
	default:
		res.Error = probeErrInvalid
	}
	return res
}

// checkTarget prueft Adresse und Familie: nur oeffentliche Unicast-Adressen, keine Zone, keine gemappten Adressen.
func (p *prober) checkTarget(t Target) (netip.Addr, string) {
	a, err := netip.ParseAddr(t.Addr)
	if err != nil || a.Zone() != "" || a.Is4In6() {
		return netip.Addr{}, probeErrInvalid
	}
	if (t.Family != 4 && t.Family != 6) || (t.Family == 4) != a.Is4() {
		return netip.Addr{}, probeErrInvalid
	}
	if !probePublic(a) && !(p.allowLoopback && a.IsLoopback()) {
		return netip.Addr{}, probeErrDenied
	}
	return a, ""
}

// Nicht oeffentliche IPv4-Bereiche (RFC 6890 und Verwandte).
var probeReserved4 = probePrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16",
	"192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)

// IPv6: nur 2000::/3, ohne IETF-Protokolle/Teredo, Doku, 6to4, 6bone und Doku 3fff::/20.
var (
	probeGlobal6   = netip.MustParsePrefix("2000::/3")
	probeReserved6 = probePrefixes("2001::/23", "2001:db8::/32", "2002::/16", "3ffe::/16", "3fff::/20")
)

func probePrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, v := range s {
		out[i] = netip.MustParsePrefix(v)
	}
	return out
}

// probePublic sagt, ob a eine oeffentliche Unicast-Adresse ist (Ziel einer Messung oder Quelle einer Probe).
func probePublic(a netip.Addr) bool {
	if !a.IsValid() || a.Zone() != "" || a.Is4In6() {
		return false
	}
	if a.Is4() {
		for _, p := range probeReserved4 {
			if p.Contains(a) {
				return false
			}
		}
		return true
	}
	if !probeGlobal6.Contains(a) {
		return false
	}
	for _, p := range probeReserved6 {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// probeFam ist der Index einer Familie in prober.ping/raw.
func probeFam(a netip.Addr) int {
	if a.Is4() {
		return 0
	}
	return 1
}

// probeSendErr ordnet einen Sendefehler einer Kennung zu.
func probeSendErr(err error) string {
	switch {
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, syscall.EADDRNOTAVAIL), errors.Is(err, syscall.EAFNOSUPPORT):
		return probeErrNoRoute
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return probeErrDenied
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return probeErrCanceled
	}
	return probeErrSocket
}

// echoConn ist die gemeinsame Sicht auf ICMP- und UDP-Sockets einer Messung.
type echoConn interface {
	SetReadDeadline(time.Time) error
}

// runEcho sendet count Pakete im Abstand gap und wartet je Paket hoechstens timeout auf die Antwort. recv liest
// genau ein Paket und liefert den Index des beantworteten Pakets (-1 = fremd/ungueltig) oder einen Lesefehler.
// Ergebnis: RTT je Paket (-1 = verloren oder nicht gesendet), Zahl der gesendeten Pakete, erster Sendefehler.
func runEcho(ctx context.Context, c echoConn, count int, gap, timeout time.Duration,
	send func(i int) error, recv func() (int, error)) ([]time.Duration, int, error) {
	var mu sync.Mutex
	sentAt := make([]time.Time, count)
	rtts := make([]time.Duration, count)
	for i := range rtts {
		rtts[i] = -1
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Duration(count-1)*gap + timeout + time.Second))
	done := make(chan struct{})
	go func() {
		defer close(done)
		fails := 0
		for {
			i, err := recv()
			now := time.Now()
			if err != nil {
				var ne net.Error
				if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrDeadlineExceeded) ||
					(errors.As(err, &ne) && ne.Timeout()) {
					return
				}
				// z. B. ECONNREFUSED nach ICMP-Port-unerreichbar: gilt als Verlust, weiter lesen
				if fails++; fails > 4*count+4 {
					return
				}
				continue
			}
			if i < 0 || i >= count {
				continue
			}
			mu.Lock()
			if !sentAt[i].IsZero() && rtts[i] < 0 {
				if d := now.Sub(sentAt[i]); d <= timeout {
					rtts[i] = d
				}
			}
			mu.Unlock()
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = c.SetReadDeadline(time.Now()) })
	defer stop()

	sent := 0
	var sendErr error
	var last time.Time
	for i := 0; i < count; i++ {
		if i > 0 {
			t := time.NewTimer(gap)
			select {
			case <-ctx.Done():
				t.Stop()
			case <-t.C:
			}
		}
		if err := ctx.Err(); err != nil {
			sendErr = err
			break
		}
		mu.Lock()
		sentAt[i] = time.Now()
		mu.Unlock()
		if err := send(i); err != nil {
			mu.Lock()
			sentAt[i] = time.Time{}
			mu.Unlock()
			sendErr = err
			break
		}
		last = time.Now()
		sent++
	}
	if sent == 0 || ctx.Err() != nil {
		_ = c.SetReadDeadline(time.Now())
	} else {
		_ = c.SetReadDeadline(last.Add(timeout))
		if ctx.Err() != nil {
			_ = c.SetReadDeadline(time.Now())
		}
	}
	<-done
	mu.Lock()
	defer mu.Unlock()
	return rtts, sent, sendErr
}

// probeStats fuellt Sent, Recv, Min, Mittel, Max und Jitter (mittlere Abweichung aufeinanderfolgender RTTs).
func probeStats(res *Result, rtts []time.Duration, sent int) {
	res.Sent = sent
	vals := make([]float64, 0, len(rtts))
	for _, d := range rtts {
		if d >= 0 {
			vals = append(vals, probeMs(d))
		}
	}
	res.Recv = len(vals)
	if len(vals) == 0 {
		return
	}
	lo, hi, sum, jit := vals[0], vals[0], 0.0, 0.0
	for i, v := range vals {
		lo, hi, sum = min(lo, v), max(hi, v), sum+v
		if i > 0 {
			jit += math.Abs(v - vals[i-1])
		}
	}
	res.MinMs = probeRound(lo)
	res.MaxMs = probeRound(hi)
	res.AvgMs = probeRound(sum / float64(len(vals)))
	if len(vals) > 1 {
		res.JitterMs = probeRound(jit / float64(len(vals)-1))
	}
}

// probeMs rechnet eine Dauer in Millisekunden um.
func probeMs(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// probeRound rundet auf Mikrosekunden (3 Nachkommastellen in ms).
func probeRound(v float64) float64 { return math.Round(v*1000) / 1000 }
