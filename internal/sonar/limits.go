package sonar

// Harte Grenzen des Kerns (Vertrag Abschnitt 8). Sie stehen fest im Code; kein Plan und keine Server-Antwort kann
// sie aendern. Zusaetzlich zum Prober prueft der Kern hier selbst, dass kein privates oder reserviertes Ziel
// gemessen wird.

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// Grenzen je Runde, Sekunde und Tag.
const (
	MaxTargetsLow    = 8    // Ziele je Runde, sparsam
	MaxTargetsNormal = 15   // normal
	MaxTargetsHigh   = 20   // grosszuegig
	MaxTargetsAnchor = 2000 // Anker

	MaxPPS       = 2  // Pakete je Sekunde (Mittel), Knoten
	MaxPPSAnchor = 50 // Anker

	DayLimitLow    = 20000 // Pakete je Tag (UTC), sparsam
	DayLimitNormal = 40000
	DayLimitHigh   = 60000
	DayLimitAnchor = 4000000 // Anker (entspricht knapp 50/s den ganzen Tag)

	MaxCount         = 5  // Pakete je Ping
	MaxTraceCount    = 3  // Versuche je Hop
	MaxTTL           = 30 // Traceroute
	MaxTracesPerHour = 2  // Traceroutes je Stunde

	MaxRounds        = 12  // Runden je Plan (mehr werden ignoriert)
	MaxAnchorTargets = 20  // Rueckfall-Ziele je Plan
	maxWorkersAnchor = 16  // gleichzeitige Messungen im Anker-Modus (Knoten: 1)
	recentMax        = 200 // Ringpuffer fuer Recent
	maxBuffered      = 20000
	maxInboundBuf    = 2000
	maxInboundRows   = 500
)

// limits sind die wirksamen Grenzen eines Knotens.
type limits struct {
	targets int
	pps     int
	day     int
}

// limitsFor liefert die Grenzen fuer Anker bzw. Budget-Stufe (unbekannt = sparsam).
func limitsFor(anchor bool, budget string) limits {
	switch {
	case anchor:
		return limits{MaxTargetsAnchor, MaxPPSAnchor, DayLimitAnchor}
	case budget == BudgetHigh:
		return limits{MaxTargetsHigh, MaxPPS, DayLimitHigh}
	case budget == BudgetNormal:
		return limits{MaxTargetsNormal, MaxPPS, DayLimitNormal}
	default:
		return limits{MaxTargetsLow, MaxPPS, DayLimitLow}
	}
}

func validBudget(b string) bool { return b == BudgetLow || b == BudgetNormal || b == BudgetHigh }

// Nicht oeffentliche IPv4-Bereiche (RFC 6890 und Verwandte).
var reserved4 = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16",
	"192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)

// IPv6: nur 2000::/3, ohne diese Bereiche (IETF-Protokolle/Teredo, Doku, 6to4, 6bone, Doku 3fff::/20).
var global6 = netip.MustParsePrefix("2000::/3")
var reserved6 = mustPrefixes("2001::/23", "2001:db8::/32", "2002::/16", "3ffe::/16", "3fff::/20")

func mustPrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, p := range s {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

// isPublicAddr sagt, ob a eine oeffentliche Unicast-Adresse ist (kein privates, reserviertes oder Sondernetz).
func isPublicAddr(a netip.Addr) bool {
	if !a.IsValid() || a.Zone() != "" {
		return false
	}
	if a.Is4In6() {
		return false // gemappte Adressen nie (koennten private IPv4 verstecken)
	}
	if a.Is4() {
		for _, p := range reserved4 {
			if p.Contains(a) {
				return false
			}
		}
		return true
	}
	if !global6.Contains(a) {
		return false
	}
	for _, p := range reserved6 {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// targetAddr prueft Adresse und Familie eines Ziels.
func targetAddr(t Target) (netip.Addr, bool) {
	a, err := netip.ParseAddr(t.Addr)
	if err != nil || !isPublicAddr(a) {
		return netip.Addr{}, false
	}
	if (t.Family == 4) != a.Is4() || (t.Family != 4 && t.Family != 6) {
		return netip.Addr{}, false
	}
	return a, true
}

// packetsOf ist die Paketzahl einer (bereits bereinigten) Messung.
func packetsOf(t Target) int {
	if t.Method == MethodTrace {
		return t.Count * t.MaxTTL
	}
	return t.Count
}

// inQuiet sagt, ob die lokale Stunde h in der Ruhezeit [von, bis) liegt; {x,x} = keine.
func inQuiet(q [2]int, h int) bool {
	from, to := q[0], q[1]
	switch {
	case from == to:
		return false
	case from < to:
		return h >= from && h < to
	default:
		return h >= from || h < to
	}
}

// bucket ist ein Token-Bucket ueber alle Messungen (Pakete je Sekunde im Mittel). Eine grosse Messung (Trace)
// darf den Stand ins Minus ziehen; die naechsten warten entsprechend laenger.
type bucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

func newBucket(pps int, now func() time.Time) *bucket {
	b := float64(max(pps, MaxCount))
	return &bucket{rate: float64(pps), burst: b, tokens: b, last: now(), now: now}
}

// reserve nimmt n Pakete, wenn genug da sind (0), sonst die Wartezeit bis dahin (nichts genommen).
func (b *bucket) reserve(n int) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = min(b.burst, b.tokens+el*b.rate)
	}
	b.last = now
	need := min(float64(n), b.burst)
	if b.tokens >= need {
		b.tokens -= float64(n)
		return 0
	}
	d := time.Duration((need - b.tokens) / b.rate * float64(time.Second))
	return max(d, time.Millisecond)
}

// wait wartet, bis n Pakete erlaubt sind, und nimmt sie.
func (b *bucket) wait(ctx context.Context, n int) error {
	for {
		d := b.reserve(n)
		if d == 0 {
			return nil
		}
		if err := sleepCtx(ctx, d); err != nil {
			return err
		}
	}
}

// sleepCtx schlaeft d oder bis ctx endet.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
