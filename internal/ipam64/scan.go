package ipam64

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// Netz-Scan (aus dem Entwurf von UlrichSchwarz, gehaertet): Die Node schickt jedem moeglichen Geraet eines direkt
// angeschlossenen Netzes ein einzelnes kleines UDP-Paket (Port 9, "discard"). Dafuer fragt der Kernel die MAC per ARP
// an; wer antwortet, steht danach in der Nachbartabelle. Es werden keine Ports abgetastet und keine besonderen Rechte
// gebraucht.
//
// Grenzen (Plan, Sicherheit): nur IPv4, nur private Netze (RFC 1918, 100.64.0.0/10), hoechstens /22 (sonst laeuft die
// Nachbartabelle des Hosts ueber, gc_thresh3 = 1024), nur Praefixe, die IPAM64 kennt und an denen die Node eine
// Adresse hat, und nicht bei Scan "aus". Ein Scan zur Zeit, im Hintergrund; die Seite fragt den Stand ab. IPv6-Netze
// werden nicht abgetastet (/64 ist zu gross), dort zaehlt die Nachbartabelle (NDP).

const (
	scanPort    = 9
	scanPause   = 2 * time.Millisecond    // zwischen zwei Adressen (ARP nicht fluten)
	scanWait    = 1500 * time.Millisecond // auf ARP-Antworten warten
	scanFresh   = 30 * time.Second        // so frisch muss die Bestaetigung nach dem Scan sein
	scanMinBits = 22                      // groesstes Netz fuer den Scan
)

var (
	// ErrNotAttached: das Netz haengt nicht direkt an der Node (z. B. Docker-Bridge, geroutetes VLAN) - kein ARP.
	ErrNotAttached = errors.New("ipam64: network not directly attached")
	// ErrNoScan: Scan fuer dieses Praefix nicht erlaubt (IPv6, oeffentlich, zu gross, Scan aus).
	ErrNoScan = errors.New("ipam64: scan not allowed for this prefix")
)

var scanPrivate = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
}

// ScanStatus ist der Stand des laufenden bzw. letzten Scans.
type ScanStatus struct {
	Running  bool      `json:"running"`
	Prefix   string    `json:"prefix,omitempty"`
	Started  time.Time `json:"started,omitzero"`
	Finished time.Time `json:"finished,omitzero"`
	Found    int       `json:"found"`
	Error    string    `json:"error,omitempty"`
}

type scanState struct {
	mu sync.Mutex
	st ScanStatus
}

// scanAllowed prueft, ob ein Praefix aktiv gescannt werden darf.
func scanAllowed(p netip.Prefix) bool {
	if !p.Addr().Is4() || p.Bits() < scanMinBits || p.Bits() > 30 {
		return false
	}
	for _, q := range scanPrivate {
		if q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// sweepUDP spricht alle Adressen des Netzes an (ohne Netz- und Broadcast-Adresse).
func sweepUDP(ctx context.Context, p netip.Prefix) {
	c, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return
	}
	defer c.Close()
	last := lastAddr(p)
	for ip := p.Masked().Addr().Next(); ip.IsValid() && ip != last && ctx.Err() == nil; ip = ip.Next() {
		_, _ = c.WriteTo([]byte{0}, net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, scanPort)))
		time.Sleep(scanPause)
	}
}

// attached meldet, ob die Node eine Adresse im Netz hat.
func (m *Module) attached(p netip.Prefix) bool { return attachedIn(m.locals(), p) }

// known liefert die Praefixe, die IPAM64 kennt (eigene und DHCP-Netze), mit ihrer Scan-Einstellung.
func (m *Module) known(ctx context.Context) map[netip.Prefix]string {
	out := map[netip.Prefix]string{}
	for _, h := range m.hintList(ctx) {
		out[h.Subnet] = ScanPassive
	}
	list, _ := m.Prefixes(ctx)
	for _, p := range list {
		if pp, err := netip.ParsePrefix(p.Prefix); err == nil && p.Status != StatusContainer {
			out[pp] = p.Scan
		}
	}
	return out
}

// poll uebernimmt die Nachbartabelle in die Sichtungen.
func (m *Module) poll(ctx context.Context) error {
	_, err := m.collect(ctx, nil, 0)
	return err
}

// collect schreibt die Sichtungen aus der Nachbartabelle (nur Adressen in bekannten Praefixen mit Scan nicht aus) und
// zaehlt die Geraete in only, deren Bestaetigung hoechstens fresh alt ist.
func (m *Module) collect(ctx context.Context, only *netip.Prefix, fresh time.Duration) (int, error) {
	tab, err := m.neigh()
	if err != nil {
		return 0, err
	}
	known := m.known(ctx)
	now := m.now()
	found := 0
	var seen []seenRow
	for ip, n := range tab {
		in := false
		for p, scan := range known {
			in = in || (scan != ScanOff && p.Contains(ip))
		}
		if !in || n.Age > seenKeep {
			continue
		}
		if only != nil && only.Contains(ip) && n.Age <= fresh {
			found++
		}
		seen = append(seen, seenRow{IP: ip, MAC: n.MAC, Last: time.Unix(now.Add(-n.Age).Unix(), 0)})
	}
	if err := m.saveSeen(ctx, seen); err != nil { // eine Transaktion je Runde, nur Aenderungen
		return found, err
	}
	if len(seen) > 0 {
		m.invalidate()
	}
	return found, nil
}

// checkScan prueft, ob ein Praefix jetzt gescannt werden darf.
func (m *Module) checkScan(ctx context.Context, p netip.Prefix) error {
	scan, ok := m.known(ctx)[p]
	if !ok {
		return ErrNotFound
	}
	if scan == ScanOff || !scanAllowed(p) {
		return ErrNoScan
	}
	if !m.attached(p) {
		return ErrNotAttached
	}
	return nil
}

// StartScan startet den Scan eines Praefixes im Hintergrund (ErrBusy, wenn schon einer laeuft).
func (m *Module) StartScan(ctx context.Context, prefix string) error {
	p, err := ParsePrefix(prefix)
	if err != nil {
		return err
	}
	if err := m.checkScan(ctx, p); err != nil {
		return err
	}
	m.mu.Lock()
	life := m.life
	if m.cancel == nil {
		life = nil
	}
	m.mu.Unlock()
	if life == nil {
		return ErrNotFound
	}
	if !m.beginScan(p) {
		return ErrBusy
	}
	go func() {
		sctx, cancel := context.WithTimeout(life, 5*time.Minute)
		defer cancel()
		n, err := m.scanOne(sctx, p)
		m.endScan(n, err)
	}()
	return nil
}

func (m *Module) beginScan(p netip.Prefix) bool {
	m.scan.mu.Lock()
	defer m.scan.mu.Unlock()
	if m.scan.st.Running {
		return false
	}
	m.scan.st = ScanStatus{Running: true, Started: m.now()}
	if p.IsValid() { // automatischer Scan: kein einzelnes Praefix
		m.scan.st.Prefix = p.String()
	}
	return true
}

func (m *Module) endScan(found int, err error) {
	m.scan.mu.Lock()
	defer m.scan.mu.Unlock()
	m.scan.st.Running, m.scan.st.Finished = false, m.now()
	m.scan.st.Found += found
	if err != nil {
		m.scan.st.Error = err.Error()
	}
}

// Scanning liefert den Stand des laufenden bzw. letzten Scans.
func (m *Module) Scanning() ScanStatus {
	m.scan.mu.Lock()
	defer m.scan.mu.Unlock()
	return m.scan.st
}

func (m *Module) scanOne(ctx context.Context, p netip.Prefix) (int, error) {
	m.sweep(ctx, p)
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-time.After(m.wait):
	}
	n, err := m.collect(ctx, &p, scanFresh)
	if err == nil {
		_ = m.core.SetSetting(ctx, setLastScan, strconv.FormatInt(m.now().Unix(), 10))
	}
	return n, err
}

// scanAll scannt alle erlaubten Praefixe mit Scan "aktiv" (automatischer Scan, im Takt der Hintergrundschleife).
func (m *Module) scanAll(ctx context.Context) {
	if !m.beginScan(netip.Prefix{}) {
		return
	}
	total := 0
	var first error
	locs := m.locals() // einmal je Lauf, nicht je Praefix
	for p, scan := range m.known(ctx) {
		if scan != ScanActive || !scanAllowed(p) || !attachedIn(locs, p) || ctx.Err() != nil {
			continue
		}
		n, err := m.scanOne(ctx, p)
		if total += n; err != nil && first == nil {
			first = err
		}
	}
	if total == 0 && first == nil { // nichts zu scannen: wenigstens die Nachbartabelle lesen
		first = m.poll(ctx)
		_ = m.core.SetSetting(ctx, setLastScan, strconv.FormatInt(m.now().Unix(), 10))
	}
	if first != nil && ctx.Err() == nil {
		m.log.Warn("ipam64: scan", "err", first)
	}
	m.endScan(total, first)
}
