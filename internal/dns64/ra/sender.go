package ra

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

// Zeiten nach RFC 4861/8106: RA alle 150-200 s, DNS-Angaben gelten 3 x 200 s; nach dem Start drei RAs im Abstand
// von 16 s, auf eine Router Solicitation hoechstens alle 3 s.
const (
	minInterval = 150 * time.Second
	maxInterval = 200 * time.Second
	Lifetime    = 3 * maxInterval
	initialGap  = 16 * time.Second
	initialRAs  = 3
	rsGap       = 3 * time.Second
	routerKeep  = 30 * time.Minute // Router ohne neues RA verschwinden aus der Liste
)

var (
	allNodes   = net.ParseIP("ff02::1")
	allRouters = net.ParseIP("ff02::2")
)

// Status ist der Zustand einer Schnittstelle (Seite, API).
type Status struct {
	Iface    string       `json:"interface"`
	DNS      []netip.Addr `json:"dns"`       // zuletzt angekuendigt
	LastSent time.Time    `json:"last_sent"` // Null = noch nicht
	Error    string       `json:"error,omitempty"`
	ErrKind  string       `json:"error_kind,omitempty"` // no_iface | no_addr | send
}

// Sender kuendigt auf den Schnittstellen den DNS-Server an und merkt sich die RAs der Router.
type Sender struct {
	Ifaces  []string
	Domains []string
	DNS     func(iface string) []netip.Addr // je RA neu gelesen (Adressen wechseln mit dem Praefix)
	Log     *slog.Logger

	mu      sync.Mutex
	state   map[string]*ifState
	routers map[string]Router // Schnittstelle|Quelle
	err     string            // Socket
	sent    atomic.Int64
}

type ifState struct {
	index  int
	mac    net.HardwareAddr
	joined bool
	dns    []netip.Addr
	last   time.Time
	err    string
	kind   string
}

func (s *Sender) init() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		s.state, s.routers = map[string]*ifState{}, map[string]Router{}
		for _, n := range s.Ifaces {
			s.state[n] = &ifState{}
		}
	}
	if s.Log == nil {
		s.Log = slog.New(slog.DiscardHandler)
	}
}

// Run sendet bis ctx endet und nimmt die Ankuendigung dann zurueck; scheitert der Socket (z. B. ohne cap_net_raw),
// versucht es jede Minute neu.
func (s *Sender) Run(ctx context.Context) {
	s.init()
	for {
		err := s.run(ctx)
		if ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		s.err = err.Error()
		s.mu.Unlock()
		s.Log.Warn("ra socket", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
	}
}

// Err: Fehler des Sockets ("" = laeuft).
func (s *Sender) Err() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Sent: gesendete RAs seit dem Start.
func (s *Sender) Sent() int64 { return s.sent.Load() }

// Status liefert den Zustand je Schnittstelle (Reihenfolge wie Ifaces).
func (s *Sender) Status() []Status {
	s.init()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Status{}
	for _, n := range s.Ifaces {
		st := s.state[n]
		out = append(out, Status{Iface: n, DNS: slices.Clone(st.dns), LastSent: st.last, Error: st.err, ErrKind: st.kind})
	}
	return out
}

// Routers liefert die Router, deren RA in den letzten 30 Minuten kam.
func (s *Sender) Routers() []Router {
	s.init()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Router{}
	for k, r := range s.routers {
		if time.Since(r.LastSeen) > routerKeep {
			delete(s.routers, k)
			continue
		}
		out = append(out, r)
	}
	sortRouters(out)
	return out
}

func sortRouters(list []Router) {
	slices.SortFunc(list, func(a, b Router) int {
		if c := strings.Compare(a.Iface, b.Iface); c != 0 {
			return c
		}
		return a.Source.Compare(b.Source)
	})
}

// listen oeffnet einen ICMPv6-Socket (braucht cap_net_raw) fuer die genannten Typen, mit Hop-Limit 255.
func listen(types ...ipv6.ICMPType) (*icmp.PacketConn, *ipv6.PacketConn, error) {
	c, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return nil, nil, err
	}
	p := c.IPv6PacketConn()
	var f ipv6.ICMPFilter
	f.SetAll(true)
	for _, t := range types {
		f.Accept(t)
	}
	if err := p.SetICMPFilter(&f); err != nil {
		c.Close()
		return nil, nil, err
	}
	if err := p.SetControlMessage(ipv6.FlagHopLimit|ipv6.FlagInterface, true); err != nil {
		c.Close()
		return nil, nil, err
	}
	_ = p.SetMulticastHopLimit(255)
	_ = p.SetHopLimit(255)
	_ = p.SetMulticastLoopback(false)
	return c, p, nil
}

func (s *Sender) run(ctx context.Context) error {
	c, p, err := listen(ipv6.ICMPTypeRouterSolicitation, ipv6.ICMPTypeRouterAdvertisement)
	if err != nil {
		return err
	}
	defer c.Close()
	s.mu.Lock()
	s.err = ""
	s.mu.Unlock()
	rs := make(chan string, 16)
	go s.read(p, rs)
	s.refresh(p)
	for _, n := range s.Ifaces { // Router fragen: seine Flags M/O gelten auch fuer das eigene RA
		if st := s.get(n); st.index > 0 {
			_ = s.write(p, n, st.index, solicit(st.mac))
		}
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	initial := initialRAs
	for {
		select {
		case <-ctx.Done():
			s.withdraw(p)
			return nil
		case n := <-rs:
			if st := s.get(n); time.Since(st.last) >= rsGap {
				time.Sleep(rand.N(500 * time.Millisecond)) // RFC 4861: zufaellig verzoegert
				s.announce(p, n)
			}
		case <-timer.C:
			s.refresh(p)
			for _, n := range s.Ifaces {
				s.announce(p, n)
			}
			next := minInterval + rand.N(maxInterval-minInterval)
			if initial--; initial > 0 {
				next = initialGap
			}
			timer.Reset(next)
		}
	}
}

// get: Kopie des Zustands einer Schnittstelle.
func (s *Sender) get(n string) ifState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.state[n]; st != nil {
		return *st
	}
	return ifState{}
}

// refresh sucht die Schnittstellen (auch spaeter angelegte) und tritt dort der Gruppe aller Router bei (fuer RS).
func (s *Sender) refresh(p *ipv6.PacketConn) {
	for _, n := range s.Ifaces {
		ifi, err := net.InterfaceByName(n)
		s.mu.Lock()
		st := s.state[n]
		if err != nil {
			st.index, st.joined, st.err, st.kind = 0, false, err.Error(), "no_iface"
			s.mu.Unlock()
			continue
		}
		if !st.joined || st.index != ifi.Index {
			st.joined = p.JoinGroup(ifi, &net.IPAddr{IP: allRouters}) == nil
		}
		st.index, st.mac = ifi.Index, ifi.HardwareAddr
		if st.kind == "no_iface" {
			st.err, st.kind = "", ""
		}
		s.mu.Unlock()
	}
}

func (s *Sender) write(p *ipv6.PacketConn, iface string, index int, b []byte) error {
	dst := allNodes
	if b[0] == typeRS {
		dst = allRouters
	}
	_, err := p.WriteTo(b, &ipv6.ControlMessage{HopLimit: 255, IfIndex: index}, &net.IPAddr{IP: dst, Zone: iface})
	return err
}

// flags: M/O aus dem neuesten RA eines Default-Routers auf der Schnittstelle.
func (s *Sender) flags(iface string) (bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var best Router
	for _, r := range s.routers {
		if r.Iface == iface && r.Lifetime > 0 && r.LastSeen.After(best.LastSeen) && time.Since(r.LastSeen) <= routerKeep {
			best = r
		}
	}
	return best.Managed, best.Other
}

// announce sendet ein RA mit den aktuellen DNS-Adressen der Schnittstelle (nicht mehr gueltige mit Lifetime 0).
func (s *Sender) announce(p *ipv6.PacketConn, n string) {
	st := s.get(n)
	if st.index == 0 {
		return
	}
	var dns []netip.Addr
	if s.DNS != nil {
		dns = s.DNS(n)
	}
	var gone []netip.Addr
	for _, a := range st.dns {
		if !slices.Contains(dns, a) {
			gone = append(gone, a)
		}
	}
	setErr := func(kind, msg string) {
		s.mu.Lock()
		s.state[n].err, s.state[n].kind = msg, kind
		s.mu.Unlock()
	}
	if len(dns) == 0 && len(gone) == 0 {
		setErr("no_addr", "no IPv6 address for DNS")
		return
	}
	m, o := s.flags(n)
	ad := Ad{Managed: m, Other: o, DNS: dns, Withdraw: gone, Lifetime: Lifetime, MAC: st.mac}
	if len(dns) > 0 {
		ad.Domains = s.Domains
	}
	if err := s.write(p, n, st.index, ad.Marshal()); err != nil {
		setErr("send", err.Error())
		return
	}
	s.sent.Add(1)
	s.mu.Lock()
	x := s.state[n]
	x.dns, x.last, x.err, x.kind = dns, time.Now(), "", ""
	if len(dns) == 0 {
		x.err, x.kind = "no IPv6 address for DNS", "no_addr"
	}
	s.mu.Unlock()
}

// withdraw nimmt die Ankuendigung zurueck (Lifetime 0): Geraete fragen den DNS-Server dann nicht mehr.
func (s *Sender) withdraw(p *ipv6.PacketConn) {
	for _, n := range s.Ifaces {
		st := s.get(n)
		if st.index == 0 || len(st.dns) == 0 {
			continue
		}
		m, o := s.flags(n)
		_ = s.write(p, n, st.index, Ad{Managed: m, Other: o, Withdraw: st.dns, Domains: s.Domains, MAC: st.mac}.Marshal())
		s.mu.Lock()
		s.state[n].dns = nil
		s.mu.Unlock()
	}
}

// read nimmt RS (-> rs) und RAs anderer Router an, bis der Socket schliesst.
func (s *Sender) read(p *ipv6.PacketConn, rs chan<- string) {
	buf := make([]byte, 1500)
	for {
		n, cm, src, err := p.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if n < 1 || cm == nil || cm.HopLimit != 255 { // RFC 4861: nur aus dem eigenen Netz
			continue
		}
		name := s.ifaceName(cm.IfIndex)
		ip := srcAddr(src)
		if name == "" || !ip.IsValid() || own(cm.IfIndex, ip) {
			continue
		}
		switch buf[0] {
		case typeRS:
			select {
			case rs <- name:
			default:
			}
		case typeRA:
			if r, ok := Parse(buf[:n]); ok {
				r.Iface, r.Source, r.LastSeen = name, ip, time.Now()
				s.mu.Lock()
				s.routers[name+"|"+ip.String()] = r
				s.mu.Unlock()
			}
		}
	}
}

func (s *Sender) ifaceName(index int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for n, st := range s.state {
		if st.index == index && index > 0 {
			return n
		}
	}
	return ""
}

func srcAddr(a net.Addr) netip.Addr {
	ia, ok := a.(*net.IPAddr)
	if !ok {
		return netip.Addr{}
	}
	ip, _ := netip.AddrFromSlice(ia.IP)
	return ip.Unmap().WithZone("")
}

// own: Adresse dieser Node auf der Schnittstelle (eigene RAs und RS nicht auswerten).
func own(index int, ip netip.Addr) bool {
	ifi, err := net.InterfaceByIndex(index)
	if err != nil {
		return false
	}
	addrs, _ := ifi.Addrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if x, ok := netip.AddrFromSlice(n.IP); ok && x.Unmap() == ip {
				return true
			}
		}
	}
	return false
}

// Probe fragt die Router auf iface per Router Solicitation und sammelt ihre RAs fuer wait (fuer die Anzeige, wenn
// der Sender aus ist).
func Probe(ctx context.Context, iface string, wait time.Duration) ([]Router, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	c, p, err := listen(ipv6.ICMPTypeRouterAdvertisement)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if _, err := p.WriteTo(solicit(ifi.HardwareAddr), &ipv6.ControlMessage{HopLimit: 255, IfIndex: ifi.Index}, &net.IPAddr{IP: allRouters, Zone: iface}); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = p.SetReadDeadline(deadline)
	got := map[netip.Addr]Router{}
	buf := make([]byte, 1500)
	for {
		n, cm, src, err := p.ReadFrom(buf)
		if err != nil {
			break // Frist abgelaufen
		}
		ip := srcAddr(src)
		if cm == nil || cm.HopLimit != 255 || cm.IfIndex != ifi.Index || !ip.IsValid() || own(ifi.Index, ip) {
			continue
		}
		if r, ok := Parse(buf[:n]); ok {
			r.Iface, r.Source, r.LastSeen = iface, ip, time.Now()
			got[ip] = r
		}
	}
	out := []Router{}
	for _, r := range got {
		out = append(out, r)
	}
	sortRouters(out)
	return out, nil
}
