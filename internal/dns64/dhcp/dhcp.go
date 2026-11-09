// Package dhcp ist der DHCP-Server von DNS64 (nur IPv4, RFC 2131/2132): Netze je Schnittstelle, feste Adressen
// (Reservierungen), Leases mit Speicher, ARP-Pruefung vor der Vergabe, Erkennen fremder DHCP-Server, Probelauf
// (nur beobachten) und PXE/Netboot. Das Paket haengt nicht von internal/dns64 ab; DNS64 liefert Netze, Reservierungen
// und den Speicher fuer Leases. Plan: docs/PLAN-NODE64-DNS64-DHCP.md.
//
// Aus = kein Socket: Erst Run oeffnet Port 67 (und fuer die Pruefung auf fremde Server kurz Port 68).
package dhcp

import (
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/iana"
)

// Scope ist ein DHCP-Netz (in der Oberflaeche "Netz").
type Scope struct {
	ID            int64
	Name          string
	Iface         string        // Schnittstelle des Hosts (eth0, eth0.20 ...)
	Subnet        netip.Prefix  // z. B. 192.168.1.0/24
	Start, End    netip.Addr    // Adressbereich fuer die Vergabe
	Router        netip.Addr    // Option 3, ungueltig = keiner
	DNS           []netip.Addr  // Option 6, leer = Adresse der Node
	Domain        string        // Option 15 und 119
	Lease         time.Duration // Option 51
	NTP           []netip.Addr  // Option 42
	Authoritative bool          // fremde Adressen: NAK (Umstieg vom Router)
	BootServer    string        // PXE: TFTP-Server (Option 66, als IP auch siaddr), leer = keiner
	BootBIOS      string        // PXE: Boot-Datei fuer BIOS (Option 67)
	BootUEFI      string        // PXE: Boot-Datei fuer UEFI
	BootIPXE      string        // PXE: Boot-Datei, wenn der Client schon iPXE ist (Option 77 "iPXE")
}

// Reservation ist eine feste Adresse fuer eine MAC.
type Reservation struct {
	Scope int64
	MAC   string // aa:bb:cc:dd:ee:ff
	IP    netip.Addr
	Name  string
}

// Zustaende eines Lease.
const (
	StateOffered = "offered" // angeboten, wartet auf REQUEST
	StateBound   = "bound"   // vergeben
	StateFree    = "free"    // zurueckgegeben (RELEASE) bzw. abgelaufen; die IP bekommt derselbe Client wieder
)

// Lease ist die Vergabe einer Adresse an eine MAC (je Netz und MAC ein Eintrag).
type Lease struct {
	Scope    int64
	MAC      string
	IP       netip.Addr
	Hostname string // vom Client (Option 12)
	Expires  time.Time
	State    string
}

// Active meldet, ob die Adresse zum Zeitpunkt now belegt ist.
func (l Lease) Active(now time.Time) bool {
	return l.State != StateFree && now.Before(l.Expires)
}

// Store speichert Leases (DNS64: Tabelle dhcp_leases).
type Store interface {
	SaveLease(Lease) error
	DeleteLease(scope int64, mac string) error
}

// Event ist eine Anfrage fuer die Liste "Letzte Anfragen" (auch im Probelauf).
type Event struct {
	Time     time.Time  `json:"time"`
	Scope    int64      `json:"scope"`
	Type     string     `json:"type"` // discover, request, decline, release, inform
	MAC      string     `json:"mac"`
	Hostname string     `json:"hostname,omitempty"`
	IP       netip.Addr `json:"ip"`
	Result   string     `json:"result"` // offer, ack, nak, ignored, observe, full, conflict, decline, release
}

// Foreign ist ein fremder DHCP-Server im Netz eines Scopes.
type Foreign struct {
	Scope    int64      `json:"scope"`
	Server   netip.Addr `json:"server"`
	LastSeen time.Time  `json:"last_seen"`
}

// Config ist der Stand, mit dem der Server startet.
type Config struct {
	Scopes       []Scope
	Reservations []Reservation
	Leases       []Lease
	Observe      bool // Probelauf: nur zuhoeren, nie antworten, nichts vergeben
}

const (
	offerHold    = time.Minute         // so lange haelt ein OFFER die Adresse
	conflictHold = time.Hour           // Adresse nach ARP-Antwort oder DECLINE gesperrt
	keepFree     = 30 * 24 * time.Hour // zurueckgegebene/abgelaufene Leases merken (gleiche IP fuer denselben Client)
	maxEvents    = 100
	probeWait    = 300 * time.Millisecond
)

// Server vergibt Adressen. Die Felder vor mu werden vor Run gesetzt.
type Server struct {
	Store     Store
	Log       *slog.Logger
	OnChange  func()                                      // Leases geaendert (DNS-Namen, Seite), ohne gehaltene Sperre
	Probe     func(iface string, src, ip netip.Addr) bool // ARP: true = Adresse antwortet (belegt); nil = keine Pruefung
	Now       func() time.Time
	Addrs     func(iface string) []netip.Prefix    // IPv4-Adressen einer Schnittstelle (Tests), nil = vom System
	OnForeign func(scope int64, server netip.Addr) // neuer fremder DHCP-Server im Netz (Benachrichtigung)

	mu        sync.Mutex
	observe   bool
	scopes    []*scope
	events    []Event
	conflicts map[netip.Addr]time.Time
	foreign   map[int64]map[netip.Addr]time.Time
	probes    map[dhcpv4.TransactionID]bool // eigene DISCOVER der Pruefung auf fremde Server
	stats     map[string]uint64
}

type scope struct {
	Scope
	self  netip.Addr // Adresse der Node im Netz (Server-ID), ungueltig = Fehler
	mac   net.HardwareAddr
	err   string
	kind  string                 // Art des Fehlers fuer die Seite: iface, addr, listen
	res   map[string]Reservation // MAC -> Reservierung
	resIP map[netip.Addr]string  // IP -> MAC
	byMAC map[string]*Lease
	byIP  map[netip.Addr]*Lease
}

// New baut den Server aus der Konfiguration (ohne Sockets).
func New(cfg Config, st Store, log *slog.Logger) *Server {
	s := &Server{Store: st, Log: log, observe: cfg.Observe, conflicts: map[netip.Addr]time.Time{}, foreign: map[int64]map[netip.Addr]time.Time{},
		probes: map[dhcpv4.TransactionID]bool{}, stats: map[string]uint64{}}
	for _, c := range cfg.Scopes {
		sc := &scope{Scope: c, res: map[string]Reservation{}, resIP: map[netip.Addr]string{}, byMAC: map[string]*Lease{}, byIP: map[netip.Addr]*Lease{}}
		for _, r := range cfg.Reservations {
			if r.Scope == c.ID && c.Subnet.Contains(r.IP) {
				sc.res[r.MAC], sc.resIP[r.IP] = r, r.MAC
			}
		}
		for _, l := range cfg.Leases {
			if l.Scope == c.ID && c.Subnet.Contains(l.IP) {
				sc.setLease(l)
			}
		}
		s.scopes = append(s.scopes, sc)
	}
	return s
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) logger() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// bind ermittelt je Scope die eigene Adresse und MAC (beim Start).
func (s *Server) bind() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sc := range s.scopes {
		sc.self, sc.err, sc.kind = netip.Addr{}, "", ""
		addrs := s.ifaceAddrs(sc.Iface)
		if addrs == nil {
			sc.err, sc.kind = "interface "+sc.Iface+" not found", "iface"
			continue
		}
		for _, p := range addrs {
			if sc.Subnet.Contains(p.Addr()) {
				sc.self = p.Addr()
				break
			}
		}
		if !sc.self.IsValid() {
			sc.err, sc.kind = "no address of "+sc.Iface+" in "+sc.Subnet.String(), "addr"
		}
		if ifi, err := net.InterfaceByName(sc.Iface); err == nil {
			sc.mac = ifi.HardwareAddr
		}
	}
}

func (s *Server) ifaceAddrs(name string) []netip.Prefix {
	if s.Addrs != nil {
		return s.Addrs(name)
	}
	return IfaceAddrs(name)
}

// IfaceAddrs liefert die IPv4-Adressen einer Schnittstelle (nil = Schnittstelle fehlt).
func IfaceAddrs(name string) []netip.Prefix {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}
	out := []netip.Prefix{}
	as, _ := ifi.Addrs()
	for _, a := range as {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP.To4()); ok && n.IP.To4() != nil {
				bits, _ := n.Mask.Size()
				out = append(out, netip.PrefixFrom(ip, bits))
			}
		}
	}
	return out
}

func (sc *scope) setLease(l Lease) {
	if old := sc.byMAC[l.MAC]; old != nil && sc.byIP[old.IP] == old {
		delete(sc.byIP, old.IP)
	}
	if other := sc.byIP[l.IP]; other != nil && other.MAC != l.MAC {
		delete(sc.byMAC, other.MAC)
	}
	c := l
	sc.byMAC[l.MAC], sc.byIP[l.IP] = &c, &c
}

func (sc *scope) dropLease(mac string) {
	if l := sc.byMAC[mac]; l != nil {
		if sc.byIP[l.IP] == l {
			delete(sc.byIP, l.IP)
		}
		delete(sc.byMAC, mac)
	}
}

func (sc *scope) inPool(ip netip.Addr) bool {
	return ip.Is4() && sc.Subnet.Contains(ip) && ip.Compare(sc.Start) >= 0 && ip.Compare(sc.End) <= 0
}

// free: Adresse fuer mac vergebbar (s.mu gehalten).
func (s *Server) free(sc *scope, ip netip.Addr, mac string, now time.Time) bool {
	if !sc.inPool(ip) || ip == sc.self || ip == sc.Router || ip == sc.Subnet.Masked().Addr() || ip == Broadcast(sc.Subnet) {
		return false
	}
	if m, ok := sc.resIP[ip]; ok && m != mac {
		return false
	}
	if l := sc.byIP[ip]; l != nil && l.MAC != mac && l.Active(now) {
		return false
	}
	return !s.conflict(ip, now)
}

// reserved: feste Adresse von mac, wenn sie gerade nutzbar ist (kein anderer Client haelt sie noch, keine Sperre).
func (s *Server) reserved(sc *scope, mac string, now time.Time) (netip.Addr, bool) {
	r, ok := sc.res[mac]
	if !ok || s.conflict(r.IP, now) {
		return netip.Addr{}, false
	}
	if l := sc.byIP[r.IP]; l != nil && l.MAC != mac && l.Active(now) {
		return netip.Addr{}, false
	}
	return r.IP, true
}

// pick waehlt die Adresse fuer ein OFFER (s.mu gehalten). fresh = neue Adresse fuer den Client (ARP-Pruefung).
func (s *Server) pick(sc *scope, mac string, want netip.Addr, now time.Time) (ip netip.Addr, fresh bool) {
	if ip, ok := s.reserved(sc, mac, now); ok {
		return ip, false
	}
	if l := sc.byMAC[mac]; l != nil && s.free(sc, l.IP, mac, now) {
		return l.IP, false
	}
	if want.IsValid() && s.free(sc, want, mac, now) {
		return want, true
	}
	var oldest *Lease
	for a := sc.Start; a.IsValid() && a.Compare(sc.End) <= 0; a = a.Next() {
		if !s.free(sc, a, mac, now) {
			continue
		}
		l := sc.byIP[a]
		if l == nil {
			return a, true
		}
		if oldest == nil || l.Expires.Before(oldest.Expires) {
			oldest = l
		}
	}
	if oldest != nil {
		return oldest.IP, true
	}
	return netip.Addr{}, false
}

func (s *Server) conflict(ip netip.Addr, now time.Time) bool {
	u, ok := s.conflicts[ip]
	return ok && now.Before(u)
}

// scopeFor waehlt das Netz einer Anfrage: ueber ein Relay das Netz des giaddr, sonst das der Schnittstelle.
func (s *Server) scopeFor(iface string, req *dhcpv4.DHCPv4) *scope {
	if gi, ok := netip.AddrFromSlice(req.GatewayIPAddr.To4()); ok && !gi.IsUnspecified() {
		for _, sc := range s.scopes {
			if sc.Subnet.Contains(gi) {
				return sc
			}
		}
		return nil
	}
	for _, sc := range s.scopes {
		if sc.Iface == iface {
			return sc
		}
	}
	return nil
}

// reply ist eine Antwort mit Ziel.
type reply struct {
	msg *dhcpv4.DHCPv4
	to  netip.AddrPort
}

// Handle verarbeitet eine Anfrage, die auf iface ankam, und liefert die Antwort (nil = keine).
func (s *Server) Handle(iface string, req *dhcpv4.DHCPv4) *reply {
	if req.OpCode != dhcpv4.OpcodeBootRequest || req.HWType != iana.HWTypeEthernet || len(req.ClientHWAddr) != 6 {
		return nil
	}
	mac := req.ClientHWAddr.String()
	s.mu.Lock()
	if s.probes[req.TransactionID] {
		s.mu.Unlock()
		return nil // eigene Pruefung auf fremde Server
	}
	sc := s.scopeFor(iface, req)
	if sc == nil || !sc.self.IsValid() {
		s.mu.Unlock()
		return nil
	}
	s.stats[strings.ToLower(req.MessageType().String())]++
	s.mu.Unlock()
	switch req.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		return s.discover(sc, req, mac)
	case dhcpv4.MessageTypeRequest:
		return s.request(sc, req, mac)
	case dhcpv4.MessageTypeDecline:
		s.decline(sc, req, mac)
	case dhcpv4.MessageTypeRelease:
		s.release(sc, req, mac)
	case dhcpv4.MessageTypeInform:
		return s.inform(sc, req, mac)
	}
	return nil
}

func ip4(ip net.IP) netip.Addr {
	a, ok := netip.AddrFromSlice(ip.To4())
	if !ok || ip.To4() == nil || a.IsUnspecified() {
		return netip.Addr{}
	}
	return a
}

func (s *Server) discover(sc *scope, req *dhcpv4.DHCPv4, mac string) *reply {
	host := hostname(req)
	for range 3 {
		now := s.now()
		s.mu.Lock()
		ip, fresh := s.pick(sc, mac, ip4(req.RequestedIPAddress()), now)
		if !ip.IsValid() {
			s.event(sc, "discover", mac, host, ip, "full")
			s.mu.Unlock()
			return nil
		}
		if s.observe {
			s.event(sc, "discover", mac, host, ip, "observe")
			s.mu.Unlock()
			return nil
		}
		hold := fresh
		if hold { // Adresse waehrend der ARP-Pruefung festhalten
			sc.setLease(Lease{Scope: sc.ID, MAC: mac, IP: ip, Hostname: host, Expires: now.Add(offerHold), State: StateOffered})
		}
		self := sc.self
		s.mu.Unlock()
		if fresh && s.Probe != nil && s.Probe(sc.Iface, self, ip) {
			s.mu.Lock()
			s.conflicts[ip] = s.now().Add(conflictHold)
			sc.dropLease(mac)
			s.event(sc, "discover", mac, host, ip, "conflict")
			s.mu.Unlock()
			s.logger().Warn("dhcp address in use (arp)", "ip", ip, "iface", sc.Iface)
			continue
		}
		s.mu.Lock()
		if l := sc.byMAC[mac]; l == nil || l.IP != ip || l.State != StateBound || !l.Active(now) {
			sc.setLease(Lease{Scope: sc.ID, MAC: mac, IP: ip, Hostname: host, Expires: now.Add(offerHold), State: StateOffered})
		}
		s.event(sc, "discover", mac, host, ip, "offer")
		r := s.build(sc, req, dhcpv4.MessageTypeOffer, ip, true)
		s.mu.Unlock()
		return r
	}
	return nil
}

func (s *Server) request(sc *scope, req *dhcpv4.DHCPv4, mac string) *reply {
	host := hostname(req)
	now := s.now()
	sid, want, ci := ip4(req.ServerIdentifier()), ip4(req.RequestedIPAddress()), ip4(req.ClientIPAddr)
	s.mu.Lock()
	defer s.mu.Unlock()
	if sid.IsValid() && sid != sc.self { // Client hat einen anderen Server gewaehlt
		if l := sc.byMAC[mac]; l != nil && l.State == StateOffered {
			sc.dropLease(mac)
		}
		s.event(sc, "request", mac, host, want, "ignored")
		return nil
	}
	ip := want
	if !ip.IsValid() {
		ip = ci
	}
	if !ip.IsValid() {
		return nil
	}
	if s.observe {
		s.event(sc, "request", mac, host, ip, "observe")
		return nil
	}
	ok, known := s.mayAck(sc, mac, ip, now, sid.IsValid())
	if !ok {
		if !known && !sc.Authoritative {
			s.event(sc, "request", mac, host, ip, "ignored")
			return nil
		}
		s.event(sc, "request", mac, host, ip, "nak")
		return s.build(sc, req, dhcpv4.MessageTypeNak, netip.Addr{}, false)
	}
	l := Lease{Scope: sc.ID, MAC: mac, IP: ip, Hostname: host, Expires: now.Add(sc.Lease), State: StateBound}
	if host == "" {
		if old := sc.byMAC[mac]; old != nil {
			l.Hostname = old.Hostname
		}
	}
	sc.setLease(l)
	s.save(l)
	s.event(sc, "request", mac, l.Hostname, ip, "ack")
	return s.build(sc, req, dhcpv4.MessageTypeAck, ip, true)
}

// mayAck: darf mac die Adresse ip bekommen? known = Server hat eine Aussage (sonst schweigt ein nicht
// autoritativer Server).
func (s *Server) mayAck(sc *scope, mac string, ip netip.Addr, now time.Time, selecting bool) (ok, known bool) {
	if !sc.Subnet.Contains(ip) {
		return false, selecting
	}
	if r, has := s.reserved(sc, mac, now); has {
		return r == ip, true // feste Adresse: andere IP -> NAK, der Client holt sich die feste
	}
	if m, has := sc.resIP[ip]; has && m != mac {
		return false, true
	}
	if l := sc.byMAC[mac]; l != nil && l.IP == ip && !s.conflict(ip, now) {
		return true, true
	}
	if l := sc.byIP[ip]; l != nil && l.MAC != mac && l.Active(now) {
		return false, true
	}
	// unbekannter Client mit freier Adresse aus dem Bereich (z. B. nach dem Umstieg vom Router): uebernehmen
	if sc.Authoritative && s.free(sc, ip, mac, now) {
		return true, true
	}
	return false, selecting
}

func (s *Server) decline(sc *scope, req *dhcpv4.DHCPv4, mac string) {
	ip := ip4(req.RequestedIPAddress())
	s.mu.Lock()
	defer s.mu.Unlock()
	if ip4(req.ServerIdentifier()) != sc.self || !ip.IsValid() {
		return
	}
	s.conflicts[ip] = s.now().Add(conflictHold)
	if l := sc.byMAC[mac]; l != nil && l.IP == ip {
		sc.dropLease(mac)
		s.deleteLease(sc.ID, mac)
	}
	s.event(sc, "decline", mac, "", ip, "decline")
	s.logger().Warn("dhcp address declined by client", "ip", ip, "mac", mac)
}

func (s *Server) release(sc *scope, req *dhcpv4.DHCPv4, mac string) {
	ci := ip4(req.ClientIPAddr)
	s.mu.Lock()
	defer s.mu.Unlock()
	l := sc.byMAC[mac]
	if l == nil || l.IP != ci || ip4(req.ServerIdentifier()) != sc.self || s.observe {
		return
	}
	nl := *l
	nl.State, nl.Expires = StateFree, s.now()
	sc.setLease(nl)
	s.save(nl)
	s.event(sc, "release", mac, nl.Hostname, ci, "release")
}

func (s *Server) inform(sc *scope, req *dhcpv4.DHCPv4, mac string) *reply {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.observe {
		s.event(sc, "inform", mac, hostname(req), ip4(req.ClientIPAddr), "observe")
		return nil
	}
	s.event(sc, "inform", mac, hostname(req), ip4(req.ClientIPAddr), "ack")
	return s.build(sc, req, dhcpv4.MessageTypeAck, netip.Addr{}, false)
}

// build baut die Antwort mit Optionen und Ziel (s.mu gehalten).
func (s *Server) build(sc *scope, req *dhcpv4.DHCPv4, mt dhcpv4.MessageType, yi netip.Addr, lease bool) *reply {
	resp, err := dhcpv4.NewReplyFromRequest(req, dhcpv4.WithMessageType(mt))
	if err != nil {
		return nil
	}
	resp.UpdateOption(dhcpv4.OptServerIdentifier(sc.self.AsSlice()))
	if mt == dhcpv4.MessageTypeNak {
		resp.ClientIPAddr, resp.YourIPAddr = net.IPv4zero, net.IPv4zero
		return &reply{msg: resp, to: dest(req, true)}
	}
	if yi.IsValid() {
		resp.YourIPAddr = yi.AsSlice()
	}
	resp.UpdateOption(dhcpv4.OptSubnetMask(net.CIDRMask(sc.Subnet.Bits(), 32)))
	resp.UpdateOption(dhcpv4.OptBroadcastAddress(Broadcast(sc.Subnet).AsSlice()))
	if sc.Router.IsValid() {
		resp.UpdateOption(dhcpv4.OptRouter(sc.Router.AsSlice()))
	}
	dns := sc.DNS
	if len(dns) == 0 {
		dns = []netip.Addr{sc.self}
	}
	resp.UpdateOption(dhcpv4.OptDNS(ips(dns)...))
	if sc.Domain != "" {
		resp.UpdateOption(dhcpv4.OptDomainName(sc.Domain))
		dhcpv4.WithDomainSearchList(sc.Domain)(resp)
	}
	if len(sc.NTP) > 0 {
		resp.UpdateOption(dhcpv4.OptNTPServers(ips(sc.NTP)...))
	}
	if lease {
		resp.UpdateOption(dhcpv4.OptIPAddressLeaseTime(sc.Lease))
		resp.UpdateOption(dhcpv4.OptRenewTimeValue(sc.Lease / 2))
		resp.UpdateOption(dhcpv4.OptRebindingTimeValue(sc.Lease * 7 / 8))
	}
	if file := bootFile(sc, req); file != "" || sc.BootServer != "" {
		if file != "" {
			resp.BootFileName = file
			resp.UpdateOption(dhcpv4.OptBootFileName(file))
		}
		if sc.BootServer != "" {
			resp.UpdateOption(dhcpv4.OptTFTPServerName(sc.BootServer))
			if a, err := netip.ParseAddr(sc.BootServer); err == nil && a.Is4() {
				resp.ServerIPAddr = a.AsSlice()
			}
		}
	}
	return &reply{msg: resp, to: dest(req, false)}
}

// bootFile waehlt die PXE-Datei: nur fuer PXE-Clients (Option 93 oder Kennung PXEClient), iPXE vor UEFI vor BIOS.
func bootFile(sc *scope, req *dhcpv4.DHCPv4) string {
	if sc.BootBIOS == "" && sc.BootUEFI == "" && sc.BootIPXE == "" {
		return ""
	}
	archs := req.ClientArch()
	if len(archs) == 0 && !strings.HasPrefix(req.ClassIdentifier(), "PXEClient") && !slices.Contains(req.UserClass(), "iPXE") {
		return ""
	}
	if sc.BootIPXE != "" && (slices.Contains(req.UserClass(), "iPXE") || string(req.Options.Get(dhcpv4.OptionUserClassInformation)) == "iPXE") {
		return sc.BootIPXE
	}
	uefi := false
	for _, a := range archs {
		if a != iana.INTEL_X86PC && a != iana.NEC_PC98 && a != iana.DEC_ALPHA && a != iana.ARC_X86 && a != iana.INTEL_LEAN_CLIENT {
			uefi = true
		}
	}
	if uefi && sc.BootUEFI != "" {
		return sc.BootUEFI
	}
	if !uefi && sc.BootBIOS != "" {
		return sc.BootBIOS
	}
	return ""
}

// dest: Ziel der Antwort nach RFC 2131 4.1 (ohne ARP-Eintrag per Broadcast statt Unicast an yiaddr).
func dest(req *dhcpv4.DHCPv4, nak bool) netip.AddrPort {
	if gi := ip4(req.GatewayIPAddr); gi.IsValid() {
		return netip.AddrPortFrom(gi, 67)
	}
	if ci := ip4(req.ClientIPAddr); ci.IsValid() && !nak {
		return netip.AddrPortFrom(ci, 68)
	}
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{255, 255, 255, 255}), 68)
}

// Broadcast ist die Broadcast-Adresse eines IPv4-Netzes.
func Broadcast(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]) | host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func ips(as []netip.Addr) []net.IP {
	out := make([]net.IP, 0, len(as))
	for _, a := range as {
		out = append(out, a.AsSlice())
	}
	return out
}

// hostname: Name des Clients (Option 12), nur druckbare Zeichen, hoechstens 63.
func hostname(req *dhcpv4.DHCPv4) string {
	h := strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return -1
		}
		return r
	}, strings.TrimSpace(req.HostName()))
	if len(h) > 63 {
		h = h[:63]
	}
	return h
}

func (s *Server) save(l Lease) {
	if s.Store != nil {
		if err := s.Store.SaveLease(l); err != nil {
			s.logger().Warn("dhcp save lease", "err", err)
		}
	}
	s.changed()
}

func (s *Server) deleteLease(scope int64, mac string) {
	if s.Store != nil {
		if err := s.Store.DeleteLease(scope, mac); err != nil {
			s.logger().Warn("dhcp delete lease", "err", err)
		}
	}
	s.changed()
}

// changed ruft OnChange ohne gehaltene Sperre (eigene Goroutine).
func (s *Server) changed() {
	if f := s.OnChange; f != nil {
		go f()
	}
}

func (s *Server) event(sc *scope, typ, mac, host string, ip netip.Addr, result string) {
	s.stats["result_"+result]++
	s.events = append(s.events, Event{Time: s.now(), Scope: sc.ID, Type: typ, MAC: mac, Hostname: host, IP: ip, Result: result})
	if len(s.events) > maxEvents {
		s.events = slices.Delete(s.events, 0, len(s.events)-maxEvents)
	}
}

// cleanup vergisst alte Leases, abgelaufene Angebote und Sperren.
func (s *Server) cleanup() {
	now := s.now()
	s.mu.Lock()
	var gone []Lease
	for _, sc := range s.scopes {
		for mac, l := range sc.byMAC {
			switch {
			case l.State == StateOffered && !l.Active(now):
				sc.dropLease(mac)
			case l.State != StateOffered && now.Sub(l.Expires) > keepFree:
				sc.dropLease(mac)
				gone = append(gone, *l)
			}
		}
	}
	for ip, u := range s.conflicts {
		if !now.Before(u) {
			delete(s.conflicts, ip)
		}
	}
	s.mu.Unlock()
	for _, l := range gone {
		s.deleteLease(l.Scope, l.MAC)
	}
}

// ---- Ansicht fuer Seite und API ----

// ScopeView ist der Zustand eines Netzes.
type ScopeView struct {
	ID       int64      `json:"id"`
	Self     netip.Addr `json:"self"`
	Error    string     `json:"error,omitempty"`
	ErrKind  string     `json:"error_kind,omitempty"` // iface (Schnittstelle fehlt), addr (keine Adresse im Netz), listen (Port 67)
	Size     int        `json:"size"`                 // Adressen im Bereich
	Used     int        `json:"used"`                 // davon vergeben oder angeboten
	Reserved int        `json:"reserved"`             // feste Adressen im Bereich
	Leases   []Lease    `json:"leases"`
}

// View ist der Zustand des Servers.
type View struct {
	Observe bool              `json:"observe"`
	Scopes  []ScopeView       `json:"scopes"`
	Events  []Event           `json:"events"`
	Foreign []Foreign         `json:"foreign"`
	Stats   map[string]uint64 `json:"stats"`
}

// Snapshot liefert den aktuellen Zustand (Leases nach IP, Anfragen neueste zuerst).
func (s *Server) Snapshot() View {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	v := View{Observe: s.observe, Stats: map[string]uint64{}}
	for k, n := range s.stats {
		v.Stats[k] = n
	}
	for _, sc := range s.scopes {
		sv := ScopeView{ID: sc.ID, Self: sc.self, Error: sc.err, ErrKind: sc.kind, Size: poolSize(sc.Start, sc.End), Leases: []Lease{}}
		for ip := range sc.resIP {
			if sc.inPool(ip) {
				sv.Reserved++
			}
		}
		for _, l := range sc.byMAC {
			if l.State == StateOffered && !l.Active(now) {
				continue
			}
			if l.Active(now) && sc.inPool(l.IP) {
				if _, res := sc.resIP[l.IP]; !res {
					sv.Used++
				}
			}
			if l.Active(now) || now.Sub(l.Expires) < 24*time.Hour {
				sv.Leases = append(sv.Leases, *l)
			}
		}
		slices.SortFunc(sv.Leases, func(a, b Lease) int { return a.IP.Compare(b.IP) })
		v.Scopes = append(v.Scopes, sv)
		for ip, t := range s.foreign[sc.ID] {
			v.Foreign = append(v.Foreign, Foreign{Scope: sc.ID, Server: ip, LastSeen: t})
		}
	}
	for i := len(s.events) - 1; i >= 0; i-- {
		v.Events = append(v.Events, s.events[i])
	}
	return v
}

func poolSize(a, b netip.Addr) int {
	if !a.Is4() || !b.Is4() || b.Less(a) {
		return 0
	}
	x, y := a.As4(), b.As4()
	return int(uint32(y[0])<<24|uint32(y[1])<<16|uint32(y[2])<<8|uint32(y[3])) - int(uint32(x[0])<<24|uint32(x[1])<<16|uint32(x[2])<<8|uint32(x[3])) + 1
}

// Carry uebernimmt Anfragen, fremde Server, Sperren und Zaehler des vorigen Servers (Neustart nach Aenderungen).
func (s *Server) Carry(old *Server) {
	if old == nil {
		return
	}
	old.mu.Lock()
	defer old.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = slices.Clone(old.events)
	maps.Copy(s.conflicts, old.conflicts)
	maps.Copy(s.stats, old.stats)
	for id, f := range old.foreign {
		s.foreign[id] = maps.Clone(f)
	}
}

// Release gibt ein Lease von Hand frei (Seite "Freigeben"): die Adresse ist sofort wieder vergebbar.
func (s *Server) Release(scope int64, mac string) bool {
	s.mu.Lock()
	var found bool
	for _, sc := range s.scopes {
		if sc.ID == scope && sc.byMAC[mac] != nil {
			sc.dropLease(mac)
			found = true
		}
	}
	s.mu.Unlock()
	if found {
		s.deleteLease(scope, mac)
	}
	return found
}

// sawForeign merkt sich einen fremden DHCP-Server im Netz eines Scopes.
func (s *Server) sawForeign(scope int64, server netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.foreign[scope] == nil {
		s.foreign[scope] = map[netip.Addr]time.Time{}
	}
	s.foreign[scope][server] = s.now()
}
