package dhcp

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/iana"
)

type memStore struct {
	mu     sync.Mutex
	leases map[string]Lease
}

func (m *memStore) SaveLease(l Lease) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.leases[l.MAC] = l
	return nil
}

// all liefert eine Kopie (der Server schreibt aus eigenen Goroutinen).
func (m *memStore) all() map[string]Lease {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]Lease{}
	for k, v := range m.leases {
		out[k] = v
	}
	return out
}

func (m *memStore) DeleteLease(_ int64, mac string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.leases, mac)
	return nil
}

var (
	macA = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x0a}
	macB = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x0b}
)

func testScope() Scope {
	return Scope{ID: 1, Name: "LAN", Iface: "eth0", Subnet: netip.MustParsePrefix("192.168.1.0/24"),
		Start: netip.MustParseAddr("192.168.1.1"), End: netip.MustParseAddr("192.168.1.5"), Router: netip.MustParseAddr("192.168.1.1"),
		Domain: "home.lan", Lease: time.Hour, Authoritative: true}
}

func newTest(t *testing.T, cfg Config) (*Server, *memStore, *time.Time) {
	t.Helper()
	if cfg.Scopes == nil {
		cfg.Scopes = []Scope{testScope()}
	}
	st := &memStore{leases: map[string]Lease{}}
	s := New(cfg, st, nil)
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }
	s.Addrs = func(string) []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("192.168.1.2/24")} }
	s.bind(false)
	return s, st, &now
}

func discover(t *testing.T, mac net.HardwareAddr, mods ...dhcpv4.Modifier) *dhcpv4.DHCPv4 {
	t.Helper()
	d, err := dhcpv4.NewDiscovery(mac, mods...)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func offerAndAck(t *testing.T, s *Server, mac net.HardwareAddr) netip.Addr {
	t.Helper()
	off := s.Handle("eth0", discover(t, mac))
	if off == nil || off.msg.MessageType() != dhcpv4.MessageTypeOffer {
		t.Fatalf("no offer: %v", off)
	}
	req, err := dhcpv4.NewRequestFromOffer(off.msg)
	if err != nil {
		t.Fatal(err)
	}
	ack := s.Handle("eth0", req)
	if ack == nil || ack.msg.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("no ack: %v", ack)
	}
	return ip4(ack.msg.YourIPAddr)
}

func TestDiscoverRequestAck(t *testing.T) {
	s, st, _ := newTest(t, Config{})
	off := s.Handle("eth0", discover(t, macA))
	if off == nil {
		t.Fatal("no offer")
	}
	m := off.msg
	// .1 ist der Router, .2 die Node: erste freie Adresse .3
	if got := ip4(m.YourIPAddr); got != netip.MustParseAddr("192.168.1.3") {
		t.Fatalf("offer %v", got)
	}
	if ip4(m.ServerIdentifier()) != netip.MustParseAddr("192.168.1.2") || len(m.DNS()) != 1 || !m.DNS()[0].Equal(net.ParseIP("192.168.1.2")) {
		t.Errorf("server id %v dns %v", m.ServerIdentifier(), m.DNS())
	}
	if m.DomainName() != "home.lan" || m.IPAddressLeaseTime(0) != time.Hour || off.to.Addr() != netip.MustParseAddr("255.255.255.255") || off.to.Port() != 68 {
		t.Errorf("domain %q lease %v to %v", m.DomainName(), m.IPAddressLeaseTime(0), off.to)
	}
	req, _ := dhcpv4.NewRequestFromOffer(m)
	ack := s.Handle("eth0", req)
	if ack == nil || ack.msg.MessageType() != dhcpv4.MessageTypeAck || ip4(ack.msg.YourIPAddr) != netip.MustParseAddr("192.168.1.3") {
		t.Fatalf("ack %v", ack)
	}
	if l := st.leases[macA.String()]; l.State != StateBound || l.IP != netip.MustParseAddr("192.168.1.3") {
		t.Errorf("stored %+v", l)
	}
	// derselbe Client bekommt dieselbe Adresse, ein anderer die naechste
	if got := ip4(s.Handle("eth0", discover(t, macA)).msg.YourIPAddr); got != netip.MustParseAddr("192.168.1.3") {
		t.Errorf("again %v", got)
	}
	if got := offerAndAck(t, s, macB); got != netip.MustParseAddr("192.168.1.4") {
		t.Errorf("second client %v", got)
	}
}

func TestRenewUnicastAndRelay(t *testing.T) {
	s, _, _ := newTest(t, Config{})
	ip := offerAndAck(t, s, macA)
	renew, _ := dhcpv4.New(dhcpv4.WithHwAddr(macA), dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest), dhcpv4.WithClientIP(ip.AsSlice()))
	r := s.Handle("eth0", renew)
	if r == nil || r.msg.MessageType() != dhcpv4.MessageTypeAck || r.to != netip.AddrPortFrom(ip, 68) {
		t.Fatalf("renew %v", r)
	}
	// Relay: Netz ueber giaddr, Antwort an das Relay
	d := discover(t, macB, dhcpv4.WithGatewayIP(net.ParseIP("192.168.1.254")))
	r = s.Handle("other0", d)
	if r == nil || r.to != netip.MustParseAddrPort("192.168.1.254:67") {
		t.Fatalf("relay %v", r)
	}
}

func TestReservationAndNAK(t *testing.T) {
	res := netip.MustParseAddr("192.168.1.50") // ausserhalb des Bereichs, aber im Netz
	s, _, _ := newTest(t, Config{Reservations: []Reservation{{Scope: 1, MAC: macA.String(), IP: res, Name: "nas"}}})
	if got := offerAndAck(t, s, macA); got != res {
		t.Fatalf("reserved %v", got)
	}
	// Neustart mit alter Adresse (INIT-REBOOT): andere IP als die feste -> NAK
	reboot, _ := dhcpv4.New(dhcpv4.WithHwAddr(macA), dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("192.168.1.3"))))
	if r := s.Handle("eth0", reboot); r == nil || r.msg.MessageType() != dhcpv4.MessageTypeNak || r.to.Addr() != netip.MustParseAddr("255.255.255.255") {
		t.Fatalf("expected nak, got %v", r)
	}
	// ein anderer Client darf die feste Adresse nicht bekommen
	other, _ := dhcpv4.New(dhcpv4.WithHwAddr(macB), dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(res.AsSlice())))
	if r := s.Handle("eth0", other); r == nil || r.msg.MessageType() != dhcpv4.MessageTypeNak {
		t.Fatalf("reserved for other: %v", r)
	}
}

func TestInitRebootForeign(t *testing.T) {
	reboot := func(ip string) *dhcpv4.DHCPv4 {
		r, _ := dhcpv4.New(dhcpv4.WithHwAddr(macA), dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
			dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(net.ParseIP(ip))))
		return r
	}
	s, _, _ := newTest(t, Config{})
	// unbekannter Client mit freier Adresse aus dem Bereich (vom alten Router): uebernehmen
	if r := s.Handle("eth0", reboot("192.168.1.4")); r == nil || r.msg.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("adopt %v", r)
	}
	// fremdes Netz: autoritativ NAK
	s, _, _ = newTest(t, Config{})
	if r := s.Handle("eth0", reboot("10.0.0.7")); r == nil || r.msg.MessageType() != dhcpv4.MessageTypeNak {
		t.Fatalf("foreign net %v", r)
	}
	// nicht autoritativ: schweigen
	sc := testScope()
	sc.Authoritative = false
	s, _, _ = newTest(t, Config{Scopes: []Scope{sc}})
	if r := s.Handle("eth0", reboot("10.0.0.7")); r != nil {
		t.Fatalf("non-authoritative answered %v", r.msg.MessageType())
	}
	if r := s.Handle("eth0", reboot("192.168.1.4")); r != nil {
		t.Fatalf("non-authoritative adopted %v", r.msg.MessageType())
	}
}

func TestOtherServerChosen(t *testing.T) {
	s, _, _ := newTest(t, Config{})
	off := s.Handle("eth0", discover(t, macA))
	req, _ := dhcpv4.NewRequestFromOffer(off.msg)
	req.UpdateOption(dhcpv4.OptServerIdentifier(net.ParseIP("192.168.1.1")))
	if r := s.Handle("eth0", req); r != nil {
		t.Fatal("answered request for other server")
	}
	if len(s.Snapshot().Scopes[0].Leases) != 0 {
		t.Error("offer not dropped")
	}
}

func TestARPConflict(t *testing.T) {
	s, _, _ := newTest(t, Config{})
	s.Probe = func(_ string, _, ip netip.Addr) bool { return ip == netip.MustParseAddr("192.168.1.3") }
	if got := ip4(s.Handle("eth0", discover(t, macA)).msg.YourIPAddr); got != netip.MustParseAddr("192.168.1.4") {
		t.Fatalf("after conflict %v", got)
	}
}

func TestPoolFullAndRelease(t *testing.T) {
	sc := testScope()
	sc.End = netip.MustParseAddr("192.168.1.3") // nur eine Adresse frei
	s, st, now := newTest(t, Config{Scopes: []Scope{sc}})
	ip := offerAndAck(t, s, macA)
	if r := s.Handle("eth0", discover(t, macB)); r != nil {
		t.Fatal("offer from full pool")
	}
	rel, _ := dhcpv4.New(dhcpv4.WithHwAddr(macA), dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease), dhcpv4.WithClientIP(ip.AsSlice()),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(net.ParseIP("192.168.1.2"))))
	s.Handle("eth0", rel)
	if st.leases[macA.String()].State != StateFree {
		t.Fatal("not released")
	}
	*now = now.Add(time.Second)
	if got := offerAndAck(t, s, macB); got != ip {
		t.Fatalf("after release %v", got)
	}
	// Leases laufen ab: Adresse wieder frei
	*now = now.Add(2 * time.Hour)
	if got := ip4(s.Handle("eth0", discover(t, macA)).msg.YourIPAddr); got != ip {
		t.Fatalf("after expiry %v", got)
	}
}

func TestObserve(t *testing.T) {
	s, st, _ := newTest(t, Config{Observe: true})
	if r := s.Handle("eth0", discover(t, macA)); r != nil {
		t.Fatal("observe answered")
	}
	v := s.Snapshot()
	if len(v.Events) != 1 || v.Events[0].Result != "observe" || v.Events[0].IP != netip.MustParseAddr("192.168.1.3") || len(st.leases) != 0 || len(v.Scopes[0].Leases) != 0 {
		t.Fatalf("observe state %+v", v)
	}
}

func TestPXE(t *testing.T) {
	sc := testScope()
	sc.BootServer, sc.BootBIOS, sc.BootUEFI, sc.BootIPXE = "192.168.1.9", "netboot.xyz.kpxe", "netboot.xyz.efi", "http://192.168.1.9/menu.ipxe"
	s, _, _ := newTest(t, Config{Scopes: []Scope{sc}})
	for _, c := range []struct {
		mods []dhcpv4.Modifier
		want string
	}{
		{nil, ""},
		{[]dhcpv4.Modifier{dhcpv4.WithOption(dhcpv4.OptClientArch(iana.INTEL_X86PC))}, "netboot.xyz.kpxe"},
		{[]dhcpv4.Modifier{dhcpv4.WithOption(dhcpv4.OptClientArch(iana.EFI_X86_64))}, "netboot.xyz.efi"},
		{[]dhcpv4.Modifier{dhcpv4.WithOption(dhcpv4.OptClientArch(iana.EFI_X86_64)), dhcpv4.WithOption(dhcpv4.OptUserClass("iPXE"))}, "http://192.168.1.9/menu.ipxe"},
	} {
		r := s.Handle("eth0", discover(t, macA, c.mods...))
		if r == nil || r.msg.BootFileName != c.want || (c.want != "" && !r.msg.ServerIPAddr.Equal(net.ParseIP("192.168.1.9"))) {
			t.Errorf("pxe %q: got %+v", c.want, r)
		}
	}
}

func TestSnapshotCounts(t *testing.T) {
	s, _, _ := newTest(t, Config{Reservations: []Reservation{{Scope: 1, MAC: macB.String(), IP: netip.MustParseAddr("192.168.1.5")}}})
	offerAndAck(t, s, macA)
	v := s.Snapshot().Scopes[0]
	if v.Size != 3 || v.Used != 1 || v.Reserved != 1 || len(v.Leases) != 1 {
		t.Fatalf("view %+v", v)
	}
}

func TestBroadcast(t *testing.T) {
	if b := Broadcast(netip.MustParsePrefix("10.1.2.0/23")); b != netip.MustParseAddr("10.1.3.255") {
		t.Fatal(b)
	}
}

// Reserve-Node: solange die Haupt-Node lebt, nur zuhoeren; danach normal antworten.
func TestStandby(t *testing.T) {
	s, st, _ := newTest(t, Config{})
	alive := true
	s.Standby = func(p netip.Prefix) bool { return alive && p == testScope().Subnet }
	if r := s.Handle("eth0", discover(t, macA)); r != nil {
		t.Fatal("standby answered")
	}
	if v := s.Snapshot(); v.Events[0].Result != "standby" || len(st.all()) != 0 {
		t.Fatalf("standby state %+v", v.Events)
	}
	alive = false
	if got := offerAndAck(t, s, macA); got != netip.MustParseAddr("192.168.1.3") {
		t.Fatalf("after failover %v", got)
	}
}

// Vergaben aus dem Cluster: die Reserve kennt sie und gibt dieselbe Adresse wieder.
func TestImport(t *testing.T) {
	s, _, now := newTest(t, Config{})
	s.Import(Lease{Scope: 1, MAC: macA.String(), IP: netip.MustParseAddr("192.168.1.5"), Hostname: "tv", Expires: now.Add(time.Hour), State: StateBound})
	if got := ip4(s.Handle("eth0", discover(t, macA)).msg.YourIPAddr); got != netip.MustParseAddr("192.168.1.5") {
		t.Fatalf("imported lease not used: %v", got)
	}
	if got := ip4(s.Handle("eth0", discover(t, macB)).msg.YourIPAddr); got == netip.MustParseAddr("192.168.1.5") {
		t.Fatal("imported address offered to other client")
	}
	s.Forget(1, macA.String()) // im Cluster geloescht: aus dem Speicher, die Adresse ist wieder frei
	for _, l := range s.Snapshot().Scopes[0].Leases {
		if l.MAC == macA.String() {
			t.Fatalf("forgotten lease still there: %+v", l)
		}
	}
	if got := ip4(s.Handle("eth0", discover(t, net.HardwareAddr{0x02, 0, 0, 0, 0, 0x0c}, dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("192.168.1.5"))))).msg.YourIPAddr); got != netip.MustParseAddr("192.168.1.5") {
		t.Fatalf("address not free after forget: %v", got)
	}
}

// Bereich verkleinert bzw. Router auf eine vergebene Adresse gelegt: Verlaengerung bekommt NAK, der Client holt eine
// neue Adresse; feste Adressen auf Router oder Node werden nie angeboten.
func TestRenewOutsidePool(t *testing.T) {
	s, _, now := newTest(t, Config{Reservations: []Reservation{{Scope: 1, MAC: macB.String(), IP: netip.MustParseAddr("192.168.1.1")}}})
	s.Import(Lease{Scope: 1, MAC: macA.String(), IP: netip.MustParseAddr("192.168.1.9"), Expires: now.Add(time.Hour), State: StateBound}) // ausserhalb .1-.5
	renew, _ := dhcpv4.New(dhcpv4.WithHwAddr(macA), dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest), dhcpv4.WithClientIP(net.ParseIP("192.168.1.9")))
	if r := s.Handle("eth0", renew); r == nil || r.msg.MessageType() != dhcpv4.MessageTypeNak {
		t.Fatalf("renew outside pool: %v", r)
	}
	if got := ip4(s.Handle("eth0", discover(t, macB)).msg.YourIPAddr); got == netip.MustParseAddr("192.168.1.1") {
		t.Fatal("reservation on the router address offered")
	}
}

// Relay-Client verlaengert per Unicast (giaddr 0, ciaddr im Relay-Netz): ACK aus dem Relay-Netz, nicht NAK aus dem LAN.
func TestRelayUnicastRenew(t *testing.T) {
	lan, far := testScope(), testScope()
	far.ID, far.Relay, far.Subnet = 2, true, netip.MustParsePrefix("10.20.0.0/24")
	far.Start, far.End, far.Router = netip.MustParseAddr("10.20.0.100"), netip.MustParseAddr("10.20.0.110"), netip.MustParseAddr("10.20.0.1")
	s, _, now := newTest(t, Config{Scopes: []Scope{lan, far}})
	s.Import(Lease{Scope: 2, MAC: macA.String(), IP: netip.MustParseAddr("10.20.0.100"), Expires: now.Add(time.Hour), State: StateBound})
	renew, _ := dhcpv4.New(dhcpv4.WithHwAddr(macA), dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest), dhcpv4.WithClientIP(net.ParseIP("10.20.0.100")))
	r := s.Handle("eth0", renew)
	if r == nil || r.msg.MessageType() != dhcpv4.MessageTypeAck || r.to != netip.MustParseAddrPort("10.20.0.100:68") {
		t.Fatalf("relay renew %v", r)
	}
	// NAK ueber das Relay mit Broadcast-Bit
	reboot, _ := dhcpv4.New(dhcpv4.WithHwAddr(macB), dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest), dhcpv4.WithGatewayIP(net.ParseIP("10.20.0.1")),
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("10.20.0.200"))))
	if r := s.Handle("eth0", reboot); r == nil || r.msg.MessageType() != dhcpv4.MessageTypeNak || !r.msg.IsBroadcast() {
		t.Fatalf("relay nak %v", r)
	}
}

// Pruef-DISCOVER einer anderen Node: Antwort ja, aber kein Angebot und kein Ereignis.
func TestProbeDiscover(t *testing.T) {
	s, _, _ := newTest(t, Config{})
	r := s.Handle("eth0", discover(t, macA, dhcpv4.WithOption(dhcpv4.OptClassIdentifier(ProbeClass))))
	if r == nil || r.msg.MessageType() != dhcpv4.MessageTypeOffer {
		t.Fatalf("probe not answered: %v", r)
	}
	if v := s.Snapshot(); len(v.Events) != 0 || len(v.Scopes[0].Leases) != 0 {
		t.Fatalf("probe left state: %+v", v)
	}
}

// DNS-Option: Bind-Adresse statt Adresse im Netz; DNS64 nicht auf Port 53 und keine andere Node: der Router.
func TestDNSOption(t *testing.T) {
	sc := testScope()
	sc.DNSBind = netip.MustParseAddr("192.168.1.250")
	s, _, _ := newTest(t, Config{Scopes: []Scope{sc}})
	if d := s.Handle("eth0", discover(t, macA)).msg.DNS(); len(d) != 1 || !d[0].Equal(net.ParseIP("192.168.1.250")) {
		t.Fatalf("bind dns %v", d)
	}
	sc.DNSBind, sc.NoSelfDNS = netip.Addr{}, true
	s, _, _ = newTest(t, Config{Scopes: []Scope{sc}})
	if d := s.Handle("eth0", discover(t, macA)).msg.DNS(); len(d) != 1 || !d[0].Equal(net.ParseIP("192.168.1.1")) {
		t.Fatalf("router fallback %v", d)
	}
	sc.ExtraDNS = []netip.Addr{netip.MustParseAddr("192.168.1.3")}
	s, _, _ = newTest(t, Config{Scopes: []Scope{sc}})
	if d := s.Handle("eth0", discover(t, macA)).msg.DNS(); len(d) != 1 || !d[0].Equal(net.ParseIP("192.168.1.3")) {
		t.Fatalf("peer dns %v", d)
	}
}

// Neustart: laufende Angebote gehen ueber (REQUEST nach dem Neustart bekommt ACK), fremde Server verfallen.
func TestCarryOffersAndForeignExpiry(t *testing.T) {
	sc := testScope()
	sc.Authoritative = false
	old, _, now := newTest(t, Config{Scopes: []Scope{sc}})
	off := old.Handle("eth0", discover(t, macA))
	old.sawForeign(1, netip.MustParseAddr("192.168.1.1"))
	s, _, _ := newTest(t, Config{Scopes: []Scope{sc}})
	s.Now = func() time.Time { return *now }
	s.Carry(old)
	req, _ := dhcpv4.NewRequestFromOffer(off.msg)
	if r := s.Handle("eth0", req); r == nil || r.msg.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("request after restart: %v", r)
	}
	*now = now.Add(foreignKeep + time.Minute)
	if len(s.Snapshot().Foreign) != 0 {
		t.Fatal("foreign server did not expire in view")
	}
	s.cleanup()
	if s.SawServer(netip.MustParseAddr("192.168.1.1"), time.Hour*24) {
		t.Fatal("foreign server not forgotten")
	}
}

// Relay-Netz: nur ueber giaddr, Server-ID = Adresse der Node auf der Schnittstelle, keine ARP-Pruefung.
func TestRelayScope(t *testing.T) {
	lan, far := testScope(), testScope()
	far.ID, far.Relay, far.Subnet = 2, true, netip.MustParsePrefix("10.20.0.0/24")
	far.Start, far.End, far.Router = netip.MustParseAddr("10.20.0.100"), netip.MustParseAddr("10.20.0.110"), netip.MustParseAddr("10.20.0.1")
	s, _, _ := newTest(t, Config{Scopes: []Scope{lan, far}})
	probed := false
	s.Probe = func(string, netip.Addr, netip.Addr) bool { probed = true; return false }
	r := s.Handle("eth0", discover(t, macA, dhcpv4.WithGatewayIP(net.ParseIP("10.20.0.1"))))
	if r == nil || ip4(r.msg.YourIPAddr) != netip.MustParseAddr("10.20.0.100") || ip4(r.msg.ServerIdentifier()) != netip.MustParseAddr("192.168.1.2") ||
		r.to != netip.MustParseAddrPort("10.20.0.1:67") || probed {
		t.Fatalf("relay offer %+v probed=%v", r, probed)
	}
	// ohne giaddr gehoert die Anfrage zum Netz der Schnittstelle
	if r := s.Handle("eth0", discover(t, macB)); r == nil || ip4(r.msg.YourIPAddr) != netip.MustParseAddr("192.168.1.3") {
		t.Fatalf("lan offer %+v", r)
	}
}
