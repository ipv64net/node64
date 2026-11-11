package dhcp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

const (
	checkEvery   = 10 * time.Minute // fremde DHCP-Server suchen, alte Leases vergessen
	foreignWait  = 6 * time.Second  // so lange auf Angebote fremder Server warten (dnsmasq/ISC pingen vorher bis 3 s)
	firstCheckIn = 2 * time.Second
	rebindEvery  = time.Minute // fehlende Schnittstellen und Adressen erneut suchen
	maxDiscover  = 16          // DISCOVER je Schnittstelle gleichzeitig (die ARP-Pruefung wartet bis 300 ms)
)

var bcast67 = netip.AddrPortFrom(netip.AddrFrom4([4]byte{255, 255, 255, 255}), 67)

// Run oeffnet je Schnittstelle Port 67, sucht regelmaessig fremde DHCP-Server und raeumt auf. Blockiert, bis ctx
// endet; danach sind alle Sockets zu. Fehler einer Schnittstelle (Port belegt, keine Adresse im Netz) stehen am
// Netz (Snapshot), die anderen laufen weiter; fehlende Schnittstellen und Adressen sucht Run jede Minute erneut.
func (s *Server) Run(ctx context.Context) {
	s.bind(false)
	var wg sync.WaitGroup
	var cmu sync.Mutex
	conns := map[string]*net.UDPConn{}
	idx := map[string]int{} // Index der Schnittstelle beim Oeffnen (neu angelegt = neuer Index, alter Socket hoert nichts)
	ifIndex := func(name string) int {
		if ifi, err := net.InterfaceByName(name); err == nil {
			return ifi.Index
		}
		return -1
	}
	reopen := func() { // Sockets zu Schnittstellen, die es so nicht mehr gibt, schliessen (open oeffnet sie neu)
		cmu.Lock()
		defer cmu.Unlock()
		for iface, c := range conns {
			if i := ifIndex(iface); i != idx[iface] {
				s.logger().Info("dhcp interface changed, reopening", "iface", iface)
				_ = c.Close()
				delete(conns, iface)
			}
		}
	}
	open := func() int {
		cmu.Lock()
		defer cmu.Unlock()
		for _, iface := range s.ifaces() {
			if conns[iface] != nil || ctx.Err() != nil {
				continue
			}
			idx[iface] = ifIndex(iface)
			c, err := listen(ctx, iface, 67)
			if err != nil {
				s.ifaceErr(iface, err)
				s.logger().Warn("dhcp listen", "iface", iface, "err", err)
				continue
			}
			conns[iface] = c
			wg.Add(1)
			go func() { defer wg.Done(); s.serve(ctx, iface, c) }()
		}
		return len(conns)
	}
	s.logger().Info("dhcp started", "interfaces", open(), "observe", s.observe)
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTimer(firstCheckIn)
		defer t.Stop()
		rb := time.NewTicker(rebindEvery)
		defer rb.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-rb.C:
				s.bind(false) // alle Netze: auch eine geaenderte Adresse der Node (Server-ID, DNS-Option)
				reopen()
				open()
				continue
			case <-t.C:
			}
			s.cleanup()
			s.checkForeign(ctx)
			every := checkEvery
			if s.CheckEvery > 0 {
				every = s.CheckEvery
			}
			t.Reset(every)
		}
	}()
	<-ctx.Done()
	cmu.Lock()
	for _, c := range conns {
		_ = c.Close()
	}
	cmu.Unlock()
	wg.Wait()
	s.logger().Info("dhcp stopped")
}

// ifaces: Schnittstellen der Netze mit eigener Adresse (je eine einmal).
func (s *Server) ifaces() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, sc := range s.scopes {
		if sc.self.IsValid() && !seen[sc.Iface] {
			seen[sc.Iface] = true
			out = append(out, sc.Iface)
		}
	}
	return out
}

func (s *Server) ifaceErr(iface string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sc := range s.scopes {
		if sc.Iface == iface {
			sc.err, sc.kind, sc.self = err.Error(), "listen", netip.Addr{}
		}
	}
}

// serve liest die Anfragen einer Schnittstelle. DISCOVER laufen nebenlaeufig (die ARP-Pruefung einer neuen Adresse
// haelt so keine anderen Anfragen auf), alle anderen der Reihe nach.
func (s *Server) serve(ctx context.Context, iface string, c *net.UDPConn) {
	var wg sync.WaitGroup
	defer wg.Wait()
	sem := make(chan struct{}, maxDiscover)
	answer := func(req *dhcpv4.DHCPv4) {
		if r := s.Handle(iface, req); r != nil {
			if _, err := c.WriteToUDPAddrPort(r.msg.ToBytes(), r.to); err != nil && ctx.Err() == nil {
				s.logger().Warn("dhcp send", "iface", iface, "to", r.to, "err", err)
			}
		}
	}
	buf := make([]byte, 1500)
	for {
		n, _, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		req, err := dhcpv4.FromBytes(buf[:n])
		if err != nil {
			continue
		}
		if req.MessageType() != dhcpv4.MessageTypeDiscover {
			answer(req)
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			answer(req)
		}()
	}
}

// checkForeign sucht in jedem Netz fremde DHCP-Server: eigenes DISCOVER per Broadcast, Angebote anderer Server
// kommen an Port 68. Ist Port 68 belegt (DHCP-Client auf dem Host), entfaellt die Pruefung.
func (s *Server) checkForeign(ctx context.Context) {
	type target struct {
		id    int64
		iface string
		mac   net.HardwareAddr
		self  netip.Addr
	}
	s.mu.Lock()
	var ts []target
	for _, sc := range s.scopes {
		if sc.self.IsValid() && len(sc.mac) == 6 && !sc.Relay {
			ts = append(ts, target{sc.ID, sc.Iface, sc.mac, sc.self})
		}
	}
	s.mu.Unlock()
	for _, t := range ts {
		servers, err := s.probeForeign(ctx, t.iface, t.mac, t.self)
		if err != nil {
			s.logger().Debug("dhcp foreign check", "iface", t.iface, "err", err)
			continue
		}
		for _, srv := range servers {
			s.mu.Lock()
			_, known := s.foreign[t.id][srv]
			s.mu.Unlock()
			s.sawForeign(t.id, srv)
			if !known {
				s.logger().Warn("dhcp foreign server", "iface", t.iface, "server", srv)
				if f := s.OnForeign; f != nil {
					f(t.id, srv)
				}
			}
		}
	}
}

func (s *Server) probeForeign(ctx context.Context, iface string, mac net.HardwareAddr, self netip.Addr) ([]netip.Addr, error) {
	c, err := listen(ctx, iface, 68)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() }) // Stopp wartet nicht auf die Frist
	defer stop()
	disc, err := dhcpv4.NewDiscovery(mac, dhcpv4.WithBroadcast(true), dhcpv4.WithOption(dhcpv4.OptClassIdentifier(ProbeClass)))
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.probes[disc.TransactionID] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.probes, disc.TransactionID)
		s.mu.Unlock()
	}()
	if _, err := c.WriteToUDPAddrPort(disc.ToBytes(), bcast67); err != nil {
		return nil, err
	}
	_ = c.SetReadDeadline(time.Now().Add(foreignWait))
	var out []netip.Addr
	buf := make([]byte, 1500)
	for {
		n, _, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			return out, nil // Frist abgelaufen
		}
		m, err := dhcpv4.FromBytes(buf[:n])
		if err != nil || m.OpCode != dhcpv4.OpcodeBootReply || m.TransactionID != disc.TransactionID || m.MessageType() != dhcpv4.MessageTypeOffer {
			continue
		}
		if srv := ip4(m.ServerIdentifier()); srv.IsValid() && srv != self && !slices.Contains(out, srv) {
			out = append(out, srv)
		}
	}
}
