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
)

var bcast67 = netip.AddrPortFrom(netip.AddrFrom4([4]byte{255, 255, 255, 255}), 67)

// Run oeffnet je Schnittstelle Port 67, sucht regelmaessig fremde DHCP-Server und raeumt auf. Blockiert, bis ctx
// endet; danach sind alle Sockets zu. Fehler einer Schnittstelle (Port belegt, keine Adresse im Netz) stehen am
// Netz (Snapshot), die anderen laufen weiter.
func (s *Server) Run(ctx context.Context) {
	s.bind()
	var wg sync.WaitGroup
	var conns []*net.UDPConn
	for _, iface := range s.ifaces() {
		c, err := listen(ctx, iface, 67)
		if err != nil {
			s.ifaceErr(iface, err)
			s.logger().Warn("dhcp listen", "iface", iface, "err", err)
			continue
		}
		conns = append(conns, c)
		wg.Add(1)
		go func() { defer wg.Done(); s.serve(ctx, iface, c) }()
	}
	s.logger().Info("dhcp started", "interfaces", len(conns), "observe", s.observe)
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTimer(firstCheckIn)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			s.cleanup()
			s.checkForeign(ctx)
			t.Reset(checkEvery)
		}
	}()
	<-ctx.Done()
	for _, c := range conns {
		_ = c.Close()
	}
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

func (s *Server) serve(ctx context.Context, iface string, c *net.UDPConn) {
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
		if r := s.Handle(iface, req); r != nil {
			if _, err := c.WriteToUDPAddrPort(r.msg.ToBytes(), r.to); err != nil {
				s.logger().Warn("dhcp send", "iface", iface, "to", r.to, "err", err)
			}
		}
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
		if sc.self.IsValid() && len(sc.mac) == 6 {
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
	disc, err := dhcpv4.NewDiscovery(mac, dhcpv4.WithBroadcast(true))
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
