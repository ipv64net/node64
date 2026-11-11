package dhcp

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

// DECLINE nur fuer die eigene Adresse des Clients: ein fremdes Geraet sperrt keine Adresse eines anderen (und fuellt
// die Liste nicht mit beliebigen Adressen).
func TestDeclineOnlyOwnAddress(t *testing.T) {
	s, _, _ := newTest(t, Config{})
	ip := offerAndAck(t, s, macA)
	decline := func(mac net.HardwareAddr) {
		d, err := dhcpv4.New(dhcpv4.WithHwAddr(mac), dhcpv4.WithMessageType(dhcpv4.MessageTypeDecline),
			dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(ip.AsSlice())), dhcpv4.WithOption(dhcpv4.OptServerIdentifier(net.ParseIP("192.168.1.2"))))
		if err != nil {
			t.Fatal(err)
		}
		s.Handle("eth0", d)
	}
	decline(macB) // fremde MAC
	s.mu.Lock()
	_, blocked := s.conflicts[ip]
	s.mu.Unlock()
	if blocked {
		t.Fatal("a foreign client blocked the address")
	}
	decline(macA) // der Client selbst
	s.mu.Lock()
	_, blocked = s.conflicts[ip]
	s.mu.Unlock()
	if !blocked {
		t.Fatal("own decline not applied")
	}
}
