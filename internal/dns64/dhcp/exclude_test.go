package dhcp

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

// Ausnahme im Adressbereich (IPAM64): wird nie angeboten, eine Anfrage darauf bekommt NAK, ein Lease darauf wird bei
// der Verlaengerung abgelehnt; eine feste Adresse auf derselben IP geht vor.
func TestExclude(t *testing.T) {
	ex := netip.MustParseAddr("192.168.1.3") // erste vergebbare Adresse (.1 Router, .2 die Node)
	s, _, _ := newTest(t, Config{Excludes: []Exclude{{Scope: 1, IP: ex}}})
	if got := offerAndAck(t, s, macA); got == ex || got != netip.MustParseAddr("192.168.1.4") {
		t.Fatalf("offered %v", got)
	}
	req, _ := dhcpv4.New(dhcpv4.WithHwAddr(macB), dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(ex.AsSlice())))
	if r := s.Handle("eth0", req); r == nil || r.msg.MessageType() != dhcpv4.MessageTypeNak {
		t.Fatalf("excluded requested: %v", r)
	}
	if v := s.Snapshot(); v.Scopes[0].Reserved != 1 {
		t.Fatalf("reserved count: %+v", v.Scopes[0])
	}

	// bestehendes Lease auf der Adresse: Verlaengerung abgelehnt
	lease := Lease{Scope: 1, MAC: macA.String(), IP: ex, Expires: time.Date(2026, 11, 9, 13, 0, 0, 0, time.UTC), State: StateBound}
	s, _, _ = newTest(t, Config{Excludes: []Exclude{{Scope: 1, IP: ex}}, Leases: []Lease{lease}})
	renew, _ := dhcpv4.New(dhcpv4.WithHwAddr(macA), dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest), dhcpv4.WithClientIP(net.IP(ex.AsSlice())))
	if r := s.Handle("eth0", renew); r == nil || r.msg.MessageType() != dhcpv4.MessageTypeNak {
		t.Fatalf("renew on excluded: %v", r)
	}

	// feste Adresse geht vor
	s, _, _ = newTest(t, Config{Reservations: []Reservation{{Scope: 1, MAC: macB.String(), IP: ex}}, Excludes: []Exclude{{Scope: 1, IP: ex}}})
	if got := offerAndAck(t, s, macB); got != ex {
		t.Fatalf("reservation lost to exclude: %v", got)
	}
}
