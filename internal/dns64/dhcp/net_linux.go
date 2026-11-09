//go:build linux

package dhcp

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// listen oeffnet einen UDP-Socket auf port, gebunden an die Schnittstelle (SO_BINDTODEVICE, braucht cap_net_raw),
// mit Broadcast. SO_REUSEADDR: mehrere Schnittstellen teilen sich Port 67.
func listen(ctx context.Context, iface string, port int) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		if err := rc.Control(func(fd uintptr) {
			for _, o := range []int{unix.SO_REUSEADDR, unix.SO_BROADCAST} {
				if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, o, 1); serr != nil {
					return
				}
			}
			serr = unix.BindToDevice(int(fd), iface)
		}); err != nil {
			return err
		}
		return serr
	}}
	pc, err := lc.ListenPacket(ctx, "udp4", ":"+strconv.Itoa(port))
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// ARPProbe fragt per ARP, ob ip im Netz der Schnittstelle schon antwortet (true = belegt). Ohne cap_net_raw oder
// bei Fehlern: false (keine Pruefung).
func ARPProbe(iface string, src, ip netip.Addr) bool {
	ifi, err := net.InterfaceByName(iface)
	if err != nil || len(ifi.HardwareAddr) != 6 || !src.Is4() || !ip.Is4() {
		return false
	}
	proto := htons(unix.ETH_P_ARP)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(proto))
	if err != nil {
		return false
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: proto, Ifindex: ifi.Index}); err != nil {
		return false
	}
	pkt := make([]byte, 28)
	binary.BigEndian.PutUint16(pkt[0:], 1)      // Ethernet
	binary.BigEndian.PutUint16(pkt[2:], 0x0800) // IPv4
	pkt[4], pkt[5] = 6, 4
	binary.BigEndian.PutUint16(pkt[6:], 1) // Anfrage
	copy(pkt[8:], ifi.HardwareAddr)
	s4, t4 := src.As4(), ip.As4()
	copy(pkt[14:], s4[:])
	copy(pkt[24:], t4[:])
	to := &unix.SockaddrLinklayer{Protocol: proto, Ifindex: ifi.Index, Halen: 6, Addr: [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}
	if err := unix.Sendto(fd, pkt, 0, to); err != nil {
		return false
	}
	deadline := time.Now().Add(probeWait)
	buf := make([]byte, 128)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return false
		}
		tv := unix.NsecToTimeval(left.Nanoseconds())
		_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return false
		}
		if n >= 28 && binary.BigEndian.Uint16(buf[6:]) == 2 && [4]byte(buf[14:18]) == t4 {
			return true
		}
	}
}
