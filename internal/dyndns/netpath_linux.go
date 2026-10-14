//go:build linux

package dyndns

import (
	"context"
	"errors"
	"net/netip"

	"golang.org/x/sys/unix"
)

// traceUDP schickt UDP-Pakete mit steigender TTL und liest die ICMP-Antworten aus der
// Fehlerwarteschlange des Sockets (IP_RECVERR). Das braucht keine Rechte (kein Raw-Socket).
// Liefert je TTL die antwortende Station (ungueltig = keine Antwort).
func traceUDP(ctx context.Context, dst netip.Addr, maxHops int) ([]netip.Addr, error) {
	if !dst.Is4() {
		return nil, errors.New("ipv4 only")
	}
	var hops []netip.Addr
	for ttl := 1; ttl <= maxHops; ttl++ {
		if ctx.Err() != nil {
			return hops, ctx.Err()
		}
		hop, reached, err := probeHop(dst, ttl)
		if err != nil {
			return hops, err
		}
		hops = append(hops, hop)
		if reached {
			break
		}
	}
	return hops, nil
}

func probeHop(dst netip.Addr, ttl int) (hop netip.Addr, reached bool, err error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return hop, false, err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, ttl); err != nil {
		return hop, false, err
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, 1); err != nil {
		return hop, false, err
	}
	if err := unix.Connect(fd, &unix.SockaddrInet4{Port: 33434 + ttl, Addr: dst.As4()}); err != nil {
		return hop, false, err
	}
	_, _ = unix.Write(fd, []byte("node64"))
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLERR}}
	if n, err := unix.Poll(pfd, 1500); err != nil || n == 0 {
		return hop, false, nil // keine Antwort von dieser Station
	}
	buf, oob := make([]byte, 512), make([]byte, 512)
	_, oobn, _, _, err := unix.Recvmsg(fd, buf, oob, unix.MSG_ERRQUEUE)
	if err != nil {
		return hop, false, nil
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return hop, false, nil
	}
	for _, msg := range msgs {
		// sock_extended_err (16 Byte) gefolgt von sockaddr_in des Absenders
		if msg.Header.Level != unix.IPPROTO_IP || msg.Header.Type != unix.IP_RECVERR || len(msg.Data) < 24 {
			continue
		}
		origin, typ := msg.Data[4], msg.Data[5]
		if origin != unix.SO_EE_ORIGIN_ICMP {
			continue
		}
		hop = netip.AddrFrom4([4]byte(msg.Data[20:24]))
		return hop, typ == 3 || hop == dst, nil // 3 = Ziel unerreichbar (Port) -> angekommen
	}
	return hop, false, nil
}
