package sonar

// ICMP-Echo (Ping). Zuerst der Linux-Ping-Socket (SOCK_DGRAM, ohne Rechte, net.ipv4.ping_group_range), sonst der
// Raw-Socket (cap_net_raw). Jede Messung oeffnet einen eigenen Socket; beim Raw-Socket filtern ID, Sequenz, Absender
// und eine zufaellige Nutzlast fremde Antworten heraus.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ICMP-Protokollnummern fuer icmp.ParseMessage.
const (
	icmpProto4 = 1
	icmpProto6 = 58
)

// icmpCanListen sagt, ob sich ein ICMP-Socket dieser Art oeffnen laesst.
func icmpCanListen(network, addr string) bool {
	c, err := icmp.ListenPacket(network, addr)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// icmpListen oeffnet den passenden ICMP-Socket fuer die Familie von a (Ping-Socket bevorzugt).
func (p *prober) icmpListen(a netip.Addr) (c *icmp.PacketConn, raw bool, ok bool) {
	fi := probeFam(a)
	nets := [2][2]string{{"udp4", "0.0.0.0"}, {"udp6", "::"}}
	raws := [2][2]string{{"ip4:icmp", "0.0.0.0"}, {"ip6:ipv6-icmp", "::"}}
	if p.ping[fi] {
		if c, err := icmp.ListenPacket(nets[fi][0], nets[fi][1]); err == nil {
			return c, false, true
		}
	}
	if p.raw[fi] {
		if c, err := icmp.ListenPacket(raws[fi][0], raws[fi][1]); err == nil {
			return c, true, true
		}
	}
	return nil, false, false
}

// icmpDst ist die Zieladresse fuer WriteTo (Ping-Socket: UDPAddr, Raw-Socket: IPAddr).
func icmpDst(a netip.Addr, raw bool) net.Addr {
	if raw {
		return &net.IPAddr{IP: a.AsSlice()}
	}
	return &net.UDPAddr{IP: a.AsSlice()}
}

// icmpPeer liest die Absenderadresse eines ICMP-Pakets.
func icmpPeer(n net.Addr) netip.Addr {
	var ip net.IP
	switch v := n.(type) {
	case *net.UDPAddr:
		ip = v.IP
	case *net.IPAddr:
		ip = v.IP
	}
	a, _ := netip.AddrFromSlice(ip)
	return a.Unmap()
}

// icmpRand16 liefert eine zufaellige 16-Bit-Zahl.
func icmpRand16() int {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return int(binary.BigEndian.Uint16(b[:]))
}

// icmpPing misst per ICMP-Echo.
func (p *prober) icmpPing(ctx context.Context, a netip.Addr, count int, res *Result) {
	c, raw, ok := p.icmpListen(a)
	if !ok {
		res.Error = probeErrICMPDenied
		return
	}
	defer c.Close()
	v6 := a.Is6()
	var echo, reply icmp.Type = ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
	proto := icmpProto4
	if v6 {
		echo, reply, proto = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply, icmpProto6
		if raw {
			var f ipv6.ICMPFilter
			f.SetAll(true)
			f.Accept(ipv6.ICMPTypeEchoReply)
			_ = c.IPv6PacketConn().SetICMPFilter(&f)
		}
	}
	dst := icmpDst(a, raw)
	id, seqBase := icmpRand16(), icmpRand16()
	var token [16]byte
	copy(token[:], "S64P")
	_, _ = rand.Read(token[4:])

	send := func(i int) error {
		m := icmp.Message{Type: echo, Body: &icmp.Echo{ID: id, Seq: (seqBase + i) & 0xffff, Data: token[:]}}
		b, err := m.Marshal(nil)
		if err != nil {
			return err
		}
		_, err = c.WriteTo(b, dst)
		return err
	}
	buf := make([]byte, 1500)
	recv := func() (int, error) {
		n, peer, err := c.ReadFrom(buf)
		if err != nil {
			return -1, err
		}
		if icmpPeer(peer) != a {
			return -1, nil
		}
		m, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil || m.Type != reply {
			return -1, nil
		}
		e, ok := m.Body.(*icmp.Echo)
		if !ok || (raw && e.ID != id) || !bytes.Equal(e.Data, token[:]) {
			return -1, nil // Ping-Socket: die ID setzt der Kernel, er ordnet die Antworten selbst zu
		}
		return int(uint16(e.Seq - seqBase)), nil
	}
	rtts, sent, err := runEcho(ctx, c, count, p.cfg.Gap, p.cfg.Timeout, send, recv)
	probeStats(res, rtts, sent)
	if err != nil && (sent == 0 || ctx.Err() != nil) {
		res.Error = probeSendErr(err)
	}
}
