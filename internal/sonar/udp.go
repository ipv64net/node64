package sonar

// UDP 6464 (Vertrag Abschnitt 4). Anfrage und Antwort sind genau 64 Byte:
//
//	0..3   "S64?" (Anfrage) bzw. "S64!" (Antwort)
//	4      Version (ProtoVersion)
//	5      Typ (1 = Echo)
//	6..13  Nonce (zufaellig je Paket, die Antwort traegt dieselbe)
//	14..17 Kurz-ID: Anfrage = Sender, Antwort = Antwortender (erste 4 Byte von SHA-256(NodeID))
//	18..63 Fuellung 0
//
// Die Antwort ist nie groesser als die Anfrage (keine Verstaerkung).

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net"
	"net/netip"
	"syscall"
)

const (
	s64PacketLen = 64
	s64TypeEcho  = 1
)

var (
	s64MagicReq  = [4]byte{'S', '6', '4', '?'}
	s64MagicResp = [4]byte{'S', '6', '4', '!'}
)

// udpShortID ist die Kurz-ID eines Knotens (erste 4 Byte von SHA-256(NodeID)).
func udpShortID(nodeID string) [4]byte {
	s := sha256.Sum256([]byte(nodeID))
	return [4]byte(s[:4])
}

// s64Encode schreibt ein Paket in b (genau 64 Byte).
func s64Encode(b []byte, magic [4]byte, nonce [8]byte, short [4]byte) {
	_ = b[s64PacketLen-1]
	copy(b[0:4], magic[:])
	b[4] = ProtoVersion
	b[5] = s64TypeEcho
	copy(b[6:14], nonce[:])
	copy(b[14:18], short[:])
	clear(b[18:s64PacketLen])
}

// s64Parse prueft ein Paket streng (Laenge, Kennung, Version, Typ, Fuellung) und liefert Nonce und Kurz-ID.
func s64Parse(b []byte, magic [4]byte) (nonce [8]byte, short [4]byte, ok bool) {
	if len(b) != s64PacketLen || [4]byte(b[0:4]) != magic || b[4] != ProtoVersion || b[5] != s64TypeEcho {
		return nonce, short, false
	}
	for _, c := range b[18:] {
		if c != 0 {
			return nonce, short, false
		}
	}
	return [8]byte(b[6:14]), [4]byte(b[14:18]), true
}

// udpPing misst per UDP 6464 bis zum Knoten selbst. Gezaehlt wird nur eine Antwort mit passender Nonce und der
// Kurz-ID des geplanten Ziels; der verbundene Socket nimmt nur Pakete von Ziel-Adresse und -Port an.
func (p *prober) udpPing(ctx context.Context, a netip.Addr, targetID string, count int, res *Result) {
	network := "udp4"
	if a.Is6() {
		network = "udp6"
	}
	c, err := net.DialUDP(network, nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(a, uint16(p.udpPort))))
	if err != nil {
		res.Error = probeSendErr(err)
		return
	}
	defer c.Close()
	want := udpShortID(targetID)
	nonces := make([][8]byte, count)
	for i := range nonces {
		_, _ = rand.Read(nonces[i][:])
	}
	send := func(i int) error {
		var b [s64PacketLen]byte
		s64Encode(b[:], s64MagicReq, nonces[i], p.short)
		_, err := c.Write(b[:])
		if errors.Is(err, syscall.ECONNREFUSED) {
			// Fehler einer frueheren Probe (Port unerreichbar) wird beim naechsten Senden gemeldet: noch einmal
			_, err = c.Write(b[:])
		}
		return err
	}
	wrong := false // nur im Lese-Goroutine geschrieben, nach runEcho gelesen
	buf := make([]byte, 2*s64PacketLen)
	recv := func() (int, error) {
		n, err := c.Read(buf)
		if err != nil {
			return -1, err
		}
		nonce, short, ok := s64Parse(buf[:n], s64MagicResp)
		if !ok {
			return -1, nil
		}
		for i := range nonces {
			if nonces[i] == nonce {
				if short != want {
					wrong = true
					return -1, nil
				}
				return i, nil
			}
		}
		return -1, nil
	}
	rtts, sent, err := runEcho(ctx, c, count, p.cfg.Gap, p.cfg.Timeout, send, recv)
	probeStats(res, rtts, sent)
	switch {
	case err != nil && (sent == 0 || ctx.Err() != nil):
		res.Error = probeSendErr(err)
	case wrong && res.Recv == 0:
		res.Error = probeErrWrongNode
	}
}
