package honeypot

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// SNMP-Falle (Stufe 2, UDP 161): liest SNMPv1/v2c-Nachrichten (BER, streng begrenzt) und meldet die Community als
// snmp:bruteforce (Password = Community, Detail = Version, PDU-Art und erste OID gekuerzt). SNMPv3: msgUserName als
// Username, Detail "v3" (Discovery ohne Namen: generic:probe). Es wird nie geantwortet – kein Missbrauch als
// Verstaerker, und ein stummer Agent verraet keine gueltige Community. Hoechstens ein Ereignis je Quelle und
// Community (bzw. v3-Name) je Minute, dazu hoechstens sensorSNMPPerSrc Ereignisse je Quelle und Minute (Zaehlung im
// Speicher, begrenzt). Kaputte Pakete: generic:probe mit den ersten Bytes (einmal je Quelle und Minute).
//
// sensorUDPServe und sensorUDPLimit nutzt auch die SIP-Falle (sensor_sip.go).

func init() {
	RegisterUDP(&UDPProto{Service: SvcSNMP, Handle: (*Sensor).handleSNMP})
}

const (
	sensorSNMPMax    = 4096 // Bytes je Paket (groessere werden verworfen)
	sensorSNMPPerSrc = 60   // Ereignisse je Quelle und Minute
	sensorSNMPOID    = 64   // Zeichen der ersten OID
	sensorSNMPKey    = 64   // Bytes der Community im Schluessel des Rate-Limits

	sensorUDPKeys = 4096 // Eintraege je Rate-Limit
)

func (s *Sensor) handleSNMP(t *trapService, pc net.PacketConn) {
	pair := newSensorUDPLimit(time.Minute, 1)
	perSrc := newSensorUDPLimit(time.Minute, sensorSNMPPerSrc)
	sensorUDPServe(pc, sensorSNMPMax, func(b []byte, from netip.AddrPort) []byte {
		ip := sensorLimitKey(from.Addr().Unmap()).String() // IPv6 je /64
		m, ok := sensorSNMPParse(b)
		var e Event
		var key string
		switch {
		case !ok:
			e = t.udpEvent(KindProbe, from)
			e.Detail, e.Payload, key = "snmp: bad packet", b[:min(len(b), MaxPayload)], "?"
		case m.version == 3 && m.user == "":
			e = t.udpEvent(KindProbe, from)
			e.Detail, key = "v3 discovery", "3"
		case m.version == 3:
			e = t.udpEvent(KindSNMPBrute, from)
			e.Username, e.Detail, key = m.user, "v3", "3"+m.user[:min(len(m.user), sensorSNMPKey)]
		default:
			e = t.udpEvent(KindSNMPBrute, from)
			e.Password, e.Detail, key = m.community, m.detail(), "c"+m.community[:min(len(m.community), sensorSNMPKey)]
		}
		now := time.Now()
		if !pair.allow(ip+"\x00"+key, now) || !perSrc.allow(ip, now) {
			return nil
		}
		t.conns.Add(1)
		s.counters.Connections.Add(1)
		if e.Kind == KindProbe {
			s.emit(e)
		} else {
			s.login(e)
		}
		return nil // nie antworten
	})
}

// sensorSNMPMsg sind die erfassten Felder einer Nachricht.
type sensorSNMPMsg struct {
	version   int // 0 = v1, 1 = v2c, 3 = v3
	community string
	pdu       byte   // Tag der PDU (0xA0 bis 0xA8)
	oid       string // erste OID, gekuerzt ("" = keine)
	user      string // v3: msgUserName
}

// detail liefert "v1|v2c <pdu> <oid>".
func (m sensorSNMPMsg) detail() string {
	v := "v1"
	if m.version == 1 {
		v = "v2c"
	}
	names := [...]string{"get", "getnext", "response", "set", "trap", "getbulk", "inform", "trap2", "report"}
	d := v + " " + names[m.pdu-0xA0]
	if m.oid != "" {
		d += " " + m.oid
	}
	return d
}

// sensorSNMPParse zerlegt eine Nachricht (nur die Felder, die erfasst werden).
func sensorSNMPParse(b []byte) (m sensorSNMPMsg, ok bool) {
	r := sensorSNMPBER{b: b}
	tag, msg := r.next()
	if r.bad || tag != 0x30 {
		return m, false
	}
	in := sensorSNMPBER{b: msg}
	tag, v := in.next()
	ver, vok := sensorSNMPInt(v)
	if in.bad || tag != 0x02 || !vok {
		return m, false
	}
	m.version = ver
	switch ver {
	case 0, 1:
		tag, c := in.next()
		if in.bad || tag != 0x04 {
			return m, false
		}
		m.community = string(c)
		tag, pdu := in.next()
		if in.bad || tag < 0xA0 || tag > 0xA8 {
			return m, false
		}
		m.pdu, m.oid = tag, sensorSNMPFirstOID(tag, pdu)
		return m, true
	case 3:
		if tag, _ := in.next(); in.bad || tag != 0x30 { // msgGlobalData
			return m, false
		}
		tag, sp := in.next() // msgSecurityParameters: OCTET STRING mit der USM-Folge
		if in.bad || tag != 0x04 {
			return m, false
		}
		sr := sensorSNMPBER{b: sp}
		tag, usm := sr.next()
		if sr.bad || tag != 0x30 {
			return m, false
		}
		u := sensorSNMPBER{b: usm}
		for _, want := range []byte{0x04, 0x02, 0x02} { // EngineID, EngineBoots, EngineTime
			if tag, _ := u.next(); u.bad || tag != want {
				return m, false
			}
		}
		tag, name := u.next()
		if u.bad || tag != 0x04 {
			return m, false
		}
		m.user = string(name)
		return m, true
	}
	return m, false
}

// sensorSNMPFirstOID liefert die erste OID einer PDU (Trap v1: Enterprise-OID, sonst die erste Variable).
func sensorSNMPFirstOID(tag byte, pdu []byte) string {
	p := sensorSNMPBER{b: pdu}
	if tag != 0xA4 {
		for i := 0; i < 3; i++ { // request-id, error-status, error-index (GetBulk: non-repeaters, max-repetitions)
			if t, _ := p.next(); t != 0x02 {
				return ""
			}
		}
		t, list := p.next()
		if p.bad || t != 0x30 {
			return ""
		}
		p = sensorSNMPBER{b: list}
		t, vb := p.next()
		if p.bad || t != 0x30 {
			return ""
		}
		p = sensorSNMPBER{b: vb}
	}
	t, oid := p.next()
	if p.bad || t != 0x06 {
		return ""
	}
	return sensorSNMPOIDString(oid)
}

// sensorSNMPOIDString wandelt eine OID in Punktschreibweise (hoechstens sensorSNMPOID Zeichen, Teilzahlen hoechstens
// 5 Bytes; danach wird abgeschnitten).
func sensorSNMPOIDString(b []byte) string {
	var sb strings.Builder
	var v uint64
	n, first := 0, true
	for _, c := range b {
		if n >= 5 || sb.Len() >= sensorSNMPOID {
			break
		}
		v, n = v<<7|uint64(c&0x7f), n+1
		if c&0x80 != 0 {
			continue
		}
		if first {
			x := min(v/40, 2)
			sb.WriteString(strconv.FormatUint(x, 10) + "." + strconv.FormatUint(v-40*x, 10))
			first = false
		} else {
			sb.WriteString("." + strconv.FormatUint(v, 10))
		}
		v, n = 0, 0
	}
	s := sb.String()
	if len(s) > sensorSNMPOID {
		s = s[:sensorSNMPOID]
	}
	return s
}

// sensorSNMPInt liest eine kleine Ganzzahl (1 bis 4 Bytes, mit Vorzeichen).
func sensorSNMPInt(b []byte) (int, bool) {
	if len(b) < 1 || len(b) > 4 {
		return 0, false
	}
	v := int(int8(b[0]))
	for _, c := range b[1:] {
		v = v<<8 | int(c)
	}
	return v, true
}

// sensorSNMPBER liest BER-Elemente (nur Tags mit einem Byte, Laenge kurz oder lang mit hoechstens 4 Bytes, nie ueber
// das Ende hinaus); bei einem Fehler wird bad gesetzt und nur noch Leeres geliefert.
type sensorSNMPBER struct {
	b   []byte
	bad bool
}

func (r *sensorSNMPBER) next() (byte, []byte) {
	if r.bad || len(r.b) < 2 || r.b[0]&0x1f == 0x1f {
		r.bad = true
		return 0, nil
	}
	tag, l, i := r.b[0], int(r.b[1]), 2
	if l&0x80 != 0 {
		k := l & 0x7f
		if k == 0 || k > 4 || len(r.b) < 2+k { // 0 = unbestimmte Laenge (nicht erlaubt)
			r.bad = true
			return 0, nil
		}
		var ul uint64 // uint64: 4 Laengenbytes laufen in int auf 32-Bit-Systemen (arm/v7) ins Negative
		for _, c := range r.b[2 : 2+k] {
			ul = ul<<8 | uint64(c)
		}
		i += k
		if ul > uint64(len(r.b)-i) {
			r.bad = true
			return 0, nil
		}
		l = int(ul)
	}
	if l > len(r.b)-i {
		r.bad = true
		return 0, nil
	}
	v := r.b[i : i+l]
	r.b = r.b[i+l:]
	return tag, v
}

// sensorUDPServe liest Pakete, bis pc geschlossen wird, und gibt jedes an handle (der Puffer wird wiederverwendet,
// handle darf ihn nicht behalten). Eine Antwort (nil = keine) wird nur gesendet, wenn sie nicht groesser als die
// Anfrage ist. Pakete ueber size Bytes werden verworfen.
func sensorUDPServe(pc net.PacketConn, size int, handle func(b []byte, from netip.AddrPort) []byte) {
	buf := make([]byte, size+1)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(time.Millisecond) // z. B. ICMP-Fehler (Windows: Verbindung zurueckgesetzt) oder zu grosses Paket
			continue
		}
		ua, ok := addr.(*net.UDPAddr)
		if !ok || n == 0 || n > size {
			continue
		}
		from := ua.AddrPort()
		if !from.Addr().IsValid() || from.Port() == 0 {
			continue
		}
		if out := handle(buf[:n], from); len(out) > 0 && len(out) <= n {
			_ = pc.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = pc.WriteTo(out, addr)
		}
	}
}

// sensorUDPLimit zaehlt Treffer je Schluessel in festen Zeitfenstern (hoechstens sensorUDPKeys Schluessel). Nur aus
// einer Goroutine nutzen (der Schleife eines UDP-Dienstes).
type sensorUDPLimit struct {
	win   time.Duration
	max   int
	m     map[string]sensorUDPHit
	swept time.Time
}

type sensorUDPHit struct {
	start time.Time
	n     int
}

func newSensorUDPLimit(win time.Duration, n int) *sensorUDPLimit {
	return &sensorUDPLimit{win: win, max: n, m: map[string]sensorUDPHit{}}
}

// allow zaehlt einen Treffer; false, wenn der Schluessel im laufenden Fenster schon max Treffer hat oder die Tabelle
// voll ist (abgelaufene Eintraege werden dann entfernt, hoechstens alle win/10).
func (l *sensorUDPLimit) allow(key string, now time.Time) bool {
	h, ok := l.m[key]
	if ok && now.Sub(h.start) < l.win {
		if h.n >= l.max {
			return false
		}
		h.n++
		l.m[key] = h
		return true
	}
	if !ok && len(l.m) >= sensorUDPKeys {
		if now.Sub(l.swept) >= l.win/10 {
			l.swept = now
			for k, x := range l.m {
				if now.Sub(x.start) >= l.win {
					delete(l.m, k)
				}
			}
		}
		if len(l.m) >= sensorUDPKeys {
			return false
		}
	}
	l.m[key] = sensorUDPHit{start: now, n: 1}
	return true
}
