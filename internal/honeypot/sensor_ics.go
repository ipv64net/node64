package honeypot

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// Fallen fuer Industrie und Gebaeudetechnik (H8 Phase 4): Modbus/TCP (502), Siemens S7comm (102, ISO-on-TCP) und
// BACnet/IP (47808/udp). Nur lesen und die Anfrage erfassen: lesende Funktionen bzw. Erkennung als ics:scan,
// schreibende bzw. steuernde (Register schreiben, CPU starten/stoppen, Download) als ics:exploit. Antworten nie
// groesser als die Anfrage: Modbus eine Exception „Illegal Function“, S7 eine COTP-Bestaetigung in der Groesse der
// Anfrage und danach Ende, BACnet gar keine Antwort (I-Am waere groesser als Who-Is).

func init() {
	RegisterTCP(&TCPProto{Service: SvcModbus, Budget: 4 << 10, Handle: (*Sensor).handleModbus})
	RegisterTCP(&TCPProto{Service: SvcS7, Budget: 4 << 10, Handle: (*Sensor).handleS7})
	RegisterUDP(&UDPProto{Service: SvcBACnet, Handle: (*Sensor).handleBACnet})
}

const (
	sensorICSWait      = 15 * time.Second // ganze Verbindung
	sensorModbusFrames = 8                // Anfragen je Verbindung
	sensorBACnetMax    = 1500             // Bytes je Paket
	sensorBACnetPerSrc = 30               // Ereignisse je Quelle und Minute
)

// ---------------------------------------------------------------- Modbus/TCP

// sensorModbusWrite: Funktionscodes, die schreiben bzw. steuern (5/6/15/16 Coils und Register, 22/23 Masken und
// Lesen+Schreiben, 8 Diagnose u. a. mit Neustart der Kommunikation).
var sensorModbusWrite = map[byte]bool{5: true, 6: true, 8: true, 15: true, 16: true, 22: true, 23: true}

func (s *Sensor) handleModbus(c *trapConn) {
	_ = c.SetDeadline(time.Now().Add(sensorICSWait))
	br := bufio.NewReaderSize(c, 512)
	for n := 0; n < sensorModbusFrames; n++ {
		hdr := make([]byte, 7) // MBAP: Transaktion 2, Protokoll 2, Laenge 2, Unit 1
		if _, err := io.ReadFull(br, hdr); err != nil {
			if n == 0 {
				e := c.event(KindProbe)
				e.Detail = "modbus: short"
				e.Payload = hdr[:min(len(hdr), MaxPayload)]
				s.emit(e)
			}
			return
		}
		ln := int(binary.BigEndian.Uint16(hdr[4:6]))
		if binary.BigEndian.Uint16(hdr[2:4]) != 0 || ln < 2 || ln > 254 {
			e := c.event(KindProbe)
			e.Detail, e.Payload = "modbus: bad header", hdr
			s.emit(e)
			return
		}
		pdu := make([]byte, ln-1)
		if _, err := io.ReadFull(br, pdu); err != nil {
			return
		}
		fc := pdu[0]
		kind := KindICSScan
		if sensorModbusWrite[fc&0x7f] {
			kind = KindICSExploit
		}
		e := c.event(kind)
		e.Detail = "modbus fc=" + strconv.Itoa(int(fc)) + " unit=" + strconv.Itoa(int(hdr[6]))
		e.Payload = append(append([]byte(nil), hdr...), pdu...)[:min(7+len(pdu), MaxPayload)]
		s.emit(e)
		// Exception 0x01 „Illegal Function“: 9 Bytes, die Anfrage hat mindestens 9 (7 MBAP + Funktion + Daten)
		if 7+len(pdu) < 9 {
			continue
		}
		out := []byte{hdr[0], hdr[1], 0, 0, 0, 3, hdr[6], fc | 0x80, 0x01}
		if _, err := c.Write(out); err != nil {
			return
		}
	}
}

// ---------------------------------------------------------------- Siemens S7 (ISO-on-TCP)

// sensorS7Func: Funktionen des S7comm-Jobs (0x32 ROSCTR 1) zur Einordnung (Name; true = schreibt bzw. steuert).
var sensorS7Func = map[byte]struct {
	name  string
	write bool
}{
	0xf0: {"setup-communication", false}, 0x04: {"read-var", false}, 0x05: {"write-var", true},
	0x1a: {"request-download", true}, 0x1b: {"download-block", true}, 0x1c: {"download-ended", true},
	0x1d: {"start-upload", false}, 0x28: {"plc-control", true}, 0x29: {"plc-stop", true},
}

func (s *Sensor) handleS7(c *trapConn) {
	_ = c.SetDeadline(time.Now().Add(sensorICSWait))
	br := bufio.NewReaderSize(c, 512)
	read := func() ([]byte, bool) { // TPKT: Version 3, reserviert, Laenge 2 (mit Kopf)
		h := make([]byte, 4)
		if _, err := io.ReadFull(br, h); err != nil || h[0] != 3 {
			return h, false
		}
		ln := int(binary.BigEndian.Uint16(h[2:4]))
		if ln < 7 || ln > 1024 {
			return h, false
		}
		body := make([]byte, ln-4)
		if _, err := io.ReadFull(br, body); err != nil {
			return h, false
		}
		return append(h, body...), true
	}
	pkt, ok := read()
	// COTP Connection Request: Laenge, 0xE0, dst-ref 2, src-ref 2, Klasse, Parameter (TSAPs, TPDU-Groesse)
	if !ok || len(pkt) < 11 || pkt[5] != 0xe0 {
		e := c.event(KindProbe)
		e.Detail, e.Payload = "s7: no cotp connect", pkt[:min(len(pkt), MaxPayload)]
		s.emit(e)
		return
	}
	// Connection Confirm genau so gross wie die Anfrage: Parameter gespiegelt, Referenzen getauscht
	cc := append([]byte(nil), pkt...)
	cc[5] = 0xd0
	cc[6], cc[7] = pkt[8], pkt[9] // dst-ref = src-ref der Anfrage
	cc[8], cc[9] = 0x00, 0x01
	if _, err := c.Write(cc); err != nil {
		return
	}
	pkt, ok = read()
	// COTP DT (Laenge 2, 0xF0, EOT) und S7comm-Kopf (0x32, ROSCTR, ...), Funktion am Anfang der Parameter
	if !ok || len(pkt) < 4+3+10 || pkt[5] != 0xf0 || pkt[7] != 0x32 {
		e := c.event(KindICSScan)
		e.Detail = "s7: cotp connect"
		s.emit(e)
		return
	}
	s7 := pkt[7:]
	hl := 10
	if s7[1] == 2 || s7[1] == 3 { // Ack-Data mit Fehlerfeld (vom Client unueblich)
		hl = 12
	}
	kind, name := KindICSScan, "rosctr="+strconv.Itoa(int(s7[1]))
	if s7[1] == 7 { // Userdata, z. B. SZL lesen (Erkennung der CPU)
		name = "userdata"
	} else if len(s7) > hl {
		if f, ok := sensorS7Func[s7[hl]]; ok {
			name = f.name
			if f.write {
				kind = KindICSExploit
			}
		} else {
			name = "func=0x" + strconv.FormatInt(int64(s7[hl]), 16)
		}
	}
	e := c.event(kind)
	e.Detail = "s7 " + name
	e.Payload = pkt[:min(len(pkt), MaxPayload)]
	s.emit(e)
}

// ---------------------------------------------------------------- BACnet/IP (UDP)

// sensorBACnetService: unbestaetigte (Who-Is, Who-Has, I-Am) bzw. bestaetigte Dienste zur Einordnung.
var (
	sensorBACnetUnconf = map[byte]string{0: "i-am", 1: "i-have", 7: "who-has", 8: "who-is"}
	sensorBACnetConf   = map[byte]struct {
		name  string
		write bool
	}{12: {"read-property", false}, 14: {"read-property-multiple", false}, 15: {"write-property", true},
		16: {"write-property-multiple", true}, 17: {"device-communication-control", true}, 20: {"reinitialize-device", true}}
)

func (s *Sensor) handleBACnet(t *trapService, pc net.PacketConn) {
	perSrc := newSensorUDPLimit(time.Minute, sensorBACnetPerSrc)
	sensorUDPServe(pc, sensorBACnetMax, func(b []byte, from netip.AddrPort) []byte {
		if !perSrc.allow(sensorLimitKey(from.Addr().Unmap()).String(), time.Now()) { // IPv6 je /64
			return nil
		}
		kind, detail := KindProbe, "bacnet: no bvlc"
		if len(b) >= 4 && b[0] == 0x81 { // BVLC: Typ 0x81, Funktion, Laenge 2
			kind, detail = KindICSScan, "bacnet bvlc="+strconv.Itoa(int(b[1]))
			if apdu, ok := sensorBACnetAPDU(b); ok {
				switch apdu[0] >> 4 {
				case 1: // Unconfirmed-Request: Dienst im zweiten Byte
					if len(apdu) > 1 {
						detail = "bacnet " + sensorBACnetName(sensorBACnetUnconf[apdu[1]], apdu[1])
					}
				case 0: // Confirmed-Request: Kopf 4 Bytes (ohne Segmentierung), Dienst im vierten
					if len(apdu) > 3 {
						f := sensorBACnetConf[apdu[3]]
						detail = "bacnet " + sensorBACnetName(f.name, apdu[3])
						if f.write {
							kind = KindICSExploit
						}
					}
				}
			}
		}
		e := t.udpEvent(kind, from)
		e.Detail, e.Payload = detail, b[:min(len(b), MaxPayload)]
		t.conns.Add(1)
		s.counters.Connections.Add(1)
		s.emit(e)
		return nil // nie antworten
	})
}

// sensorBACnetAPDU springt ueber BVLC und NPDU (Version 1, Steuerbyte mit optionalen Ziel-/Quelladressen).
func sensorBACnetAPDU(b []byte) ([]byte, bool) {
	if len(b) < 6 {
		return nil, false
	}
	n := b[4:] // NPDU
	if n[0] != 1 || len(n) < 2 {
		return nil, false
	}
	ctl, i := n[1], 2
	if ctl&0x80 != 0 { // Netzwerknachricht, keine APDU
		return nil, false
	}
	if ctl&0x20 != 0 { // Ziel: Netz 2, Laenge 1, Adresse, spaeter Hop-Count 1
		if len(n) < i+3 {
			return nil, false
		}
		i += 3 + int(n[i+2])
	}
	if ctl&0x08 != 0 { // Quelle: Netz 2, Laenge 1, Adresse
		if len(n) < i+3 {
			return nil, false
		}
		i += 3 + int(n[i+2])
	}
	if ctl&0x20 != 0 {
		i++ // Hop-Count
	}
	if len(n) <= i {
		return nil, false
	}
	return n[i:], true
}

func sensorBACnetName(name string, svc byte) string {
	if name != "" {
		return name
	}
	return "service=" + strconv.Itoa(int(svc))
}
