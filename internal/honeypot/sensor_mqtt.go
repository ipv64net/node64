package honeypot

import (
	"bufio"
	"encoding/binary"
	"io"
	"time"
)

// MQTT-Falle (Stufe 2, Port 1883): liest genau ein CONNECT (MQTT 3.1, 3.1.1, 5), meldet Username/Password als
// mqtt:bruteforce und antwortet mit CONNACK "bad user name or password"; ohne Anmeldedaten CONNACK "not authorized"
// und generic:probe. Danach wird getrennt (wie ein Broker nach abgelehntem CONNECT) – kein SUBSCRIBE, kein PUBLISH.
// Alles andere als ein gueltiges CONNECT wird als generic:probe mit den ersten Bytes gemeldet.

func init() {
	RegisterTCP(&TCPProto{Service: SvcMQTT, Budget: sensorMQTTMax + 16, Handle: (*Sensor).handleMQTT})
}

const (
	sensorMQTTWait = 15 * time.Second // ganze Verbindung
	sensorMQTTMax  = 4096             // Remaining Length eines CONNECT
)

// sensorMQTTConnect sind die Felder eines CONNECT.
type sensorMQTTConnect struct {
	level            byte
	client           string
	user, pass       string
	hasUser, hasPass bool
}

func (s *Sensor) handleMQTT(c *trapConn) {
	_ = c.SetDeadline(time.Now().Add(sensorMQTTWait))
	br := bufio.NewReaderSize(c, 512)
	probe := func(detail string, payload []byte) {
		e := c.event(KindProbe)
		e.Detail = detail
		if len(payload) > 0 {
			e.Payload = payload[:min(len(payload), MaxPayload)]
		}
		s.emit(e)
	}
	first, err := br.ReadByte()
	if err != nil {
		probe("", nil)
		return
	}
	more, _ := br.Peek(min(br.Buffered(), MaxPayload-1))
	head := append([]byte{first}, more...) // erste Bytes, wie empfangen
	n, ok := sensorMQTTLen(br)
	if first != 0x10 || !ok || n > sensorMQTTMax {
		probe("mqtt: no connect", head)
		return
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(br, body); err != nil {
		probe("mqtt: short connect", head)
		return
	}
	m, ok := sensorMQTTParse(body)
	if !ok {
		probe("mqtt: bad connect", head)
		return
	}
	detail := ""
	if m.client != "" {
		detail = "client=" + sensorPlainClip(m.client, sensorPlainClient)
	}
	// CONNACK: 3.x Return Code 4/5, 5.0 Reason Code 0x86/0x87 (dazu leere Properties)
	rc3, rc5 := byte(5), byte(0x87) // not authorized
	if m.hasUser || m.hasPass {
		e := c.event(KindMQTTBrute)
		e.Username, e.Password, e.Detail, e.Client = m.user, m.pass, detail, sensorMQTTVersion(m.level)
		s.login(e)
		sensorPlainPause()
		rc3, rc5 = 4, 0x86 // bad user name or password
	} else {
		e := c.event(KindProbe)
		e.Detail, e.Client = detail, sensorMQTTVersion(m.level)
		s.emit(e)
	}
	ack := []byte{0x20, 2, 0, rc3}
	if m.level == 5 {
		ack = []byte{0x20, 3, 0, rc5, 0}
	}
	_, _ = c.Write(ack)
}

func sensorMQTTVersion(level byte) string {
	switch level {
	case 3:
		return "MQTT 3.1"
	case 4:
		return "MQTT 3.1.1"
	}
	return "MQTT 5.0"
}

// sensorMQTTLen liest die Remaining Length (hoechstens 4 Bytes).
func sensorMQTTLen(br io.ByteReader) (int, bool) {
	n, mul := 0, 1
	for i := 0; i < 4; i++ {
		b, err := br.ReadByte()
		if err != nil {
			return 0, false
		}
		n += int(b&0x7f) * mul
		if b&0x80 == 0 {
			return n, true
		}
		mul *= 128
	}
	return 0, false
}

// sensorMQTTParse zerlegt den Rumpf eines CONNECT (variabler Kopf und Payload).
func sensorMQTTParse(b []byte) (m sensorMQTTConnect, ok bool) {
	r := &sensorMQTTReader{b: b}
	name := r.str()
	m.level = r.byte()
	flags := r.byte()
	r.skip(2) // Keep Alive
	if r.bad || !(name == "MQTT" && (m.level == 4 || m.level == 5) || name == "MQIsdp" && m.level == 3) || flags&1 != 0 {
		return m, false
	}
	if m.level == 5 {
		r.props()
	}
	m.client = r.str()
	if flags&0x04 != 0 { // Will
		if m.level == 5 {
			r.props()
		}
		r.str() // Topic
		r.str() // Nachricht
	}
	if m.hasUser = flags&0x80 != 0; m.hasUser {
		m.user = r.str()
	}
	if m.hasPass = flags&0x40 != 0; m.hasPass {
		m.pass = r.str()
	}
	return m, !r.bad
}

// sensorMQTTReader liest Felder aus einem Paket; bei zu kurzem Paket wird bad gesetzt und nur noch Leeres geliefert.
type sensorMQTTReader struct {
	b   []byte
	bad bool
}

func (r *sensorMQTTReader) skip(n int) []byte {
	if r.bad || n < 0 || n > len(r.b) {
		r.bad = true
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *sensorMQTTReader) byte() byte {
	if v := r.skip(1); v != nil {
		return v[0]
	}
	return 0
}

// str liest einen String bzw. Binaerdaten mit 2-Byte-Laenge.
func (r *sensorMQTTReader) str() string {
	l := r.skip(2)
	if l == nil {
		return ""
	}
	return string(r.skip(int(binary.BigEndian.Uint16(l))))
}

// props ueberspringt die Properties (MQTT 5): Variable Byte Integer als Laenge.
func (r *sensorMQTTReader) props() {
	n, mul := 0, 1
	for i := 0; ; i++ {
		if i == 4 {
			r.bad = true
			return
		}
		b := r.byte()
		if r.bad {
			return
		}
		n += int(b&0x7f) * mul
		if b&0x80 == 0 {
			break
		}
		mul *= 128
	}
	r.skip(n)
}
