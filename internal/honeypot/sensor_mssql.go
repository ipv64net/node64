package honeypot

import (
	"bufio"
	"encoding/binary"
	"io"
	"strings"
	"time"
	"unicode/utf16"
)

// MSSQL-Falle (Stufe 2, Port 1433, TDS): beantwortet PRELOGIN (Version, Verschluesselung ENCRYPT_NOT_SUP), liest
// ein LOGIN7 (HostName, UserName, Password, AppName, ServerName), meldet es als db:bruteforce und
// antwortet mit dem ERROR-Token 18456 "Login failed for user ..."; danach wird getrennt. Keine Datenbank, keine
// Abfragen. Besteht der Client auf Verschluesselung (PRELOGIN ENCRYPT_ON/REQ oder gleich ein TLS-ClientHello wie bei
// TDS 8), wird generic:probe mit Detail "tls" gemeldet und getrennt. Alles andere: generic:probe mit den ersten Bytes.

func init() {
	RegisterTCP(&TCPProto{Service: SvcMSSQL, Budget: 2*sensorMSSQLMax + 64, Handle: (*Sensor).handleMSSQL})
}

const (
	sensorMSSQLWait  = 20 * time.Second // ganze Verbindung
	sensorMSSQLMax   = 8192             // Bytes je Nachricht (alle Pakete zusammen)
	sensorMSSQLChars = 128              // Zeichen je Textfeld des LOGIN7 (Rest verworfen)

	tdsPrelogin = 0x12
	tdsLogin7   = 0x10
	tdsReply    = 0x04

	tdsEncOff    = 0x00
	tdsEncOn     = 0x01
	tdsEncNotSup = 0x02
	tdsEncReq    = 0x03
)

// sensorMSSQLLogin sind die Felder eines LOGIN7.
type sensorMSSQLLogin struct {
	tds                           uint32 // TDS-Version des Clients (z. B. 0x74000004)
	host, user, pass, app, server string
	integrated                    bool // Windows-Anmeldung (SSPI), keine Zugangsdaten
}

func (s *Sensor) handleMSSQL(c *trapConn) {
	_ = c.SetDeadline(time.Now().Add(sensorMSSQLWait))
	br := bufio.NewReaderSize(c, 1024)
	var head []byte // erste Bytes der Verbindung (Probe)
	probe := func(detail string) {
		e := c.event(KindProbe)
		e.Detail = detail
		if len(head) > 0 {
			e.Payload = head[:min(len(head), MaxPayload)]
		}
		s.emit(e)
	}
	if b, err := br.Peek(1); err != nil {
		probe("")
		return
	} else if b[0] == 0x16 { // TLS-ClientHello ohne PRELOGIN (TDS 8, strict)
		head, _ = br.Peek(min(br.Buffered(), MaxPayload))
		head = append([]byte(nil), head...)
		probe("tls")
		return
	}
	typ, msg, err := sensorMSSQLRead(br, &head)
	if err != nil {
		probe("mssql: " + err.Error())
		return
	}
	if typ == tdsPrelogin {
		enc, ok := sensorMSSQLPrelogin(msg)
		if !ok {
			probe("mssql: bad prelogin")
			return
		}
		if _, err := c.Write(sensorMSSQLPreloginReply()); err != nil {
			probe("mssql: prelogin")
			return
		}
		if enc == tdsEncOn || enc == tdsEncReq { // Client bricht ohne TLS ab, Anmeldung kaeme nur verschluesselt
			probe("tls")
			return
		}
		if typ, msg, err = sensorMSSQLRead(br, nil); err != nil {
			probe("mssql: prelogin")
			return
		}
	}
	if typ != tdsLogin7 {
		probe("mssql: no login")
		return
	}
	m, ok := sensorMSSQLParseLogin(msg)
	if !ok {
		probe("mssql: bad login")
		return
	}
	detail := ""
	if m.app != "" {
		detail = "app=" + sensorPlainClip(m.app, sensorPlainClient)
	}
	if m.user == "" && m.pass == "" {
		e := c.event(KindProbe)
		e.Detail, e.Client, e.Host = detail, sensorPlainClip(m.host, sensorPlainClient), sensorPlainClip(m.server, sensorPlainClient)
		if m.integrated {
			e.Detail = strings.TrimSpace("sspi " + detail)
		}
		s.emit(e)
	} else {
		e := c.event(KindDBBrute)
		e.Username, e.Password, e.Detail = m.user, m.pass, detail
		e.Client, e.Host = sensorPlainClip(m.host, sensorPlainClient), sensorPlainClip(m.server, sensorPlainClient)
		s.login(e)
		sensorPlainPause()
	}
	_, _ = c.Write(sensorMSSQLLoginFailed(m.user, m.tds))
}

// sensorMSSQLError ist ein Lesefehler mit kurzem Text fuer das Detail der Probe.
type sensorMSSQLError string

func (e sensorMSSQLError) Error() string { return string(e) }

// sensorMSSQLRead liest eine Nachricht (Pakete bis EOM, alle vom selben Typ, zusammen hoechstens sensorMSSQLMax
// Bytes). head (falls nicht nil) bekommt die ersten Bytes, wie empfangen.
func sensorMSSQLRead(br *bufio.Reader, head *[]byte) (byte, []byte, error) {
	var typ byte
	var msg []byte
	for i := 0; ; i++ {
		var h [8]byte
		n, err := io.ReadFull(br, h[:])
		if head != nil && i == 0 {
			more, _ := br.Peek(min(br.Buffered(), MaxPayload-n))
			*head = append(append([]byte(nil), h[:n]...), more...)
		}
		if err != nil {
			if n == 0 && i == 0 {
				return 0, nil, sensorMSSQLError("no packet")
			}
			return 0, nil, sensorMSSQLError("short packet")
		}
		size := int(binary.BigEndian.Uint16(h[2:4]))
		if i == 0 {
			typ = h[0]
		}
		if h[0] != typ || size < 8 || len(msg)+size-8 > sensorMSSQLMax {
			return 0, nil, sensorMSSQLError("bad packet")
		}
		if typ != tdsPrelogin && typ != tdsLogin7 {
			return typ, nil, nil // anderer Typ: Inhalt egal (Probe)
		}
		part := make([]byte, size-8)
		if _, err := io.ReadFull(br, part); err != nil {
			return 0, nil, sensorMSSQLError("short packet")
		}
		msg = append(msg, part...)
		if h[1]&0x01 != 0 { // EOM
			return typ, msg, nil
		}
	}
}

// sensorMSSQLPrelogin liefert den Verschluesselungswunsch aus einem PRELOGIN (ohne Option: ENCRYPT_OFF).
func sensorMSSQLPrelogin(b []byte) (byte, bool) {
	enc := byte(tdsEncOff)
	for i := 0; i < len(b); i += 5 {
		if b[i] == 0xff { // Terminator
			return enc, true
		}
		if i+5 > len(b) {
			return 0, false
		}
		off, n := int(binary.BigEndian.Uint16(b[i+1:])), int(binary.BigEndian.Uint16(b[i+3:]))
		if off+n > len(b) {
			return 0, false
		}
		if b[i] == 0x01 && n >= 1 { // ENCRYPTION
			enc = b[off]
		}
	}
	return 0, false
}

// sensorMSSQLPreloginReply ist die PRELOGIN-Antwort: VERSION 15.0.2000, ENCRYPT_NOT_SUP, INSTOPT 0, THREADID leer,
// MARS aus.
func sensorMSSQLPreloginReply() []byte {
	body := []byte{
		0x00, 0, 26, 0, 6, // VERSION
		0x01, 0, 32, 0, 1, // ENCRYPTION
		0x02, 0, 33, 0, 1, // INSTOPT
		0x03, 0, 34, 0, 0, // THREADID
		0x04, 0, 34, 0, 1, // MARS
		0xff,
		0x0f, 0x00, 0x07, 0xd0, 0x00, 0x00, // 15.0.2000.0
		tdsEncNotSup,
		0x00,
		0x00,
	}
	return sensorMSSQLPacket(tdsReply, body)
}

// sensorMSSQLPacket setzt einen TDS-Kopf vor body (ein Paket, EOM).
func sensorMSSQLPacket(typ byte, body []byte) []byte {
	p := make([]byte, 8, 8+len(body))
	p[0], p[1] = typ, 0x01
	binary.BigEndian.PutUint16(p[2:], uint16(8+len(body)))
	p[6] = 1 // PacketID
	return append(p, body...)
}

// sensorMSSQLParseLogin zerlegt ein LOGIN7 (Offsets und Laengen aus dem festen Teil, Texte in UCS-2).
func sensorMSSQLParseLogin(b []byte) (m sensorMSSQLLogin, ok bool) {
	if len(b) < 56 {
		return m, false
	}
	m.tds = binary.LittleEndian.Uint32(b[4:])
	m.integrated = b[25]&0x80 != 0 // OptionFlags2 fIntSecurity
	field := func(at int, pass bool) (string, bool) {
		off, n := int(binary.LittleEndian.Uint16(b[at:])), int(binary.LittleEndian.Uint16(b[at+2:]))
		if n == 0 {
			return "", true
		}
		if off+2*n > len(b) {
			return "", false
		}
		raw := b[off : off+2*min(n, sensorMSSQLChars)]
		if pass { // Passwort: je Byte XOR 0xA5, dann Nibbles tauschen
			raw = append([]byte(nil), raw...)
			for i, x := range raw {
				x ^= 0xa5
				raw[i] = x<<4 | x>>4
			}
		}
		u := make([]uint16, len(raw)/2)
		for i := range u {
			u[i] = binary.LittleEndian.Uint16(raw[2*i:])
		}
		return strings.ToValidUTF8(string(utf16.Decode(u)), "?"), true
	}
	var okH, okU, okP, okA, okS bool
	m.host, okH = field(36, false)
	m.user, okU = field(40, false)
	m.pass, okP = field(44, true)
	m.app, okA = field(48, false)
	m.server, okS = field(52, false)
	if !okH || !okU || !okP || !okA || !okS {
		return m, false
	}
	return m, true
}

// sensorMSSQLLoginFailed ist die Antwort auf ein abgelehntes LOGIN7: ERROR 18456 (Klasse 14) und DONE mit
// DONE_ERROR; Zeilennummer und Zeilenzahl je nach TDS-Version 2/4 bzw. 4/8 Bytes.
func sensorMSSQLLoginFailed(user string, tds uint32) []byte {
	wide := tds >= 0x72000000
	msg := utf16.Encode([]rune("Login failed for user '" + sensorPlainClip(user, sensorMSSQLChars) + "'."))
	srv := utf16.Encode([]rune("DB01"))
	var t []byte
	t = binary.LittleEndian.AppendUint32(t, 18456)
	t = append(t, 1, 14) // State, Class
	t = binary.LittleEndian.AppendUint16(t, uint16(len(msg)))
	for _, u := range msg {
		t = binary.LittleEndian.AppendUint16(t, u)
	}
	t = append(t, byte(len(srv)))
	for _, u := range srv {
		t = binary.LittleEndian.AppendUint16(t, u)
	}
	t = append(t, 0) // ProcName leer
	if wide {
		t = binary.LittleEndian.AppendUint32(t, 1)
	} else {
		t = binary.LittleEndian.AppendUint16(t, 1)
	}
	body := []byte{0xaa}
	body = binary.LittleEndian.AppendUint16(body, uint16(len(t)))
	body = append(body, t...)
	body = append(body, 0xfd, 0x02, 0x00, 0x00, 0x00) // DONE: Status DONE_ERROR, CurCmd 0
	if wide {
		body = append(body, 0, 0, 0, 0, 0, 0, 0, 0)
	} else {
		body = append(body, 0, 0, 0, 0)
	}
	return sensorMSSQLPacket(tdsReply, body)
}
