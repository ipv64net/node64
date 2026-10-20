package honeypot

import (
	"bytes"
	"encoding/binary"
	"io"
	"strconv"
	"strings"
	"time"
)

// RDP-Falle (Stufe 2, Port 3389): liest genau einen X.224 Connection Request (in TPKT), nimmt den Benutzernamen aus
// dem Cookie "mstshash=" (Klartext, vor jeder Verschluesselung) und die angeforderten Protokolle aus dem RDP
// Negotiation Request, antwortet mit X.224 Connection Confirm und RDP Negotiation Failure und trennt. Kein TLS, kein
// CredSSP, kein Desktop – ein Passwort kommt in diesem Schritt nie vor. Mit Benutzername rdp:bruteforce, sonst
// generic:probe (z. B. Scanner ohne Cookie, Routing-Token, kein RDP).

func init() {
	RegisterTCP(&TCPProto{Service: SvcRDP, Budget: sensorRDPMax + 16, Handle: (*Sensor).handleRDP})
}

const (
	sensorRDPWait = 10 * time.Second // ganze Verbindung
	sensorRDPMax  = 2048             // Laenge eines TPKT (ein Connection Request hat meist unter 100 Bytes)
	sensorRDPHead = 4 + 7            // TPKT-Kopf + fester Teil des X.224 Connection Request
)

// Fehlercodes der RDP Negotiation Failure (MS-RDPBCGR 2.2.1.2.2).
const (
	sensorRDPSSLRequired    = 1 // SSL_REQUIRED_BY_SERVER
	sensorRDPSSLNoCert      = 3 // SSL_CERT_NOT_ON_SERVER
	sensorRDPHybridRequired = 5 // HYBRID_REQUIRED_BY_SERVER
)

// sensorRDPRequest sind die Felder eines Connection Request.
type sensorRDPRequest struct {
	user  string // aus "Cookie: mstshash=<name>"
	token bool   // Routing-Token "Cookie: msts=..." (Lastverteiler) statt Benutzername
	neg   bool   // RDP Negotiation Request vorhanden
	flags byte
	proto uint32 // angeforderte Protokolle
}

func (s *Sensor) handleRDP(c *trapConn) {
	_ = c.SetDeadline(time.Now().Add(sensorRDPWait))
	probe := func(detail string, b []byte) {
		e := c.event(KindProbe)
		e.Detail = detail
		if len(b) > 0 {
			e.Payload = b[:min(len(b), MaxPayload)]
		}
		s.emit(e)
	}
	head := make([]byte, 4)
	if n, err := io.ReadFull(c, head); err != nil {
		if n > 0 {
			probe("rdp: short", head[:n])
		} else {
			probe("", nil)
		}
		return
	}
	if head[0] != 3 || head[1] != 0 {
		// kein TPKT: kurz nachlesen und wie am generischen TCP-Port einordnen (TLS, HTTP, SSH)
		buf := make([]byte, MaxPayload)
		copy(buf, head)
		_ = c.SetReadDeadline(time.Now().Add(sensorTCPMore))
		n, _ := c.Read(buf[4:])
		e := c.event(KindProbe)
		e.Payload = buf[:4+n]
		sensorSniff(&e, buf[:4+n])
		if e.Detail == "" {
			e.Detail = "rdp: no tpkt"
		}
		s.emit(e)
		return
	}
	size := int(binary.BigEndian.Uint16(head[2:]))
	if size < sensorRDPHead || size > sensorRDPMax {
		probe("rdp: bad tpkt", head)
		return
	}
	pkt := make([]byte, size)
	copy(pkt, head)
	if n, err := io.ReadFull(c, pkt[4:]); err != nil {
		probe("rdp: short tpkt", pkt[:4+n])
		return
	}
	r, ok := sensorRDPParse(pkt)
	if !ok {
		probe("rdp: no connection request", pkt)
		return
	}
	if r.user != "" {
		e := c.event(KindRDPBrute)
		e.Username, e.Detail = r.user, r.detail()
		e.Payload = pkt[:min(len(pkt), MaxPayload)]
		s.login(e)
		sensorPlainPause()
	} else {
		probe(r.detail(), pkt)
	}
	// X.224 Connection Confirm (DST-REF = SRC-REF des Clients) mit RDP Negotiation Failure
	out := []byte{3, 0, 0, 19, 14, 0xd0, pkt[8], pkt[9], 0x12, 0x34, 0, 3, 0, 8, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(out[15:], r.failure())
	_, _ = c.Write(out)
}

// sensorRDPParse zerlegt einen vollstaendigen TPKT mit X.224 Connection Request (mindestens sensorRDPHead Bytes).
// Der Benutzername wird mit derselben Auswertung wie am generischen TCP-Port gelesen (sensorSniff), aber nur aus der
// Cookie-Zeile.
func sensorRDPParse(pkt []byte) (sensorRDPRequest, bool) {
	var r sensorRDPRequest
	if len(pkt) < sensorRDPHead || pkt[4] < 6 || pkt[5]&0xf0 != 0xe0 { // LI, Code CR
		return r, false
	}
	data := pkt[sensorRDPHead:]
	if bytes.HasPrefix(data, []byte("Cookie: ")) {
		end, next := len(data), len(data)
		if i := bytes.Index(data, []byte("\r\n")); i >= 0 {
			end, next = i, i+2
		}
		var e Event
		sensorSniff(&e, pkt[:sensorRDPHead+end])
		r.user = sensorPlainClip(strings.TrimSpace(e.Username), MaxText)
		r.token = r.user == "" && bytes.HasPrefix(data[len("Cookie: "):end], []byte("msts="))
		data = data[next:]
	}
	if len(data) >= 8 && data[0] == 1 && binary.LittleEndian.Uint16(data[2:]) == 8 { // TYPE_RDP_NEG_REQ
		r.neg, r.flags, r.proto = true, data[1], binary.LittleEndian.Uint32(data[4:])
	}
	return r, true
}

// detail beschreibt die Anfrage kurz, z. B. "req=ssl,hybrid" oder "req=none routing-token".
func (r sensorRDPRequest) detail() string {
	p := []string{"req=none"}
	if r.neg {
		p[0] = "req=" + sensorRDPProtos(r.proto)
		if r.flags&1 != 0 { // RESTRICTED_ADMIN_MODE_REQUIRED
			p = append(p, "restricted-admin")
		}
	}
	if r.token {
		p = append(p, "routing-token")
	}
	return strings.Join(p, " ")
}

// failure waehlt einen zur Anfrage passenden Fehler: wer CredSSP kann, bekommt "kein Zertifikat", wer nur TLS kann,
// "CredSSP verlangt", alle anderen "TLS verlangt".
func (r sensorRDPRequest) failure() uint32 {
	switch {
	case r.proto&(2|8) != 0: // PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX
		return sensorRDPSSLNoCert
	case r.proto&1 != 0: // PROTOCOL_SSL
		return sensorRDPHybridRequired
	default:
		return sensorRDPSSLRequired
	}
}

// sensorRDPProtos benennt die angeforderten Protokolle (0 = Standard-RDP-Sicherheit).
func sensorRDPProtos(v uint32) string {
	if v == 0 {
		return "rdp"
	}
	var p []string
	for i, n := range []string{"ssl", "hybrid", "rdstls", "hybrid-ex", "rdsaad"} {
		if v&(1<<i) != 0 {
			p = append(p, n)
			v &^= 1 << i
		}
	}
	if v != 0 {
		p = append(p, "0x"+strconv.FormatUint(uint64(v), 16))
	}
	return strings.Join(p, ",")
}
