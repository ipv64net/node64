package honeypot

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"strconv"
	"time"
)

// VNC-Falle (Stufe 2, Port 5900, RFB): sendet "RFB 003.008", liest die Version des Clients (3.3, 3.7, 3.8 und
// Abweichungen wie 3.889 werden wie in RFC 6143 eingeordnet), bietet nur Sicherheitstyp 2 (VNC-Authentifizierung)
// an, schickt eine zufaellige 16-Byte-Challenge und liest die 16-Byte-Antwort. Die Antwort wird als vnc:bruteforce
// gemeldet (ohne Benutzername/Passwort, das Passwort steckt DES-verschluesselt in der Antwort), danach SecurityResult
// "failed" (ab 3.8 mit Grund) und Trennung. Kein Desktop, keine weiteren Nachrichten.

func init() {
	RegisterTCP(&TCPProto{Service: SvcVNC, Budget: sensorVNCBudget, Handle: (*Sensor).handleVNC})
}

const (
	sensorVNCWait   = 15 * time.Second // ganze Verbindung
	sensorVNCBudget = 256              // Client schickt hoechstens 12 + 1 + 16 Bytes
	sensorVNCReason = "Authentication failed"
)

func (s *Sensor) handleVNC(c *trapConn) {
	_ = c.SetDeadline(time.Now().Add(sensorVNCWait))
	client := ""
	probe := func(detail string, b []byte) {
		e := c.event(KindProbe)
		e.Detail, e.Client = detail, client
		if len(b) > 0 {
			e.Payload = b[:min(len(b), MaxPayload)]
		}
		s.emit(e)
	}
	if _, err := io.WriteString(c, "RFB 003.008\n"); err != nil {
		return
	}
	ver := make([]byte, 12)
	if n, err := io.ReadFull(c, ver); err != nil {
		if n > 0 {
			probe("vnc: short version", ver[:n])
		} else {
			probe("", nil)
		}
		return
	}
	minor, ok := sensorVNCVersion(ver)
	if !ok {
		probe("vnc: bad version", ver)
		return
	}
	client = string(ver[:11])
	if minor < 7 {
		// 3.3: der Server bestimmt den Typ (uint32)
		if _, err := c.Write([]byte{0, 0, 0, 2}); err != nil {
			return
		}
	} else {
		// 3.7/3.8: Liste der Typen, Client waehlt einen
		if _, err := c.Write([]byte{1, 2}); err != nil {
			return
		}
		t := make([]byte, 1)
		if _, err := io.ReadFull(c, t); err != nil {
			probe("vnc: no security type", nil)
			return
		}
		if t[0] != 2 {
			probe("vnc: security type "+strconv.Itoa(int(t[0])), t)
			return
		}
	}
	challenge := make([]byte, 16)
	_, _ = rand.Read(challenge)
	if _, err := c.Write(challenge); err != nil {
		return
	}
	resp := make([]byte, 16)
	if n, err := io.ReadFull(c, resp); err != nil {
		probe("vnc: no response", resp[:n])
		return
	}
	e := c.event(KindVNCBrute)
	e.Detail, e.Client, e.Payload = "vnc-auth", client, resp
	s.login(e)
	sensorPlainPause()
	res := []byte{0, 0, 0, 1} // SecurityResult failed
	if minor >= 8 {
		res = binary.BigEndian.AppendUint32(res, uint32(len(sensorVNCReason)))
		res = append(res, sensorVNCReason...)
	}
	_, _ = c.Write(res)
}

// sensorVNCVersion prueft "RFB xxx.yyy\n" und liefert die Unterversion, nach der sich der Server richtet: unter 3.7
// gilt 3.3, ueber 3.8 (oder Hauptversion ueber 3) gilt 3.8.
func sensorVNCVersion(v []byte) (int, bool) {
	if len(v) != 12 || string(v[:4]) != "RFB " || v[7] != '.' || v[11] != '\n' {
		return 0, false
	}
	major, minor := 0, 0
	for i := 4; i < 11; i++ {
		switch {
		case i == 7:
		case v[i] < '0' || v[i] > '9':
			return 0, false
		case i < 7:
			major = major*10 + int(v[i]-'0')
		default:
			minor = minor*10 + int(v[i]-'0')
		}
	}
	if major < 3 {
		return 0, false
	}
	switch {
	case major > 3 || minor >= 8:
		return 8, true
	case minor == 7:
		return 7, true
	default:
		return 3, true
	}
}
