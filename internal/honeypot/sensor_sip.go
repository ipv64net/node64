package honeypot

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/netip"
	"strings"
	"time"
)

// SIP-Falle (Stufe 2, UDP 5060): liest SIP-Anfragen begrenzt (erste Zeile und hoechstens sensorSIPLines
// Kopfzeilen), User-Agent ins UA-Feld, Methode ins Feld Method. REGISTER/INVITE mit "Authorization: Digest
// username=..." -> sip:bruteforce (Username, Detail "digest"; das Passwort steckt nur als Hash in der Anfrage und
// wird nicht erfasst), sonst sip:scan (Detail: Methode und Nutzer der Request-URI). Antwort: REGISTER/INVITE
// 401 Unauthorized mit WWW-Authenticate (neue Nonce), andere 404 Not Found, ACK nie; nur die fuer eine Antwort
// noetigen Kopfzeilen (Via, From, To, Call-ID, CSeq; knapp, damit sie meist kleiner als die Anfrage ist). Die
// Antwort ist nie groesser als die Anfrage (sonst nur die Statuszeile, passt auch die nicht: keine Antwort). Hoechstens sensorSIPPerSrc Ereignisse und Antworten je Quelle
// und Minute; Pakete, die keine Anfrage sind (auch SIP-Antworten), werden als generic:probe gemeldet, nie beantwortet.

func init() {
	RegisterUDP(&UDPProto{Service: SvcSIP, Handle: (*Sensor).handleSIP})
}

const (
	sensorSIPMax    = 4096 // Bytes je Paket (groessere werden verworfen)
	sensorSIPLines  = 40   // Kopfzeilen
	sensorSIPPerSrc = 30   // Ereignisse und Antworten je Quelle und Minute
	sensorSIPField  = 256  // Zeichen je uebernommener Kopfzeile
	sensorSIPVias   = 4    // Via-Kopfzeilen in der Antwort
)

func (s *Sensor) handleSIP(t *trapService, pc net.PacketConn) {
	lim := newSensorUDPLimit(time.Minute, sensorSIPPerSrc)
	sensorUDPServe(pc, sensorSIPMax, func(b []byte, from netip.AddrPort) []byte {
		if !lim.allow(sensorLimitKey(from.Addr().Unmap()).String(), time.Now()) {
			return nil
		}
		t.conns.Add(1)
		s.counters.Connections.Add(1)
		r, ok := sensorSIPParse(b)
		if !ok {
			e := t.udpEvent(KindProbe, from)
			e.Detail, e.Payload = "sip: no request", b[:min(len(b), MaxPayload)]
			s.emit(e)
			return nil
		}
		e := t.udpEvent(KindSIPScan, from)
		e.Method, e.UA = r.method, r.ua
		code, auth := "404 Not Found", false
		if r.method == "REGISTER" || r.method == "INVITE" {
			code, auth = "401 Unauthorized", true
		}
		if auth && r.digest {
			e.Kind, e.Username, e.Detail = KindSIPBrute, r.user, "digest"
			s.login(e)
		} else {
			e.Detail = strings.ToLower(r.method)
			if u := sensorSIPURIUser(r.uri); u != "" {
				e.Detail += " " + u
			}
			s.emit(e)
		}
		if r.method == "ACK" {
			return nil
		}
		return sensorSIPAnswer(&r, code, auth, len(b))
	})
}

// sensorSIPReq sind die gelesenen Teile einer Anfrage (Texte gekuerzt, ohne Steuerzeichen).
type sensorSIPReq struct {
	method, uri, ua string
	digest          bool   // Authorization: Digest mit username
	user            string // Digest-Username
	via             []string
	from, to        string
	callID, cseq    string
}

// sensorSIPParse liest erste Zeile ("METHODE URI SIP/2.0") und Kopfzeilen bis zur Leerzeile.
func sensorSIPParse(b []byte) (r sensorSIPReq, ok bool) {
	rest := b
	for i := 0; i <= sensorSIPLines && len(rest) > 0; i++ {
		var line []byte
		line, rest, _ = bytes.Cut(rest, []byte("\n"))
		line = bytes.TrimSuffix(line, []byte("\r"))
		if i == 0 {
			p := bytes.SplitN(line, []byte(" "), 3)
			if len(p) != 3 || !sensorSIPMethod(p[0]) || !bytes.EqualFold(p[2], []byte("SIP/2.0")) || len(p[1]) == 0 {
				return r, false
			}
			r.method, r.uri = string(p[0]), sensorPlainClip(string(p[1]), sensorSIPField)
			continue
		}
		if len(line) == 0 {
			break
		}
		name, val, found := bytes.Cut(line, []byte(":"))
		if !found {
			continue
		}
		v := sensorPlainClip(string(bytes.TrimSpace(val)), sensorSIPField)
		switch strings.ToLower(string(bytes.TrimSpace(name))) {
		case "via", "v":
			if len(r.via) < sensorSIPVias {
				r.via = append(r.via, v)
			}
		case "from", "f":
			r.from = v
		case "to", "t":
			r.to = v
		case "call-id", "i":
			r.callID = v
		case "cseq":
			r.cseq = v
		case "user-agent":
			r.ua = v
		case "authorization", "proxy-authorization":
			if u, ok := sensorSIPDigestUser(string(bytes.TrimSpace(val))); ok {
				r.digest, r.user = true, sensorPlainClip(u, MaxText)
			}
		}
	}
	return r, r.method != ""
}

// sensorSIPMethod: Methode aus 2 bis 16 Grossbuchstaben.
func sensorSIPMethod(b []byte) bool {
	if len(b) < 2 || len(b) > 16 {
		return false
	}
	for _, c := range b {
		if c < 'A' || c > 'Z' {
			return false
		}
	}
	return true
}

// sensorSIPDigestUser liefert den Parameter username aus "Digest k=v, k="v", ..." (Werte in Anfuehrungszeichen
// duerfen \ als Escape enthalten).
func sensorSIPDigestUser(v string) (string, bool) {
	scheme, params, _ := strings.Cut(v, " ")
	if !strings.EqualFold(scheme, "Digest") {
		return "", false
	}
	for params != "" {
		params = strings.TrimLeft(params, " \t,")
		key, after, found := strings.Cut(params, "=")
		if !found {
			return "", false
		}
		key = strings.TrimSpace(key)
		after = strings.TrimLeft(after, " \t")
		var val string
		if strings.HasPrefix(after, `"`) {
			var sb strings.Builder
			i, esc := 1, false
			for ; i < len(after); i++ {
				c := after[i]
				if esc {
					sb.WriteByte(c)
					esc = false
					continue
				}
				if c == '\\' {
					esc = true
					continue
				}
				if c == '"' {
					break
				}
				sb.WriteByte(c)
			}
			val, params = sb.String(), after[min(i+1, len(after)):]
		} else {
			val, params, _ = strings.Cut(after, ",")
			val = strings.TrimSpace(val)
		}
		if strings.EqualFold(key, "username") {
			return val, true
		}
	}
	return "", false
}

// sensorSIPURIUser liefert den Nutzer einer SIP-URI ("sip:100@host" -> "100"), gekuerzt; sonst "".
func sensorSIPURIUser(uri string) string {
	l := strings.ToLower(uri)
	switch {
	case strings.HasPrefix(l, "sip:"):
		uri = uri[4:]
	case strings.HasPrefix(l, "sips:"):
		uri = uri[5:]
	default:
		return ""
	}
	u, _, found := strings.Cut(uri, "@")
	if !found {
		return ""
	}
	u, _, _ = strings.Cut(u, ";")
	return sensorPlainClip(strings.ReplaceAll(u, " ", ""), 32)
}

// sensorSIPAnswer baut die Antwort; ist sie groesser als limit, nur die Statuszeile, passt auch die nicht: nil.
func sensorSIPAnswer(r *sensorSIPReq, code string, auth bool, limit int) []byte {
	status := "SIP/2.0 " + code + "\r\n"
	var b strings.Builder
	b.WriteString(status)
	for _, v := range r.via {
		b.WriteString("Via: " + v + "\r\n")
	}
	if r.from != "" {
		b.WriteString("From: " + r.from + "\r\n")
	}
	if r.to != "" {
		to := r.to
		if !strings.Contains(strings.ToLower(to), ";tag=") {
			to += ";tag=" + sensorSIPRand(4)
		}
		b.WriteString("To: " + to + "\r\n")
	}
	if r.callID != "" {
		b.WriteString("Call-ID: " + r.callID + "\r\n")
	}
	if r.cseq != "" {
		b.WriteString("CSeq: " + r.cseq + "\r\n")
	}
	if auth {
		b.WriteString(`WWW-Authenticate: Digest realm="sip", nonce="` + sensorSIPRand(8) + `"` + "\r\n") // MD5 ist Standard
	}
	b.WriteString("\r\n") // ohne Content-Length (bei UDP erlaubt: Rumpf bis Paketende, hier leer)
	if out := b.String(); len(out) <= limit {
		return []byte(out)
	}
	if status += "\r\n"; len(status) <= limit {
		return []byte(status)
	}
	return nil
}

// sensorSIPRand liefert n zufaellige Bytes als Hex (Tag, Nonce).
func sensorSIPRand(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
