package honeypot

import (
	"encoding/base64"
	"io"
	"strconv"
	"strings"
)

// Mail-Fallen (Stufe 2): SMTP (25, 587), POP3 (110) und IMAP (143) ohne TLS. Jede Anmeldung (SMTP AUTH PLAIN/LOGIN,
// POP3 USER/PASS, APOP und AUTH, IMAP LOGIN und AUTHENTICATE) wird als mail:auth-bruteforce gemeldet und abgelehnt.
// SMTP nimmt keine Mail an (kein Relay): RCPT wird abgewiesen und einmal je Verbindung als Relay-Test gemeldet.
// Nach sensorMailTries Versuchen wird getrennt. Zeilen-Sitzung und Grenzen siehe sensorPlain (sensor_ftp.go).

func init() {
	RegisterTCP(&TCPProto{Service: SvcSMTP, Budget: sensorPlainBudget, Handle: (*Sensor).handleSMTP})
	RegisterTCP(&TCPProto{Service: SvcPOP3, Budget: sensorPlainBudget, Handle: (*Sensor).handlePOP3})
	RegisterTCP(&TCPProto{Service: SvcIMAP, Budget: sensorPlainBudget, Handle: (*Sensor).handleIMAP})
}

const (
	sensorMailTries = 5
	sensorMailHost  = "mail.localdomain"
	sensorIMAPCaps  = "IMAP4rev1 LITERAL+ SASL-IR ID ENABLE IDLE AUTH=PLAIN AUTH=LOGIN"
)

func (s *Sensor) handleSMTP(c *trapConn) {
	p := newSensorPlain(s, c)
	defer p.probe()
	if p.write("220 "+sensorMailHost+" ESMTP\r\n") != nil {
		return
	}
	from, relay := "", false
	for p.tries < sensorMailTries {
		line, err := p.line()
		if err != nil {
			return
		}
		verb, arg := p.cmd(line)
		var out string
		switch verb {
		case "EHLO":
			p.client = sensorPlainClip(strings.TrimSpace(arg), sensorPlainClient)
			out = "250-" + sensorMailHost + "\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-AUTH PLAIN LOGIN\r\n" +
				"250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250 SMTPUTF8\r\n"
		case "HELO":
			p.client = sensorPlainClip(strings.TrimSpace(arg), sensorPlainClient)
			out = "250 " + sensorMailHost + "\r\n"
		case "AUTH":
			mech, initial, _ := strings.Cut(arg, " ")
			if mech == "" {
				out = "501 5.5.4 Syntax: AUTH mechanism\r\n"
				break
			}
			user, pass, r := p.sasl(mech, strings.TrimSpace(initial), "334 ")
			switch r {
			case sensorSASLErr:
				return
			case sensorSASLAbort:
				out = "501 5.7.0 Authentication aborted\r\n"
			case sensorSASLBad:
				out = "501 5.5.2 Cannot decode response\r\n"
			case sensorSASLUnknown:
				out = "535 5.7.8 Error: authentication failed: Invalid authentication mechanism\r\n"
			default:
				p.login(KindMailBrute, user, pass, strings.ToLower(mech))
				sensorPlainPause()
				out = "535 5.7.8 Error: authentication failed: authentication failure\r\n"
			}
		case "STARTTLS":
			out = "454 4.7.0 TLS not available due to local problem\r\n"
		case "MAIL":
			from = sensorMailAddr(arg)
			out = "250 2.1.0 Ok\r\n"
		case "RCPT":
			if !relay { // Relay-Test einmal je Verbindung melden
				relay, p.other = true, true
				e := c.event(KindProbe)
				e.Detail, e.Client = "relay", p.client
				e.Payload = []byte("MAIL FROM:" + from + " RCPT TO:" + sensorMailAddr(arg))
				s.emit(e)
			}
			out = "554 5.7.1 Relay access denied\r\n"
		case "DATA", "BDAT":
			out = "554 5.5.1 Error: no valid recipients\r\n"
		case "RSET":
			from = ""
			out = "250 2.0.0 Ok\r\n"
		case "NOOP":
			out = "250 2.0.0 Ok\r\n"
		case "VRFY":
			out = "252 2.0.0 Cannot VRFY user\r\n"
		case "QUIT":
			_ = p.write("221 2.0.0 Bye\r\n")
			return
		default:
			out = "502 5.5.2 Error: command not recognized\r\n"
		}
		if p.write(out) != nil {
			return
		}
	}
	_ = p.write("421 4.7.0 " + sensorMailHost + " Error: too many errors\r\n")
}

// sensorMailAddr liefert die Adresse aus "FROM:<a@b>" bzw. "TO:<a@b>" (gekuerzt, ohne Parameter).
func sensorMailAddr(arg string) string {
	_, a, ok := strings.Cut(arg, ":")
	if !ok {
		a = arg
	}
	a = strings.TrimSpace(a)
	if i := strings.IndexByte(a, '>'); i >= 0 {
		a = a[:i+1]
	} else if i := strings.IndexByte(a, ' '); i >= 0 {
		a = a[:i]
	}
	return sensorPlainClip(a, 100)
}

func (s *Sensor) handlePOP3(c *trapConn) {
	p := newSensorPlain(s, c)
	defer p.probe()
	if p.write("+OK POP3 server ready\r\n") != nil {
		return
	}
	const fail = "-ERR [AUTH] Authentication failed.\r\n"
	user := ""
	for p.tries < sensorMailTries {
		line, err := p.line()
		if err != nil {
			return
		}
		verb, arg := p.cmd(line)
		var out string
		switch verb {
		case "CAPA":
			out = "+OK\r\nCAPA\r\nTOP\r\nUIDL\r\nRESP-CODES\r\nAUTH-RESP-CODE\r\nUSER\r\nSASL PLAIN LOGIN\r\n.\r\n"
		case "USER":
			if user = strings.TrimSpace(arg); user == "" {
				out = "-ERR No username given.\r\n"
				break
			}
			out = "+OK\r\n"
		case "PASS":
			if user == "" {
				out = "-ERR No username given.\r\n"
				break
			}
			p.login(KindMailBrute, user, arg, "user")
			user = ""
			sensorPlainPause()
			out = fail
		case "APOP": // nur der Name ist lesbar (Digest statt Passwort)
			name, _, _ := strings.Cut(strings.TrimSpace(arg), " ")
			if name == "" {
				out = "-ERR Invalid APOP arguments.\r\n"
				break
			}
			p.login(KindMailBrute, name, "", "apop")
			sensorPlainPause()
			out = fail
		case "AUTH":
			mech, initial, _ := strings.Cut(arg, " ")
			if mech == "" {
				out = "+OK\r\nPLAIN\r\nLOGIN\r\n.\r\n"
				break
			}
			u, pw, r := p.sasl(mech, strings.TrimSpace(initial), "+ ")
			switch r {
			case sensorSASLErr:
				return
			case sensorSASLAbort:
				out = "-ERR Authentication aborted.\r\n"
			case sensorSASLBad:
				out = "-ERR Invalid base64 data.\r\n"
			case sensorSASLUnknown:
				out = "-ERR Unsupported authentication mechanism.\r\n"
			default:
				p.login(KindMailBrute, u, pw, strings.ToLower(mech))
				sensorPlainPause()
				out = fail
			}
		case "STLS":
			out = "-ERR TLS not available.\r\n"
		case "QUIT":
			_ = p.write("+OK Logging out.\r\n")
			return
		default:
			out = "-ERR Unknown command.\r\n"
		}
		if p.write(out) != nil {
			return
		}
	}
	_ = p.write("-ERR Too many invalid commands.\r\n")
}

func (s *Sensor) handleIMAP(c *trapConn) {
	p := newSensorPlain(s, c)
	defer p.probe()
	if p.write("* OK [CAPABILITY "+sensorIMAPCaps+"] IMAP server ready\r\n") != nil {
		return
	}
	for p.tries < sensorMailTries {
		line, err := p.line()
		if err != nil {
			return
		}
		tag, rest, _ := strings.Cut(line, " ")
		if !sensorIMAPTag(tag) {
			p.note("")
			if p.write("* BAD Error in IMAP command received by server.\r\n") != nil {
				return
			}
			continue
		}
		verb, arg, _ := strings.Cut(rest, " ")
		verb = strings.ToUpper(verb)
		p.note(verb)
		const fail = " NO [AUTHENTICATIONFAILED] Authentication failed.\r\n"
		var out string
		switch verb {
		case "CAPABILITY":
			out = "* CAPABILITY " + sensorIMAPCaps + "\r\n" + tag + " OK Capability completed.\r\n"
		case "NOOP":
			out = tag + " OK NOOP completed.\r\n"
		case "ID":
			out = "* ID NIL\r\n" + tag + " OK ID completed.\r\n"
		case "LOGIN":
			args, ok, err := p.imapArgs(arg, 2)
			if err != nil {
				return
			}
			if !ok || len(args) != 2 {
				out = tag + " BAD Error in IMAP command LOGIN: Invalid arguments.\r\n"
				break
			}
			p.login(KindMailBrute, args[0], args[1], "login")
			sensorPlainPause()
			out = tag + fail
		case "AUTHENTICATE":
			mech, initial, _ := strings.Cut(arg, " ")
			if mech == "" {
				out = tag + " BAD Error in IMAP command AUTHENTICATE: Invalid arguments.\r\n"
				break
			}
			u, pw, r := p.sasl(mech, strings.TrimSpace(initial), "+ ")
			switch r {
			case sensorSASLErr:
				return
			case sensorSASLAbort:
				out = tag + " BAD Authentication aborted by client.\r\n"
			case sensorSASLBad:
				out = tag + " BAD Invalid base64 data in continued response.\r\n"
			case sensorSASLUnknown:
				out = tag + " NO Unsupported authentication mechanism.\r\n"
			default:
				p.login(KindMailBrute, u, pw, strings.ToLower(mech))
				sensorPlainPause()
				out = tag + fail
			}
		case "STARTTLS":
			out = tag + " NO [UNAVAILABLE] TLS not available.\r\n"
		case "LOGOUT":
			_ = p.write("* BYE Logging out\r\n" + tag + " OK Logout completed.\r\n")
			return
		default:
			out = tag + " BAD Error in IMAP command received by server.\r\n"
		}
		if p.write(out) != nil {
			return
		}
	}
	_ = p.write("* BYE Too many invalid IMAP commands.\r\n")
}

// sensorIMAPTag prueft ein Tag (1–32 druckbare Zeichen ohne Sonderzeichen der IMAP-Syntax); es wird zurueckgeschickt.
func sensorIMAPTag(t string) bool {
	if t == "" || len(t) > 32 {
		return false
	}
	for i := 0; i < len(t); i++ {
		b := t[i]
		if b <= ' ' || b >= 127 || strings.IndexByte(`(){%*"\+`, b) >= 0 {
			return false
		}
	}
	return true
}

// imapArgs liest bis zu n Argumente: Atom, "Quoted" (mit \" und \\) oder Literal {k} bzw. {k+} am Zeilenende (bei
// {k} erst nach "+"-Antwort; k hoechstens sensorPlainLine). ok=false bei Syntaxfehler, err bei Verbindungsfehler.
func (p *sensorPlain) imapArgs(rest string, n int) (args []string, ok bool, err error) {
	for len(args) < n {
		rest = strings.TrimLeft(rest, " ")
		if rest == "" {
			break
		}
		switch rest[0] {
		case '"':
			v, r, good := sensorIMAPQuoted(rest)
			if !good {
				return args, false, nil
			}
			args, rest = append(args, v), r
		case '{':
			if !strings.HasSuffix(rest, "}") {
				return args, false, nil
			}
			num := rest[1 : len(rest)-1]
			sync := !strings.HasSuffix(num, "+")
			k, e := strconv.Atoi(strings.TrimSuffix(num, "+"))
			if e != nil || k < 0 || k > sensorPlainLine {
				return args, false, nil
			}
			if sync {
				if err := p.write("+ Ready for literal data\r\n"); err != nil {
					return args, false, err
				}
			}
			p.deadline(sensorPlainWait)
			b := make([]byte, k)
			if _, err := io.ReadFull(p.br, b); err != nil {
				return args, false, err
			}
			args = append(args, string(b))
			if rest, err = p.line(); err != nil { // Rest der Befehlszeile nach dem Literal
				return args, false, err
			}
		default:
			i := strings.IndexByte(rest, ' ')
			if i < 0 {
				i = len(rest)
			}
			args, rest = append(args, rest[:i]), rest[i:]
		}
	}
	return args, true, nil
}

// sensorIMAPQuoted liest einen IMAP-String in Anfuehrungszeichen; liefert Wert und Rest.
func sensorIMAPQuoted(s string) (string, string, bool) {
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 >= len(s) {
				return "", "", false
			}
			i++
			b.WriteByte(s[i])
		case '"':
			return b.String(), s[i+1:], true
		default:
			b.WriteByte(s[i])
		}
	}
	return "", "", false
}

// Ergebnis eines SASL-Austauschs.
const (
	sensorSASLOK      = iota
	sensorSASLAbort   // Client hat mit "*" abgebrochen
	sensorSASLBad     // nicht dekodierbar
	sensorSASLUnknown // Mechanismus nicht angeboten
	sensorSASLErr     // Verbindung weg oder Grenze erreicht
)

// sasl fuehrt PLAIN oder LOGIN durch (initial = Antwort aus der Befehlszeile, SASL-IR); cont ist das Praefix der
// Rueckfrage ("334 " bei SMTP, "+ " bei POP3/IMAP).
func (p *sensorPlain) sasl(mech, initial, cont string) (user, pass string, res int) {
	next := func(challenge string) (string, int) {
		if err := p.write(cont + challenge + "\r\n"); err != nil {
			return "", sensorSASLErr
		}
		l, err := p.line()
		if err != nil {
			return "", sensorSASLErr
		}
		if strings.TrimSpace(l) == "*" {
			return "", sensorSASLAbort
		}
		return l, sensorSASLOK
	}
	switch strings.ToUpper(mech) {
	case "PLAIN":
		resp := initial
		if resp == "" {
			if resp, res = next(""); res != sensorSASLOK {
				return "", "", res
			}
		}
		u, pw, ok := sensorSASLPlain(resp)
		if !ok {
			return "", "", sensorSASLBad
		}
		return u, pw, sensorSASLOK
	case "LOGIN":
		resp := initial
		if resp == "" {
			if resp, res = next("VXNlcm5hbWU6"); res != sensorSASLOK { // "Username:"
				return "", "", res
			}
		}
		u, ok := sensorB64(resp)
		if !ok {
			return "", "", sensorSASLBad
		}
		if resp, res = next("UGFzc3dvcmQ6"); res != sensorSASLOK { // "Password:"
			return "", "", res
		}
		pw, ok := sensorB64(resp)
		if !ok {
			return "", "", sensorSASLBad
		}
		return u, pw, sensorSASLOK
	}
	return "", "", sensorSASLUnknown
}

// sensorB64 dekodiert eine SASL-Antwort (Base64, zur Not ohne Auffuellung).
func sensorB64(s string) (string, bool) {
	s = strings.TrimSpace(s)
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		if b, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "=")); err != nil {
			return "", false
		}
	}
	return string(b), true
}

// sensorSASLPlain zerlegt PLAIN: authzid \0 authcid \0 passwd (ohne authcid gilt authzid).
func sensorSASLPlain(s string) (user, pass string, ok bool) {
	d, ok := sensorB64(s)
	if !ok {
		return "", "", false
	}
	parts := strings.SplitN(d, "\x00", 3)
	if len(parts) != 3 {
		return "", "", false
	}
	if user = parts[1]; user == "" {
		user = parts[0]
	}
	return user, parts[2], true
}
