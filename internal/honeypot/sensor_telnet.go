package honeypot

import (
	"bufio"
	"io"
	"time"
)

// Telnet-Falle je Profil: BusyBox-telnetd (IoT/Router, "<host> login: ") oder Linux mit login(1) ("Debian GNU/Linux
// 12" bzw. Ubuntu aus /etc/issue.net, dann "<host> login: "). Login- und Passwort-Abfrage, immer "Login incorrect",
// nach sensorTelTries Versuchen getrennt. Telnet-Optionen (IAC) werden gelesen und ignoriert.
const (
	sensorTelTries   = 3
	sensorTelTimeout = 60 * time.Second
)

// sensorTelDelay ist die Pause vor "Login incorrect" (wie login(1)); Tests setzen sie kurz.
var sensorTelDelay = 500 * time.Millisecond

// Optionen beim Verbindungsaufbau: BusyBox telnetd DO ECHO, DO NAWS, WILL ECHO, WILL SGA; telnetd unter Linux
// (netkit/inetutils) DO TTYPE, DO TSPEED, DO XDISPLOC, DO NEW-ENVIRON, dann WILL ECHO, WILL SGA.
var (
	sensorTelIAC      = []byte{255, 253, 1, 255, 253, 31, 255, 251, 1, 255, 251, 3}
	sensorTelIACLinux = []byte{255, 253, 24, 255, 253, 32, 255, 253, 35, 255, 253, 39, 255, 251, 1, 255, 251, 3}
)

// sensorTelGreeting liefert Optionen, Begruessung (vor dem ersten Prompt) und Prompt zum Profil.
func sensorTelGreeting(persona string, id *sensorIdent) (iac []byte, greet, prompt string) {
	prompt = id.telnetHost(persona) + " login: "
	if persona == PersonaLinux {
		return sensorTelIACLinux, "\r\n" + id.osIssue() + "\r\n", prompt
	}
	return sensorTelIAC, "\r\n", prompt
}

const (
	telIAC  = 255
	telSB   = 250
	telSE   = 240
	telWILL = 251
	telDONT = 254
)

func (s *Sensor) handleTelnet(c *trapConn) {
	_ = c.SetDeadline(time.Now().Add(sensorTelTimeout))
	p := s.personas()
	iac, greet, prompt := sensorTelGreeting(p.of(c.t.key), p.id)
	if _, err := c.Write(append(append([]byte{}, iac...), greet+prompt...)); err != nil {
		return
	}
	tl := &sensorTelLine{br: bufio.NewReaderSize(c, 512), w: c}
	attempts, empty := 0, 0
	for attempts < sensorTelTries {
		user, err := tl.line(true)
		if err != nil {
			if user != "" {
				attempts++
				s.telLogin(c, user, "")
			}
			break
		}
		if user == "" {
			if empty++; empty > 5 {
				break
			}
			if _, err := io.WriteString(c, prompt); err != nil {
				break
			}
			continue
		}
		if _, err := io.WriteString(c, "Password: "); err != nil {
			break
		}
		pass, err := tl.line(false)
		attempts++
		s.telLogin(c, user, pass)
		if err != nil {
			break
		}
		time.Sleep(sensorTelDelay)
		msg := "\r\nLogin incorrect\r\n"
		if attempts < sensorTelTries {
			msg += prompt
		}
		if _, err := io.WriteString(c, msg); err != nil {
			break
		}
	}
	if attempts == 0 {
		s.emit(c.event(KindProbe))
	}
}

func (s *Sensor) telLogin(c *trapConn, user, pass string) {
	e := c.event(KindTelnetBrute)
	e.Username, e.Password = user, pass
	s.login(e)
}

// sensorTelLine liest Zeilen aus einem Telnet-Strom ohne Optionen.
type sensorTelLine struct {
	br *bufio.Reader
	w  io.Writer
	cr bool // letztes Zeichen war CR (folgendes LF/NUL gehoert dazu)
}

// line liest bis CR/LF (hoechstens MaxText Zeichen, Rest verworfen); echo schickt sichtbare Zeichen zurueck
// (Server hat WILL ECHO angeboten). Bei Fehler wird das bis dahin Gelesene mitgeliefert.
func (t *sensorTelLine) line(echo bool) (string, error) {
	var buf []byte
	for {
		b, err := t.br.ReadByte()
		if err != nil {
			return string(buf), err
		}
		if b == telIAC {
			cmd, err := t.br.ReadByte()
			if err != nil {
				return string(buf), err
			}
			switch {
			case cmd == telIAC:
				// IAC IAC = Byte 255 (in Logins bedeutungslos)
			case cmd >= telWILL && cmd <= telDONT:
				if _, err := t.br.ReadByte(); err != nil {
					return string(buf), err
				}
			case cmd == telSB:
				if err := t.skipSB(); err != nil {
					return string(buf), err
				}
			}
			continue
		}
		prevCR := t.cr
		t.cr = b == '\r'
		switch {
		case b == 0:
			continue
		case b == '\n' && prevCR:
			continue
		case b == '\r' || b == '\n':
			if echo {
				_, _ = io.WriteString(t.w, "\r\n")
			}
			return string(buf), nil
		case b == 8 || b == 127:
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
			}
		default:
			if len(buf) < MaxText {
				buf = append(buf, b)
				if echo && b >= 32 {
					_, _ = t.w.Write([]byte{b})
				}
			}
		}
	}
}

// skipSB ueberliest eine Unterverhandlung bis IAC SE.
func (t *sensorTelLine) skipSB() error {
	for {
		b, err := t.br.ReadByte()
		if err != nil {
			return err
		}
		if b != telIAC {
			continue
		}
		b, err = t.br.ReadByte()
		if err != nil {
			return err
		}
		if b == telSE {
			return nil
		}
	}
}
