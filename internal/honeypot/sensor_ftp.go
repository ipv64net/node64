package honeypot

import (
	"bufio"
	"errors"
	"io"
	"math/rand/v2"
	"strings"
	"time"
)

// FTP-Falle (Stufe 2): Banner, USER/PASS werden erfasst und immer mit 530 abgelehnt (auch anonymous), nach
// sensorFTPTries Versuchen getrennt. Kein Datenkanal (PASV/PORT), keine Dateien, kein TLS (AUTH TLS -> 502).
//
// Die Zeilen-Sitzung sensorPlain (Zeitlimit je Befehl, Gesamtzeit, Zeilenlaenge, Befehlszahl) nutzen auch SMTP,
// POP3 und IMAP (sensor_mail.go).

func init() {
	RegisterTCP(&TCPProto{Service: SvcFTP, Budget: sensorPlainBudget, Handle: (*Sensor).handleFTP})
}

const (
	sensorFTPTries = 5

	sensorPlainLine   = 512              // Zeichen je Zeile (Rest verworfen)
	sensorPlainWait   = 30 * time.Second // je Befehl
	sensorPlainTotal  = 2 * time.Minute  // je Verbindung
	sensorPlainCmds   = 40               // Zeilen je Verbindung
	sensorPlainBudget = 16 << 10         // gelesene Bytes je Verbindung
	sensorPlainClient = 64               // Zeichen der Client-Kennung (EHLO-Name, Client-ID)
)

// sensorPlainDelay ist die Grundpause vor einer Ablehnung (dazu zufaellig bis zu derselben Dauer); Tests setzen 0.
var sensorPlainDelay = 400 * time.Millisecond

var errSensorPlainLimit = errors.New("too many commands")

func (s *Sensor) handleFTP(c *trapConn) {
	p := newSensorPlain(s, c)
	user, pending := "", false
	defer func() {
		if pending { // USER ohne PASS bis zum Ende
			s.ftpLogin(p, user, "")
		}
		p.probe()
	}()
	if p.write("220 FTP server ready\r\n") != nil {
		return
	}
	for p.tries < sensorFTPTries {
		line, err := p.line()
		if err != nil {
			return
		}
		verb, arg := p.cmd(line)
		var out string
		switch verb {
		case "USER":
			if arg = strings.TrimSpace(arg); arg == "" {
				out = "501 Syntax error in parameters or arguments.\r\n"
				break
			}
			user, pending = arg, true
			out = "331 Please specify the password.\r\n"
		case "PASS":
			if !pending {
				out = "503 Login with USER first.\r\n"
				break
			}
			pending = false
			s.ftpLogin(p, user, arg)
			sensorPlainPause()
			out = "530 Login incorrect.\r\n"
		case "SYST":
			out = "215 UNIX Type: L8\r\n"
		case "FEAT":
			out = "211-Features:\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r\n SIZE\r\n UTF8\r\n211 End\r\n"
		case "AUTH", "PBSZ", "PROT", "CCC":
			out = "502 Command not implemented.\r\n"
		case "OPTS":
			out = "200 Always in UTF8 mode.\r\n"
		case "NOOP":
			out = "200 NOOP ok.\r\n"
		case "QUIT":
			_ = p.write("221 Goodbye.\r\n")
			return
		default:
			out = "530 Please login with USER and PASS.\r\n"
		}
		if p.write(out) != nil {
			return
		}
	}
}

func (s *Sensor) ftpLogin(p *sensorPlain, user, pass string) {
	detail := ""
	if u := strings.ToLower(user); u == "anonymous" || u == "ftp" {
		detail = "anonymous"
	}
	p.login(KindFTPBrute, user, pass, detail)
}

// sensorPlain ist eine zeilenbasierte Sitzung (FTP, SMTP, POP3, IMAP) mit Zeitlimits und kurzer Mitschrift fuer
// Verbindungen ohne Anmeldung.
type sensorPlain struct {
	s      *Sensor
	c      *trapConn
	br     *bufio.Reader
	end    time.Time // Ende der Gesamtzeit
	cmds   int       // gelesene Zeilen
	tries  int       // gemeldete Anmeldeversuche
	other  bool      // anderes Ereignis gemeldet (z. B. Relay-Test), keine Probe am Ende
	client string    // Client-Kennung (EHLO-Name), gekuerzt
	first  string    // erste Zeile (Probe)
	verbs  []string  // Befehle (Probe)
}

func newSensorPlain(s *Sensor, c *trapConn) *sensorPlain {
	return &sensorPlain{s: s, c: c, br: bufio.NewReaderSize(c, 1024), end: time.Now().Add(sensorPlainTotal)}
}

// deadline setzt das Zeitlimit fuer den naechsten Schritt (hoechstens bis zum Ende der Gesamtzeit).
func (p *sensorPlain) deadline(d time.Duration) {
	t := time.Now().Add(d)
	if t.After(p.end) {
		t = p.end
	}
	_ = p.c.SetDeadline(t)
}

func (p *sensorPlain) write(s string) error {
	p.deadline(sensorPlainWait)
	_, err := io.WriteString(p.c, s)
	return err
}

// line liest die naechste Zeile ohne CR/LF (hoechstens sensorPlainLine Zeichen, Rest verworfen). Eine
// unvollstaendige Zeile am Ende gilt als Fehler.
func (p *sensorPlain) line() (string, error) {
	if p.cmds >= sensorPlainCmds {
		return "", errSensorPlainLimit
	}
	p.cmds++
	p.deadline(sensorPlainWait)
	buf := make([]byte, 0, 64)
	for {
		b, err := p.br.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '\n' {
			break
		}
		if len(buf) < sensorPlainLine {
			buf = append(buf, b)
		}
	}
	l := strings.TrimSuffix(string(buf), "\r")
	if p.first == "" {
		p.first = l
	}
	return l, nil
}

// cmd zerlegt eine Zeile in Befehl (gross) und Argument (Rest ohne fuehrende Leerzeichen) und merkt den Befehl.
func (p *sensorPlain) cmd(line string) (string, string) {
	verb, arg, _ := strings.Cut(line, " ")
	verb = strings.ToUpper(strings.TrimSpace(verb))
	p.note(verb)
	return verb, strings.TrimLeft(arg, " ")
}

// note merkt einen Befehl fuer die Probe (nur Buchstaben/Ziffern, gekuerzt, hoechstens 16).
func (p *sensorPlain) note(verb string) {
	if len(p.verbs) >= 16 {
		return
	}
	v := strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return '?'
	}, verb)
	if len(v) > 16 {
		v = v[:16]
	}
	if v == "" {
		v = "-"
	}
	p.verbs = append(p.verbs, v)
}

// login meldet einen Anmeldeversuch.
func (p *sensorPlain) login(kind, user, pass, detail string) {
	p.tries++
	e := p.c.event(kind)
	e.Username, e.Password, e.Detail, e.Client = user, pass, detail, p.client
	p.s.login(e)
}

// probe meldet eine Verbindung ohne Anmeldung (Befehle im Detail, erste Zeile als Payload).
func (p *sensorPlain) probe() {
	if p.tries > 0 || p.other {
		return
	}
	e := p.c.event(KindProbe)
	e.Client = p.client
	e.Detail = strings.Join(p.verbs, " ")
	if p.first != "" {
		e.Payload = []byte(p.first[:min(len(p.first), MaxPayload)])
	}
	p.s.emit(e)
}

// sensorPlainPause wartet vor einer Ablehnung (wie ein echter Server, bremst Durchprobieren).
func sensorPlainPause() {
	if d := sensorPlainDelay; d > 0 {
		time.Sleep(d + rand.N(d))
	}
}

// sensorPlainClip kuerzt eine Client-Kennung auf n Bytes (ohne Steuerzeichen, gueltiges UTF-8).
func sensorPlainClip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, "?"))
	if len(s) > n {
		s = strings.ToValidUTF8(s[:n], "")
	}
	return s
}
