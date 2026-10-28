package honeypot

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net"
	"strings"
	"time"
)

// MikroTik-API-Falle (Stufe 2, Port 8728 und 8729): ein Dienst fuer beide Ports – beginnt die Verbindung mit 0x16 0x03
// (TLS-Handshake), wickelt der Dienst TLS selbst mit dem Zertifikat des Sensors ab (API-SSL), sonst Klartext.
// Gelesen werden API-Saetze (Woerter mit Laengenkodierung, ein Satz endet mit einem leeren Wort):
//   - /login mit =name= und =password= (neues Verfahren) -> router:bruteforce, Antwort !trap
//     "=message=invalid user name or password (6)" und !done;
//   - altes Verfahren: /login ohne Passwort -> !done =ret=<Challenge>, dann /login =name= =response= -> Name ohne
//     Passwort mit Detail "challenge" (bleibt die Antwort aus, wird ein schon genannter Name am Ende gemeldet);
//   - jeder andere Befehl vor dem Login: !fatal "not logged in" und Trennung.
//
// Hoechstens sensorMTAPITries Versuche je Verbindung. Ohne Anmeldung: generic:probe mit den Befehlen.

func init() {
	RegisterTCP(&TCPProto{Service: SvcMTAPI, Budget: sensorMTAPIBudget, Handle: (*Sensor).handleMTAPI})
}

const (
	sensorMTAPITries  = 5
	sensorMTAPIWord   = 1024     // Bytes je Wort
	sensorMTAPIWords  = 32       // Woerter je Satz
	sensorMTAPICmds   = 40       // Saetze je Verbindung
	sensorMTAPIBudget = 16 << 10 // gelesene Bytes (Klartext) je Verbindung
)

var errSensorMTAPIWord = errors.New("bad word")

// sensorMTAPI ist eine API-Sitzung.
type sensorMTAPI struct {
	s     *Sensor
	c     *trapConn
	br    *bufio.Reader
	head  *sensorMTAPIHead
	end   time.Time // Ende der Gesamtzeit
	tls   bool
	bad   bool     // kaputte Wortlaenge
	sents int      // gelesene Saetze
	tries int      // gemeldete Anmeldeversuche
	cmds  []string // Befehle (Probe)
}

func (s *Sensor) handleMTAPI(c *trapConn) {
	a := &sensorMTAPI{s: s, c: c, end: time.Now().Add(sensorPlainTotal)}
	a.deadline(sensorPlainWait)
	// 0x16 0x03 ist ein TLS-Record (Handshake, Version 3.x); 0x16 allein kann auch die Laenge des ersten Wortes sein
	// (22 Bytes, z. B. "/system/resource/print"), daher auch das zweite Byte
	first := make([]byte, 1, 2)
	if _, err := io.ReadFull(c, first); err != nil {
		a.finish() // nur Verbindung
		return
	}
	if first[0] == 0x16 {
		first = first[:2]
		if _, err := io.ReadFull(c, first[1:]); err != nil {
			a.head = &sensorMTAPIHead{b: first[:1]}
			a.finish()
			return
		}
	}
	var src io.Reader = io.MultiReader(bytes.NewReader(first), c)
	if len(first) == 2 && first[1] == 0x03 { // TLS-Handshake (API-SSL)
		cert, err := s.tlsCert()
		if err != nil {
			return
		}
		tc := tls.Server(&sensorMTAPIPrefix{Conn: c.Conn, pre: first}, &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS10})
		_ = tc.SetDeadline(time.Now().Add(sensorTCPWait))
		if err := tc.Handshake(); err != nil {
			e := c.event(KindProbe)
			e.Detail, e.Client = "tls: no handshake", "tls"
			s.emit(e)
			return
		}
		c.Conn, a.tls, src = tc, true, c // ab hier liest und schreibt c ueber TLS (Budget zaehlt den Klartext)
	}
	a.head = &sensorMTAPIHead{r: src}
	a.br = bufio.NewReaderSize(a.head, 512)

	name, pending := "", false // altes Verfahren: Challenge ausgegeben
	defer func() {
		if pending && name != "" {
			a.login(name, "", "challenge")
		}
		a.finish()
	}()
	for a.tries < sensorMTAPITries {
		words, err := a.sentence()
		if err != nil {
			a.bad = errors.Is(err, errSensorMTAPIWord)
			return
		}
		if len(words) == 0 {
			continue // leerer Satz
		}
		cmd := words[0]
		a.note(cmd)
		var user, pass, tag string
		var hasPass, hasResp bool
		for _, w := range words[1:] {
			switch {
			case strings.HasPrefix(w, "=name="):
				user = w[len("=name="):]
			case strings.HasPrefix(w, "=password="):
				pass, hasPass = w[len("=password="):], true
			case strings.HasPrefix(w, "=response="):
				hasResp = true // Hash der Challenge, ohne Nutzen fuer die Statistik
			case strings.HasPrefix(w, ".tag="):
				tag = sensorPlainClip(w[len(".tag="):], 32)
			}
		}
		trap := [][]string{{"!trap", "=message=invalid user name or password (6)"}, {"!done"}}
		var out [][]string
		switch {
		case cmd == "/login" && hasPass:
			pending = false
			a.login(user, pass, "")
			sensorPlainPause()
			out = trap
		case cmd == "/login" && hasResp:
			if user == "" {
				user = name
			}
			pending = false
			a.login(user, "", "challenge")
			sensorPlainPause()
			out = trap
		case cmd == "/login":
			var ch [16]byte
			_, _ = rand.Read(ch[:])
			name, pending = user, true
			out = [][]string{{"!done", "=ret=" + hex.EncodeToString(ch[:])}}
		case cmd == "/quit":
			_ = a.write(tag, [][]string{{"!fatal", "session terminated on request"}})
			return
		default:
			_ = a.write(tag, [][]string{{"!fatal", "not logged in"}})
			return
		}
		if a.write(tag, out) != nil {
			return
		}
	}
}

// deadline setzt das Zeitlimit fuer den naechsten Schritt (hoechstens bis zum Ende der Gesamtzeit).
func (a *sensorMTAPI) deadline(d time.Duration) {
	t := time.Now().Add(d)
	if t.After(a.end) {
		t = a.end
	}
	_ = a.c.SetDeadline(t)
}

// sentence liest einen Satz (ohne das abschliessende leere Wort).
func (a *sensorMTAPI) sentence() ([]string, error) {
	if a.sents >= sensorMTAPICmds {
		return nil, errSensorPlainLimit
	}
	a.sents++
	a.deadline(sensorPlainWait)
	var words []string
	for {
		n, err := sensorMTAPILen(a.br)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return words, nil
		}
		if n < 0 || n > sensorMTAPIWord || len(words) >= sensorMTAPIWords {
			return nil, errSensorMTAPIWord
		}
		w := make([]byte, n)
		if _, err := io.ReadFull(a.br, w); err != nil {
			return nil, err
		}
		words = append(words, string(w))
	}
}

// sensorMTAPILen liest die Laenge eines Wortes (1 bis 5 Bytes; 0xF1 bis 0xFF sind Steuerbytes und hier ungueltig).
func sensorMTAPILen(br io.ByteReader) (int, error) {
	b, err := br.ReadByte()
	if err != nil {
		return 0, err
	}
	var n uint32 // uint32: 4 Laengenbytes passen auf 32-Bit-Systemen (arm/v7) nicht sicher in int
	var k int
	switch {
	case b < 0x80:
		return int(b), nil
	case b < 0xC0:
		n, k = uint32(b&0x3f), 1
	case b < 0xE0:
		n, k = uint32(b&0x1f), 2
	case b < 0xF0:
		n, k = uint32(b&0x0f), 3
	case b == 0xF0:
		k = 4
	default:
		return 0, errSensorMTAPIWord
	}
	for ; k > 0; k-- {
		x, err := br.ReadByte()
		if err != nil {
			return 0, err
		}
		n = n<<8 | uint32(x)
	}
	if n > math.MaxInt32 { // passt nicht in int auf 32 Bit; so lang ist ohnehin kein Wort
		return 0, errSensorMTAPIWord
	}
	return int(n), nil
}

// sensorMTAPIEnc haengt ein Wort mit Laengenkodierung an (eigene Woerter sind kurz).
func sensorMTAPIEnc(dst []byte, w string) []byte {
	switch n := len(w); {
	case n < 0x80:
		dst = append(dst, byte(n))
	case n < 0x4000:
		dst = append(dst, byte(n>>8)|0x80, byte(n))
	default:
		dst = append(dst, byte(n>>16)|0xC0, byte(n>>8), byte(n))
	}
	return append(dst, w...)
}

// write schickt Saetze (mit .tag=, wenn die Anfrage eins hatte).
func (a *sensorMTAPI) write(tag string, sents [][]string) error {
	var b []byte
	for _, st := range sents {
		for _, w := range st {
			b = sensorMTAPIEnc(b, w)
		}
		if tag != "" {
			b = sensorMTAPIEnc(b, ".tag="+tag)
		}
		b = append(b, 0)
	}
	a.deadline(sensorPlainWait)
	_, err := a.c.Write(b)
	return err
}

// note merkt einen Befehl fuer die Probe (gekuerzt, hoechstens 8).
func (a *sensorMTAPI) note(cmd string) {
	if len(a.cmds) < 8 {
		if cmd = sensorPlainClip(strings.ReplaceAll(cmd, " ", "?"), 32); cmd == "" {
			cmd = "-"
		}
		a.cmds = append(a.cmds, cmd)
	}
}

// login meldet einen Anmeldeversuch.
func (a *sensorMTAPI) login(user, pass, detail string) {
	a.tries++
	e := a.c.event(KindRouterBrute)
	e.Username, e.Password, e.Detail = user, pass, detail
	if a.tls {
		e.Client = "tls"
	}
	a.s.login(e)
}

// finish meldet eine Verbindung ohne Anmeldung (Befehle im Detail, erste Bytes als Payload).
func (a *sensorMTAPI) finish() {
	if a.tries > 0 {
		return
	}
	e := a.c.event(KindProbe)
	e.Detail = strings.Join(a.cmds, " ")
	if a.bad {
		e.Detail = strings.TrimSpace(e.Detail + " mikrotik-api: bad word")
	}
	if a.tls {
		e.Client = "tls"
	}
	if a.head != nil && len(a.head.b) > 0 {
		e.Payload = a.head.b
	}
	a.s.emit(e)
}

// sensorMTAPIHead merkt sich die ersten gelesenen Bytes (Probe).
type sensorMTAPIHead struct {
	r io.Reader
	b []byte
}

func (h *sensorMTAPIHead) Read(p []byte) (int, error) {
	n, err := h.r.Read(p)
	if k := min(n, MaxPayload-len(h.b)); k > 0 {
		h.b = append(h.b, p[:k]...)
	}
	return n, err
}

// sensorMTAPIPrefix liefert vor der Verbindung die schon gelesenen Bytes (erstes Byte des TLS-Handshakes).
type sensorMTAPIPrefix struct {
	net.Conn
	pre []byte
}

func (p *sensorMTAPIPrefix) Read(b []byte) (int, error) {
	if len(p.pre) > 0 {
		n := copy(b, p.pre)
		p.pre = p.pre[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}
