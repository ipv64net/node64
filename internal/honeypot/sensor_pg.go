package honeypot

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"strconv"
	"time"
)

// PostgreSQL-Falle (Stufe 2, Port 5432): liest die StartupMessage (Protokoll 3.0: user, database, application_name),
// lehnt SSL- und GSSAPI-Verschluesselung mit 'N' ab, fordert das Passwort im Klartext an
// (AuthenticationCleartextPassword) und meldet es als db:bruteforce (Detail "db=<database>"). Antwort immer FATAL
// 28P01, danach getrennt – keine Abfragen, keine Datenbank dahinter. CancelRequest wird ohne Antwort geschlossen.
// Verbindungen ohne verwertbare Anmeldung sind generic:probe (Detail "pg: ...", erste Bytes als Payload).
//
// Die binaere Sitzung sensorDB (Zeitlimits, erste Bytes, Probe) nutzt auch MySQL (sensor_mysql.go).

func init() {
	RegisterTCP(&TCPProto{Service: SvcPostgre, Budget: sensorDBBudget, Handle: (*Sensor).handlePG})
}

const (
	sensorDBWait   = 15 * time.Second // je Schritt
	sensorDBTotal  = 45 * time.Second // je Verbindung
	sensorDBBudget = 16 << 10         // gelesene Bytes je Verbindung
	sensorDBName   = 64               // Zeichen von Datenbank- und Benutzername in Detail bzw. Fehlertext

	sensorPGMax       = 4096 // Laenge einer StartupMessage bzw. PasswordMessage
	sensorPGNegotiate = 2    // SSL-/GSS-Anfragen je Verbindung
	sensorPGSSL       = 80877103
	sensorPGGSS       = 80877104
	sensorPGCancel    = 80877102
)

func (s *Sensor) handlePG(c *trapConn) {
	d := newSensorDB(s, c)
	why, user := "", ""
	defer func() { d.probe(why, user) }()
	var params map[string]string
	for neg := 0; params == nil; {
		code, body, bad := d.pgStartup()
		if bad != "" {
			if bad != "-" || why == "" { // nach 'N' ohne neue Nachricht getrennt: Grund (ssl/gss) bleibt
				why = bad
			}
			return
		}
		switch {
		case code == sensorPGSSL || code == sensorPGGSS:
			if len(body) != 0 || neg >= sensorPGNegotiate {
				why = "pg: negotiate"
				return
			}
			neg++
			why = "pg: ssl"
			if code == sensorPGGSS {
				why = "pg: gss"
			}
			if d.write([]byte{'N'}) != nil {
				return
			}
		case code == sensorPGCancel:
			why = "pg: cancel"
			return
		case code>>16 == 3:
			why = ""
			if params = sensorPGParams(body); params == nil {
				why = "pg: bad startup"
				return
			}
		case code>>16 >= 1 && code>>16 <= 2:
			v := strconv.Itoa(int(code>>16)) + "." + strconv.Itoa(int(code&0xffff))
			why = "pg: protocol " + v
			_ = d.write(sensorPGError("0A000", "unsupported frontend protocol "+v+": server supports 3.0 to 3.0"))
			return
		default:
			why = "pg: bad startup"
			return
		}
	}
	user = params["user"]
	if user == "" {
		why = "pg: no user"
		_ = d.write(sensorPGError("28000", "no PostgreSQL user name specified in startup packet"))
		return
	}
	db := params["database"]
	if db == "" { // wie der Server: Standard ist der Benutzername
		db = user
	}
	if d.write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 3}) != nil { // AuthenticationCleartextPassword
		why = "pg: no password"
		return
	}
	t, err := d.read(1)
	if err != nil || t[0] != 'p' {
		why = "pg: no password"
		return
	}
	l, err := d.read(4)
	if err != nil {
		why = "pg: bad password"
		return
	}
	n := int(binary.BigEndian.Uint32(l))
	if n < 5 || n > sensorPGMax {
		why = "pg: bad password"
		return
	}
	body, err := d.read(n - 4)
	if err != nil {
		why = "pg: bad password"
		return
	}
	pass, _, _ := bytes.Cut(body, []byte{0})
	d.login(user, string(pass), "db="+sensorPlainClip(db, sensorDBName), sensorPlainClip(params["application_name"], sensorPlainClient))
	sensorPlainPause()
	_ = d.write(sensorPGError("28P01", "password authentication failed for user \""+sensorPlainClip(user, sensorDBName)+"\"",
		"F", "auth.c", "L", "323", "R", "auth_failed"))
}

// pgStartup liest eine Nachricht ohne Typ-Byte (Laenge, Code, Rumpf); bad ist bei Fehler der Grund fuer die Probe.
func (d *sensorDB) pgStartup() (code uint32, body []byte, bad string) {
	h, err := d.read(8)
	if err != nil {
		if len(h) == 0 {
			return 0, nil, "-" // nichts mehr gesendet
		}
		return 0, nil, "pg: short startup"
	}
	n := int(binary.BigEndian.Uint32(h))
	if n < 8 || n > sensorPGMax {
		return 0, nil, "pg: bad startup"
	}
	body, err = d.read(n - 8)
	if err != nil {
		return 0, nil, "pg: short startup"
	}
	return binary.BigEndian.Uint32(h[4:]), body, ""
}

// sensorPGParams zerlegt die Parameter einer StartupMessage (Name\0Wert\0 ... \0); nil bei Formfehler.
func sensorPGParams(b []byte) map[string]string {
	m := map[string]string{}
	for {
		k, rest, ok := bytes.Cut(b, []byte{0})
		if !ok {
			return nil
		}
		if len(k) == 0 {
			return m
		}
		v, rest, ok := bytes.Cut(rest, []byte{0})
		if !ok {
			return nil
		}
		if len(m) < 32 {
			m[string(k)] = string(v)
		}
		b = rest
	}
}

// sensorPGError baut eine ErrorResponse (FATAL) mit SQLSTATE, Text und weiteren Feldern (Kennbuchstabe, Wert).
func sensorPGError(code, msg string, more ...string) []byte {
	f := []string{"S", "FATAL", "V", "FATAL", "C", code, "M", msg}
	f = append(f, more...)
	b := []byte{'E', 0, 0, 0, 0}
	for i := 0; i+1 < len(f); i += 2 {
		b = append(b, f[i][0])
		b = append(b, f[i+1]...)
		b = append(b, 0)
	}
	b = append(b, 0)
	binary.BigEndian.PutUint32(b[1:], uint32(len(b)-1))
	return b
}

// sensorDB ist eine binaere Datenbank-Sitzung (PostgreSQL, MySQL) mit Zeitlimits und den ersten Bytes des Clients
// fuer die Probe.
type sensorDB struct {
	s    *Sensor
	c    *trapConn
	br   *bufio.Reader
	end  time.Time // Ende der Gesamtzeit
	head []byte    // erste Bytes des Clients (hoechstens MaxPayload)
	done bool      // Ereignis gemeldet, keine Probe am Ende
}

func newSensorDB(s *Sensor, c *trapConn) *sensorDB {
	return &sensorDB{s: s, c: c, br: bufio.NewReaderSize(c, 512), end: time.Now().Add(sensorDBTotal)}
}

// deadline setzt das Zeitlimit fuer den naechsten Schritt (hoechstens bis zum Ende der Gesamtzeit).
func (d *sensorDB) deadline() {
	t := time.Now().Add(sensorDBWait)
	if t.After(d.end) {
		t = d.end
	}
	_ = d.c.SetDeadline(t)
}

// read liest genau n Bytes (n vom Aufrufer begrenzt) und merkt die ersten Bytes; bei Fehler das Gelesene.
func (d *sensorDB) read(n int) ([]byte, error) {
	d.deadline()
	b := make([]byte, n)
	k, err := io.ReadFull(d.br, b)
	if r := MaxPayload - len(d.head); r > 0 {
		d.head = append(d.head, b[:min(k, r)]...)
	}
	return b[:k], err
}

func (d *sensorDB) write(b []byte) error {
	d.deadline()
	_, err := d.c.Write(b)
	return err
}

// login meldet einen Anmeldeversuch.
func (d *sensorDB) login(user, pass, detail, client string) {
	d.done = true
	e := d.c.event(KindDBBrute)
	e.Username, e.Password, e.Detail, e.Client = user, pass, detail, client
	d.s.login(e)
}

// probe meldet eine Verbindung ohne Anmeldung (Grund im Detail, ggf. Benutzername, erste Bytes als Payload).
func (d *sensorDB) probe(why, user string) {
	if d.done {
		return
	}
	d.done = true
	if why == "-" {
		why = ""
	}
	e := d.c.event(KindProbe)
	e.Detail, e.Username = why, user
	if more, _ := d.br.Peek(min(d.br.Buffered(), MaxPayload-len(d.head))); len(more) > 0 {
		d.head = append(d.head, more...)
	}
	if len(d.head) > 0 {
		e.Payload = d.head
	}
	d.s.emit(e)
}
