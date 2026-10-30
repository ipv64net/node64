package honeypot

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"strings"
)

// MySQL-Falle (Stufe 2, Port 3306): Server-Greeting je Profil (Protokoll 10, 20 Byte Zufalls-Salt, MySQL 8.0 mit
// caching_sha2_password oder MariaDB mit mysql_native_password, ohne SSL/Kompression/LOCAL INFILE), liest die Handshake-Response (Username, Datenbank,
// Client-Attribute) und wechselt per AuthSwitchRequest auf mysql_clear_password. Antwortet der Client im Klartext,
// wird das Passwort erfasst, sonst bleibt es leer (Detail "hash"); gemeldet als db:bruteforce, Antwort immer
// ERR 1045. Eine SSL-Anfrage des Clients wird als db:bruteforce mit Detail "tls" gemeldet und getrennt (kein TLS).
// Keine Befehle, keine Datenbank dahinter. Sitzung und Grenzen siehe sensorDB (sensor_pg.go).

func init() {
	RegisterTCP(&TCPProto{Service: SvcMySQL, Budget: sensorDBBudget, Handle: (*Sensor).handleMySQL})
}

const (
	sensorMySQLMax    = 4096 // Laenge eines Pakets vom Client
	sensorMySQLNative = "mysql_native_password"
	sensorMySQLSHA2   = "caching_sha2_password" // Standard ab MySQL 8.0
	sensorMySQLClear  = "mysql_clear_password"

	sensorMySQLCapDB      = 0x8      // CLIENT_CONNECT_WITH_DB
	sensorMySQLCap41      = 0x200    // CLIENT_PROTOCOL_41
	sensorMySQLCapSSL     = 0x800    // CLIENT_SSL
	sensorMySQLCapSecure  = 0x8000   // CLIENT_SECURE_CONNECTION
	sensorMySQLCapPlugin  = 0x80000  // CLIENT_PLUGIN_AUTH
	sensorMySQLCapAttrs   = 0x100000 // CLIENT_CONNECT_ATTRS
	sensorMySQLCapLenData = 0x200000 // CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
)

func (s *Sensor) handleMySQL(c *trapConn) {
	d := newSensorDB(s, c)
	why := ""
	defer func() { d.probe(why, "") }()
	salt := make([]byte, 20)
	for i := range salt {
		salt[i] = byte(0x21 + rand.N(94)) // druckbar, ohne NUL
	}
	p := s.personas()
	if d.write(sensorMySQLPacket(0, sensorMySQLGreeting(sensorMySQLProfileFor(p.of(c.t.key), p.identFor(c.t.key)), 10+rand.Uint32N(90000), salt))) != nil {
		return
	}
	seq, body, bad := d.mysqlRead()
	if bad != "" {
		why = bad
		return
	}
	if len(body) < 4 || binary.LittleEndian.Uint16(body)&sensorMySQLCap41 == 0 {
		why = "mysql: old client"
		return
	}
	caps := binary.LittleEndian.Uint32(body)
	if len(body) == 32 && caps&sensorMySQLCapSSL != 0 { // SSLRequest: kein TLS, Verbindung endet
		d.done = true
		e := c.event(KindDBBrute)
		e.Detail = "tls"
		s.emit(e)
		return
	}
	r := &sensorMySQLReader{b: body}
	r.skip(32) // Capabilities, max. Paketgroesse, Zeichensatz, Fuellbytes
	user := r.cstr()
	var auth []byte
	switch {
	case caps&sensorMySQLCapLenData != 0:
		auth = r.skip(r.lenenc())
	case caps&sensorMySQLCapSecure != 0:
		auth = r.skip(int(r.byte()))
	default:
		auth = []byte(r.cstr())
	}
	if r.bad {
		why = "mysql: bad handshake"
		return
	}
	// Rest ist optional: bei Formfehler gilt, was bis dahin gelesen wurde
	db, plugin, client := "", "", ""
	if caps&sensorMySQLCapDB != 0 {
		db = r.cstr()
	}
	if caps&sensorMySQLCapPlugin != 0 {
		plugin = r.cstr()
	}
	if caps&sensorMySQLCapAttrs != 0 && !r.bad {
		client = r.attrs()
	}
	detail := ""
	if db != "" {
		detail = "db=" + sensorPlainClip(db, sensorDBName)
	}
	using := "YES"
	switch {
	case plugin == sensorMySQLClear: // Client schickt schon Klartext
		pass, _, _ := bytes.Cut(auth, []byte{0})
		d.login(user, string(pass), detail, client)
	case len(auth) == 0: // leeres Passwort
		using = "NO"
		d.login(user, "", detail, client)
	case caps&sensorMySQLCapPlugin != 0:
		seq++
		sw := append([]byte{0xfe}, sensorMySQLClear...)
		if d.write(sensorMySQLPacket(seq, append(sw, 0))) != nil {
			d.login(user, "", strings.TrimSpace("hash "+detail), client)
			return
		}
		n, reply, bad := d.mysqlRead()
		if bad != "" {
			d.login(user, "", strings.TrimSpace("hash "+detail), client)
			return
		}
		seq = n
		pass, _, _ := bytes.Cut(reply, []byte{0})
		d.login(user, string(pass), detail, client)
	default:
		d.login(user, "", strings.TrimSpace("hash "+detail), client)
	}
	sensorPlainPause()
	msg := "Access denied for user '" + sensorPlainClip(user, sensorDBName) + "'@'" + c.src.String() +
		"' (using password: " + using + ")"
	_ = d.write(sensorMySQLPacket(seq+1, sensorMySQLErr(1045, "28000", msg)))
}

// mysqlRead liest ein Paket (Laenge 3 Byte, Sequenz); bad ist bei Fehler der Grund fuer die Probe.
func (d *sensorDB) mysqlRead() (seq byte, body []byte, bad string) {
	h, err := d.read(4)
	if err != nil {
		if len(h) == 0 {
			return 0, nil, "-" // nichts gesendet
		}
		return 0, nil, "mysql: bad handshake"
	}
	n := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
	if n > sensorMySQLMax {
		return 0, nil, "mysql: bad handshake"
	}
	if body, err = d.read(n); err != nil {
		return 0, nil, "mysql: bad handshake"
	}
	return h[3], body, ""
}

// sensorMySQLProfile ist das Greeting eines Profils: Version, Faehigkeiten (ohne SSL, Kompression und LOCAL INFILE),
// Zeichensatz und Auth-Plugin passend zur Version.
type sensorMySQLProfile struct {
	version string
	caps    uint32
	charset byte
	plugin  string
	ext     uint32 // MariaDB: erweiterte Faehigkeiten in den letzten 4 Fuellbytes
}

// sensorMySQLProfileFor: MySQL 8.0 wie das offizielle Image (caching_sha2_password, utf8mb4_0900_ai_ci), MariaDB
// 10.11 als Paket der Distribution bzw. 11.4 wie das offizielle Image (mysql_native_password, utf8mb4_general_ci,
// Version mit "5.5.5-" davor wie bei MariaDB ueblich). Patch-Stand je Sensor.
func sensorMySQLProfileFor(persona string, id *sensorIdent) sensorMySQLProfile {
	if id.old { // „verwundbar wirken“: MariaDB 10.3 (Debian 10) bzw. MySQL 5.7, beide ohne Sicherheits-Updates
		if persona == PersonaMariaDB || persona == PersonaMariaDB11 {
			return sensorMySQLProfile{version: "5.5.5-10.3." + id.choose("mariadb-old", "27", "31", "34") + "-MariaDB-0+deb10u1", caps: 0x81bff75e,
				charset: 45, plugin: sensorMySQLNative, ext: 0x1d}
		}
		return sensorMySQLProfile{version: "5.7." + id.choose("mysql-old", "33", "36", "40") + "-log", caps: 0x81fff7ff, charset: 33, plugin: sensorMySQLNative}
	}
	switch persona {
	case PersonaMariaDB:
		v := "5.5.5-10.11." + id.choose("mariadb", "6", "11", "13", "14") + "-MariaDB-0+deb12u1"
		if id.ubuntu() {
			v = "5.5.5-10.11." + id.choose("mariadb", "8", "13") + "-MariaDB-0ubuntu0.24.04.1"
		}
		return sensorMySQLProfile{version: v, caps: 0x81bff75e, charset: 45, plugin: sensorMySQLNative, ext: 0x1d}
	case PersonaMariaDB11:
		return sensorMySQLProfile{version: "5.5.5-11.4." + id.choose("mariadb11", "3", "4", "5", "7") + "-MariaDB-ubu2404", caps: 0x81bff75e,
			charset: 45, plugin: sensorMySQLNative, ext: 0x1d}
	}
	return sensorMySQLProfile{version: "8.0." + id.choose("mysql", "36", "37", "39", "40", "41", "42", "43"), caps: 0xdbfff75f, charset: 255,
		plugin: sensorMySQLSHA2}
}

// sensorMySQLGreeting baut das Server-Greeting (Protokoll 10).
func sensorMySQLGreeting(pr sensorMySQLProfile, id uint32, salt []byte) []byte {
	b := append([]byte{10}, pr.version...)
	b = append(b, 0)
	b = binary.LittleEndian.AppendUint32(b, id)
	b = append(b, salt[:8]...)
	b = append(b, 0)
	b = binary.LittleEndian.AppendUint16(b, uint16(pr.caps&0xffff))
	b = append(b, pr.charset)
	b = binary.LittleEndian.AppendUint16(b, 0x02) // SERVER_STATUS_AUTOCOMMIT
	b = binary.LittleEndian.AppendUint16(b, uint16(pr.caps>>16))
	b = append(b, byte(len(salt)+1))
	b = append(b, make([]byte, 6)...)
	b = binary.LittleEndian.AppendUint32(b, pr.ext)
	b = append(b, salt[8:]...)
	b = append(b, 0)
	b = append(b, pr.plugin...)
	return append(b, 0)
}

// sensorMySQLErr baut ein ERR-Paket (Protokoll 4.1).
func sensorMySQLErr(code uint16, state, msg string) []byte {
	b := binary.LittleEndian.AppendUint16([]byte{0xff}, code)
	b = append(b, '#')
	b = append(b, state...)
	return append(b, msg...)
}

func sensorMySQLPacket(seq byte, payload []byte) []byte {
	n := len(payload)
	return append([]byte{byte(n), byte(n >> 8), byte(n >> 16), seq}, payload...)
}

// sensorMySQLReader liest Felder aus einem Paket; bei zu kurzem Paket wird bad gesetzt und nur noch Leeres geliefert.
type sensorMySQLReader struct {
	b   []byte
	bad bool
}

func (r *sensorMySQLReader) skip(n int) []byte {
	if r.bad || n < 0 || n > len(r.b) {
		r.bad = true
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *sensorMySQLReader) byte() byte {
	if v := r.skip(1); v != nil {
		return v[0]
	}
	return 0
}

// cstr liest bis NUL (ohne NUL am Paketende: der Rest).
func (r *sensorMySQLReader) cstr() string {
	if r.bad {
		return ""
	}
	v, rest, ok := bytes.Cut(r.b, []byte{0})
	if !ok {
		rest = nil
	}
	r.b = rest
	return string(v)
}

// lenenc liest eine Laenge (length-encoded integer); zu grosse Werte fuehren bei skip zu bad.
func (r *sensorMySQLReader) lenenc() int {
	b := r.byte()
	switch {
	case b < 0xfb:
		return int(b)
	case b == 0xfc:
		v := r.skip(2)
		if v == nil {
			return -1
		}
		return int(binary.LittleEndian.Uint16(v))
	case b == 0xfd:
		v := r.skip(3)
		if v == nil {
			return -1
		}
		return int(v[0]) | int(v[1])<<8 | int(v[2])<<16
	case b == 0xfe:
		v := r.skip(8)
		if v == nil || binary.LittleEndian.Uint64(v) > sensorMySQLMax {
			return -1
		}
		return int(binary.LittleEndian.Uint64(v))
	}
	return -1
}

// attrs liest die Client-Attribute und liefert "_client_name _client_version" (gekuerzt).
func (r *sensorMySQLReader) attrs() string {
	a := &sensorMySQLReader{b: r.skip(r.lenenc())}
	name, ver := "", ""
	for len(a.b) > 0 && !a.bad {
		k := string(a.skip(a.lenenc()))
		v := string(a.skip(a.lenenc()))
		switch k {
		case "_client_name":
			name = v
		case "_client_version":
			ver = v
		}
	}
	return sensorPlainClip(strings.TrimSpace(name+" "+ver), sensorPlainClient)
}
