package honeypot

import (
	"errors"
	"io"
	"strconv"
	"strings"
)

// Redis-Falle (Stufe 2, Port 6379, RESP und Inline-Befehle): wie ein Server mit Passwort. Ohne Anmeldung bekommt
// jeder Befehl ausser AUTH, PING, QUIT und HELLO "-NOAUTH". AUTH <pass>, AUTH <user> <pass> und HELLO ... AUTH
// <user> <pass> werden als db:bruteforce gemeldet und mit WRONGPASS abgelehnt. Befehle, die die Server-Konfiguration
// aendern wuerden (CONFIG, SLAVEOF/REPLICAOF, MODULE, EVAL, SCRIPT, FLUSHALL), werden als db:exploit gemeldet
// (Befehl im Detail, Befehl mit Argumenten als Payload) und ebenfalls mit NOAUTH beantwortet. Hoechstens
// sensorRedisCmds Befehle je Verbindung; Zeitlimits, Zeilenlaenge und Probe wie sensorPlain (sensor_ftp.go).

func init() {
	RegisterTCP(&TCPProto{Service: SvcRedis, Budget: 64 << 10, Handle: (*Sensor).handleRedis})
}

const (
	sensorRedisCmds    = 20      // Befehle je Verbindung
	sensorRedisArgs    = 64      // Argumente je Befehl (Multibulk-Laenge)
	sensorRedisArg     = 512     // Bytes je Argument, die behalten werden (Rest verworfen)
	sensorRedisBulkMax = 1 << 20 // angekuendigte Laenge eines Arguments (mehr: Protokollfehler)

	sensorRedisNoAuth   = "-NOAUTH Authentication required.\r\n"
	sensorRedisWrongPwd = "-WRONGPASS invalid username-password pair or user is disabled.\r\n"
)

// sensorRedisExploit sind Befehle, die die Server-Konfiguration aendern oder Code laufen lassen wuerden.
var sensorRedisExploit = map[string]bool{
	"CONFIG": true, "SLAVEOF": true, "REPLICAOF": true, "MODULE": true, "EVAL": true, "EVALSHA": true,
	"SCRIPT": true, "FLUSHALL": true,
}

// errSensorRedisProto ist ein Protokollfehler (Antwort steht im Text, danach wird getrennt).
type errSensorRedisProto string

func (e errSensorRedisProto) Error() string { return string(e) }

func (s *Sensor) handleRedis(c *trapConn) {
	p := newSensorPlain(s, c)
	defer p.probe()
	for n := 0; n < sensorRedisCmds; n++ {
		p.deadline(sensorPlainWait)
		args, err := sensorRedisRead(p)
		if err != nil {
			var pe errSensorRedisProto
			if errors.As(err, &pe) {
				_ = p.write("-ERR Protocol error: " + string(pe) + "\r\n")
			}
			return
		}
		if len(args) == 0 { // leere Zeile oder *0: wird ignoriert
			continue
		}
		verb := strings.ToUpper(args[0])
		p.note(verb)
		if p.first == "" {
			p.first = strings.Join(args, " ")
		}
		var out string
		switch verb {
		case "PING":
			out = "+PONG\r\n"
			if len(args) > 1 {
				out = "$" + strconv.Itoa(len(args[1])) + "\r\n" + args[1] + "\r\n"
			}
		case "QUIT":
			_ = p.write("+OK\r\n")
			return
		case "AUTH":
			switch len(args) {
			case 2:
				p.login(KindDBBrute, "", args[1], "auth")
				sensorPlainPause()
				out = sensorRedisWrongPwd
			case 3:
				p.login(KindDBBrute, args[1], args[2], "auth")
				sensorPlainPause()
				out = sensorRedisWrongPwd
			default:
				out = "-ERR wrong number of arguments for 'auth' command\r\n"
			}
		case "HELLO":
			out = s.redisHello(p, args)
		case "CLIENT":
			if len(args) > 2 && strings.EqualFold(args[1], "SETNAME") {
				p.client = sensorPlainClip(args[2], sensorPlainClient)
			}
			out = sensorRedisNoAuth
		default:
			if sensorRedisExploit[verb] {
				p.other = true
				e := c.event(KindDBExploit)
				e.Detail, e.Client = verb, p.client
				if len(args) > 1 && (verb == "CONFIG" || verb == "MODULE" || verb == "SCRIPT") {
					e.Detail += " " + strings.ToUpper(sensorPlainClip(args[1], 16))
				}
				pl := strings.Join(args, " ")
				e.Payload = []byte(pl[:min(len(pl), MaxPayload)])
				s.emit(e)
			}
			out = sensorRedisNoAuth
		}
		if p.write(out) != nil {
			return
		}
	}
}

// redisHello: HELLO [protover [AUTH user pass] [SETNAME name]]; mit AUTH ein Anmeldeversuch.
func (s *Sensor) redisHello(p *sensorPlain, args []string) string {
	if len(args) > 1 {
		if v := args[1]; v != "2" && v != "3" {
			return "-NOPROTO unsupported protocol version\r\n"
		}
	}
	user, pass, auth := "", "", false
	for i := 2; i < len(args); i++ {
		switch strings.ToUpper(args[i]) {
		case "AUTH":
			if i+2 >= len(args) {
				return "-ERR Syntax error in HELLO option 'auth'\r\n"
			}
			user, pass, auth = args[i+1], args[i+2], true
			i += 2
		case "SETNAME":
			if i+1 >= len(args) {
				return "-ERR Syntax error in HELLO option 'setname'\r\n"
			}
			p.client = sensorPlainClip(args[i+1], sensorPlainClient)
			i++
		default:
			return "-ERR Syntax error in HELLO option '" + sensorPlainClip(args[i], 32) + "'\r\n"
		}
	}
	if !auth {
		return "-NOAUTH HELLO must be called with the client already authenticated, otherwise the HELLO <proto> " +
			"AUTH <user> <pass> option can be used to authenticate the client and select the RESP protocol version " +
			"at the same time\r\n"
	}
	p.login(KindDBBrute, user, pass, "hello")
	sensorPlainPause()
	return sensorRedisWrongPwd
}

// sensorRedisRead liest einen Befehl: RESP-Array aus Bulk-Strings oder eine Inline-Zeile (durch Leerzeichen
// getrennt). Argumente werden auf sensorRedisArg Bytes gekuerzt, der Rest gelesen und verworfen.
func sensorRedisRead(p *sensorPlain) ([]string, error) {
	b, err := p.br.Peek(1)
	if err != nil {
		return nil, err
	}
	if b[0] != '*' {
		l, err := sensorRedisLine(p, sensorPlainLine)
		if err != nil {
			return nil, err
		}
		return strings.Fields(l), nil
	}
	l, err := sensorRedisLine(p, 32)
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(l[1:])
	if err != nil || n > sensorRedisArgs {
		return nil, errSensorRedisProto("invalid multibulk length")
	}
	args := make([]string, 0, max(n, 0))
	for i := 0; i < n; i++ {
		l, err := sensorRedisLine(p, 32)
		if err != nil {
			return nil, err
		}
		if l == "" || l[0] != '$' {
			got := "?"
			if l != "" {
				got = sensorPlainClip(l[:1], 1)
			}
			return nil, errSensorRedisProto("expected '$', got '" + got + "'")
		}
		size, err := strconv.Atoi(l[1:])
		if err != nil || size < 0 || size > sensorRedisBulkMax {
			return nil, errSensorRedisProto("invalid bulk length")
		}
		keep := min(size, sensorRedisArg)
		buf := make([]byte, keep)
		if _, err := io.ReadFull(p.br, buf); err != nil {
			return nil, err
		}
		if _, err := io.CopyN(io.Discard, p.br, int64(size-keep+2)); err != nil { // Rest und CRLF
			return nil, err
		}
		args = append(args, string(buf))
	}
	return args, nil
}

// sensorRedisLine liest eine Zeile ohne CR/LF (hoechstens n Zeichen behalten, Rest verworfen).
func sensorRedisLine(p *sensorPlain, n int) (string, error) {
	buf := make([]byte, 0, min(n, 64))
	for {
		b, err := p.br.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '\n' {
			break
		}
		if len(buf) < n {
			buf = append(buf, b)
		}
	}
	return strings.TrimSuffix(string(buf), "\r"), nil
}
