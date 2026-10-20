package honeypot

import (
	"bytes"
	"encoding/binary"
	"strings"
	"time"
)

// TCP-Falle fuer beliebige Ports: annehmen, kurz auf die ersten Bytes warten, melden, schliessen. Bekannte
// Protokolle bekommen einen Zusatz (RDP-Cookie, TLS-SNI, HTTP-Pfad, SSH-Client).
const (
	sensorTCPWait = 5 * time.Second
	sensorTCPMore = 500 * time.Millisecond // Nachlesen, bis ein TLS-ClientHello vollstaendig ist
	sensorTCPBuf  = 4096                   // ClientHello mit Post-Quanten-Schluessel (ML-KEM) ist ueber 2 KiB
)

func (s *Sensor) handleTCP(c *trapConn) {
	buf := make([]byte, sensorTCPBuf)
	_ = c.SetReadDeadline(time.Now().Add(sensorTCPWait))
	n, _ := c.Read(buf)
	// TLS: ClientHello kann groesser als der erste Block sein, SNI steht oft weiter hinten
	for n >= 5 && n < len(buf) && buf[0] == 0x16 && n < 5+int(binary.BigEndian.Uint16(buf[3:5])) {
		_ = c.SetReadDeadline(time.Now().Add(sensorTCPMore))
		m, err := c.Read(buf[n:])
		n += m
		if err != nil || m == 0 {
			break
		}
	}
	e := c.event(KindProbe)
	if n > 0 {
		e.Payload = buf[:min(n, MaxPayload)]
		sensorSniff(&e, buf[:n])
	}
	s.emit(e)
}

// sensorSniff ordnet die ersten Bytes einem bekannten Protokoll zu und fuellt passende Felder.
func sensorSniff(e *Event, b []byte) {
	switch {
	case len(b) >= 4 && b[0] == 3 && b[1] == 0: // TPKT (RDP)
		e.Detail = "rdp"
		if i := bytes.Index(b, []byte("mstshash=")); i >= 0 {
			u := b[i+len("mstshash="):]
			if j := bytes.IndexAny(u, "\r\n"); j >= 0 {
				u = u[:j]
			}
			e.Username = string(u)
		}
	case len(b) >= 6 && b[0] == 0x16 && b[1] == 3 && b[5] == 1: // TLS-Handshake, ClientHello
		e.Detail = "tls"
		e.Host = sensorSNI(b)
		e.Fingerprint, _ = sensorFingerprint(b) // JA4, nur bei vollstaendigem ClientHello
	case bytes.HasPrefix(b, []byte("SSH-")):
		e.Detail = "ssh"
		e.Client = sensorFirstLine(b)
		e.Fingerprint, _ = sensorFingerprint(b) // HASSH, falls der KEXINIT schon dabei ist
	default:
		line := sensorFirstLine(b)
		f := strings.Fields(line)
		if len(f) == 3 && strings.HasPrefix(f[2], "HTTP/") && sensorHTTPMethod(f[0]) {
			e.Detail = "http"
			e.Method, e.Path = f[0], f[1]
			for _, l := range strings.Split(string(b), "\n") {
				k, v, ok := strings.Cut(strings.TrimRight(l, "\r"), ":")
				if !ok {
					continue
				}
				switch strings.ToLower(strings.TrimSpace(k)) {
				case "host":
					e.Host = strings.TrimSpace(v)
				case "user-agent":
					e.UA = strings.TrimSpace(v)
				}
			}
		}
	}
}

func sensorFirstLine(b []byte) string {
	if i := bytes.IndexAny(b, "\r\n"); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func sensorHTTPMethod(m string) bool {
	switch m {
	case "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE", "PROPFIND":
		return true
	}
	return false
}

// sensorSNI liest den Servernamen aus einem (moeglicherweise abgeschnittenen) TLS-ClientHello; "" wenn keiner.
func sensorSNI(b []byte) string {
	// Record (5) + Handshake-Kopf (4) + Version (2) + Random (32)
	p := 5 + 4 + 2 + 32
	if len(b) < p+1 {
		return ""
	}
	p += 1 + int(b[p]) // Session-ID
	if len(b) < p+2 {
		return ""
	}
	p += 2 + int(binary.BigEndian.Uint16(b[p:])) // Cipher-Suites
	if len(b) < p+1 {
		return ""
	}
	p += 1 + int(b[p]) // Kompression
	if len(b) < p+2 {
		return ""
	}
	end := min(len(b), p+2+int(binary.BigEndian.Uint16(b[p:])))
	p += 2
	for p+4 <= end {
		typ, l := binary.BigEndian.Uint16(b[p:]), int(binary.BigEndian.Uint16(b[p+2:]))
		p += 4
		if p+l > end {
			return ""
		}
		if typ == 0 { // server_name: Liste (2), Typ (1), Laenge (2), Name
			d := b[p : p+l]
			if len(d) < 5 || d[2] != 0 {
				return ""
			}
			n := int(binary.BigEndian.Uint16(d[3:]))
			if 5+n > len(d) {
				return ""
			}
			return string(d[5 : 5+n])
		}
		p += l
	}
	return ""
}
