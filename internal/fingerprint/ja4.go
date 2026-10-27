// Package fingerprint berechnet Fingerabdruecke von Werkzeugen aus den Rohbytes am Anfang einer Verbindung. Genutzt
// von Honeypot64 (internal/honeypot) und den CDN64-Servern (internal/cdnedge), damit beide dieselben Werte bilden.
//
// JA4 (FoxIO, "JA4 TLS Client", technical_details/JA4.md) aus dem TLS-ClientHello, z. B.
// t13d1516h2_8daaf6152771_e5627efa2ab1. Nur TCP ("t"); crypto/tls liefert weder die Reihenfolge der Extensions noch
// die rohen Listen, deshalb selbst geparst.
package fingerprint

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
)

// MaxHello: groessere ClientHello bekommen keinen Fingerabdruck.
const MaxHello = 8 << 10

// TLSHello setzt die Handshake-Nachricht ClientHello (mit 4 Byte Kopf) aus den TLS-Records am Anfang des
// Datenstroms zusammen. nil und more = true: es fehlen noch Bytes; nil und more = false: kein ClientHello.
func TLSHello(b []byte) (hello []byte, more bool) {
	var hs []byte
	for p := 0; ; {
		if len(b)-p < 5 {
			return nil, true
		}
		if b[p] != 0x16 || b[p+1] != 3 {
			return nil, false
		}
		l := int(binary.BigEndian.Uint16(b[p+3:]))
		if l == 0 {
			return nil, false
		}
		if len(b)-p-5 < l {
			return nil, true
		}
		hs = append(hs, b[p+5:p+5+l]...)
		p += 5 + l
		if len(hs) < 4 {
			continue
		}
		if hs[0] != 1 { // client_hello
			return nil, false
		}
		n := 4 + (int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3]))
		if n > MaxHello {
			return nil, false
		}
		if len(hs) >= n {
			return hs[:n], false
		}
	}
}

// JA4 berechnet JA4 aus der Handshake-Nachricht ClientHello (mit Kopf); "" wenn sie nicht lesbar ist.
func JA4(hello []byte) string {
	if len(hello) < 4 || hello[0] != 1 {
		return ""
	}
	r := reader{b: hello[4:]}
	ver := r.u16()
	r.take(32)     // Random
	r.take(r.u8()) // Session-ID
	cs := r.take(r.u16())
	r.take(r.u8()) // Kompression
	if r.bad || len(cs)%2 != 0 {
		return ""
	}
	var ciphers, exts, sigs []string
	for i := 0; i+1 < len(cs); i += 2 {
		if v := binary.BigEndian.Uint16(cs[i:]); !grease(v) {
			ciphers = append(ciphers, hex4(v))
		}
	}
	nExt, sni, alpn := 0, "i", "00"
	if len(r.b) > 0 { // Extensions sind optional
		er := reader{b: r.take(r.u16())}
		for !r.bad && !er.bad && len(er.b) > 0 {
			typ := uint16(er.u16())
			data := er.take(er.u16())
			if er.bad {
				return ""
			}
			if grease(typ) {
				continue
			}
			nExt++
			switch typ {
			case 0x0000: // server_name
				sni = "d"
			case 0x0010: // ALPN: erster Eintrag
				ar := reader{b: data}
				ar.u16()
				if v := ar.take(ar.u8()); !ar.bad {
					alpn = alpnChars(v)
				}
			case 0x000d: // signature_algorithms in Originalreihenfolge
				sr := reader{b: data}
				l := sr.take(sr.u16())
				for i := 0; i+1 < len(l); i += 2 {
					if v := binary.BigEndian.Uint16(l[i:]); !grease(v) {
						sigs = append(sigs, hex4(v))
					}
				}
			case 0x002b: // supported_versions: hoechste (ohne GREASE)
				vr := reader{b: data}
				l := vr.take(vr.u8())
				best := 0
				for i := 0; i+1 < len(l); i += 2 {
					if v := binary.BigEndian.Uint16(l[i:]); !grease(v) && int(v) > best {
						best = int(v)
					}
				}
				if best > 0 {
					ver = best
				}
			}
			if typ != 0x0000 && typ != 0x0010 {
				exts = append(exts, hex4(typ))
			}
		}
		if r.bad || er.bad {
			return ""
		}
	}
	a := "t" + tlsVersion(ver) + sni + count(len(ciphers)) + count(nExt) + alpn
	slices.Sort(ciphers)
	slices.Sort(exts)
	bh, ch := "000000000000", "000000000000"
	if len(ciphers) > 0 {
		bh = sha12(strings.Join(ciphers, ","))
	}
	if len(exts) > 0 {
		s := strings.Join(exts, ",")
		if len(sigs) > 0 {
			s += "_" + strings.Join(sigs, ",")
		}
		ch = sha12(s)
	}
	return a + "_" + bh + "_" + ch
}

// reader liest Felder fester Laenge; ein Zugriff ueber das Ende setzt bad.
type reader struct {
	b   []byte
	bad bool
}

func (r *reader) take(n int) []byte {
	if r.bad || n < 0 || n > len(r.b) {
		r.bad = true
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) u8() int {
	if v := r.take(1); v != nil {
		return int(v[0])
	}
	return 0
}

func (r *reader) u16() int {
	if v := r.take(2); v != nil {
		return int(binary.BigEndian.Uint16(v))
	}
	return 0
}

// grease: GREASE-Wert (RFC 8701: 0x0a0a, 0x1a1a … 0xfafa), zaehlt bei JA4 nicht.
func grease(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

func hex4(v uint16) string {
	return hex.EncodeToString([]byte{byte(v >> 8), byte(v)})
}

func tlsVersion(v int) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	}
	return "00"
}

func count(n int) string {
	if n > 99 {
		n = 99
	}
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

// alpnChars: erstes und letztes Zeichen des ersten ALPN-Werts; nicht alphanumerisch = erstes und letztes Zeichen der
// Hex-Darstellung; leer = "00".
func alpnChars(v []byte) string {
	if len(v) == 0 {
		return "00"
	}
	f, l := v[0], v[len(v)-1]
	if alnum(f) && alnum(l) {
		return string([]byte{f, l})
	}
	h := hex.EncodeToString(v)
	return string([]byte{h[0], h[len(h)-1]})
}

func alnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func sha12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}
