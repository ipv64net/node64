package honeypot

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// Fingerabdruecke der Werkzeuge (H6), aus den Rohbytes am Anfang einer Verbindung selbst geparst (crypto/tls und
// x/crypto/ssh liefern weder die Reihenfolge der Extensions noch die rohen Listen):
//   - JA4 (FoxIO, "JA4 TLS Client", technical_details/JA4.md) aus dem TLS-ClientHello, z. B. t13d1516h2_8daaf6152771_e5627efa2ab1.
//     Nur TCP ("t"); QUIC/DTLS gibt es im Honeypot nicht.
//   - HASSH (Salesforce) aus dem SSH_MSG_KEXINIT des Clients: MD5 (hex) ueber
//     kex_algorithms;encryption_algorithms_client_to_server;mac_algorithms_client_to_server;compression_algorithms_client_to_server.
//
// Event.Fingerprint ist "ja4:<ja4>" bzw. "hassh:<md5>". Mitgeschnitten werden hoechstens sensorFPMax Bytes; was
// laenger ist oder nicht passt, bekommt keinen Fingerabdruck.

const sensorFPMax = 8 << 10

// sensorFPCap schneidet die ersten Bytes einer Verbindung mit (trapConn.Read), bis ClientHello bzw. KEXINIT
// vollstaendig ist, und haelt danach nur noch das Ergebnis.
type sensorFPCap struct {
	mu   sync.Mutex
	buf  []byte
	done bool
	fp   string
}

func (f *sensorFPCap) feed(p []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.done || len(p) == 0 {
		return
	}
	f.buf = append(f.buf, p[:min(len(p), sensorFPMax-len(f.buf))]...)
	fp, more := sensorFingerprint(f.buf)
	if !more || len(f.buf) >= sensorFPMax {
		f.done, f.fp, f.buf = true, fp, nil
	}
}

func (f *sensorFPCap) get() string {
	if f == nil {
		return ""
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fp
}

// sensorFingerprint liefert den Fingerabdruck der ersten Bytes einer Verbindung ("ja4:…", "hassh:…" oder "") und ob
// noch Bytes fehlen (more = true: unvollstaendig, spaeter erneut versuchen).
func sensorFingerprint(b []byte) (fp string, more bool) {
	switch {
	case len(b) == 0:
		return "", true
	case b[0] == 0x16:
		hello, more := sensorTLSHello(b)
		if hello == nil {
			return "", more
		}
		if j := sensorJA4(hello); j != "" {
			return "ja4:" + j, false
		}
		return "", false
	case bytes.HasPrefix(b, []byte("SSH-")) || bytes.HasPrefix([]byte("SSH-"), b):
		h, more := sensorHASSH(b)
		if h != "" {
			return "hassh:" + h, false
		}
		return "", more
	}
	return "", false
}

// sensorTLSHello setzt die Handshake-Nachricht ClientHello (mit 4 Byte Kopf) aus den TLS-Records am Anfang des
// Datenstroms zusammen. nil und more = true: es fehlen noch Bytes; nil und more = false: kein ClientHello.
func sensorTLSHello(b []byte) (hello []byte, more bool) {
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
		if n > sensorFPMax {
			return nil, false
		}
		if len(hs) >= n {
			return hs[:n], false
		}
	}
}

// sensorJA4 berechnet JA4 aus der Handshake-Nachricht ClientHello (mit Kopf); "" wenn sie nicht lesbar ist.
func sensorJA4(hello []byte) string {
	if len(hello) < 4 || hello[0] != 1 {
		return ""
	}
	r := fpReader{b: hello[4:]}
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
		if v := binary.BigEndian.Uint16(cs[i:]); !fpGrease(v) {
			ciphers = append(ciphers, fpHex4(v))
		}
	}
	nExt, sni, alpn := 0, "i", "00"
	if len(r.b) > 0 { // Extensions sind optional
		er := fpReader{b: r.take(r.u16())}
		for !r.bad && !er.bad && len(er.b) > 0 {
			typ := uint16(er.u16())
			data := er.take(er.u16())
			if er.bad {
				return ""
			}
			if fpGrease(typ) {
				continue
			}
			nExt++
			switch typ {
			case 0x0000: // server_name
				sni = "d"
			case 0x0010: // ALPN: erster Eintrag
				ar := fpReader{b: data}
				ar.u16()
				if v := ar.take(ar.u8()); !ar.bad {
					alpn = fpALPN(v)
				}
			case 0x000d: // signature_algorithms in Originalreihenfolge
				sr := fpReader{b: data}
				l := sr.take(sr.u16())
				for i := 0; i+1 < len(l); i += 2 {
					if v := binary.BigEndian.Uint16(l[i:]); !fpGrease(v) {
						sigs = append(sigs, fpHex4(v))
					}
				}
			case 0x002b: // supported_versions: hoechste (ohne GREASE)
				vr := fpReader{b: data}
				l := vr.take(vr.u8())
				best := 0
				for i := 0; i+1 < len(l); i += 2 {
					if v := binary.BigEndian.Uint16(l[i:]); !fpGrease(v) && int(v) > best {
						best = int(v)
					}
				}
				if best > 0 {
					ver = best
				}
			}
			if typ != 0x0000 && typ != 0x0010 {
				exts = append(exts, fpHex4(typ))
			}
		}
		if r.bad || er.bad {
			return ""
		}
	}
	a := "t" + fpTLSVersion(ver) + sni + fpCount(len(ciphers)) + fpCount(nExt) + alpn
	slices.Sort(ciphers)
	slices.Sort(exts)
	bh, ch := "000000000000", "000000000000"
	if len(ciphers) > 0 {
		bh = fpSHA12(strings.Join(ciphers, ","))
	}
	if len(exts) > 0 {
		s := strings.Join(exts, ",")
		if len(sigs) > 0 {
			s += "_" + strings.Join(sigs, ",")
		}
		ch = fpSHA12(s)
	}
	return a + "_" + bh + "_" + ch
}

// sensorHASSH berechnet HASSH aus Versionszeile und erstem Binaerpaket (KEXINIT) des Clients. "" und more = true:
// es fehlen noch Bytes; "" und more = false: nicht lesbar.
func sensorHASSH(b []byte) (string, bool) {
	if len(b) < 4 {
		return "", bytes.HasPrefix([]byte("SSH-"), b)
	}
	if !bytes.HasPrefix(b, []byte("SSH-")) {
		return "", false
	}
	i := bytes.IndexByte(b, '\n')
	if i < 0 {
		return "", len(b) < 255
	}
	if i >= 255 { // Versionszeile hoechstens 255 Zeichen (RFC 4253)
		return "", false
	}
	p := b[i+1:]
	if len(p) < 5 {
		return "", true
	}
	l := int(binary.BigEndian.Uint32(p))
	if l < 2 || l > sensorFPMax {
		return "", false
	}
	if len(p) < 4+l {
		return "", true
	}
	pad := int(p[4])
	if pad+1 >= l {
		return "", false
	}
	r := fpReader{b: p[5 : 4+l-pad]}
	if r.u8() != 20 { // SSH_MSG_KEXINIT
		return "", false
	}
	r.take(16) // Cookie
	var lists [10][]byte
	for k := range lists {
		lists[k] = r.take(r.u32())
	}
	if r.bad {
		return "", false
	}
	sum := md5.Sum([]byte(string(lists[0]) + ";" + string(lists[2]) + ";" + string(lists[4]) + ";" + string(lists[6])))
	return hex.EncodeToString(sum[:]), false
}

// fpReader liest Felder fester Laenge; ein Zugriff ueber das Ende setzt bad.
type fpReader struct {
	b   []byte
	bad bool
}

func (r *fpReader) take(n int) []byte {
	if r.bad || n < 0 || n > len(r.b) {
		r.bad = true
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *fpReader) u8() int {
	if v := r.take(1); v != nil {
		return int(v[0])
	}
	return 0
}

func (r *fpReader) u16() int {
	if v := r.take(2); v != nil {
		return int(binary.BigEndian.Uint16(v))
	}
	return 0
}

func (r *fpReader) u32() int {
	if v := r.take(4); v != nil {
		return int(binary.BigEndian.Uint32(v))
	}
	return 0
}

// fpGrease: GREASE-Wert (RFC 8701: 0x0a0a, 0x1a1a … 0xfafa), zaehlt bei JA4 nicht.
func fpGrease(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

func fpHex4(v uint16) string {
	return hex.EncodeToString([]byte{byte(v >> 8), byte(v)})
}

func fpTLSVersion(v int) string {
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

func fpCount(n int) string {
	if n > 99 {
		n = 99
	}
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

// fpALPN: erstes und letztes Zeichen des ersten ALPN-Werts; nicht alphanumerisch = erstes und letztes Zeichen der
// Hex-Darstellung; leer = "00".
func fpALPN(v []byte) string {
	if len(v) == 0 {
		return "00"
	}
	f, l := v[0], v[len(v)-1]
	if fpAlnum(f) && fpAlnum(l) {
		return string([]byte{f, l})
	}
	h := hex.EncodeToString(v)
	return string([]byte{h[0], h[len(h)-1]})
}

func fpAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func fpSHA12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}
