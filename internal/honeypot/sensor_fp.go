package honeypot

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"sync"

	"github.com/ipv64net/node64/internal/fingerprint"
)

// Fingerabdruecke der Werkzeuge (H6), aus den Rohbytes am Anfang einer Verbindung selbst geparst (crypto/tls und
// x/crypto/ssh liefern weder die Reihenfolge der Extensions noch die rohen Listen):
//   - JA4 (FoxIO, "JA4 TLS Client", technical_details/JA4.md) aus dem TLS-ClientHello, z. B. t13d1516h2_8daaf6152771_e5627efa2ab1.
//     Nur TCP ("t"); QUIC/DTLS gibt es im Honeypot nicht. Berechnung in internal/fingerprint (auch fuer die CDN64-Server).
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
		hello, more := fingerprint.TLSHello(b)
		if hello == nil {
			return "", more
		}
		if j := fingerprint.JA4(hello); j != "" {
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

func (r *fpReader) u32() int {
	if v := r.take(4); v != nil {
		return int(binary.BigEndian.Uint32(v))
	}
	return 0
}
