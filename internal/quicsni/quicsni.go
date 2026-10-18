// Package quicsni liest den Servernamen (SNI) aus den ersten QUIC-Paketen eines Clients (Initial, QUIC v1 und v2).
// Die Initial-Pakete sind nur mit Schluesseln geschuetzt, die sich aus der Ziel-Connection-ID ableiten (RFC 9001
// Abschnitt 5.2, RFC 9369) - jeder auf dem Weg kann sie lesen. Damit kann ein Server QUIC nach dem Namen
// weiterreichen, ohne TLS zu beenden (CDN64 Modus 1). Der ClientHello verteilt sich oft auf mehrere Pakete (grosse
// Schluessel, Chromes Umsortierung der CRYPTO-Frames): Assembler setzt ihn zusammen.
package quicsni

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/cryptobyte"
)

const (
	versionV1 = 0x00000001
	versionV2 = 0x6b3343cf
)

var (
	saltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	saltV2 = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}

	errNotInitial = errors.New("not a quic initial packet")
	errShort      = errors.New("packet too short")
)

// IsInitial: beginnt das Datagramm mit einem Initial-Paket (QUIC v1/v2)? Schnelle Vorpruefung ohne Entschluesseln.
func IsInitial(b []byte) bool {
	if len(b) < 7 || b[0]&0xc0 != 0xc0 {
		return false
	}
	switch binary.BigEndian.Uint32(b[1:5]) {
	case versionV1:
		return (b[0]>>4)&0x3 == 0
	case versionV2:
		return (b[0]>>4)&0x3 == 1
	}
	return false
}

// Chunk ist ein Stueck des CRYPTO-Streams (Offset im Stream, Daten).
type Chunk struct {
	Offset uint64
	Data   []byte
}

// Parse entschluesselt das erste Initial-Paket des Datagramms und liefert die Ziel-Connection-ID und die
// CRYPTO-Daten. b wird nicht veraendert.
func Parse(b []byte) (dcid []byte, chunks []Chunk, err error) {
	if !IsInitial(b) {
		return nil, nil, errNotInitial
	}
	version := binary.BigEndian.Uint32(b[1:5])
	p := 5
	dl := int(b[p])
	p++
	if dl > 20 || p+dl > len(b) {
		return nil, nil, errShort
	}
	dcid = append([]byte(nil), b[p:p+dl]...)
	p += dl
	if p >= len(b) {
		return nil, nil, errShort
	}
	sl := int(b[p])
	p++
	if sl > 20 || p+sl > len(b) {
		return nil, nil, errShort
	}
	p += sl
	tokLen, n := varint(b[p:])
	if n == 0 || uint64(len(b)-p-n) < tokLen {
		return nil, nil, errShort
	}
	p += n + int(tokLen)
	length, n := varint(b[p:])
	if n == 0 {
		return nil, nil, errShort
	}
	p += n
	pnOff := p
	if length < 20 || uint64(len(b)-pnOff) < length {
		return nil, nil, errShort
	}
	key, iv, hp, err := initialKeys(dcid, version)
	if err != nil {
		return nil, nil, err
	}
	// Kopfschutz entfernen
	hdr := append([]byte(nil), b[:pnOff+4]...)
	block, err := aes.NewCipher(hp)
	if err != nil {
		return nil, nil, err
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, b[pnOff+4:pnOff+20])
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&0x3) + 1
	var pn uint64
	for i := 0; i < pnLen; i++ {
		hdr[pnOff+i] ^= mask[1+i]
		pn = pn<<8 | uint64(hdr[pnOff+i])
	}
	hdr = hdr[:pnOff+pnLen]
	// Nutzlast entschluesseln (AES-128-GCM, Nonce = IV xor Paketnummer)
	kb, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(kb)
	if err != nil {
		return nil, nil, err
	}
	nonce := append([]byte(nil), iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	ct := b[pnOff+pnLen : pnOff+int(length)]
	plain, err := aead.Open(nil, nonce, ct, hdr)
	if err != nil {
		return nil, nil, err
	}
	chunks = cryptoFrames(plain)
	return dcid, chunks, nil
}

// cryptoFrames liest die CRYPTO-Frames (PADDING, PING und ACK werden uebersprungen; bei anderen Frames ist Schluss).
func cryptoFrames(p []byte) []Chunk {
	var out []Chunk
	for len(p) > 0 {
		t, n := varint(p)
		if n == 0 {
			return out
		}
		p = p[n:]
		switch {
		case t == 0x00 || t == 0x01: // PADDING, PING
		case t == 0x06: // CRYPTO
			off, n1 := varint(p)
			if n1 == 0 {
				return out
			}
			l, n2 := varint(p[n1:])
			if n2 == 0 || uint64(len(p)-n1-n2) < l {
				return out
			}
			d := p[n1+n2 : n1+n2+int(l)]
			out = append(out, Chunk{Offset: off, Data: append([]byte(nil), d...)})
			p = p[n1+n2+int(l):]
		case t == 0x02 || t == 0x03: // ACK (im ersten Flug eines Clients selten)
			rest, ok := skipACK(p, t == 0x03)
			if !ok {
				return out
			}
			p = rest
		default:
			return out
		}
	}
	return out
}

func skipACK(p []byte, ecn bool) ([]byte, bool) {
	cnt := 4 // largest, delay, range count, first range
	var ranges uint64
	for i := 0; i < cnt; i++ {
		v, n := varint(p)
		if n == 0 {
			return nil, false
		}
		if i == 2 {
			ranges = v
		}
		p = p[n:]
	}
	if ranges > 256 {
		return nil, false
	}
	extra := int(ranges) * 2
	if ecn {
		extra += 3
	}
	for i := 0; i < extra; i++ {
		_, n := varint(p)
		if n == 0 {
			return nil, false
		}
		p = p[n:]
	}
	return p, true
}

func initialKeys(dcid []byte, version uint32) (key, iv, hp []byte, err error) {
	salt, pre := saltV1, "quic "
	if version == versionV2 {
		salt, pre = saltV2, "quicv2 "
	}
	secret, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		return nil, nil, nil, err
	}
	client, err := expandLabel(secret, "client in", 32)
	if err != nil {
		return nil, nil, nil, err
	}
	if key, err = expandLabel(client, pre+"key", 16); err != nil {
		return nil, nil, nil, err
	}
	if iv, err = expandLabel(client, pre+"iv", 12); err != nil {
		return nil, nil, nil, err
	}
	hp, err = expandLabel(client, pre+"hp", 16)
	return key, iv, hp, err
}

// expandLabel: HKDF-Expand-Label aus TLS 1.3 (leerer Kontext).
func expandLabel(secret []byte, label string, n int) ([]byte, error) {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = append(info, byte(n>>8), byte(n), byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	return hkdf.Expand(sha256.New, secret, string(info), n)
}

// varint: QUIC-Zahl variabler Laenge; n = 0 bei zu kurzen Daten.
func varint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	l := 1 << (b[0] >> 6)
	if len(b) < l {
		return 0, 0
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < l; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, l
}

// ---------------------------------------------------------------- ClientHello zusammensetzen

// Assembler sammelt CRYPTO-Daten einer Verbindung, bis der ClientHello vollstaendig ist.
type Assembler struct {
	parts map[uint64][]byte
	size  int
}

// maxHello: groesser wird kein ClientHello, den wir abwarten (Schutz des Speichers).
const maxHello = 16 << 10

// Add nimmt Stuecke auf; true, wenn der ClientHello danach vollstaendig ist.
func (a *Assembler) Add(chunks []Chunk) bool {
	if a.parts == nil {
		a.parts = map[uint64][]byte{}
	}
	for _, c := range chunks {
		if c.Offset > maxHello || a.size > maxHello {
			continue
		}
		if old, ok := a.parts[c.Offset]; !ok || len(old) < len(c.Data) {
			a.size += len(c.Data) - len(old)
			a.parts[c.Offset] = c.Data
		}
	}
	_, ok := a.Hello()
	return ok
}

// Hello: der zusammenhaengende Anfang des Streams, wenn er einen ganzen ClientHello enthaelt.
func (a *Assembler) Hello() ([]byte, bool) {
	var buf []byte
	for {
		next := uint64(len(buf))
		var best []byte
		for off, d := range a.parts { // ein Stueck, das an der aktuellen Stelle beginnt oder sie ueberdeckt
			if off <= next && off+uint64(len(d)) > next && (best == nil || off+uint64(len(d)) > next+uint64(len(best))) {
				best = d[next-off:]
			}
		}
		if best == nil {
			break
		}
		buf = append(buf, best...)
	}
	if len(buf) < 4 || buf[0] != 0x01 { // Handshake-Typ ClientHello
		return nil, false
	}
	n := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
	if n > maxHello || len(buf) < 4+n {
		return nil, false
	}
	return buf[:4+n], true
}

// ServerName liest SNI aus einem ClientHello (mit Handshake-Kopf).
func ServerName(hello []byte) (string, bool) {
	s := cryptobyte.String(hello)
	var typ uint8
	var body cryptobyte.String
	if !s.ReadUint8(&typ) || typ != 1 || !s.ReadUint24LengthPrefixed(&body) {
		return "", false
	}
	var sid, suites, comp, exts cryptobyte.String
	if !body.Skip(2+32) || !body.ReadUint8LengthPrefixed(&sid) || !body.ReadUint16LengthPrefixed(&suites) ||
		!body.ReadUint8LengthPrefixed(&comp) || !body.ReadUint16LengthPrefixed(&exts) {
		return "", false
	}
	for !exts.Empty() {
		var et uint16
		var ed cryptobyte.String
		if !exts.ReadUint16(&et) || !exts.ReadUint16LengthPrefixed(&ed) {
			return "", false
		}
		if et != 0 { // server_name
			continue
		}
		var list cryptobyte.String
		if !ed.ReadUint16LengthPrefixed(&list) {
			return "", false
		}
		for !list.Empty() {
			var nt uint8
			var name cryptobyte.String
			if !list.ReadUint8(&nt) || !list.ReadUint16LengthPrefixed(&name) {
				return "", false
			}
			if nt == 0 && len(name) > 0 {
				return string(name), true
			}
		}
	}
	return "", false
}
