// Package geoip ordnet IP-Adressen einem Land zu (Herkunft der Angreifer in Honeypot64). Die Daten kommen von
// ipv64.net: country_ranges.txt.gz (gzip-Text, je Zeile "<CC> <erste IP> <letzte IP>", Kommentare mit #), taeglich
// nach dem Standort aus DB-IP "IP to Country Lite" (CC BY 4.0, Namensnennung an der Anzeige), Luecken aus den Daten
// der Registrierungsstellen, in blocklists/index.json als "geo" eingetragen. Keine GeoIP-Datenbank im Image.
//
// Geladen wird nur, wenn ein Teil der Node es braucht (Start, z. B. beim Start von Honeypot64): zuerst aus dem
// Zwischenspeicher <data>/geoip (sofort nutzbar), dann von ipv64.net und danach taeglich nur bei Aenderung (ETag,
// If-Modified-Since). Fehler werden nur geloggt; fehlt die Datei bei ipv64 (404), gibt es einfach keine Laender.
//
// Speicher: sortierte Bereiche getrennt nach IPv4 (Anfang, Ende je uint32, Land uint16 = 10 Byte je Bereich) und
// IPv6 (obere 64 Bit von Anfang und Ende, Land = 18 Byte je Bereich; feinere Bereiche als /64 fallen zusammen, der
// erste gilt), Suche per Binaersuche ohne Zuweisungen.
package geoip

import (
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"time"
)

// Grenzen gegen kaputte oder zu grosse Dateien (Variablen nur fuer Tests).
var (
	maxFile  int64 = 32 << 20  // gepackte Datei
	maxRaw   int64 = 128 << 20 // entpackt
	maxLines       = 2_000_000 // Zeilen (inkl. Kommentare)
)

const maxLineLen = 256 // Zeichen je Zeile ("CC" + zwei IPv6-Adressen sind < 90)

var (
	errTooLarge = errors.New("geoip: file too large")
	errNoRanges = errors.New("geoip: no ranges in file")
)

type rng4 struct {
	s, e uint32
	c    uint16
}

type rng6 struct {
	s, e uint64
	c    uint16
}

// table sind die geladenen Bereiche (unveraenderlich nach dem Aufbau, wird als Ganzes ersetzt).
type table struct {
	v4s, v4e []uint32
	v4c      []uint16
	v6s, v6e []uint64
	v6c      []uint16
	updated  time.Time // Stand der Datei (Abruf bzw. Aenderung des Zwischenspeichers)
}

// bytes: ungefaehrer Speicherbedarf der Bereiche.
func (t *table) bytes() int {
	return len(t.v4s)*10 + len(t.v6s)*18
}

func ccCode(b []byte) (uint16, bool) {
	if len(b) != 2 {
		return 0, false
	}
	x, y := b[0]&^0x20, b[1]&^0x20 // Grossbuchstaben
	if x < 'A' || x > 'Z' || y < 'A' || y > 'Z' {
		return 0, false
	}
	return uint16(x)<<8 | uint16(y), true
}

func ccString(c uint16) string { return string([]byte{byte(c >> 8), byte(c)}) }

// parse liest die entpackte Datei. Unlesbare Zeilen werden uebersprungen (skipped); ohne einen Bereich ist es ein
// Fehler (dann bleibt der bisherige Stand).
func parse(r io.Reader) (t *table, skipped int, err error) {
	sc := bufio.NewScanner(io.LimitReader(r, maxRaw+1))
	sc.Buffer(make([]byte, 0, maxLineLen), maxLineLen)
	var r4 []rng4
	var r6 []rng6
	var read int64
	lines := 0
	for sc.Scan() {
		line := sc.Bytes()
		read += int64(len(line)) + 1
		if read > maxRaw {
			return nil, 0, errTooLarge
		}
		if lines++; lines > maxLines {
			return nil, 0, fmt.Errorf("geoip: more than %d lines", maxLines)
		}
		f, n := fields3(line)
		if n == 0 {
			continue // leer oder Kommentar
		}
		if n != 3 {
			skipped++
			continue
		}
		c, ok := ccCode(f[0])
		if !ok {
			skipped++
			continue
		}
		a, err1 := netip.ParseAddr(string(f[1]))
		b, err2 := netip.ParseAddr(string(f[2]))
		if err1 != nil || err2 != nil || a.Zone() != "" || b.Zone() != "" {
			skipped++
			continue
		}
		a, b = a.Unmap(), b.Unmap()
		switch {
		case a.Is4() && b.Is4():
			s, e := v4(a), v4(b)
			if s > e {
				skipped++
				continue
			}
			r4 = append(r4, rng4{s, e, c})
		case a.Is6() && b.Is6():
			s, e := v6hi(a), v6hi(b)
			if a.Compare(b) > 0 {
				skipped++
				continue
			}
			r6 = append(r6, rng6{s, e, c})
		default:
			skipped++
		}
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, 0, fmt.Errorf("geoip: line %d too long", lines+1)
		}
		return nil, 0, err
	}
	if len(r4)+len(r6) == 0 {
		return nil, skipped, errNoRanges
	}
	r4, r6 = merge4(r4), merge6(r6)
	t = &table{v4s: make([]uint32, len(r4)), v4e: make([]uint32, len(r4)), v4c: make([]uint16, len(r4)),
		v6s: make([]uint64, len(r6)), v6e: make([]uint64, len(r6)), v6c: make([]uint16, len(r6))}
	for i, x := range r4 {
		t.v4s[i], t.v4e[i], t.v4c[i] = x.s, x.e, x.c
	}
	for i, x := range r6 {
		t.v6s[i], t.v6e[i], t.v6c[i] = x.s, x.e, x.c
	}
	return t, skipped, nil
}

// parseGzip entpackt und liest die Datei von ipv64.net bzw. aus dem Zwischenspeicher.
func parseGzip(r io.Reader) (*table, int, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, 0, fmt.Errorf("geoip: %w", err)
	}
	defer zr.Close()
	return parse(zr)
}

// fields3 zerlegt eine Zeile in drei Felder. n = Anzahl der Felder (0 = leer oder Kommentar, 4 = mehr als drei).
func fields3(line []byte) (out [3][]byte, n int) {
	i := 0
	for i < len(line) {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t' || line[i] == '\r') {
			i++
		}
		if i == len(line) {
			break
		}
		if line[i] == '#' {
			break // Kommentar (ganze Zeile oder Rest)
		}
		j := i
		for j < len(line) && line[j] != ' ' && line[j] != '\t' && line[j] != '\r' {
			j++
		}
		if n == 3 {
			return out, 4
		}
		out[n] = line[i:j]
		n++
		i = j
	}
	return out, n
}

func v4(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

func v6hi(a netip.Addr) uint64 {
	b := a.As16()
	return binary.BigEndian.Uint64(b[:8])
}

// merge4 sortiert und fasst zusammen: angrenzende Bereiche desselben Landes werden einer, Ueberschneidungen gehen an
// den frueheren Bereich (der spaetere wird gekuerzt oder faellt weg; bei gleichem Anfang zaehlt die Reihenfolge der Datei).
func merge4(r []rng4) []rng4 {
	slices.SortStableFunc(r, func(a, b rng4) int {
		if a.s != b.s {
			if a.s < b.s {
				return -1
			}
			return 1
		}
		return 0
	})
	out := r[:0]
	for _, x := range r {
		if n := len(out); n > 0 {
			p := &out[n-1]
			if x.s <= p.e {
				if x.e <= p.e {
					continue
				}
				x.s = p.e + 1
			}
			if p.c == x.c && x.s == p.e+1 {
				p.e = x.e
				continue
			}
		}
		out = append(out, x)
	}
	return slices.Clip(out)
}

func merge6(r []rng6) []rng6 {
	slices.SortStableFunc(r, func(a, b rng6) int {
		if a.s != b.s {
			if a.s < b.s {
				return -1
			}
			return 1
		}
		return 0
	})
	out := r[:0]
	for _, x := range r {
		if n := len(out); n > 0 {
			p := &out[n-1]
			if x.s <= p.e {
				if x.e <= p.e {
					continue
				}
				x.s = p.e + 1
			}
			if p.c == x.c && x.s == p.e+1 {
				p.e = x.e
				continue
			}
		}
		out = append(out, x)
	}
	return slices.Clip(out)
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// lookup liefert das Land (0 = keins). Private, reservierte und lokale Adressen haben nie ein Land.
func (t *table) lookup(a netip.Addr) uint16 {
	if t == nil || !a.IsValid() {
		return 0
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || cgnat.Contains(a) {
		return 0
	}
	if a.Is4() {
		v := v4(a)
		lo, hi := 0, len(t.v4s) // erster Bereich mit Anfang > v
		for lo < hi {
			m := int(uint(lo+hi) >> 1)
			if t.v4s[m] <= v {
				lo = m + 1
			} else {
				hi = m
			}
		}
		if i := lo - 1; i >= 0 && v <= t.v4e[i] {
			return t.v4c[i]
		}
		return 0
	}
	v := v6hi(a)
	lo, hi := 0, len(t.v6s)
	for lo < hi {
		m := int(uint(lo+hi) >> 1)
		if t.v6s[m] <= v {
			lo = m + 1
		} else {
			hi = m
		}
	}
	if i := lo - 1; i >= 0 && v <= t.v6e[i] {
		return t.v6c[i]
	}
	return 0
}
