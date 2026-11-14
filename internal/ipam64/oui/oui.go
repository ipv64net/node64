// Package oui liefert den Hersteller zu einer MAC-Adresse (Plan IPAM64, Entscheidung E4). Die Liste (IEEE MA-L,
// MA-M, MA-S) liegt gepackt im Binary (oui.txt.gz, je Zeile "<hex-praefix>\t<Hersteller>", Praefix 6, 7 oder 9
// Hex-Ziffern) und wird beim ersten Aufruf geladen. Erzeugt wird sie mit "go run gen.go" in diesem Ordner (laedt die
// oeffentlichen CSV-Dateien der IEEE). Zufaellig vergebene MACs (Bit "lokal verwaltet", z. B. Smartphones mit privater
// WLAN-Adresse) erkennt Random ohne Liste.
package oui

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"net"
	"strings"
	"sync"
)

//go:embed oui.txt.gz
var data []byte

var (
	once  sync.Once
	table map[string]string // Praefix (klein, ohne Trenner) -> Hersteller
)

func load() {
	table = map[string]string{}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return
	}
	defer zr.Close()
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		if p, name, ok := strings.Cut(line, "\t"); ok && name != "" {
			table[strings.ToLower(p)] = name
		}
	}
}

// Random meldet eine lokal verwaltete (meist zufaellige) MAC-Adresse.
func Random(mac string) bool {
	hw, err := net.ParseMAC(mac)
	return err == nil && len(hw) > 0 && hw[0]&0x02 != 0
}

// Lookup liefert den Hersteller ("" = unbekannt bzw. zufaellige MAC). Laengere Praefixe (MA-S, MA-M) gehen vor.
func Lookup(mac string) string {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 || hw[0]&0x02 != 0 {
		return ""
	}
	once.Do(load)
	h := strings.ReplaceAll(hw.String(), ":", "")
	for _, n := range []int{9, 7, 6} {
		if v, ok := table[h[:n]]; ok {
			return v
		}
	}
	return ""
}

// Size ist die Zahl der Eintraege (0 = keine Liste eingebaut).
func Size() int {
	once.Do(load)
	return len(table)
}
