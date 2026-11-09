// Package m64bsd liest FreeBSD-Werte fuer den Monitor64-Agent (OPNsense, pfSense, TrueNAS CORE, FreeBSD;
// Plan docs/PLAN-NODE64-MONITOR64.md, Phase 3 "FreeBSD-Agent").
//
// Collect liefert denselben m64proto.Report wie der Linux-Sammler (m64linux):
//   - sysctl (ohne Programmaufruf, golang.org/x/sys/unix): CPU-Zaehler kern.cp_time, Speicher vm.stats.vm.*,
//     hw.physmem, ZFS-ARC als Cache, Swap vm.swap_info, Load vm.loadavg, Startzeit kern.boottime, Temperaturen
//     dev.cpu.N.temperature und hw.acpi.thermal.tzN.temperature.
//   - getfsstat/statfs: lokale Dateisysteme (MNT_LOCAL), Filter wie unter Linux.
//   - Programme (ohne Shell, mit Zeitlimit und begrenzter Ausgabe): netstat -ibn --libxo json und ifconfig -a
//     (Zaehler, Link, lagg), iostat -x -I (Platten-Zaehler seit dem Start), geom disk list (Seriennummern),
//     zpool, gmirror/graid status, smartctl, pkg version/audit, freebsd-version.
//   - Langsame Abschnitte (SMART 30 min, Updates 60 min, Neustart 10 min) puffert ein Cache im Hintergrund.
//
// Alle Parser arbeiten auf Rohtext bzw. Rohbytes und sind plattformunabhaengig (Tests unter Linux/Windows); nur
// sys_freebsd.go greift auf sysctl/getfsstat/statfs zu. Alles, was vom Host kommt, ist nicht vertrauenswuerdig:
// Groessen und Anzahlen sind begrenzt, aus Daten wird nie etwas ausgefuehrt (Geraetenamen fuer smartctl nur nach
// Pruefung mit m64linux.ValidSmartDevice).
package m64bsd

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ipv64net/node64/internal/m64proto"
)

// Grenzen gegen ausufernde Hosts.
const (
	maxItems = 512 // Eintraege je Abschnitt (Dateisysteme, Schnittstellen, Platten, Sensoren ...)
	maxText  = 300 // Laenge freier Texte (Fehler, Scrub-Zeile)
)

var errFormat = errors.New("unbekanntes Format")

// clip kuerzt freie Texte vom Host, ersetzt ungueltiges UTF-8 und Steuerzeichen.
func clip(s string) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > maxText {
		i := maxText
		for i > 0 && !utf8.RuneStart(s[i]) {
			i--
		}
		s = strings.TrimSpace(s[:i])
	}
	return s
}

// clipN kuerzt zusaetzlich auf n Bytes (Namen, Versionen).
func clipN(s string, n int) string {
	s = clip(s)
	if len(s) > n {
		i := n
		for i > 0 && !utf8.RuneStart(s[i]) {
			i--
		}
		s = strings.TrimSpace(s[:i])
	}
	return s
}

// errText macht aus einem Fehler einen kurzen Text fuer SectionErr.
func errText(err error) string {
	if err == nil {
		return ""
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return clip(pe.Op + " " + filepath.ToSlash(pe.Path) + ": " + pe.Err.Error())
	}
	return clip(err.Error())
}

// addErr haengt einen Abschnittsfehler an.
func addErr(r *m64proto.Report, sec string, err error) {
	if err == nil {
		return
	}
	r.Errors = append(r.Errors, m64proto.SectionErr{Section: sec, Error: errText(err)})
}

// addNote haengt einen Hinweis an.
func addNote(r *m64proto.Report, sec, note string) {
	r.Notes = append(r.Notes, m64proto.SectionNote{Section: sec, Note: clip(note)})
}

// lines teilt Text in Zeilen (ohne \r).
func lines(b []byte) []string {
	s := strings.ReplaceAll(string(b), "\r", "")
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func u64(s string) uint64 {
	v, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	return v
}

func ptrF64(v float64) *float64 { return &v }
func ptrBool(v bool) *bool      { return &v }
