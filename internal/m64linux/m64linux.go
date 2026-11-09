// Package m64linux liest Linux-Werte fuer Monitor64 (Plan docs/PLAN-NODE64-MONITOR64.md, Abschnitte
// "Monitor64-Agent" und "SSH ohne Agent").
//
// Zwei Wege fuehren zum selben m64proto.Report:
//   - Collect: der Agent liest /proc und /sys direkt, Groessen per statfs, Programme ueber eine injizierbare
//     Exec-Funktion; langsame Abschnitte (SMART, Updates) puffert ein Cache.
//   - Script/ParseScriptOutput: die Node schickt ein festes Skript per "sh -s", das nur liest und Rohtexte in
//     Abschnitten ausgibt; ParseScriptOutput macht daraus den Report.
//
// Die Parser arbeiten auf Rohtext und sind plattformunabhaengig. Dateien aus /proc und /sys laufen in beiden Wegen
// ueber dieselbe Quelle (source): lokal das Dateisystem, beim Skript eine Tabelle aus der Ausgabe.
//
// Alles, was vom Host kommt, ist nicht vertrauenswuerdig: Groessen und Anzahlen sind begrenzt, aus Daten wird nie
// etwas ausgefuehrt (Geraetenamen fuer smartctl nur nach Pruefung mit DeviceRE).
package m64linux

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ipv64net/node64/internal/m64proto"
)

// Grenzen gegen ausufernde Hosts.
const (
	maxFileBytes = 1 << 20 // eine Datei aus /proc bzw. /sys
	maxItems     = 512     // Eintraege je Abschnitt (Dateisysteme, Schnittstellen, Platten, Sensoren ...)
	maxText      = 300     // Laenge freier Texte (Fehler, Scrub-Zeile)
)

// source liefert Dateien aus /proc und /sys (lokal oder aus der Skript-Ausgabe).
type source interface {
	ReadFile(p string) ([]byte, error)
	Exists(p string) bool
	ReadDir(dir string) []string // Namen, sortiert
	Readlink(p string) (string, error)
}

// osSource liest das echte Dateisystem unterhalb von root.
type osSource struct{ root string }

func (s osSource) full(p string) string {
	if s.root == "" || s.root == "/" {
		return filepath.FromSlash(p)
	}
	return filepath.Join(s.root, filepath.FromSlash(p))
}

func (s osSource) ReadFile(p string) ([]byte, error) {
	f, err := os.Open(s.full(p))
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) { // Host-Pfad statt Pfad unter der Wurzel melden
			return nil, &fs.PathError{Op: "read", Path: p, Err: pe.Err}
		}
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxFileBytes))
}

func (s osSource) Exists(p string) bool {
	_, err := os.Lstat(s.full(p))
	return err == nil
}

func (s osSource) ReadDir(dir string) []string {
	ents, err := os.ReadDir(s.full(dir))
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		out = append(out, e.Name())
		if len(out) >= 4*maxItems {
			break
		}
	}
	sort.Strings(out)
	return out
}

func (s osSource) Readlink(p string) (string, error) {
	l, err := os.Readlink(s.full(p))
	return filepath.ToSlash(l), err
}

// mapSource ist eine Dateitabelle (Pfad -> Inhalt) aus der Skript-Ausgabe. Verzeichnisse ergeben sich aus den Pfaden.
type mapSource struct{ files map[string][]byte }

func (m mapSource) ReadFile(p string) ([]byte, error) {
	if b, ok := m.files[p]; ok {
		return b, nil
	}
	return nil, &fs.PathError{Op: "read", Path: p, Err: fs.ErrNotExist}
}

func (m mapSource) Exists(p string) bool {
	if _, ok := m.files[p]; ok {
		return true
	}
	pre := p + "/"
	for k := range m.files {
		if strings.HasPrefix(k, pre) {
			return true
		}
	}
	return false
}

func (m mapSource) ReadDir(dir string) []string {
	pre := strings.TrimSuffix(dir, "/") + "/"
	seen := map[string]bool{}
	for k := range m.files {
		rest, ok := strings.CutPrefix(k, pre)
		if !ok || rest == "" {
			continue
		}
		name, _, _ := strings.Cut(rest, "/")
		seen[name] = true
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func (m mapSource) Readlink(p string) (string, error) {
	if b, ok := m.files[p]; ok {
		return strings.TrimSpace(string(b)), nil
	}
	return "", fs.ErrNotExist
}

// readStr liest eine einzeilige Datei (getrimmt); "" bei Fehler.
func readStr(src source, p string) string {
	b, err := src.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// readInt liest eine Zahl aus einer Datei.
func readInt(src source, p string) (int64, bool) {
	s := readStr(src, p)
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// linkBase liefert den letzten Teil eines Symlinks (z. B. master -> ../../bond0 = "bond0").
func linkBase(src source, p string) string {
	l, err := src.Readlink(p)
	if err != nil || l == "" {
		return ""
	}
	return path.Base(strings.TrimRight(l, "/"))
}

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

func ptrU64(v uint64) *uint64   { return &v }
func ptrF64(v float64) *float64 { return &v }
func ptrBool(v bool) *bool      { return &v }
