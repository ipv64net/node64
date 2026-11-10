// Package agentdist ist die Verteilung des Monitor64-Agents: das Verzeichnis der Dateien (agents.json, signiert wie
// das Manifest der Selbst-Updates) und der Zwischenspeicher der Node, die die Dateien bei Bedarf laedt, prueft und
// vorhaelt (store.go). Ablage und Release-Ablauf: docs/MONITOR64-AGENT-RELEASE.md.
//
//	<Basis>/agents.json (+ .sig)                                     Version und Dateien je Plattform (Groesse, SHA-256)
//	<Basis>/<version>/monitor64-agent-<os>-<arch>[.exe]              Programm
//	<Basis>/<version>/monitor64-agent-<os>-<arch>[.exe].update.json  signierte Kopfzeile (m64proto.UpdateHeader)
//	<Basis>/<version>/install.sh, install.ps1, SHA256SUMS            Installationsskripte und Pruefsummen
//
// Das Paket bleibt klein (kein Kern, keine Datenbank), damit auch cmd/node64-release es nutzen kann.
package agentdist

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/selfupdate"
)

const (
	IndexFile      = "agents.json" // Verzeichnis; Signatur daneben als agents.json.sig
	SumsFile       = "SHA256SUMS"
	HeaderSuffix   = ".update.json"
	filePrefix     = "monitor64-agent-"
	MaxIndexBytes  = 64 << 10
	MaxScriptBytes = 256 << 10
	MaxHeaderBytes = 4 << 10
	maxFiles       = 64
)

// Platform ist eine Plattform, fuer die der Agent gebaut wird.
type Platform struct {
	OS, Arch string // GOOS, GOARCH
	GOARM    string // nur arm
}

// Platforms: Linux amd64/arm64/armv7, Windows amd64, FreeBSD amd64/arm64.
var Platforms = []Platform{{"linux", "amd64", ""}, {"linux", "arm64", ""}, {"linux", "arm", "7"}, {"windows", "amd64", ""},
	{"freebsd", "amd64", ""}, {"freebsd", "arm64", ""}}

// Key ist der Schluessel einer Plattform im Verzeichnis ("linux-amd64"; GOARCH arm heisst armv7 wie im Dateinamen).
func Key(goos, goarch string) string {
	if goarch == "arm" {
		goarch = "armv7"
	}
	return goos + "-" + goarch
}

// FileName ist der Dateiname des Programms einer Plattform (monitor64-agent-linux-armv7, ...-windows-amd64.exe).
func FileName(goos, goarch string) string {
	name := filePrefix + Key(goos, goarch)
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// ParseFileName liest GOOS und GOARCH aus einem Dateinamen (Umkehrung von FileName).
func ParseFileName(name string) (goos, goarch string, ok bool) {
	rest, ok := strings.CutPrefix(name, filePrefix)
	if !ok {
		return "", "", false
	}
	rest = strings.TrimSuffix(rest, ".exe")
	goos, goarch, ok = strings.Cut(rest, "-")
	if !ok || !reToken.MatchString(goos) || !reToken.MatchString(goarch) {
		return "", "", false
	}
	if goarch == "armv7" {
		goarch = "arm"
	}
	if FileName(goos, goarch) != name {
		return "", "", false
	}
	return goos, goarch, true
}

// File ist ein Eintrag im Verzeichnis: Programm einer Plattform oder Skript.
type File struct {
	Name   string `json:"name"`
	OS     string `json:"os,omitempty"`   // GOOS (nur Programme)
	Arch   string `json:"arch,omitempty"` // GOARCH (nur Programme; arm = ARMv7)
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"` // hex, klein
}

// Index ist agents.json: die aktuelle Version des Agents mit ihren Dateien. Unbekannte Felder werden ignoriert.
type Index struct {
	Version string          `json:"version"`
	Date    string          `json:"date,omitempty"`
	Files   map[string]File `json:"files"`             // Key(os, arch) -> Programm
	Scripts map[string]File `json:"scripts,omitempty"` // install.sh, install.ps1
}

var (
	reVersion = regexp.MustCompile(`^[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}(-[0-9A-Za-z][0-9A-Za-z.-]{0,30})?$`)
	reToken   = regexp.MustCompile(`^[a-z0-9]{1,16}$`)
	reScript  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,40}\.(sh|ps1)$`)
	reSHA     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidVersion: Version als MAJOR.MINOR.PATCH[-vorab] (wird auch als Ordnername benutzt).
func ValidVersion(v string) bool { return reVersion.MatchString(v) }

// Parse liest und prueft ein Verzeichnis (ohne Signatur): Version, Namen (nur feste Muster, keine Pfade), Groessen
// und Pruefsummen.
func Parse(raw []byte) (*Index, error) {
	if len(raw) > MaxIndexBytes {
		return nil, errors.New("agent index too large")
	}
	var ix Index
	if err := json.Unmarshal(raw, &ix); err != nil {
		return nil, fmt.Errorf("agent index: %w", err)
	}
	if !ValidVersion(ix.Version) {
		return nil, fmt.Errorf("agent index: invalid version %q", ix.Version)
	}
	if len(ix.Files) == 0 || len(ix.Files)+len(ix.Scripts) > maxFiles {
		return nil, errors.New("agent index: no files or too many")
	}
	for k, f := range ix.Files {
		if !reToken.MatchString(f.OS) || !reToken.MatchString(f.Arch) || k != Key(f.OS, f.Arch) || f.Name != FileName(f.OS, f.Arch) {
			return nil, fmt.Errorf("agent index: invalid entry %q", k)
		}
		if f.Size <= 0 || f.Size > m64proto.MaxUpdateBytes || !reSHA.MatchString(f.SHA256) {
			return nil, fmt.Errorf("agent index: invalid size or checksum of %s", f.Name)
		}
	}
	for k, f := range ix.Scripts {
		if !reScript.MatchString(k) || f.Name != k {
			return nil, fmt.Errorf("agent index: invalid script %q", k)
		}
		if f.Size <= 0 || f.Size > MaxScriptBytes || !reSHA.MatchString(f.SHA256) {
			return nil, fmt.Errorf("agent index: invalid size or checksum of %s", f.Name)
		}
	}
	return &ix, nil
}

// Verify prueft die Signatur (wie beim Manifest der Selbst-Updates: base64 ed25519 ueber die Datei) und liest das
// Verzeichnis.
func Verify(raw, sig []byte, keys []ed25519.PublicKey) (*Index, error) {
	if len(raw) > MaxIndexBytes {
		return nil, errors.New("agent index too large")
	}
	if _, err := selfupdate.Verify(raw, sig, keys); err != nil {
		return nil, err
	}
	return Parse(raw)
}

// Lookup findet eine Datei nach ihrem Namen (Programm oder Skript).
func (ix *Index) Lookup(name string) (f File, program, ok bool) {
	if ix == nil {
		return File{}, false, false
	}
	if goos, goarch, isProg := ParseFileName(name); isProg {
		f, ok = ix.Files[Key(goos, goarch)]
		return f, true, ok && f.Name == name
	}
	f, ok = ix.Scripts[name]
	return f, false, ok
}

// Names liefert die Dateinamen der Programme und der Skripte, jeweils sortiert.
func (ix *Index) Names() (programs, scripts []string) {
	for _, f := range ix.Files {
		programs = append(programs, f.Name)
	}
	for k := range ix.Scripts {
		scripts = append(scripts, k)
	}
	sort.Strings(programs)
	sort.Strings(scripts)
	return programs, scripts
}

// Sums ist der Inhalt von SHA256SUMS ("<sha256>  <name>" je Programm, sortiert); die Installationsskripte pruefen
// damit die geladene Datei.
func (ix *Index) Sums() []byte {
	var b strings.Builder
	progs, _ := ix.Names()
	for _, name := range progs {
		f, _, _ := ix.Lookup(name)
		b.WriteString(f.SHA256 + "  " + name + "\n")
	}
	return []byte(b.String())
}

// CheckHeader prueft die signierte Kopfzeile eines Programms gegen das Verzeichnis: gleiche Version, Plattform,
// Groesse und Pruefsumme, Signatur eines Release-Schluessels ueber m64proto.SignedMessage (wie der Agent sie prueft).
func CheckHeader(h m64proto.UpdateHeader, version string, f File, keys []ed25519.PublicKey) error {
	if h.Version != version || h.OS != f.OS || h.Arch != f.Arch {
		return fmt.Errorf("update header of %s does not match the index (%s %s/%s)", f.Name, h.Version, h.OS, h.Arch)
	}
	if h.Size != f.Size || h.SHA256 != f.SHA256 {
		return fmt.Errorf("update header of %s: size or checksum differs from the index", f.Name)
	}
	sig, err := base64.StdEncoding.DecodeString(h.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("update header of %s: invalid signature format", f.Name)
	}
	msg := m64proto.SignedMessage(h.Version, h.OS, h.Arch, h.SHA256)
	for _, k := range keys {
		if ed25519.Verify(k, msg, sig) {
			return nil
		}
	}
	return fmt.Errorf("update header of %s: signature does not match a release key", f.Name)
}

// Build baut das Verzeichnis aus einem Ordner mit den gebauten Dateien (monitor64-agent-<os>-<arch>[.exe],
// install.sh, install.ps1). Fuer das Release-Werkzeug.
func Build(version, dir string) (*Index, error) {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	if !ValidVersion(version) {
		return nil, fmt.Errorf("invalid version %q", version)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	ix := &Index{Version: version, Date: time.Now().UTC().Format(time.RFC3339), Files: map[string]File{}, Scripts: map[string]File{}}
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || strings.HasSuffix(name, HeaderSuffix) {
			continue
		}
		goos, goarch, isProg := ParseFileName(name)
		if !isProg && !reScript.MatchString(name) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		f := File{Name: name, Size: int64(len(b)), SHA256: hex.EncodeToString(sum[:])}
		if isProg {
			f.OS, f.Arch = goos, goarch
			ix.Files[Key(goos, goarch)] = f
		} else {
			ix.Scripts[name] = f
		}
	}
	if len(ix.Files) == 0 {
		return nil, fmt.Errorf("%s: no %s<os>-<arch> files", dir, filePrefix)
	}
	raw, _ := json.Marshal(ix)
	if _, err := Parse(raw); err != nil { // dieselbe Pruefung wie die Node
		return nil, err
	}
	return ix, nil
}
