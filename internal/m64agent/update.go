package m64agent

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
)

const maxUpdateHeader = 4 << 10

// Dateien neben der Programmdatei fuer den Rueckfall nach einem Update.
const (
	oldSuffix    = ".old"    // vorherige Version
	markerSuffix = ".update" // Merker: neue Version noch nicht bestaetigt
	failedSuffix = ".failed" // Version, die nicht gestartet ist (wird nicht erneut angenommen)
)

// HealthyAfter: so lange muss die neue Version nach einem Update laufen, bis sie als gesund gilt (ConfirmUpdate).
const HealthyAfter = 60 * time.Second

// ParseReleaseKeys liest die eingebauten Release-Schluessel: base64 (32 Byte ed25519), durch Komma oder
// Leerzeichen getrennt (gesetzt per -ldflags "-X main.ReleaseKeys=...").
func ParseReleaseKeys(s string) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		b, err := base64.StdEncoding.DecodeString(f)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("release key %q: not a base64 ed25519 public key", f)
		}
		out = append(out, ed25519.PublicKey(b))
	}
	return out, nil
}

// readUpdateHeader liest die erste Zeile (JSON) ohne mehr als maxUpdateHeader Byte zu puffern.
func readUpdateHeader(br *bufio.Reader) (m64proto.UpdateHeader, error) {
	var h m64proto.UpdateHeader
	var line []byte
	for {
		b, err := br.ReadByte()
		if err != nil {
			return h, errors.New("header incomplete")
		}
		if b == '\n' {
			break
		}
		line = append(line, b)
		if len(line) > maxUpdateHeader {
			return h, errors.New("header too large")
		}
	}
	if err := json.Unmarshal(line, &h); err != nil {
		return h, errors.New("header is not valid JSON")
	}
	return h, nil
}

// checkUpdateHeader prueft Plattform, Groesse, Version (kein Downgrade) und Signatur, bevor die Datei gelesen wird.
func checkUpdateHeader(h m64proto.UpdateHeader, current string, keys []ed25519.PublicKey) error {
	if len(keys) == 0 {
		return errors.New("no release key built in - updates disabled")
	}
	if h.OS != runtime.GOOS || h.Arch != runtime.GOARCH {
		return fmt.Errorf("wrong platform %s/%s (agent is %s/%s)", h.OS, h.Arch, runtime.GOOS, runtime.GOARCH)
	}
	if h.Size <= 0 || h.Size > m64proto.MaxUpdateBytes {
		return fmt.Errorf("invalid size %d", h.Size)
	}
	if len(h.SHA256) != 64 || strings.ToLower(h.SHA256) != h.SHA256 {
		return errors.New("invalid sha256")
	}
	if _, err := hex.DecodeString(h.SHA256); err != nil {
		return errors.New("invalid sha256")
	}
	nv, ok := parseSemver(h.Version)
	if !ok {
		return fmt.Errorf("invalid version %q", h.Version)
	}
	cv, ok := parseSemver(current)
	if !ok {
		cv = semver{}
	}
	if compareSemver(nv, cv) <= 0 {
		return fmt.Errorf("version %s is not newer than %s", h.Version, current)
	}
	sig, err := base64.StdEncoding.DecodeString(h.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("invalid signature")
	}
	msg := m64proto.SignedMessage(h.Version, h.OS, h.Arch, h.SHA256)
	for _, k := range keys {
		if ed25519.Verify(k, msg, sig) {
			return nil
		}
	}
	return errors.New("signature does not match a release key")
}

// applyUpdate liest genau h.Size Byte, prueft SHA256 und ersetzt exe atomar (neue Datei daneben, dann umbenennen).
// Die bisherige Datei bleibt als <exe>.old fuer den Rueckfall. Bei jedem Fehler bleibt die alte Datei unveraendert.
func applyUpdate(r io.Reader, h m64proto.UpdateHeader, exe string) error {
	if b, err := os.ReadFile(exe + failedSuffix); err == nil && sameVersion(string(b), h.Version) {
		return fmt.Errorf("version %s did not start on this host before - refused", h.Version)
	}
	dir := filepath.Dir(exe)
	f, err := os.CreateTemp(dir, "."+filepath.Base(exe)+".new-*")
	if err != nil {
		return fmt.Errorf("temporary file: %w", err)
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	hs := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, hs), io.LimitReader(r, h.Size))
	if err != nil {
		return fmt.Errorf("receive: %w", err)
	}
	if n != h.Size {
		return fmt.Errorf("file incomplete (%d of %d bytes)", n, h.Size)
	}
	if hex.EncodeToString(hs.Sum(nil)) != h.SHA256 {
		return errors.New("sha256 does not match")
	}
	if err := f.Chmod(0o755); err != nil && runtime.GOOS != "windows" {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := keepOld(exe); err != nil {
		return fmt.Errorf("keep previous version: %w", err)
	}
	if err := os.Rename(tmp, exe); err != nil {
		return fmt.Errorf("replace: %w", err)
	}
	ok = true
	syncDir(dir)
	return nil
}

// keepOld legt die laufende Datei als <exe>.old ab (harter Verweis, sonst Kopie).
func keepOld(exe string) error {
	old := exe + oldSuffix
	if err := os.Remove(old); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if os.Link(exe, old) == nil {
		return nil
	}
	in, err := os.Open(exe)
	if err != nil {
		return err
	}
	defer in.Close()
	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	return writeFileAtomic(old, data, 0o755)
}

// restoreOld setzt <exe>.old wieder als Programmdatei ein.
func restoreOld(exe string) error {
	if err := os.Rename(exe+oldSuffix, exe); err != nil {
		return err
	}
	syncDir(filepath.Dir(exe))
	return nil
}

// updateMarker steht nach einem Update neben der Programmdatei, bis die neue Version HealthyAfter gelaufen ist.
type updateMarker struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Starts int    `json:"starts"` // Starts der neuen Version ohne Bestaetigung
}

// markerMu schuetzt den Merker innerhalb des Prozesses: der Bestaetigungs-Timer der laufenden Version darf den
// Merker eines gerade eingespielten weiteren Updates nicht zwischen Lesen und Loeschen erwischen.
var markerMu sync.Mutex

// WriteUpdateMarker merkt ein Update von from nach to (vor dem Neustart).
func WriteUpdateMarker(exe, from, to string) error {
	markerMu.Lock()
	defer markerMu.Unlock()
	b, _ := json.Marshal(updateMarker{From: from, To: to})
	return writeFileAtomic(exe+markerSuffix, b, 0o600)
}

// readMarker liest den Merker (ok=false: kaputt).
func readMarker(mp string) (updateMarker, bool, error) {
	var m updateMarker
	b, err := os.ReadFile(mp)
	if err != nil {
		return m, false, err
	}
	return m, json.Unmarshal(b, &m) == nil, nil
}

// UpdateStart wertet beim Start den Merker aus. Erster Start der neuen Version: zaehlt den Start und liefert
// pending (der Aufrufer ruft nach HealthyAfter ConfirmUpdate). Weiterer Start ohne Bestaetigung (die neue Version ist
// abgestuerzt oder kam nicht hoch): alte Datei zurueck, die Version wird kuenftig abgelehnt, rolledBack (der Aufrufer
// startet die alte Datei). Der Aufrufer ruft UpdateStart als Erstes beim Start auf, vor allem, was scheitern kann
// (Flags, Schluessel, Port) - sonst greift der Rueckfall nicht, wenn die neue Version schon daran scheitert.
// Versionen werden unabhaengig von der Schreibweise verglichen ("v1.3.0" = "1.3.0").
func UpdateStart(exe, version string) (pending, rolledBack bool, err error) {
	markerMu.Lock()
	mp := exe + markerSuffix
	m, ok, err := readMarker(mp)
	if errors.Is(err, os.ErrNotExist) {
		markerMu.Unlock()
		return false, false, nil
	}
	if err != nil {
		markerMu.Unlock()
		return false, false, err
	}
	if !ok || !sameVersion(m.To, version) {
		// kaputt oder fremd (z. B. Datei von Hand ersetzt): nichts tun
		_ = os.Remove(mp)
		markerMu.Unlock()
		return false, false, nil
	}
	if m.Starts == 0 {
		m.Starts++
		b, _ := json.Marshal(m)
		err = writeFileAtomic(mp, b, 0o600)
		markerMu.Unlock()
		return true, false, err
	}
	markerMu.Unlock()
	return false, true, RollbackUpdate(exe, version)
}

// RollbackUpdate setzt die vorherige Version wieder ein und merkt die fehlgeschlagene (wird nicht erneut angenommen).
func RollbackUpdate(exe, failed string) error {
	markerMu.Lock()
	_ = os.Remove(exe + markerSuffix)
	markerMu.Unlock()
	if err := restoreOld(exe); err != nil {
		return fmt.Errorf("restore previous version: %w", err)
	}
	_ = writeFileAtomic(exe+failedSuffix, []byte(failed+"\n"), 0o600)
	return nil
}

// ConfirmUpdate: die laufende Version (version) laeuft gesund - ihr Merker kommt weg, <exe>.old bleibt fuer den
// Notfall. Gehoert der Merker schon zu einem weiteren Update (andere Zielversion), bleibt er stehen: sonst haette die
// naechste Version keinen Rueckfall.
func ConfirmUpdate(exe, version string) {
	markerMu.Lock()
	defer markerMu.Unlock()
	mp := exe + markerSuffix
	m, ok, err := readMarker(mp)
	if err != nil || (ok && !sameVersion(m.To, version)) {
		return
	}
	_ = os.Remove(mp)
}

// sameVersion vergleicht Versionen unabhaengig von der Schreibweise ("v1.3.0" = "1.3.0", Build-Angabe nach "+"
// zaehlt nicht); keine SemVer: Text ohne fuehrendes "v".
func sameVersion(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	va, oka := parseSemver(a)
	vb, okb := parseSemver(b)
	if oka && okb {
		return compareSemver(va, vb) == 0
	}
	return strings.TrimPrefix(a, "v") == strings.TrimPrefix(b, "v")
}

// semver ist eine Version MAJOR.MINOR.PATCH[-pre] (Build-Angaben nach "+" zaehlen nicht).
type semver struct {
	n   [3]uint64
	pre string
}

func parseSemver(s string) (semver, bool) {
	var v semver
	s = strings.TrimPrefix(s, "v")
	s, _, _ = strings.Cut(s, "+")
	core, pre, hasPre := strings.Cut(s, "-")
	if hasPre && pre == "" {
		return v, false
	}
	v.pre = pre
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		if p == "" || len(p) > 9 || (len(p) > 1 && p[0] == '0') {
			return v, false
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return v, false
		}
		v.n[i] = n
	}
	return v, true
}

// compareSemver vergleicht nach SemVer 2.0 (Vorabversion kleiner als die fertige).
func compareSemver(a, b semver) int {
	for i := range 3 {
		if a.n[i] != b.n[i] {
			if a.n[i] < b.n[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case a.pre == b.pre:
		return 0
	case a.pre == "":
		return 1
	case b.pre == "":
		return -1
	}
	ap, bp := strings.Split(a.pre, "."), strings.Split(b.pre, ".")
	for i := 0; i < len(ap) && i < len(bp); i++ {
		if ap[i] == bp[i] {
			continue
		}
		an, aerr := strconv.ParseUint(ap[i], 10, 64)
		bn, berr := strconv.ParseUint(bp[i], 10, 64)
		switch {
		case aerr == nil && berr == nil:
			if an < bn {
				return -1
			}
			return 1
		case aerr == nil:
			return -1
		case berr == nil:
			return 1
		case ap[i] < bp[i]:
			return -1
		default:
			return 1
		}
	}
	switch {
	case len(ap) < len(bp):
		return -1
	case len(ap) > len(bp):
		return 1
	}
	return 0
}
