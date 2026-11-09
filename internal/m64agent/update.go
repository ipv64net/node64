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

	"github.com/ipv64net/node64/internal/m64proto"
)

const maxUpdateHeader = 4 << 10

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
// Bei jedem Fehler bleibt die alte Datei unveraendert.
func applyUpdate(r io.Reader, h m64proto.UpdateHeader, exe string) error {
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
	if err := os.Rename(tmp, exe); err != nil {
		return fmt.Errorf("replace: %w", err)
	}
	ok = true
	syncDir(dir)
	return nil
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
