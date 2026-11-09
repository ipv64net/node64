package m64agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/crypto/ssh"
)

// LoadOrCreateHostKey liest den Hostschluessel (OpenSSH-Format) oder erzeugt beim ersten Start einen neuen
// (ed25519, Datei 0600). Zu offene Rechte einer vorhandenen Datei werden auf 0600 gesetzt.
func LoadOrCreateHostKey(path string) (ssh.Signer, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		if fi, serr := os.Stat(path); serr == nil && runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
			_ = os.Chmod(path, 0o600)
		}
		s, perr := ssh.ParsePrivateKey(b)
		if perr != nil {
			return nil, fmt.Errorf("host key %s: %w", path, perr)
		}
		return s, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	blk, err := ssh.MarshalPrivateKey(priv, "monitor64-agent")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(path, pem.EncodeToMemory(blk), 0o600); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

// ReadHostKeyFingerprint liefert den Fingerabdruck des vorhandenen Hostschluessels (ohne ihn anzulegen).
func ReadHostKeyFingerprint(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return "", err
	}
	return Fingerprint(s.PublicKey()), nil
}

// Fingerprint liefert den Fingerabdruck wie OpenSSH ("SHA256:...").
func Fingerprint(pub ssh.PublicKey) string {
	return ssh.FingerprintSHA256(pub)
}

// writeFileAtomic schreibt erst in eine Nachbardatei und benennt dann um: Leser sehen nie eine halbe Datei.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(perm); err != nil && runtime.GOOS != "windows" {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	syncDir(dir)
	return nil
}

// syncDir sichert das Umbenennen (nur Unix; unter Windows nicht moeglich und nicht noetig).
func syncDir(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
