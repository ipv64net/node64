//go:build linux || windows || freebsd

package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/ipv64net/node64/internal/m64agent"
)

// Gemeinsame Helfer fuer install unter Linux, Windows und FreeBSD.

func say(format string, a ...any) { fmt.Printf("monitor64-agent: "+format+"\n", a...) }

// checkInstallArgs prueft Schluessel und Port.
func checkInstallArgs(key string, port int) (string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", errors.New(`--key is missing (public key of the node)`)
	}
	if n, err := m64agent.ParseKeys([]byte(key)); err != nil || n != 1 {
		if err == nil {
			err = errors.New("exactly one key expected")
		}
		return "", fmt.Errorf("--key: %w", err)
	}
	if port <= 0 || port > 65535 {
		return "", fmt.Errorf("invalid port %d", port)
	}
	return key, nil
}

// writePushTargets nimmt die Ziele aus --connect in <dir>/connect auf (gleiche Adresse = neuer Token).
func writePushTargets(path string, add []m64agent.PushTarget) error {
	if len(add) == 0 {
		return nil
	}
	old, err := m64agent.ReadPushFile(path)
	if err != nil {
		say("WARNING: %v - file replaced", err)
		old = nil
	}
	all, err := m64agent.AddPushTargets(old, add)
	if err != nil {
		return fmt.Errorf("--connect: %w", err)
	}
	if err := m64agent.WritePushFile(path, all); err != nil {
		return err
	}
	for _, t := range add {
		say("connects to node %s (push, %s)", t.String(), path)
	}
	return nil
}

// addKey haengt den Schluessel an die Liste an, falls er fehlt. Zeilenenden CRLF (unter Windows bearbeitet) werden
// dabei zu LF.
func addKey(path, key string) (bool, error) {
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	text := strings.ReplaceAll(string(old), "\r", "")
	// Vergleich ueber den Schluessel selbst (Kommentar und Optionen egal)
	newBlob := keyBlob(key)
	for _, line := range strings.Split(text, "\n") {
		if b := keyBlob(line); b != "" && b == newBlob {
			return false, nil
		}
	}
	data := strings.TrimRight(text, "\n")
	if data != "" {
		data += "\n"
	}
	data += key + "\n"
	if _, err := m64agent.ParseKeys([]byte(data)); err != nil {
		// Vorhandene Liste fehlerhaft: neuen Schluessel trotzdem aufnehmen, kaputte Zeilen bleiben (Agent ueberspringt sie).
		say("WARNING: %s contains invalid lines: %v", path, err)
	}
	return true, m64agent.WriteKeysFile(path, []byte(data))
}

// keyBlob liefert "art schluessel" einer authorized_keys-Zeile ("" wenn keiner erkannt).
func keyBlob(line string) string {
	f := strings.Fields(line)
	for i := 0; i+1 < len(f); i++ {
		if strings.HasPrefix(f[i], "ssh-") || strings.HasPrefix(f[i], "ecdsa-") || strings.HasPrefix(f[i], "sk-") {
			return f[i] + " " + f[i+1]
		}
	}
	return ""
}

// copyFile kopiert atomar: neue Datei daneben, dann umbenennen (unter Linux klappt das auch, wenn der Dienst die
// Datei gerade nutzt; unter Windows ist der Dienst vorher angehalten). mode gilt unter Windows nur fuer das
// Schreibschutz-Merkmal.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".monitor64-agent.new-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}
