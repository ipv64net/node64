package store

import (
	"os"
	"path/filepath"
	"strings"
)

// PrivateFiles setzt eine SQLite-Datei samt -wal/-shm auf nur-Besitzer (0600 bzw. ohne Rechte fuer Gruppe/andere):
// die Datenbanken enthalten Passwort-Hashes, Tokens, Abfrageprotokolle und verschluesselte Geheimnisse, SQLite legt
// sie aber mit 0644 an. Neue -wal/-shm uebernehmen die Rechte der Datenbank. Fehler zaehlen nicht (z. B. Windows).
func PrivateFiles(path string) {
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if fi, err := os.Stat(p); err == nil && fi.Mode().Perm()&0o077 != 0 {
			_ = os.Chmod(p, fi.Mode().Perm()&^0o077)
		}
	}
}

// privateBackups setzt vorhandene Backups (*.db) im Backup-Verzeichnis auf nur-Besitzer.
func privateBackups(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".db") {
			PrivateFiles(filepath.Join(dir, e.Name()))
		}
	}
}
