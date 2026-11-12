package privdrop

import (
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// owner liest Besitzer und Gruppe aus dem Stat-Ergebnis.
func owner(info fs.FileInfo) (uid, gid int, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}

// Drop: Nur beim Start als root (user: "0:0"). Uebergibt dataDir dem Ziel-Benutzer (NODE64_UID/NODE64_GID,
// Standard 65532), legt root ab und startet das Programm per exec neu - als normaler Benutzer greifen dann die
// Datei-Capabilities des Images wieder (Ports unter 1024, ICMP). Zusatzgruppen (group_add, z. B. Docker-Socket)
// bleiben, nur die Gruppe root faellt weg. NODE64_UID=0 laesst Node64 als root laufen. Kehrt nur zurueck, wenn
// nichts zu tun ist oder der Ordner nicht uebergeben werden konnte (dann weiter als root, mit Hinweis).
func Drop(dataDir string) {
	if os.Getuid() != 0 || dataDir == "" {
		return
	}
	uid, gid, err := target(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "node64:", err)
		os.Exit(1)
	}
	if uid == 0 {
		return
	}
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		fmt.Fprintf(os.Stderr, "node64: data dir %s: %v - running as root\n", dataDir, err)
		return
	}
	changed, failed, err := own(dataDir, uid, gid, os.Lchown)
	if err != nil {
		fmt.Fprintf(os.Stderr, "node64: data dir %s could not be handed to %d:%d (%v) - running as root\n", dataDir, uid, gid, err)
		return
	}
	if changed > 0 || failed > 0 {
		fmt.Fprintf(os.Stderr, "node64: started as root - data dir %s handed to %d:%d (%d entries changed, %d skipped), continuing as %d:%d\n",
			dataDir, uid, gid, changed, failed, uid, gid)
	}
	groups, _ := os.Getgroups()
	keep := make([]int, 0, len(groups))
	for _, g := range groups {
		if g != 0 && g != gid {
			keep = append(keep, g)
		}
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "node64: cannot drop root:", err)
		os.Exit(1)
	}
	// Reihenfolge: erst Gruppen, dann GID, zuletzt UID (danach waeren die anderen nicht mehr erlaubt). Ein halber
	// Wechsel darf nicht weiterlaufen.
	runtime.LockOSThread()
	if err := syscall.Setgroups(keep); err != nil {
		fmt.Fprintln(os.Stderr, "node64: cannot drop root (groups):", err)
		os.Exit(1)
	}
	if err := syscall.Setgid(gid); err != nil {
		fmt.Fprintln(os.Stderr, "node64: cannot drop root (gid):", err)
		os.Exit(1)
	}
	if err := syscall.Setuid(uid); err != nil {
		fmt.Fprintln(os.Stderr, "node64: cannot drop root (uid):", err)
		os.Exit(1)
	}
	err = unix.Exec(self, os.Args, os.Environ())
	fmt.Fprintln(os.Stderr, "node64: restart as", uid, "failed:", err)
	os.Exit(1)
}
