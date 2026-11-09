package m64linux

import (
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/m64proto"
)

// Paketverwalter. Name = Updates.Manager; aptcheck ist apt mit /usr/lib/update-notifier/apt-check (Ubuntu).
const (
	mgrAptCheck = "aptcheck"
	mgrApt      = "apt"
	mgrDnf      = "dnf"
	mgrYum      = "yum"
	mgrZypper   = "zypper"
	mgrPacman   = "pacman"
	mgrApk      = "apk"
	mgrOpkg     = "opkg"
)

const aptCheckPath = "/usr/lib/update-notifier/apt-check"

// ParseUpdates wertet die Ausgaben eines Paketverwalters aus: list = Liste der Updates, sec = Liste der
// Sicherheitsupdates (nur dnf/yum/zypper; sonst nil).
func ParseUpdates(mgr string, list, sec []byte) (*m64proto.Updates, error) {
	u := &m64proto.Updates{Manager: mgr}
	switch mgr {
	case mgrAptCheck:
		u.Manager = mgrApt
		p, s, err := ParseAptCheck(list)
		if err != nil {
			return nil, err
		}
		u.Pending, u.Security = p, s
	case mgrApt:
		u.Pending, u.Security = ParseAptSim(list)
	case mgrDnf, mgrYum:
		u.Pending = ParseDnfCheckUpdate(list)
		u.Security = ParseDnfSecurity(sec)
	case mgrZypper:
		u.Pending = ParseZypperUpdates(list)
		u.Security = ParseZypperSecurity(sec)
	case mgrPacman:
		u.Pending = countLines(list, func(f []string, ln string) bool {
			return len(f) >= 2 && !strings.HasPrefix(ln, "::") && !strings.Contains(ln, "[ignored]") &&
				!strings.HasPrefix(f[0], "error") && !strings.HasPrefix(f[0], "warning")
		})
	case mgrApk:
		u.Pending = countLines(list, func(_ []string, ln string) bool { return strings.Contains(ln, "upgradable from") })
	case mgrOpkg:
		u.Pending = countLines(list, func(f []string, _ string) bool { return len(f) >= 5 && f[1] == "-" && f[3] == "-" })
	default:
		return nil, errFormat
	}
	return u, nil
}

func countLines(b []byte, ok func(f []string, ln string) bool) int {
	n := 0
	for _, ln := range lines(b) {
		if f := strings.Fields(ln); len(f) > 0 && ok(f, ln) {
			n++
		}
	}
	return n
}

// ParseAptCheck liest die Ausgabe von apt-check ("<Updates>;<Sicherheitsupdates>", steht auf stderr).
func ParseAptCheck(b []byte) (pending, security int, err error) {
	for _, ln := range lines(b) {
		a, c, ok := strings.Cut(strings.TrimSpace(ln), ";")
		if !ok {
			continue
		}
		p, err1 := strconv.Atoi(a)
		s, err2 := strconv.Atoi(c)
		if err1 == nil && err2 == nil && p >= 0 && s >= 0 {
			return p, s, nil
		}
	}
	return 0, 0, errFormat
}

// aptSimArgs ist die Simulation fuer apt (Agent und Skript): dist-upgrade statt upgrade, damit auch
// zurueckgehaltene Pakete ("kept back", brauchen neue Abhaengigkeiten) zaehlen. Nur Simulation (-s), ohne Sperre.
var aptSimArgs = []string{"-s", "-o", "Debug::NoLocking=1", "dist-upgrade"}

// ParseAptSim zaehlt die "Inst"-Zeilen von "apt-get -s dist-upgrade", die ein vorhandenes Paket erneuern
// ("Inst paket [alte Version] (neue ...)"); neu hinzukommende Abhaengigkeiten (ohne "[...]") zaehlen nicht.
// Sicherheitsupdates an der Quelle "*-security".
func ParseAptSim(b []byte) (pending, security int) {
	for _, ln := range lines(b) {
		if !strings.HasPrefix(ln, "Inst ") {
			continue
		}
		if f := strings.Fields(ln); len(f) < 3 || !strings.HasPrefix(f[2], "[") {
			continue
		}
		pending++
		if strings.Contains(strings.ToLower(ln), "security") {
			security++
		}
	}
	return
}

// ParseDnfCheckUpdate zaehlt die Pakete aus "dnf -q check-update" (bzw. yum); Obsoletes zaehlen nicht.
func ParseDnfCheckUpdate(b []byte) int {
	ls := lines(b)
	n := 0
	for i, ln := range ls {
		if strings.HasPrefix(ln, "Obsoleting") {
			break
		}
		if ln == "" || ln[0] == ' ' || ln[0] == '\t' {
			continue
		}
		f := strings.Fields(ln)
		if !strings.Contains(f[0], ".") || strings.HasSuffix(f[0], ":") {
			continue
		}
		switch {
		case len(f) >= 3:
			n++
		case len(f) == 1 && i+1 < len(ls) && len(ls[i+1]) > 0 && (ls[i+1][0] == ' ' || ls[i+1][0] == '\t'):
			n++ // langer Name, Rest in der naechsten Zeile
		}
	}
	return n
}

// ParseDnfSecurity zaehlt die Pakete aus "dnf -q updateinfo list --security" (dnf4: "ID Wichtigkeit/Sec. Paket",
// dnf5: "ID security Wichtigkeit Paket Datum"); jedes Paket einmal.
func ParseDnfSecurity(b []byte) int {
	seen := map[string]bool{}
	for _, ln := range lines(b) {
		f := strings.Fields(ln)
		if len(f) < 3 || !(strings.Contains(f[1], "Sec.") || strings.EqualFold(f[1], "security")) {
			continue
		}
		for _, p := range f[2:] {
			if strings.Contains(p, ".") && strings.Contains(p, "-") {
				seen[p] = true
				break
			}
		}
		if len(seen) >= 100000 {
			break
		}
	}
	return len(seen)
}

// zypperTable liest eine zypper-Tabelle ("a | b | c") und liefert Kopf und Zeilen.
func zypperTable(b []byte) (head []string, rows [][]string) {
	for _, ln := range lines(b) {
		if !strings.Contains(ln, "|") || strings.HasPrefix(strings.TrimSpace(ln), "--") {
			continue
		}
		cols := strings.Split(ln, "|")
		for i := range cols {
			cols[i] = strings.TrimSpace(cols[i])
		}
		if head == nil {
			head = cols
			continue
		}
		rows = append(rows, cols)
	}
	return
}

func colIndex(head []string, name string) int {
	for i, h := range head {
		if strings.EqualFold(h, name) {
			return i
		}
	}
	return -1
}

// ParseZypperUpdates zaehlt "zypper -n -q list-updates" (Zeilen mit Status "v").
func ParseZypperUpdates(b []byte) int {
	_, rows := zypperTable(b)
	n := 0
	for _, r := range rows {
		if len(r) > 1 && r[0] == "v" {
			n++
		}
	}
	return n
}

// ParseZypperSecurity zaehlt "zypper -n -q list-patches --category security" (Status "needed").
func ParseZypperSecurity(b []byte) int {
	head, rows := zypperTable(b)
	ci, si := colIndex(head, "Category"), colIndex(head, "Status")
	if si < 0 {
		return 0
	}
	n := 0
	for _, r := range rows {
		if si >= len(r) || r[si] != "needed" {
			continue
		}
		if ci >= 0 && ci < len(r) && r[ci] != "security" {
			continue
		}
		n++
	}
	return n
}
