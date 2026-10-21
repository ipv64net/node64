package netstat

import (
	"bufio"
	"encoding/hex"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// Listener ist ein Socket, der im Netz-Namensraum des Prozesses (im Container: dem des Containers, mit
// --network host: dem des Hosts) auf Verbindungen wartet: TCP im Zustand LISTEN, UDP ohne feste Gegenstelle.
type Listener struct {
	Proto string     // tcp oder udp
	Addr  netip.Addr // 0.0.0.0 bzw. :: = alle Adressen (bleibt beim Unmap erhalten: Familie des Sockets)
	Port  int
}

// procRoot ist /proc (Tests: eigenes Verzeichnis).
var procRoot = "/proc"

// Listeners liest /proc/net/tcp, tcp6, udp und udp6 (nur Linux). ok = false, wenn keine Datei lesbar ist (andere
// Systeme): dann ist unbekannt, welche Ports offen sind.
func Listeners() (list []Listener, ok bool) {
	for _, f := range []struct{ file, proto string }{{"tcp", "tcp"}, {"tcp6", "tcp"}, {"udp", "udp"}, {"udp6", "udp"}} {
		fh, err := os.Open(procRoot + "/net/" + f.file)
		if err != nil {
			continue
		}
		ok = true
		list = append(list, parseProcNet(fh, f.proto)...)
		_ = fh.Close()
	}
	return list, ok
}

// parseProcNet liest eine Tabelle im Format von /proc/net/tcp (Kopfzeile, dann "sl local rem st …").
func parseProcNet(r io.Reader, proto string) []Listener {
	var out []Listener
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first { // Kopfzeile
			first = false
			continue
		}
		fs := strings.Fields(sc.Text())
		if len(fs) < 4 {
			continue
		}
		st := fs[3]
		if (proto == "tcp" && st != "0A") || (proto == "udp" && st != "07") { // 0A = LISTEN, 07 = nicht verbunden
			continue
		}
		addr, port, ok := parseHexAddr(fs[1])
		if !ok {
			continue
		}
		out = append(out, Listener{Proto: proto, Addr: addr, Port: port})
	}
	return out
}

// parseHexAddr: "0100007F:1F90" (IPv4) bzw. 32 Hex-Zeichen (IPv6), je 32-Bit-Wort in Byte-Reihenfolge des Rechners
// (little endian), Port big endian.
func parseHexAddr(s string) (netip.Addr, int, bool) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.Addr{}, 0, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	b, err := hex.DecodeString(h)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return netip.Addr{}, 0, false
	}
	for i := 0; i < len(b); i += 4 { // je Wort umdrehen
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	addr, _ := netip.AddrFromSlice(b)
	return addr.Unmap(), int(port), true
}

// Covers: lauscht der Socket fuer proto/port auf bind ("" bzw. 0.0.0.0/:: = alle Adressen)? 0.0.0.0 gilt nur fuer
// IPv4-Adressen, :: fuer IPv6 und IPv4 (Go lauscht auf :: fuer beide Familien).
func (l Listener) Covers(proto string, bind string, port int) bool {
	if l.Proto != proto || l.Port != port {
		return false
	}
	b := strings.Trim(bind, "[]")
	if b == "" || b == "0.0.0.0" || b == "::" {
		return true // eine bestimmte Adresse zaehlt fuer "alle" (zumindest dort offen)
	}
	a, err := netip.ParseAddr(b)
	if l.Addr.IsUnspecified() {
		return err != nil || l.Addr.Is6() || a.Unmap().Is4()
	}
	return err == nil && a.Unmap() == l.Addr
}

// Privileges: darf der Prozess Ports unter 1024 oeffnen? (nur Linux, sonst Known = false)
type Privileges struct {
	Known       bool // /proc lesbar
	Root        bool // effektive UID 0 (nur Anzeige: Ports unter 1024 haengen an CapNetBind, nicht an der UID)
	CapNetBind  bool // Faehigkeit cap_net_bind_service in CapEff (root hat sie normalerweise, z. B. per setcap im Image)
	UnprivStart int  // net.ipv4.ip_unprivileged_port_start (-1 = unbekannt; Docker setzt im Container meist 0)
	Container   bool // laeuft in einem Container (/.dockerenv bzw. /run/.containerenv)
}

// LowPortOK: darf port geoeffnet werden (ab 1024 immer)?
func (p Privileges) LowPortOK(port int) bool {
	return port >= 1024 || p.CapNetBind || (p.UnprivStart >= 0 && port >= p.UnprivStart)
}

// ReadPrivileges liest UID, Faehigkeiten und die Grenze fuer Ports ohne Rechte.
func ReadPrivileges() Privileges {
	p := Privileges{UnprivStart: -1}
	if raw, err := os.ReadFile(procRoot + "/self/status"); err == nil {
		p.Known = true
		for _, line := range strings.Split(string(raw), "\n") {
			k, v, _ := strings.Cut(line, ":")
			v = strings.TrimSpace(v)
			switch k {
			case "Uid": // real, effektiv, …
				if f := strings.Fields(v); len(f) > 1 {
					p.Root = f[1] == "0"
				}
			case "CapEff":
				if n, err := strconv.ParseUint(v, 16, 64); err == nil {
					p.CapNetBind = n&(1<<10) != 0 // CAP_NET_BIND_SERVICE = 10
				}
			}
		}
	}
	if raw, err := os.ReadFile(procRoot + "/sys/net/ipv4/ip_unprivileged_port_start"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil {
			p.UnprivStart = n
		}
	}
	for _, f := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(f); err == nil {
			p.Container = true
		}
	}
	return p
}
