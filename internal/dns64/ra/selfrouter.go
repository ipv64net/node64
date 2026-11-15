package ra

import (
	"os"
	"strconv"
	"strings"
)

// Router-Dienst auf demselben Host (radvd, odhcpd, dnsmasq): Er sendet von derselben Link-Local-Adresse wie Node64,
// ein eigenes RA (Router-Lifetime 0) naehme den Geraeten dessen Default-Route. Sein RA kommt oft erst nach Minuten
// (radvd/odhcpd alle bis zu 600 s; die eigene RS beim Start erreicht ihn nicht). Erkennbar ist er aber sofort: er
// tritt auf der Schnittstelle der Gruppe aller Router (ff02::2) bei, sichtbar in /proc/net/igmp6 (auch ohne Zugriff
// auf seine Prozesse). Mitglieder sonst: der eigene Sender und der Kernel bei IPv6-Forwarding.

const allRoutersHex = "ff020000000000000000000000000002"

// hostRouter: auf iface hoert ausser dem eigenen Sender (joined) und dem Kernel noch jemand auf RS (Variable fuer Tests).
var hostRouter = func(iface string, joined bool) bool {
	b, err := os.ReadFile("/proc/net/igmp6")
	if err != nil || iface == "" || iface == ".." || strings.Contains(iface, "/") {
		return false
	}
	fw, _ := os.ReadFile("/proc/sys/net/ipv6/conf/" + iface + "/forwarding")
	f := strings.TrimSpace(string(fw))
	return othersListen(routerListeners(string(b), iface), joined, f != "" && f != "0")
}

// routerListeners: Spalte users der Gruppe ff02::2 auf iface in /proc/net/igmp6 (0 = keine Mitgliedschaft).
func routerListeners(igmp6, iface string) int {
	for _, l := range strings.Split(igmp6, "\n") {
		if f := strings.Fields(l); len(f) >= 4 && f[1] == iface && f[2] == allRoutersHex {
			n, _ := strconv.Atoi(f[3])
			return n
		}
	}
	return 0
}

// othersListen: Mitglieder ohne den eigenen Sender und den Kernel (beim Forwarding tritt er selbst bei).
func othersListen(users int, joined, forwarding bool) bool {
	if joined {
		users--
	}
	if forwarding {
		users--
	}
	return users > 0
}
