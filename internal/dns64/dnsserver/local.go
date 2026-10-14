package dnsserver

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// localSuffixes are names that only exist inside the home network. They are
// sent to the router (if LOCAL_DNS is set) and never to public resolvers.
var localSuffixes = []string{
	".local", ".lan", ".home", ".home.arpa", ".internal", ".localdomain", ".localhost",
	".fritz.box", ".speedport.ip",
	// reverse lookups for private address ranges
	".10.in-addr.arpa", ".168.192.in-addr.arpa", ".254.169.in-addr.arpa", ".127.in-addr.arpa",
	".d.f.ip6.arpa", ".8.e.f.ip6.arpa", ".9.e.f.ip6.arpa", ".a.e.f.ip6.arpa", ".b.e.f.ip6.arpa",
}

func isLocalName(name string) bool {
	if name == "" {
		return false
	}
	if !strings.Contains(name, ".") {
		return true // single label like "nas" or "drucker"
	}
	for _, s := range localSuffixes {
		if strings.HasSuffix(name, s) || name == s[1:] {
			return true
		}
	}
	// 172.16.0.0/12 -> 16..31.172.in-addr.arpa
	if strings.HasSuffix(name, ".172.in-addr.arpa") {
		labels := strings.Split(name, ".")
		if len(labels) >= 4 {
			switch labels[len(labels)-4] {
			case "16", "17", "18", "19", "20", "21", "22", "23",
				"24", "25", "26", "27", "28", "29", "30", "31":
				return true
			}
		}
	}
	return false
}

func remoteIP(a net.Addr) netip.Addr {
	var ip net.IP
	switch v := a.(type) {
	case *net.UDPAddr:
		ip = v.IP
	case *net.TCPAddr:
		ip = v.IP
	}
	addr, _ := netip.AddrFromSlice(ip)
	return addr.Unmap()
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10") // Tailscale & co.

// clientACL accepts private/local addresses plus any address in a subnet
// directly attached to this host (covers public IPv6 prefixes at home).
type clientACL struct {
	extra   []netip.Prefix // from the settings
	mu      sync.RWMutex
	nets    []netip.Prefix
	updated time.Time
}

func newClientACL(extra []netip.Prefix) *clientACL {
	a := &clientACL{extra: extra}
	a.refresh()
	return a
}

func (a *clientACL) allowed(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || cgnat.Contains(ip) {
		return true
	}
	for _, p := range a.extra {
		if p.Contains(ip) {
			return true
		}
	}
	a.mu.RLock()
	stale := time.Since(a.updated) > time.Minute
	nets := a.nets
	a.mu.RUnlock()
	if stale {
		a.refresh()
		a.mu.RLock()
		nets = a.nets
		a.mu.RUnlock()
	}
	for _, p := range nets {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (a *clientACL) refresh() {
	var nets []netip.Prefix
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, ad := range addrs {
			if n, ok := ad.(*net.IPNet); ok {
				if p, err := netip.ParsePrefix(n.String()); err == nil {
					nets = append(nets, p.Masked())
				}
			}
		}
	}
	a.mu.Lock()
	a.nets = nets
	a.updated = time.Now()
	a.mu.Unlock()
}
