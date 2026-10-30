package dnsserver

import (
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"

	"github.com/ipv64net/node64/internal/dns64/querylog"
)

// localSuffixes are names that only exist inside the home network. They are
// sent to the router (if LOCAL_DNS is set) and never to public resolvers.
var localSuffixes = []string{
	".local", ".lan", ".home", ".home.arpa", ".internal", ".localdomain", ".localhost",
	".fritz.box", ".speedport.ip",
	// reverse lookups for private address ranges
	".10.in-addr.arpa", ".168.192.in-addr.arpa", ".254.169.in-addr.arpa", ".127.in-addr.arpa",
	".c.f.ip6.arpa", ".d.f.ip6.arpa", ".8.e.f.ip6.arpa", ".9.e.f.ip6.arpa", ".a.e.f.ip6.arpa", ".b.e.f.ip6.arpa",
	".1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", // ::1
}

// ReasonSearch: das Geraet hat an eine oeffentliche Domain seine Suchdomain gehaengt (z. B. example.com.home.local),
// meist nachdem die eigentliche Anfrage scheiterte (SERVFAIL, keine Adresse). Nur Hinweis im Abfrage-Log.
const ReasonSearch = "search:"

// markSearchSuffix kennzeichnet eine unbeantwortete lokale Anfrage, deren vorderer Teil eine oeffentliche Domain ist.
func markSearchSuffix(name string, e *querylog.Entry) {
	if base := searchBase(name); base != "" && e.Reason == "" {
		e.Reason = ReasonSearch + base
	}
}

// searchBase: "example.com" bei "example.com.home.local" ("" = keine angehaengte Suchdomain erkennbar). Der vordere
// Teil braucht mindestens zwei Labels mit oeffentlicher (ICANN-)Endung, der hintere muss lokal sein.
func searchBase(name string) string {
	if strings.HasPrefix(name, "_") {
		return "" // Dienst-Suche (SRV), z. B. _ldap._tcp.dc._msdcs.<Zone>
	}
	labels := strings.Split(name, ".")
	for i := len(labels) - 1; i >= 2; i-- { // laengster oeffentlicher Teil vorne (example.co.uk, nicht example.co)
		base := strings.Join(labels[:i], ".")
		if !isLocalName(strings.Join(labels[i:], ".")) {
			continue
		}
		if ps, icann := publicsuffix.PublicSuffix(base); icann && ps != base {
			return base
		}
	}
	return ""
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

// ownPTR: Rueckwaertssuche fuer eine globale IPv6-Adresse aus einem angeschlossenen Netz (das eigene /64). Die
// Namen kennt nur der Router, wie bei privaten Adressen; oeffentliche Upstreams sollen sie nicht sehen.
func (a *clientACL) ownPTR(name string, qtype uint16) bool {
	if a == nil || qtype != dns.TypePTR {
		return false
	}
	ip, ok := arpa6(name)
	if !ok {
		return false
	}
	a.mu.RLock()
	nets := a.nets // von allowed() je Anfrage aktuell gehalten
	a.mu.RUnlock()
	for _, p := range nets {
		if p.Addr().Is6() && p.Contains(ip) {
			return true
		}
	}
	return false
}

// arpa6 liest die Adresse aus einem vollstaendigen ip6.arpa-Namen (32 Nibbles).
func arpa6(name string) (netip.Addr, bool) {
	v6, ok := strings.CutSuffix(name, ".ip6.arpa")
	if !ok {
		return netip.Addr{}, false
	}
	p := strings.Split(v6, ".")
	if len(p) != 32 {
		return netip.Addr{}, false
	}
	var b [16]byte
	for i := 0; i < 32; i++ {
		x := p[31-i]
		n, err := strconv.ParseUint(x, 16, 8)
		if err != nil || len(x) != 1 {
			return netip.Addr{}, false
		}
		b[i/2] |= byte(n) << (4 * (1 - i%2))
	}
	return netip.AddrFrom16(b), true
}

// tldQuery: Frage nach einer echten Top-Level-Domain (com, de), die validierende Resolver hinter Node64 fuer die
// Kette stellen (DS, DNSKEY, NS, SOA). Sie geht an die Upstreams, obwohl einzelne Labels sonst lokal sind; Geraetenamen
// wie "nas" oder "media" fragen weiter den Router (Adressen, PTR und alles andere).
func tldQuery(name string, qtype uint16) bool {
	switch qtype {
	case dns.TypeDS, dns.TypeDNSKEY, dns.TypeNS, dns.TypeSOA, dns.TypeCDS, dns.TypeCDNSKEY, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM:
	default:
		return false
	}
	if name == "" || strings.Contains(name, ".") {
		return false
	}
	ps, icann := publicsuffix.PublicSuffix(name)
	return icann && ps == name
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

// privateNets are never routed on the internet (plus loopback, link-local and CGNAT).
var privateNets = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), cgnat,
	netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("::1/128"),
}

// PrivatePrefix reports whether p lies completely inside a private, loopback, link-local or CGNAT range.
func PrivatePrefix(p netip.Prefix) bool {
	p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-unmapBits(p)).Masked()
	for _, q := range privateNets {
		if q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

func unmapBits(p netip.Prefix) int {
	if p.Addr().Is4In6() {
		return 96
	}
	return 0
}

// attachedAllowed: a network on one of our interfaces counts only if it is private or an IPv6 /64 (or
// smaller). A public IPv4 network on a rented server would otherwise open the resolver to the neighbours
// in the data centre.
func attachedAllowed(p netip.Prefix) bool {
	if PrivatePrefix(p) {
		return true
	}
	a := p.Addr()
	return a.Is6() && !a.Is4In6() && p.Bits() >= 64
}

// Refused counts queries from outside the allowed networks (since start).
type Refused struct {
	Count  int64
	LastIP netip.Addr
	LastAt time.Time
}

// clientACL accepts private/local addresses plus any address in a subnet
// directly attached to this host (covers public IPv6 prefixes at home).
type clientACL struct {
	extra   []netip.Prefix // from the settings
	mu      sync.RWMutex
	nets    []netip.Prefix
	updated time.Time

	log     *slog.Logger // nil = no log line
	refused atomic.Int64
	lastMu  sync.Mutex
	last    Refused
	logged  time.Time // last log line (at most one per hour)
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
		if p.Bits() > 0 && p.Contains(ip) {
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
	a.refuse(ip)
	return false
}

// refuse counts a query from outside and logs at most once per hour, so an accidental exposure shows up.
func (a *clientACL) refuse(ip netip.Addr) {
	n := a.refused.Add(1)
	now := time.Now()
	a.lastMu.Lock()
	a.last = Refused{Count: n, LastIP: ip, LastAt: now}
	logIt := a.log != nil && now.Sub(a.logged) >= time.Hour
	if logIt {
		a.logged = now
	}
	a.lastMu.Unlock()
	if logIt {
		a.log.Warn("dns64 refused query from outside the allowed networks", "ip", ip.String(), "count", n)
	}
}

func (a *clientACL) stats() Refused {
	a.lastMu.Lock()
	defer a.lastMu.Unlock()
	r := a.last
	r.Count = a.refused.Load()
	return r
}

func (a *clientACL) refresh() {
	var nets []netip.Prefix
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, ad := range addrs {
			if n, ok := ad.(*net.IPNet); ok {
				if p, err := netip.ParsePrefix(n.String()); err == nil && attachedAllowed(p.Masked()) {
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
