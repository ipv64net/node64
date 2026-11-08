package cdn64

import (
	"context"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Dynamische IP-Regeln der Zugriffslisten (GitHub #32): "self" (eigene oeffentliche Adressen der Node: IPv4 und das
// /64 der IPv6), "self4", "self6" und DNS-Namen (z. B. ein DynDNS-Name: A als /32, AAAA als /64). Zu Hause kommen
// Geraete ueber CDN64 mit der oeffentlichen Adresse des Anschlusses herein, nicht mit der privaten - "allow self" laesst
// sie ohne Anmeldung durch. Die Adressen werden zwischengespeichert und im Hintergrund erneuert; die erste Anfrage
// wartet hoechstens dynWait. Achtung: bei DS-Lite/CGNAT teilen sich viele Anschluesse die IPv4 - dann "self6".

const (
	dynSelfTTL = 5 * time.Minute  // eigene Adressen
	dynNameTTL = time.Minute      // DNS-Namen
	dynFailTTL = 30 * time.Second // nach einem Fehler so lange nicht erneut fragen
	dynWait    = 3 * time.Second  // erste Abfrage im Weg der Anfrage
)

var dynNameRe = regexp.MustCompile(`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$`)

// dynRule: Art einer dynamischen Regel ("" = feste Adresse bzw. Netz).
func dynRule(cidr string) string {
	switch c := strings.ToLower(strings.TrimSpace(cidr)); {
	case c == "self" || c == "self4" || c == "self6":
		return c
	case len(c) <= 253 && strings.Contains(c, ".") && dynNameRe.MatchString(c):
		if _, err := netip.ParseAddr(c); err == nil { // a.b.c.d ist keine Name
			return ""
		}
		return "name"
	}
	return ""
}

type dynEntry struct {
	nets []netip.Prefix
	at   time.Time
	ttl  time.Duration
	busy bool
}

// dynAddrs loest dynamische Regeln auf (eine Instanz je Modul, alle Listen teilen den Cache).
type dynAddrs struct {
	publicIP func(ctx context.Context, family string) (string, error) // nil = eigene Adresse unbekannt
	lookup   func(ctx context.Context, host string) ([]netip.Addr, error)
	now      func() time.Time
	mu       sync.Mutex
	cache    map[string]*dynEntry // "self4", "self6", "name:<host>"
}

func newDynAddrs() *dynAddrs {
	return &dynAddrs{now: time.Now, cache: map[string]*dynEntry{},
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}}
}

// matches: passt ip auf die dynamische Regel (kind aus dynRule, cidr = Wert der Regel)?
func (d *dynAddrs) matches(kind, cidr string, ip netip.Addr) bool {
	if d == nil {
		return false
	}
	var keys []string
	switch kind {
	case "self":
		keys = []string{"self4", "self6"}
	case "self4", "self6":
		keys = []string{kind}
	case "name":
		keys = []string{"name:" + strings.ToLower(strings.TrimSpace(cidr))}
	default:
		return false
	}
	for _, k := range keys {
		for _, p := range d.get(k) {
			if p.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// get: Netze zu einem Schluessel - aus dem Cache, abgelaufen im Hintergrund erneuert, beim ersten Mal mit Wartezeit.
func (d *dynAddrs) get(key string) []netip.Prefix {
	d.mu.Lock()
	e := d.cache[key]
	now := d.now()
	if e != nil && now.Sub(e.at) < e.ttl {
		nets := e.nets
		d.mu.Unlock()
		return nets
	}
	if e != nil { // abgelaufen: alten Stand nutzen, im Hintergrund erneuern
		nets := e.nets
		if !e.busy {
			e.busy = true
			go d.refresh(key)
		}
		d.mu.Unlock()
		return nets
	}
	d.cache[key] = &dynEntry{busy: true}
	d.mu.Unlock()
	return d.refresh(key)
}

func (d *dynAddrs) refresh(key string) []netip.Prefix {
	ctx, cancel := context.WithTimeout(context.Background(), dynWait)
	defer cancel()
	nets, ttl := d.resolve(ctx, key)
	d.mu.Lock()
	defer d.mu.Unlock()
	e := d.cache[key]
	if e == nil {
		e = &dynEntry{}
		d.cache[key] = e
	}
	if len(nets) > 0 || e.nets == nil {
		e.nets = nets
	} // Fehler: letzten guten Stand behalten
	e.at, e.ttl, e.busy = d.now(), ttl, false
	return e.nets
}

func (d *dynAddrs) resolve(ctx context.Context, key string) ([]netip.Prefix, time.Duration) {
	switch key {
	case "self4", "self6":
		if d.publicIP == nil {
			return nil, dynFailTTL
		}
		fam := "ipv4"
		if key == "self6" {
			fam = "ipv6"
		}
		s, err := d.publicIP(ctx, fam)
		a, perr := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil || perr != nil {
			return nil, dynFailTTL
		}
		return []netip.Prefix{dynNet(a)}, dynSelfTTL
	}
	host := strings.TrimPrefix(key, "name:")
	addrs, err := d.lookup(ctx, host)
	if err != nil || len(addrs) == 0 {
		return nil, dynFailTTL
	}
	var out []netip.Prefix
	seen := map[netip.Prefix]bool{}
	for _, a := range addrs {
		p := dynNet(a)
		if p.IsValid() && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, dynNameTTL
}

// dynNet: IPv4 als /32, IPv6 als /64 (Geraete eines Anschlusses haben eigene Adressen im selben Netz).
func dynNet(a netip.Addr) netip.Prefix {
	a = a.Unmap().WithZone("")
	if a.Is4() {
		return netip.PrefixFrom(a, 32)
	}
	p, _ := a.Prefix(64)
	return p
}

// SetPublicIP haengt die Abfrage der eigenen oeffentlichen Adresse an (Regel "self", family ipv4 | ipv6).
func (m *Module) SetPublicIP(f func(ctx context.Context, family string) (string, error)) {
	m.dyn.publicIP = f
}
