package cdn64

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Dynamische IP-Regeln der Zugriffslisten (GitHub #32): "self" (eigene oeffentliche Adressen der Node: IPv4 und das
// /64 der IPv6), "self4", "self6" und DNS-Namen (z. B. ein DynDNS-Name: A als /32, AAAA als /64). Zu Hause kommen
// Geraete ueber CDN64 mit der oeffentlichen Adresse des Anschlusses herein, nicht mit der privaten - "allow self" laesst
// sie ohne Anmeldung durch. Die Adressen werden zwischengespeichert und im Hintergrund erneuert; ohne gueltigen Stand
// wartet eine Anfrage je Regel hoechstens dynWait (parallele Anfragen warten auf dieselbe Abfrage). "self" fragt nur
// die Familie der Client-Adresse ab. Bei DS-Lite/CGNAT teilen sich viele Anschluesse die IPv4: meldet DynDNS das,
// nehmen "self" und "self4" keine IPv4 auf (nur das /64 der IPv6).
// Laesst sich eine Regel nicht aufloesen, passt "allow" nicht und "deny" greift (sicher).

const (
	dynSelfTTL = 5 * time.Minute  // eigene Adressen
	dynNameTTL = time.Minute      // DNS-Namen
	dynFailTTL = 30 * time.Second // nach einem Fehler so lange nicht erneut fragen
	dynWait    = 3 * time.Second  // Abfrage im Weg der Anfrage (ohne gueltigen Stand)
	dynKeep    = 2                // letzten guten Stand bei Fehlern hoechstens dynKeep x normale TTL behalten, danach leer
)

var dynNameRe = regexp.MustCompile(`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$`)

// dynNorm: Grundform einer dynamischen Regel (klein, ohne Punkt am Ende eines FQDN).
func dynNorm(cidr string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cidr)), ".")
}

// dynRule: Art einer dynamischen Regel ("" = feste Adresse bzw. Netz).
func dynRule(cidr string) string {
	switch c := dynNorm(cidr); {
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
	at   time.Time     // letzte Abfrage
	ttl  time.Duration // Gueltigkeit der letzten Abfrage
	good time.Time     // letzte erfolgreiche Abfrage (Null = noch keine)
	done chan struct{} // laufende Abfrage (nil = keine), wird danach geschlossen
}

// dynAddrs loest dynamische Regeln auf (eine Instanz je Modul, alle Listen teilen den Cache).
type dynAddrs struct {
	publicIP func(ctx context.Context, family string) (string, error) // nil = eigene Adresse unbekannt
	sharedV4 func(ctx context.Context) string                         // IPv4 geteilt (cgnat, dslite; "" = nein), nil = ohne Befund
	lookup   func(ctx context.Context, host string) ([]netip.Addr, error)
	now      func() time.Time
	log      *slog.Logger
	warned   atomic.Bool // Warnung zur geteilten IPv4 schon geschrieben
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
	hit, _ := d.match(kind, cidr, ip)
	return hit
}

// match: wie matches; known = false, wenn es fuer die Regel keinen gueltigen Stand gibt (Aufloesung gestoert).
func (d *dynAddrs) match(kind, cidr string, ip netip.Addr) (hit, known bool) {
	if d == nil {
		return false, true // ohne Aufloeser gelten dynamische Regeln nicht
	}
	ip = ip.Unmap()
	var key string
	switch kind {
	case "self":
		key = "self6"
		if ip.Is4() { // nur die Familie des Clients abfragen
			key = "self4"
		}
	case "self4", "self6":
		if ip.Is4() != (kind == "self4") { // andere Familie passt nie
			return false, true
		}
		key = kind
	case "name":
		key = "name:" + dynNorm(cidr)
	default:
		return false, true
	}
	nets, known := d.get(key)
	for _, p := range nets {
		if p.Contains(ip) {
			return true, true
		}
	}
	return false, known
}

// dynMaxAge: so lange gilt der letzte gute Stand hoechstens (auch wenn neue Abfragen scheitern).
func dynMaxAge(key string) time.Duration {
	if strings.HasPrefix(key, "name:") {
		return dynKeep * dynNameTTL
	}
	return dynKeep * dynSelfTTL
}

// state: Netze des Eintrags; ok = false ohne gueltigen Stand (nie aufgeloest oder zu alt). Nur mit d.mu.
func (e *dynEntry) state(key string, now time.Time) ([]netip.Prefix, bool) {
	if e.good.IsZero() || now.Sub(e.good) >= dynMaxAge(key) {
		return nil, false
	}
	return e.nets, true
}

// get: Netze zu einem Schluessel - aus dem Cache, abgelaufen im Hintergrund erneuert; ohne gueltigen Stand wartet die
// Anfrage hoechstens dynWait auf die (gemeinsame) Abfrage. ok = false: kein gueltiger Stand.
func (d *dynAddrs) get(key string) ([]netip.Prefix, bool) {
	d.mu.Lock()
	e := d.cache[key]
	if e == nil {
		e = &dynEntry{}
		d.cache[key] = e
	}
	now := d.now()
	if e.done == nil && (e.at.IsZero() || now.Sub(e.at) >= e.ttl) { // abgelaufen: neu abfragen
		e.done = make(chan struct{})
		go d.refresh(key, e, e.done)
	}
	nets, ok := e.state(key, now)
	done := e.done
	d.mu.Unlock()
	if ok || done == nil { // gueltiger (ggf. alter) Stand bzw. eben gescheitert: nicht warten
		return nets, ok
	}
	t := time.NewTimer(dynWait)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return e.state(key, d.now())
}

// refresh fragt im Hintergrund ab und schliesst danach done.
func (d *dynAddrs) refresh(key string, e *dynEntry, done chan struct{}) {
	ctx, cancel := context.WithTimeout(context.Background(), dynWait)
	defer cancel()
	nets, ttl, ok := d.resolve(ctx, key)
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if ok {
		e.nets, e.good = nets, now
	} else if _, valid := e.state(key, now); !valid { // Fehler: letzten guten Stand nur bis dynMaxAge behalten
		e.nets = nil
	}
	e.at, e.ttl, e.done = now, ttl, nil
	close(done)
}

// resolve fragt einen Schluessel ab; ok = false bei einem Fehler.
func (d *dynAddrs) resolve(ctx context.Context, key string) ([]netip.Prefix, time.Duration, bool) {
	switch key {
	case "self4", "self6":
		if d.publicIP == nil {
			return nil, dynFailTTL, false
		}
		fam := "ipv4"
		if key == "self6" {
			fam = "ipv6"
		} else if d.shared(ctx) != "" { // DS-Lite/CGNAT: die IPv4 teilen sich viele Anschluesse
			return nil, dynSelfTTL, true
		}
		s, err := d.publicIP(ctx, fam)
		a, perr := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil || perr != nil {
			return nil, dynFailTTL, false
		}
		return []netip.Prefix{dynNet(a)}, dynSelfTTL, true
	}
	host := strings.TrimPrefix(key, "name:")
	addrs, err := d.lookup(ctx, host)
	if err != nil || len(addrs) == 0 {
		return nil, dynFailTTL, false
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
	return out, dynNameTTL, true
}

// shared: Art der geteilten IPv4 laut DynDNS ("" = eigene IPv4 bzw. ohne Befund); warnt einmal im Log.
func (d *dynAddrs) shared(ctx context.Context) string {
	if d.sharedV4 == nil {
		return ""
	}
	kind := d.sharedV4(ctx)
	if kind != "" && d.log != nil && d.warned.CompareAndSwap(false, true) {
		d.log.Warn("access lists: rule self ignores IPv4, the connection shares its IPv4 (use self6)", "kind", kind)
	}
	return kind
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

// SetSharedIPv4 haengt die Abfrage an, ob sich der Anschluss die IPv4 teilt (Befund von DynDNS: cgnat, dslite;
// "" = nein). Dann nehmen "self" und "self4" keine IPv4 auf.
func (m *Module) SetSharedIPv4(f func(ctx context.Context) string) {
	m.dyn.sharedV4, m.dyn.log = f, m.log
}
