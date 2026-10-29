package certs

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/ipv64net/node64/internal/ipv64api"
)

// DNSAPI sind die DNS-Zugriffe bei ipv64 (Domains des Accounts, TXT-Records fuer DNS-01).
type DNSAPI interface {
	Ready(ctx context.Context) bool // API-Key eingetragen
	Domains(ctx context.Context) ([]string, error)
	AddTXT(ctx context.Context, domain, prefix, value string) error
	DeleteTXT(ctx context.Context, domain, prefix, value string) error
}

// IPv64 ist DNSAPI ueber den zentralen API-Key.
func IPv64(k *ipv64api.Key) DNSAPI { return ipv64DNS{k} }

type ipv64DNS struct{ k *ipv64api.Key }

func (d ipv64DNS) Ready(ctx context.Context) bool { return d.k != nil && d.k.Get(ctx) != "" }

func (d ipv64DNS) Domains(ctx context.Context) ([]string, error) {
	list, err := d.k.Client().Domains(ctx, d.k.Get(ctx))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(list))
	for _, x := range list {
		out = append(out, strings.ToLower(x.Name))
	}
	return out, nil
}

func (d ipv64DNS) AddTXT(ctx context.Context, domain, prefix, value string) error {
	_, err := d.k.Client().AddRecord(ctx, d.k.Get(ctx), domain, "TXT", prefix, value)
	return err
}

func (d ipv64DNS) DeleteTXT(ctx context.Context, domain, prefix, value string) error {
	return d.k.Client().DeleteRecordByContent(ctx, d.k.Get(ctx), domain, "TXT", prefix, value)
}

// ipv64Target: ipv64-Domain (laengste passende) und Praefix des TXT-Records fuer einen Namen (Wildcard wie
// sein Elternname).
func (m *Manager) ipv64Target(ctx context.Context, name string) (zone, prefix string, err error) {
	base := strings.TrimPrefix(name, "*.")
	domains, err := m.d.DNS.Domains(ctx)
	if err != nil {
		return "", "", fmt.Errorf("ipv64 domains: %w", err)
	}
	for _, d := range domains {
		if (base == d || strings.HasSuffix(base, "."+d)) && len(d) > len(zone) {
			zone = d
		}
	}
	if zone == "" {
		return "", "", fmt.Errorf("%s is not in a domain of the ipv64 account", name)
	}
	prefix = "_acme-challenge"
	if base != zone {
		prefix += "." + strings.TrimSuffix(base, "."+zone)
	}
	return zone, prefix, nil
}

// aliasTarget: wohin der CNAME _acme-challenge.<name> zeigen muss (Praefix des TXT-Records bei ipv64).
func aliasTarget(zone, prefix string) (txtPrefix, fqdn string) {
	txtPrefix = "_acme-challenge"
	if prefix != "" {
		txtPrefix += "." + prefix
	}
	return txtPrefix, txtPrefix + "." + zone
}

// AliasCNAME: der CNAME, den der Nutzer bei seinem DNS-Anbieter anlegen muss (fuer die Oberflaeche).
func AliasCNAME(name, zone, prefix string) (from, to string) {
	_, to = aliasTarget(strings.ToLower(zone), strings.ToLower(prefix))
	return "_acme-challenge." + strings.TrimPrefix(strings.ToLower(name), "*."), to
}

// checkAlias: der CNAME fuer jeden Namen ist gesetzt.
func (m *Manager) checkAlias(ctx context.Context, c *Cert) error {
	_, want := aliasTarget(c.AliasZone, c.AliasPrefix)
	for _, n := range c.Names {
		from, _ := AliasCNAME(n, c.AliasZone, c.AliasPrefix)
		got, err := m.cnameOf(ctx, from)
		got = strings.TrimSuffix(strings.ToLower(got), ".")
		if err != nil || got != want {
			found := got
			if found == "" {
				found = "none"
			}
			return fmt.Errorf("CNAME %s -> %s missing (found: %s)", from, want, found)
		}
	}
	return nil
}

// lookupCNAME ueber oeffentliche Resolver (nicht der eigene: im Heimnetz koennte er anders antworten oder sperren).
func lookupCNAME(ctx context.Context, name string) (string, error) {
	ans, err := publicLookup(ctx, name, dns.TypeCNAME)
	if err != nil {
		return "", err
	}
	for _, rr := range ans {
		if cn, ok := rr.(*dns.CNAME); ok {
			return cn.Target, nil
		}
	}
	return "", nil
}

var (
	waitDNS  = 8 * time.Minute // ipv64 meist Sekunden, manche Anbieter (netcup) Minuten
	txtEvery = 3 * time.Second // Abstand der Runden
)

// nameserver: ein zustaendiger Nameserver der Zone mit seinen Adressen (ip:53, IPv4 und IPv6).
type nameserver struct {
	Name  string
	Addrs []string
}

// lookupNS findet die Nameserver der Zone (Domain oder eine Ebene darueber): je Nameserver seine Adressen als
// ip:53, IPv4 und IPv6 (wer nur eine Familie nach aussen hat, erreicht ihn trotzdem). Eine Ebene mit CNAME zaehlt
// nicht: der Resolver folgt ihm sonst und liefert die Nameserver des Ziels (z. B. ein Name, der auf ein CDN zeigt).
// Erst ueber den System-Resolver; sperrt oder faelscht der (Blockliste, 0.0.0.0) oder antwortet nicht, ueber
// oeffentliche Resolver.
var lookupNS = func(ctx context.Context, domain string) ([]nameserver, error) {
	out, err := findNS(ctx, domain, systemNS)
	if err == nil {
		return out, nil
	}
	out, perr := findNS(ctx, domain, publicNS)
	if perr == nil {
		return out, nil
	}
	return nil, fmt.Errorf("no nameserver for %s (system resolver: %v; public resolvers: %v)", domain, err, perr)
}

// nsLookup: die Abfragen fuer findNS (System-Resolver oder oeffentliche Resolver).
type nsLookup struct {
	cname func(ctx context.Context, name string) string // Ziel, "" = kein CNAME
	ns    func(ctx context.Context, name string) ([]string, error)
	ip    func(ctx context.Context, fam, host string) []netip.Addr
}

var systemNS = nsLookup{
	cname: func(ctx context.Context, name string) string {
		cn, err := net.DefaultResolver.LookupCNAME(ctx, name)
		if err != nil {
			return ""
		}
		return cn
	},
	ns: func(ctx context.Context, name string) ([]string, error) {
		ns, err := net.DefaultResolver.LookupNS(ctx, name)
		var out []string
		for _, n := range ns {
			out = append(out, n.Host)
		}
		return out, err
	},
	ip: func(ctx context.Context, fam, host string) []netip.Addr {
		ips, _ := net.DefaultResolver.LookupNetIP(ctx, fam, host)
		return ips
	},
}

var publicNS = nsLookup{
	cname: func(ctx context.Context, name string) string {
		cn, _ := lookupCNAME(ctx, name)
		return cn
	},
	ns: func(ctx context.Context, name string) ([]string, error) {
		ans, err := publicLookup(ctx, name, dns.TypeNS)
		var out []string
		for _, rr := range ans {
			if n, ok := rr.(*dns.NS); ok {
				out = append(out, n.Ns)
			}
		}
		return out, err
	},
	ip: func(ctx context.Context, fam, host string) []netip.Addr {
		qt := dns.TypeA
		if fam == "ip6" {
			qt = dns.TypeAAAA
		}
		ans, _ := publicLookup(ctx, host, qt)
		var out []netip.Addr
		for _, rr := range ans {
			switch r := rr.(type) {
			case *dns.A:
				if a, ok := netip.AddrFromSlice(r.A); ok {
					out = append(out, a)
				}
			case *dns.AAAA:
				if a, ok := netip.AddrFromSlice(r.AAAA); ok {
					out = append(out, a)
				}
			}
		}
		return out
	},
}

func findNS(ctx context.Context, domain string, l nsLookup) ([]nameserver, error) {
	name := domain
	var hosts []string
	var lastErr error
	for strings.Count(name, ".") >= 1 {
		if cn := l.cname(ctx, name); cn == "" || strings.EqualFold(strings.TrimSuffix(cn, "."), name) {
			ns, err := l.ns(ctx, name)
			if err != nil {
				lastErr = err
			}
			if len(ns) > 0 {
				for _, n := range ns {
					hosts = append(hosts, strings.TrimSuffix(n, "."))
				}
				break
			}
		}
		name = name[strings.Index(name, ".")+1:]
	}
	var out []nameserver
	for _, h := range hosts {
		var addrs []string
		for _, fam := range []string{"ip4", "ip6"} { // IPv4 zuerst: Docker-Bridges haben oft kein IPv6
			for _, ip := range l.ip(ctx, fam, h) {
				if usableAddr(ip) { // Sperrantwort (0.0.0.0, ::) ueberspringen
					addrs = append(addrs, net.JoinHostPort(ip.Unmap().String(), "53"))
					break
				}
			}
		}
		if len(addrs) > 0 {
			out = append(out, nameserver{Name: h, Addrs: addrs})
		}
	}
	if len(out) == 0 {
		if lastErr == nil && len(hosts) > 0 {
			lastErr = errors.New("nameserver addresses blocked or missing (" + strings.Join(hosts, ", ") + ")")
		} else if lastErr == nil {
			lastErr = errors.New("no NS records")
		}
		return nil, errors.New(shortErr(lastErr))
	}
	return out, nil
}

// Stand eines Nameservers bei der TXT-Pruefung (der hoechste zaehlt).
type txtState int

const (
	txtUnreachable txtState = iota // keine Antwort (Zeitueberschreitung, Port 53 gesperrt)
	txtNotAuth                     // Antwort ohne AA: ein Resolver unterwegs antwortet statt des Nameservers (Port 53 umgeleitet)
	txtMissing                     // zustaendige Antwort, aber ohne den Wert (noch nicht da)
	txtFound
)

// publicCheck: ueber oeffentliche Resolver (DoH ueber feste IPs bei mehreren Betreibern, dazu Port 53) pruefen, wenn
// kein Nameserver direkt antwortet; Fehler = keiner erreichbar. Austauschbar fuer Tests.
var publicCheck = publicTXT

// directRounds: so viele Runden ohne zustaendige Antwort, dann zusaetzlich ueber oeffentliche Resolver pruefen.
const directRounds = 3

// stableRounds: so viele Runden hintereinander muessen alle erreichbaren Adressen aller Nameserver den Wert liefern.
// Ein Nameserver-Verbund mit Cache (z. B. PowerDNS hinter einem Verteiler) liefert kurz nach dem Anlegen abwechselnd
// alt/leer und neu; ein einzelner Treffer genuegte nicht – die CA fragte von mehreren Standorten und fand nichts bzw.
// den alten Wert (Test 2026-10-29 mit ns1/ns2.ipv64.net). Variable fuer Tests.
var stableRounds = 3

// waitTXT wartet, bis alle Nameserver der Zone den TXT-Record ausliefern (ipv64 schreibt nach einigen Sekunden).
// Erreicht die Node keinen Nameserver direkt (Port 53 nach aussen gesperrt oder auf einen eigenen Resolver
// umgeleitet, in Heimnetzen haeufig), genuegt es, wenn oeffentliche Resolver ueber DoH den Wert liefern - die fragen
// die Nameserver selbst, wie spaeter Let's Encrypt.
func waitTXT(ctx context.Context, zone, fqdn, want string) error {
	servers, err := lookupNS(ctx, zone)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(waitDNS)
	var details []string
	var pubErr error
	stable := 0
	for round := 1; ; round++ {
		ok, auth := 0, false
		details = details[:0]
		// ein Nameserver gilt, wenn eine seiner Adressen (v4 oder v6) liefert und keine erreichbare Adresse noch ohne
		// den Wert antwortet (nicht erreichbare Familien zaehlen nicht, z. B. kein IPv6)
		for _, ns := range servers {
			st, detail, missing := txtUnreachable, "", ""
			for _, a := range ns.Addrs {
				s, d := queryTXT(ctx, a, fqdn, want)
				if s >= st {
					st, detail = s, d
				}
				if s == txtMissing && missing == "" {
					missing = d
				}
			}
			if st >= txtMissing {
				auth = true
			}
			if st == txtFound && missing == "" {
				ok++
			} else {
				if missing != "" {
					detail = missing
				}
				details = append(details, ns.Name+": "+detail)
			}
		}
		if ok == len(servers) {
			if stable++; stable >= stableRounds {
				return nil
			}
		} else {
			stable = 0
		}
		if !auth && round >= directRounds {
			found, err := publicCheck(ctx, fqdn, want)
			if found {
				return nil
			}
			pubErr = err
		}
		if time.Now().After(deadline) {
			msg := fmt.Sprintf("TXT record %s not visible on %d of %d nameservers after %s (%s)", fqdn, len(servers)-ok, len(servers), waitDNS, strings.Join(details, "; "))
			if !auth {
				msg += "; the nameservers cannot be queried directly from here (outgoing port 53 blocked or redirected to a local resolver?)"
				if pubErr != nil {
					msg += "; no public resolver reachable either (" + pubErr.Error() + ") – a firewall or DNS filter blocks them: allow one of them or enter a reachable resolver under Certificates → DNS-01 check"
				} else {
					msg += "; public resolvers are reachable but do not show the record either"
				}
			}
			return errors.New(msg)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(txtEvery):
		}
	}
}

// queryTXT fragt einen Nameserver direkt (ohne Rekursion), erst UDP, bei Fehler, abgeschnittener oder nicht
// zustaendiger Antwort noch einmal per TCP (manche Netze leiten nur UDP 53 um).
func queryTXT(ctx context.Context, server, fqdn, want string) (txtState, string) {
	st, detail := queryTXTNet(ctx, "udp", server, fqdn, want)
	if st == txtFound || st == txtMissing {
		return st, detail
	}
	if st2, d2 := queryTXTNet(ctx, "tcp", server, fqdn, want); st2 >= st {
		return st2, d2
	}
	return st, detail
}

func queryTXTNet(ctx context.Context, network, server, fqdn, want string) (txtState, string) {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(fqdn), dns.TypeTXT)
	q.RecursionDesired = false
	c := &dns.Client{Net: network, Timeout: 3 * time.Second}
	r, _, err := c.ExchangeContext(ctx, q, server)
	if err != nil || r == nil {
		if err == nil {
			err = errors.New("no answer")
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return txtUnreachable, "no answer (timeout)"
		}
		return txtUnreachable, err.Error()
	}
	if r.Truncated {
		return txtUnreachable, "truncated answer"
	}
	if !r.Authoritative {
		return txtNotAuth, "answer not authoritative (" + dns.RcodeToString[r.Rcode] + ", port 53 redirected?)"
	}
	if r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError {
		return txtUnreachable, dns.RcodeToString[r.Rcode]
	}
	if txtIn(r, want) {
		return txtFound, ""
	}
	if r.Rcode == dns.RcodeNameError {
		return txtMissing, "record not there yet (NXDOMAIN)"
	}
	return txtMissing, "record not there yet"
}

func txtIn(r *dns.Msg, want string) bool {
	for _, rr := range r.Answer {
		if t, ok := rr.(*dns.TXT); ok && strings.Join(t.Txt, "") == want {
			return true
		}
	}
	return false
}
