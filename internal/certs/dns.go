package certs

import (
	"context"
	"errors"
	"fmt"
	"net"
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

// oeffentliche Resolver fuer die CNAME-Pruefung (nicht der eigene: im Heimnetz koennte er anders antworten)
var publicResolvers = []string{"1.1.1.1:53", "9.9.9.9:53", "[2606:4700:4700::1111]:53", "[2620:fe::fe]:53"}

func lookupCNAME(ctx context.Context, name string) (string, error) {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeCNAME)
	c := &dns.Client{Timeout: 4 * time.Second}
	var lastErr error = errors.New("no resolver reachable")
	for _, s := range publicResolvers {
		r, _, err := c.ExchangeContext(ctx, q, s)
		if err != nil || r == nil {
			lastErr = err
			continue
		}
		for _, rr := range r.Answer {
			if cn, ok := rr.(*dns.CNAME); ok {
				return cn.Target, nil
			}
		}
		return "", nil
	}
	return "", lastErr
}

const waitDNS = 8 * time.Minute // ipv64 meist Sekunden, manche Anbieter (netcup) Minuten

// lookupNS findet die Nameserver der Zone (Domain oder eine Ebene darueber), als ip:53.
var lookupNS = func(ctx context.Context, domain string) ([]string, error) {
	name := domain
	var hosts []string
	for strings.Count(name, ".") >= 1 {
		if ns, err := net.DefaultResolver.LookupNS(ctx, name); err == nil && len(ns) > 0 {
			for _, n := range ns {
				hosts = append(hosts, strings.TrimSuffix(n.Host, "."))
			}
			break
		}
		name = name[strings.Index(name, ".")+1:]
	}
	var out []string
	for _, h := range hosts {
		for _, fam := range []string{"ip4", "ip6"} { // IPv4 zuerst: Docker-Bridges haben oft kein IPv6
			if ips, err := net.DefaultResolver.LookupNetIP(ctx, fam, h); err == nil && len(ips) > 0 {
				out = append(out, net.JoinHostPort(ips[0].Unmap().String(), "53"))
				break
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no nameserver for " + domain)
	}
	return out, nil
}

// waitTXT wartet, bis alle Nameserver der Zone den TXT-Record ausliefern (ipv64 schreibt nach einigen Sekunden).
func waitTXT(ctx context.Context, zone, fqdn, want string) error {
	servers, err := lookupNS(ctx, zone)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(waitDNS)
	for {
		ok := 0
		for _, s := range servers {
			if hasTXT(ctx, s, fqdn, want) {
				ok++
			}
		}
		if ok == len(servers) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("TXT record not visible on %d of %d nameservers after %s", len(servers)-ok, len(servers), waitDNS)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

func hasTXT(ctx context.Context, server, fqdn, want string) bool {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(fqdn), dns.TypeTXT)
	q.RecursionDesired = false
	c := &dns.Client{Timeout: 3 * time.Second}
	r, _, err := c.ExchangeContext(ctx, q, server)
	if err != nil || r == nil {
		return false
	}
	for _, rr := range r.Answer {
		if t, ok := rr.(*dns.TXT); ok && strings.Join(t.Txt, "") == want {
			return true
		}
	}
	return false
}
