package checks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

// DNS-Check (Typ dns): fragt einen Namen ab und prueft die Antwort. Ziel ist der Name, gefragt wird der
// Standard-Resolver, ein bestimmter Server oder direkt die zustaendigen Nameserver der Zone.

// DNSParams gelten fuer den Typ dns.
type DNSParams struct {
	RecordType string   `json:"record_type,omitempty"` // A (Standard), AAAA, CNAME, MX, TXT, NS, SRV, CAA, PTR, SOA
	Resolver   string   `json:"resolver,omitempty"`    // system (Standard), server, authoritative
	Server     string   `json:"server,omitempty"`      // bei server: IP oder IP:Port
	Expect     string   `json:"expect,omitempty"`      // any (Standard), contains, equals, regex, nxdomain, public_ip
	Values     []string `json:"values,omitempty"`      // contains/equals: erwartete Werte; regex: Muster
	DNSSEC     bool     `json:"dnssec,omitempty"`      // Antwort muss validiert sein (AD-Flag des Resolvers)
	MinTTL     int      `json:"min_ttl,omitempty"`     // Sekunden; 0 = egal
}

// DNSRecordTypes sind die abfragbaren Typen in Anzeigereihenfolge.
var DNSRecordTypes = []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA", "PTR", "SOA"}

// DNSExpects sind die moeglichen Erwartungen in Anzeigereihenfolge.
var DNSExpects = []string{"any", "contains", "equals", "regex", "nxdomain", "public_ip"}

func (p *DNSParams) defaults() {
	p.RecordType = strings.ToUpper(strings.TrimSpace(p.RecordType))
	if p.RecordType == "" {
		p.RecordType = "A"
	}
	if p.Resolver == "" {
		p.Resolver = "system"
	}
	if p.Expect == "" {
		p.Expect = "any"
	}
}

// dnsName: Ziel als vollstaendiger Name; bei PTR darf auch eine IP stehen.
func dnsName(target, rtype string) (string, error) {
	t := strings.TrimSpace(strings.ToLower(target))
	if rtype == "PTR" {
		if ip := net.ParseIP(t); ip != nil {
			return dns.ReverseAddr(ip.String())
		}
	}
	t = strings.TrimSuffix(t, ".")
	if t == "" {
		return "", errors.New("name is required")
	}
	if a, err := idna.Lookup.ToASCII(t); err == nil { // IDN (buecher.example) als Punycode
		t = a
	}
	if _, ok := dns.IsDomainName(t); !ok || !dnsNameRe.MatchString(t) {
		return "", fmt.Errorf("%q is not a valid domain name", target)
	}
	return dns.Fqdn(t), nil
}

// dnsNameRe: Buchstaben, Ziffern, Bindestrich, Unterstrich (_dmarc, _sip._tcp), * am Anfang.
var dnsNameRe = regexp.MustCompile(`^(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)

func validateDNS(def Definition) error {
	var p DNSParams
	if err := decode(def.Params, &p); err != nil {
		return err
	}
	p.defaults()
	if !slices.Contains(DNSRecordTypes, p.RecordType) {
		return fmt.Errorf("record_type must be one of %s", strings.Join(DNSRecordTypes, ", "))
	}
	if _, err := dnsName(def.Target, p.RecordType); err != nil {
		return err
	}
	switch p.Resolver {
	case "system", "authoritative":
	case "server":
		if _, err := dnsServerAddr(p.Server); err != nil {
			return err
		}
	default:
		return errors.New("resolver must be system, server or authoritative")
	}
	switch p.Expect {
	case "any", "nxdomain":
	case "contains", "equals":
		if len(cleanValues(p.Values)) == 0 {
			return errors.New("values are required for " + p.Expect)
		}
	case "regex":
		if len(p.Values) == 0 || strings.TrimSpace(p.Values[0]) == "" {
			return errors.New("a regex is required")
		}
		if _, err := regexp.Compile(p.Values[0]); err != nil {
			return fmt.Errorf("regex: %w", err)
		}
	case "public_ip":
		if p.RecordType != "A" && p.RecordType != "AAAA" {
			return errors.New("public_ip needs record_type A or AAAA")
		}
	default:
		return fmt.Errorf("expect must be one of %s", strings.Join(DNSExpects, ", "))
	}
	if p.MinTTL < 0 || p.MinTTL > 7*86400 {
		return errors.New("min_ttl must be between 0 and 604800")
	}
	return nil
}

func cleanValues(in []string) []string {
	var out []string
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// dnsServerAddr: "1.1.1.1", "1.1.1.1:5353", "2606:4700::1111", "[2606:4700::1111]:53" -> host:port.
func dnsServerAddr(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("server is required")
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.String(), nil
	}
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return netip.AddrPortFrom(a, 53).String(), nil
	}
	return "", fmt.Errorf("server %q must be an IP address (optionally with port)", s)
}

// DNSNeedsNode: der Check kann nur auf der Node laufen (privater Server, oeffentliche IP der Node).
func DNSNeedsNode(params []byte) bool {
	var p DNSParams
	if decode(params, &p) != nil {
		return false
	}
	p.defaults()
	if p.Expect == "public_ip" {
		return true
	}
	if p.Resolver == "server" {
		if addr, err := dnsServerAddr(p.Server); err == nil {
			if ap, err := netip.ParseAddrPort(addr); err == nil {
				a := ap.Addr()
				return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()
			}
		}
	}
	return false
}

type dnsChecker struct{ r *Runner }

func (c *dnsChecker) Type() Type { return TypeDNS }

func (c *dnsChecker) Check(ctx context.Context, def Definition, _ net.IP) Result {
	var p DNSParams
	if err := decode(def.Params, &p); err != nil {
		return fail(ReasonInvalid, err.Error(), 0, nil)
	}
	p.defaults()
	name, err := dnsName(def.Target, p.RecordType)
	if err != nil {
		return fail(ReasonInvalid, err.Error(), 0, nil)
	}
	qtype := dns.StringToType[p.RecordType]
	details := map[string]any{"name": name, "record_type": p.RecordType, "resolver": p.Resolver}

	servers, err := c.servers(ctx, p, name, def.Timeouts.Connect)
	if err != nil {
		return fail(ReasonDNSFailed, err.Error(), 0, details)
	}
	start := time.Now()
	resp, server, err := exchange(ctx, name, qtype, servers, p.Resolver != "authoritative", p.DNSSEC, def.Timeouts.Connect)
	lat := time.Since(start)
	details["server"] = server
	if err != nil {
		if isTimeout(err) || errors.Is(err, context.DeadlineExceeded) {
			return fail(ReasonTimeout, "no answer from "+server+" after "+lat.Round(time.Millisecond).String(), lat, details)
		}
		return fail(ReasonDNSFailed, shortErr(err), lat, details)
	}
	details["rcode"] = dns.RcodeToString[resp.Rcode]
	values, minTTL := answerValues(resp, qtype)
	details["values"] = values
	if len(values) > 0 {
		details["ttl"] = minTTL
	}
	if p.DNSSEC {
		details["ad"] = resp.AuthenticatedData
	}

	if p.Expect == "nxdomain" {
		if resp.Rcode == dns.RcodeNameError {
			return ok("NXDOMAIN as expected", lat, details)
		}
		return fail(ReasonDNSMismatch, fmt.Sprintf("expected NXDOMAIN, got %s %s", dns.RcodeToString[resp.Rcode], strings.Join(values, ", ")), lat, details)
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
	case dns.RcodeNameError:
		return fail(ReasonDNSNXDomain, name+" does not exist (NXDOMAIN)", lat, details)
	default:
		return fail(ReasonDNSFailed, "server answered "+dns.RcodeToString[resp.Rcode], lat, details)
	}
	if p.DNSSEC && !resp.AuthenticatedData {
		return fail(ReasonDNSSEC, "answer is not DNSSEC validated (AD flag missing)", lat, details)
	}
	if len(values) == 0 {
		return fail(ReasonDNSMismatch, "no "+p.RecordType+" record for "+name, lat, details)
	}
	if p.MinTTL > 0 && minTTL < uint32(p.MinTTL) {
		return fail(ReasonDNSMismatch, fmt.Sprintf("TTL %d below %d", minTTL, p.MinTTL), lat, details)
	}
	shown := strings.Join(values, ", ")
	if len(shown) > 200 {
		shown = shown[:200] + "…"
	}
	switch p.Expect {
	case "contains", "equals":
		want := normValues(cleanValues(p.Values), p.RecordType)
		have := normValues(values, p.RecordType)
		var missing []string
		for _, w := range want {
			if !slices.Contains(have, w) {
				missing = append(missing, w)
			}
		}
		if len(missing) > 0 {
			return fail(ReasonDNSMismatch, fmt.Sprintf("%s missing (got %s)", strings.Join(missing, ", "), shown), lat, details)
		}
		if p.Expect == "equals" && len(have) != len(want) {
			return fail(ReasonDNSMismatch, fmt.Sprintf("unexpected records (got %s)", shown), lat, details)
		}
	case "regex":
		re, err := regexp.Compile(p.Values[0])
		if err != nil {
			return fail(ReasonInvalid, err.Error(), lat, details)
		}
		match := false
		for _, v := range values {
			match = match || re.MatchString(v)
		}
		if !match {
			return fail(ReasonDNSMismatch, fmt.Sprintf("no record matches %s (got %s)", p.Values[0], shown), lat, details)
		}
	case "public_ip":
		if c.r == nil || c.r.PublicIP == nil {
			return fail(ReasonInvalid, "public_ip can only be checked on the node", lat, details)
		}
		fam := "ipv4"
		if p.RecordType == "AAAA" {
			fam = "ipv6"
		}
		ip, err := c.r.PublicIP(ctx, fam)
		if err != nil {
			return fail(ReasonInternal, "public "+fam+" address unknown: "+err.Error(), lat, details)
		}
		details["public_ip"] = ip
		if !slices.Contains(normValues(values, p.RecordType), normValues([]string{ip}, p.RecordType)[0]) {
			return fail(ReasonDNSMismatch, fmt.Sprintf("%s points to %s, public address is %s", strings.TrimSuffix(name, "."), shown, ip), lat, details)
		}
	}
	return ok(p.RecordType+" "+shown, lat, details)
}

// servers: wen fragen (host:port), je nach Resolver-Art.
func (c *dnsChecker) servers(ctx context.Context, p DNSParams, name string, timeout time.Duration) ([]string, error) {
	switch p.Resolver {
	case "server":
		a, err := dnsServerAddr(p.Server)
		if err != nil {
			return nil, err
		}
		return []string{a}, nil
	case "authoritative":
		return authoritativeServers(ctx, name, timeout)
	}
	return systemServers()
}

// systemServers: die Resolver aus /etc/resolv.conf (im Container die von Docker).
func systemServers() ([]string, error) {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(cfg.Servers) == 0 {
		return nil, errors.New("no system resolver (/etc/resolv.conf)")
	}
	out := make([]string, 0, len(cfg.Servers))
	for _, s := range cfg.Servers {
		out = append(out, net.JoinHostPort(s, cfg.Port))
	}
	return out, nil
}

// authoritativeServers: Nameserver der Zone des Namens (NS ueber den Standard-Resolver, von rechts gesucht).
func authoritativeServers(ctx context.Context, name string, timeout time.Duration) ([]string, error) {
	rctx, cancel := context.WithTimeout(ctx, 2*timeout)
	defer cancel()
	labels := dns.SplitDomainName(name)
	for i := 0; i < len(labels); i++ {
		zone := strings.Join(labels[i:], ".")
		nss, err := net.DefaultResolver.LookupNS(rctx, zone)
		if err != nil || len(nss) == 0 {
			continue
		}
		var out []string
		for _, ns := range nss {
			addrs, err := net.DefaultResolver.LookupIPAddr(rctx, strings.TrimSuffix(ns.Host, "."))
			if err != nil {
				continue
			}
			for _, a := range addrs {
				out = append(out, net.JoinHostPort(a.IP.String(), "53"))
			}
		}
		// IPv4 zuerst: ohne IPv6-Route kostet jede v6-Adresse sonst einen Timeout
		sort.SliceStable(out, func(a, b int) bool { return !strings.HasPrefix(out[a], "[") && strings.HasPrefix(out[b], "[") })
		if len(out) > 0 {
			return out, nil
		}
	}
	return nil, errors.New("no authoritative name server found for " + name)
}

// exchange fragt die Server der Reihe nach (UDP, bei abgeschnittener Antwort TCP); der erste, der antwortet, gilt.
func exchange(ctx context.Context, name string, qtype uint16, servers []string, recursion, dnssec bool, timeout time.Duration) (*dns.Msg, string, error) {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = recursion
	m.SetEdns0(1232, dnssec)
	if dnssec {
		m.AuthenticatedData = true
	}
	var last error
	for _, s := range servers {
		cl := &dns.Client{Net: "udp", Timeout: timeout}
		resp, _, err := cl.ExchangeContext(ctx, m, s)
		if err == nil && resp.Truncated {
			cl.Net = "tcp"
			resp, _, err = cl.ExchangeContext(ctx, m, s)
		}
		if err == nil {
			return resp, s, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	if len(servers) > 0 && last != nil {
		return nil, servers[len(servers)-1], last
	}
	return nil, "", errors.New("no server")
}

// answerValues: Werte der Antwort zum gefragten Typ (wie man sie eintraegt) und die kleinste TTL.
func answerValues(resp *dns.Msg, qtype uint16) ([]string, uint32) {
	var out []string
	var minTTL uint32
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype != qtype {
			continue
		}
		var v string
		switch x := rr.(type) {
		case *dns.A:
			v = x.A.String()
		case *dns.AAAA:
			v = x.AAAA.String()
		case *dns.CNAME:
			v = x.Target
		case *dns.MX:
			v = strconv.Itoa(int(x.Preference)) + " " + x.Mx
		case *dns.TXT:
			v = strings.Join(x.Txt, "")
		case *dns.NS:
			v = x.Ns
		case *dns.SRV:
			v = fmt.Sprintf("%d %d %d %s", x.Priority, x.Weight, x.Port, x.Target)
		case *dns.CAA:
			v = fmt.Sprintf("%d %s \"%s\"", x.Flag, x.Tag, x.Value)
		case *dns.PTR:
			v = x.Ptr
		case *dns.SOA:
			v = fmt.Sprintf("%s %s %d", x.Ns, x.Mbox, x.Serial)
		default:
			v = strings.TrimPrefix(rr.String(), rr.Header().String())
		}
		out = append(out, v)
		if t := rr.Header().Ttl; minTTL == 0 || t < minTTL {
			minTTL = t
		}
	}
	sort.Strings(out)
	return out, minTTL
}

// normValues vergleicht unabhaengig von Schreibweise: Namen klein und ohne Punkt am Ende, IPs normalisiert.
func normValues(in []string, rtype string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if rtype == "A" || rtype == "AAAA" {
			if a, err := netip.ParseAddr(v); err == nil {
				out = append(out, a.Unmap().String())
				continue
			}
		}
		if rtype != "TXT" {
			v = strings.ToLower(strings.TrimSuffix(v, "."))
			v = strings.ReplaceAll(v, ". ", " ")
		}
		out = append(out, v)
	}
	return out
}
