package certs

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/ipv64net/node64/internal/dns64/upstream"
)

// Oeffentliche Resolver fuer die DNS-01-Pruefung, wenn die Nameserver der Zone nicht direkt erreichbar sind (Port 53
// nach aussen gesperrt oder umgeleitet) oder der eigene Resolver Namen sperrt (Blocklisten von DNS64, Pi-hole usw.).
// Die DoH-Server werden ueber ihre festen IP-Adressen erreicht – ein DNS-Filter, der z. B. cloudflare-dns.com sperrt,
// wirkt darauf nicht; die Pruefung fragt mehrere Betreiber, ein gesperrter oder ausgefallener haelt sie nicht auf.
// Eigene Resolver (Zertifikate → Konto) kommen dazu.

const setCheckResolvers = "certs.check_resolvers" // eigene Resolver, je Zeile: IP, IP:Port oder https://, tls://, quic://

// checkPath ist ein Weg zu einem oeffentlichen Resolver: DoH/DoT/DoQ (srv) oder klassisch (plain, ip:port).
type checkPath struct {
	Name  string
	srv   upstream.Server
	plain string
}

// defaultPaths: DoH bei mehreren Betreibern (feste IPs), dazu klassisch ueber Port 53, falls 443 gesperrt ist.
func defaultPaths() []checkPath {
	var out []checkPath
	for _, name := range []string{"Cloudflare", "Quad9", "Google", "DNS4EU", "dnsforge", "AdGuard", "Mullvad"} {
		for _, s := range upstream.Presets {
			if s.Name == name && upstream.Proto(s.URL) == "doh" {
				out = append(out, checkPath{Name: name + " (DoH)", srv: s})
				break
			}
		}
	}
	for _, a := range []string{"1.1.1.1:53", "9.9.9.9:53", "8.8.8.8:53", "[2606:4700:4700::1111]:53"} {
		out = append(out, checkPath{Name: a, plain: a})
	}
	return out
}

// parsePath liest einen eigenen Resolver: IP, IP:Port oder https://…, tls://…, quic://… (ein Eintrag der Vorschlaege
// bringt seine festen IPs mit, sonst loest der System-Resolver den Namen auf).
func parsePath(s string) (checkPath, error) {
	s = strings.TrimSpace(s)
	if p := upstream.Proto(s); p != "" && p != "dns" {
		srv := upstream.Server{Name: s, URL: s}
		for _, ps := range upstream.Presets {
			if strings.EqualFold(ps.URL, s) {
				srv.IPs = ps.IPs
			}
		}
		return checkPath{Name: s, srv: srv}, nil
	}
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		ap := netip.AddrPortFrom(a, 53).String()
		return checkPath{Name: ap, plain: ap}, nil
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return checkPath{Name: ap.String(), plain: ap.String()}, nil
	}
	return checkPath{}, fmt.Errorf("%q: not an IP address or https://, tls://, quic:// URL", s)
}

// ParseCheckResolvers prueft die Eingabe der eigenen Resolver (Formular; Zeilen, Kommas oder Leerzeichen trennen).
func ParseCheckResolvers(text string) ([]string, error) {
	var out []string
	for _, f := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t' }) {
		p, err := parsePath(f)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Name)
	}
	if len(out) > 10 {
		return nil, errors.New("at most 10 resolvers")
	}
	return out, nil
}

// CheckResolvers liefert die eigenen Resolver der DNS-01-Pruefung.
func (m *Manager) CheckResolvers(ctx context.Context) []string {
	var out []string
	for _, f := range strings.Split(m.d.Store.SettingOr(ctx, setCheckResolvers, ""), "\n") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// SetCheckResolvers speichert die eigenen Resolver (leer = nur die eingebauten).
func (m *Manager) SetCheckResolvers(ctx context.Context, list []string) error {
	return m.d.Store.SetSetting(ctx, setCheckResolvers, strings.Join(list, "\n"))
}

// paths: eigene Resolver zuerst, dann die eingebauten.
func (m *Manager) paths(ctx context.Context) []checkPath {
	var out []checkPath
	for _, s := range m.CheckResolvers(ctx) {
		if p, err := parsePath(s); err == nil {
			out = append(out, p)
		}
	}
	return append(out, defaultPaths()...)
}

// waitTXTFor ist der txtVisible-Haken des Managers: waitTXT mit den eingestellten Resolvern.
func (m *Manager) waitTXTFor(ctx context.Context, zone, fqdn, want string) error {
	ps := newPathSet(m.paths(ctx))
	defer ps.close()
	return waitTXT(withPaths(ctx, ps), zone, fqdn, want)
}

// pathSet haelt die Verbindungen zu den Resolvern fuer die Dauer einer Pruefung (DoH ueber HTTP/2 wiederverwendet).
type pathSet struct {
	paths []checkPath
	mu    sync.Mutex
	res   map[int]*upstream.Resolver
}

func newPathSet(p []checkPath) *pathSet { return &pathSet{paths: p, res: map[int]*upstream.Resolver{}} }

func (ps *pathSet) close() {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	for _, r := range ps.res {
		r.Close()
	}
}

func (ps *pathSet) exchange(ctx context.Context, i int, q *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p := ps.paths[i]
	var r *dns.Msg
	var err error
	if p.plain != "" {
		c := &dns.Client{Timeout: 4 * time.Second}
		if r, _, err = c.ExchangeContext(ctx, q, p.plain); err == nil && r != nil && r.Truncated {
			c.Net = "tcp"
			r, _, err = c.ExchangeContext(ctx, q, p.plain)
		}
	} else {
		ps.mu.Lock()
		res := ps.res[i]
		if res == nil {
			res = upstream.New([]upstream.Server{p.srv}, upstream.ModeOrdered)
			ps.res[i] = res
		}
		ps.mu.Unlock()
		r, _, err = res.Exchange(ctx, q)
	}
	if err == nil && r == nil {
		err = errors.New("no answer")
	}
	if err == nil && r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError {
		err = errors.New("answer " + dns.RcodeToString[r.Rcode])
	}
	return r, err
}

// all fragt alle Resolver gleichzeitig; je Resolver Antwort oder Fehler.
func (ps *pathSet) all(ctx context.Context, q *dns.Msg) ([]*dns.Msg, []error) {
	resp, errs := make([]*dns.Msg, len(ps.paths)), make([]error, len(ps.paths))
	var wg sync.WaitGroup
	for i := range ps.paths {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp[i], errs[i] = ps.exchange(ctx, i, q.Copy())
		}(i)
	}
	wg.Wait()
	return resp, errs
}

type pathsKey struct{}

func withPaths(ctx context.Context, ps *pathSet) context.Context {
	return context.WithValue(ctx, pathsKey{}, ps)
}

// pathsOf: die Resolver der laufenden Pruefung, sonst die eingebauten (Aufrufer schliesst mit done).
func pathsOf(ctx context.Context) (ps *pathSet, done func()) {
	if ps, ok := ctx.Value(pathsKey{}).(*pathSet); ok {
		return ps, func() {}
	}
	ps = newPathSet(defaultPaths())
	return ps, ps.close
}

// publicLookup: Antworten eines Typs ueber den ersten oeffentlichen Resolver, der antwortet.
func publicLookup(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
	ps, done := pathsOf(ctx)
	defer done()
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	var errs []string
	for i, p := range ps.paths {
		r, err := ps.exchange(ctx, i, q)
		if err == nil {
			return r.Answer, nil
		}
		errs = append(errs, p.Name+": "+shortErr(err))
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.New("no public resolver reachable (" + strings.Join(errs, "; ") + ")")
}

// publicTXT: zeigt ein oeffentlicher Resolver den Wert? Alle werden gefragt (ein Resolver kann die fruehere
// NXDOMAIN-Antwort noch im Cache haben); Fehler nur, wenn keiner erreichbar ist – mit Grund je Resolver.
func publicTXT(ctx context.Context, fqdn, want string) (bool, error) {
	ps, done := pathsOf(ctx)
	defer done()
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(fqdn), dns.TypeTXT)
	resp, errs := ps.all(ctx, q)
	reached := false
	var why []string
	for i, r := range resp {
		if errs[i] != nil {
			why = append(why, ps.paths[i].Name+": "+shortErr(errs[i]))
			continue
		}
		reached = true
		if txtIn(r, want) {
			return true, nil
		}
	}
	if !reached {
		return false, errors.New(strings.Join(why, "; "))
	}
	return false, nil
}

// shortErr kuerzt Fehlertexte fuer die Meldung.
func shortErr(err error) string {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	s := err.Error()
	if len(s) > 90 {
		s = s[:90] + "…"
	}
	return s
}

// usableAddr: eine Adresse, die ein oeffentlicher Nameserver haben kann – Sperrantworten von DNS-Filtern (0.0.0.0,
// ::, 127.0.0.1, private Adressen) zaehlen nicht.
func usableAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsValid() && a.IsGlobalUnicast() && !a.IsPrivate()
}

// PathResult ist das Ergebnis eines Pruefwegs (Knopf „DNS-Prüfung testen“).
type PathResult struct {
	Name   string
	Direct bool // Nameserver von ipv64 direkt (sonst oeffentlicher Resolver)
	OK     bool
	Detail string
}

// CheckDNSPaths prueft, welche Wege der DNS-01-Pruefung von hier aus gehen: die Nameserver von ipv64.net direkt
// (Port 53, zustaendige Antwort) und jeder oeffentliche Resolver. Ein Weg genuegt.
func (m *Manager) CheckDNSPaths(ctx context.Context) []PathResult {
	ps := newPathSet(m.paths(ctx))
	defer ps.close()
	ctx = withPaths(ctx, ps)
	var out []PathResult
	if ns, err := lookupNS(ctx, "ipv64.net"); err != nil {
		out = append(out, PathResult{Name: "ipv64.net", Direct: true, Detail: shortErr(err)})
	} else {
		for _, n := range ns {
			res := PathResult{Name: n.Name, Direct: true}
			for _, a := range n.Addrs {
				st, d := queryTXT(ctx, a, "ipv64.net", "\x00")
				if st >= txtMissing {
					res.OK, res.Detail = true, ""
					break
				}
				res.Detail = d
			}
			out = append(out, res)
		}
	}
	q := new(dns.Msg)
	q.SetQuestion("ipv64.net.", dns.TypeSOA)
	_, errs := ps.all(ctx, q)
	for i, p := range ps.paths {
		res := PathResult{Name: p.Name, OK: errs[i] == nil}
		if errs[i] != nil {
			res.Detail = shortErr(errs[i])
		}
		out = append(out, res)
	}
	return out
}
