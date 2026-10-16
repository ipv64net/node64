// Package localnet talks to the home router's DNS server: it forwards local
// names and turns client IPs into device names via reverse lookups.
package localnet

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	nameTTL     = 10 * time.Minute
	lookupLimit = 800 * time.Millisecond
)

type Resolver struct {
	static string // LOCAL_DNS from the environment, empty = auto-detect
	log    *slog.Logger

	mu     sync.RWMutex
	addr   string // "ip:53" of the router, empty if none found
	source string // "config" or "auto"

	namesMu sync.Mutex
	names   map[string]nameEntry
}

type nameEntry struct {
	name    string
	expires time.Time
}

func New(static string, log *slog.Logger) *Resolver {
	r := &Resolver{static: static, log: log, names: map[string]nameEntry{}}
	if static != "" {
		r.addr, r.source = static, "config"
	}
	return r
}

// Run keeps looking for the router's DNS server when none is configured.
func (r *Resolver) Run(ctx context.Context) {
	if r.static != "" {
		return
	}
	for {
		r.detect(ctx)
		wait := time.Hour
		if r.Addr() == "" {
			wait = 5 * time.Minute
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (r *Resolver) detect(ctx context.Context) {
	gws := gateways()
	found := ""
	for _, gw := range gws {
		if addr := net.JoinHostPort(gw, "53"); probe(ctx, addr) {
			found = addr
			break
		}
	}
	r.mu.Lock()
	changed := found != r.addr
	r.addr, r.source = found, "auto"
	r.mu.Unlock()
	if changed {
		if found != "" {
			r.log.Info("router DNS detected", "addr", found)
		} else {
			r.log.Info("no router DNS found; local names will answer NXDOMAIN", "gateways", strings.Join(gws, ", "))
		}
	}
}

// Addr returns the router's DNS address or "" if unknown.
func (r *Resolver) Addr() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.addr
}

func (r *Resolver) Source() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.source
}

// Exchange forwards a query to the router over UDP, retrying over TCP when
// the answer was truncated.
func (r *Resolver) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	addr := r.Addr()
	if addr == "" {
		return nil, net.ErrClosed
	}
	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	resp, _, err := c.ExchangeContext(ctx, req, addr)
	if err == nil && resp.Truncated {
		c.Net = "tcp"
		resp, _, err = c.ExchangeContext(ctx, req, addr)
	}
	return resp, err
}

// Hostnames resolves device names for the given IPs in parallel. IPs without
// a name are missing from the result. Results (also misses) are cached.
func (r *Resolver) Hostnames(ctx context.Context, ips []string) map[string]string {
	out := map[string]string{}
	var todo []string
	now := time.Now()
	r.namesMu.Lock()
	for _, ip := range ips {
		if e, ok := r.names[ip]; ok && now.Before(e.expires) {
			if e.name != "" {
				out[ip] = e.name
			}
		} else {
			todo = append(todo, ip)
		}
	}
	r.namesMu.Unlock()
	if len(todo) == 0 {
		return out
	}

	ctx, cancel := context.WithTimeout(ctx, lookupLimit)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, ip := range todo {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name, ok := r.lookup(ctx, ip)
			if !ok {
				return // timeout or no router: don't cache, try again later
			}
			r.namesMu.Lock()
			r.names[ip] = nameEntry{name, time.Now().Add(nameTTL)}
			if len(r.names) > 4096 {
				clear(r.names)
			}
			r.namesMu.Unlock()
			if name != "" {
				mu.Lock()
				out[ip] = name
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return out
}

// lookup returns the PTR name for ip. ok is false when no answer came back.
func (r *Resolver) lookup(ctx context.Context, ip string) (string, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", true
	}
	if addr.IsLoopback() {
		return "localhost", true
	}
	arpa, err := dns.ReverseAddr(ip)
	if err != nil {
		return "", true
	}
	req := new(dns.Msg)
	req.SetQuestion(arpa, dns.TypePTR)
	resp, err := r.Exchange(ctx, req)
	if err != nil {
		return "", false
	}
	for _, rr := range resp.Answer {
		if p, ok := rr.(*dns.PTR); ok {
			return strings.TrimSuffix(p.Ptr, "."), true
		}
	}
	return "", true
}

func probe(ctx context.Context, addr string) bool {
	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeNS)
	c := &dns.Client{Net: "udp", Timeout: time.Second}
	resp, _, err := c.ExchangeContext(ctx, req, addr)
	return err == nil && resp.Rcode != dns.RcodeRefused
}

// gateways lists the default gateways to try for the router's DNS: IPv4 first, then IPv6 (a link-local
// gateway carries its interface as zone, e.g. fe80::1%eth0).
func gateways() []string {
	var out []string
	if gw := defaultGateway(); gw.IsValid() {
		out = append(out, gw.String())
	}
	if f, err := os.Open("/proc/net/ipv6_route"); err == nil {
		out = append(out, ipv6Gateways(f)...)
		f.Close()
	}
	return out
}

// ipv6Gateways reads the next hops of the IPv6 default routes from /proc/net/ipv6_route
// (dest destlen src srclen nexthop metric refcnt use flags iface).
func ipv6Gateways(r io.Reader) []string {
	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[1] != "00" || strings.Trim(f[0], "0") != "" {
			continue
		}
		b, err := hex.DecodeString(f[4])
		if err != nil || len(b) != 16 {
			continue
		}
		a := netip.AddrFrom16([16]byte(b))
		if a.IsUnspecified() || a.IsLoopback() {
			continue
		}
		if a.IsLinkLocalUnicast() {
			a = a.WithZone(f[9])
		}
		if s := a.String(); !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// defaultGateway reads the IPv4 default route from /proc/net/route. With
// host networking that is the home router. Returns an invalid Addr elsewhere.
func defaultGateway() netip.Addr {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return netip.Addr{}
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// Iface Destination Gateway Flags ...
		if len(fields) < 3 || fields[1] != "00000000" {
			continue
		}
		b, err := hex.DecodeString(fields[2])
		if err != nil || len(b) != 4 {
			continue
		}
		var ip [4]byte
		binary.LittleEndian.PutUint32(ip[:], binary.BigEndian.Uint32(b))
		if a := netip.AddrFrom4(ip); !a.IsUnspecified() {
			return a
		}
	}
	return netip.Addr{}
}
