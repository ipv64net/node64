package healthchecks

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Oeffentliche Adresse der Node fuer den DNS-Check "entspricht meiner oeffentlichen IP": ueber IPv4 bzw. IPv6
// erzwungen bei ipv64 gefragt (wie das DynDNS-Modul), fuer 5 Minuten gemerkt.

var publicIPSources = map[string]string{
	"ipv4": "https://ipv4.ipv64.net/ipcheck.php?ipv4",
	"ipv6": "https://ipv6.ipv64.net/ipcheck.php?ipv6",
}

type publicIPCache struct {
	mu  sync.Mutex
	got map[string]publicIPEntry
}

type publicIPEntry struct {
	ip  string
	err error
	at  time.Time
}

func newPublicIP() func(ctx context.Context, family string) (string, error) {
	c := &publicIPCache{got: map[string]publicIPEntry{}}
	return c.get
}

func (c *publicIPCache) get(ctx context.Context, family string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.got[family]; ok && time.Since(e.at) < 5*time.Minute && (e.err == nil || time.Since(e.at) < time.Minute) {
		return e.ip, e.err
	}
	ip, err := fetchPublicIP(ctx, family)
	c.got[family] = publicIPEntry{ip: ip, err: err, at: time.Now()}
	return ip, err
}

func fetchPublicIP(ctx context.Context, family string) (string, error) {
	src, ok := publicIPSources[family]
	if !ok {
		return "", fmt.Errorf("unknown family %q", family)
	}
	network := "tcp4"
	if family == "ipv6" {
		network = "tcp6"
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	cl := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext:       func(ctx context.Context, _, addr string) (net.Conn, error) { return d.DialContext(ctx, network, addr) },
		DisableKeepAlives: true,
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "node64")
	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	for _, f := range strings.FieldsFunc(string(body), func(r rune) bool {
		return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r == ':' || r == '.')
	}) {
		if a, err := netip.ParseAddr(f); err == nil {
			a = a.Unmap()
			if (family == "ipv4") == a.Is4() {
				return a.String(), nil
			}
		}
	}
	return "", fmt.Errorf("no %s address in answer", family)
}
