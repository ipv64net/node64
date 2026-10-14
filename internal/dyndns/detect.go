package dyndns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Quellen fuer die oeffentliche Adresse: zuerst eine eigene URL (falls gesetzt), dann ipv64.
const (
	defaultSource4 = "https://ipv4.ipv64.net/ipcheck.php?ipv4"
	defaultSource6 = "https://ipv6.ipv64.net/ipcheck.php?ipv6"
	fallbackSource = "https://ipv64.net/api/v2/ip" // liefert die Adresse der Familie, ueber die gefragt wird
)

// fetchFunc fragt eine Quelle ueber die angegebene Familie (4 oder 6).
type fetchFunc func(ctx context.Context, fam int, source string) (netip.Addr, error)

// newFetcher baut einen Abruf, der die Verbindung auf IPv4 bzw. IPv6 erzwingt. So sieht die
// Gegenstelle immer die oeffentliche Adresse des Anschlusses (bei IPv4 die des Routers), nie
// eine interne Container-Adresse.
func newFetcher(userAgent string) fetchFunc {
	clients := map[int]*http.Client{}
	for _, fam := range []int{4, 6} {
		network := "tcp4"
		if fam == 6 {
			network = "tcp6"
		}
		d := &net.Dialer{Timeout: 5 * time.Second}
		tr := &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return d.DialContext(ctx, network, addr)
			},
			TLSHandshakeTimeout: 5 * time.Second,
			DisableKeepAlives:   true,
			ForceAttemptHTTP2:   true,
		}
		clients[fam] = &http.Client{Transport: tr, Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return errors.New("too many redirects")
				}
				return nil
			}}
	}
	return func(ctx context.Context, fam int, source string) (netip.Addr, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			return netip.Addr{}, err
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := clients[fam].Do(req)
		if err != nil {
			return netip.Addr{}, shortErr(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		if resp.StatusCode != http.StatusOK {
			return netip.Addr{}, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		addr, ok := extractIP(string(body), fam)
		if !ok {
			return netip.Addr{}, fmt.Errorf("no IPv%d address in answer", fam)
		}
		if !publicAddr(addr) {
			return netip.Addr{}, fmt.Errorf("not a public address: %s", addr)
		}
		return addr, nil
	}
}

// extractIP findet die erste Adresse der Familie in einer Antwort (reiner Text oder JSON).
func extractIP(body string, fam int) (netip.Addr, bool) {
	fields := strings.FieldsFunc(body, func(r rune) bool {
		return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r == ':' || r == '.')
	})
	for _, f := range fields {
		a, err := netip.ParseAddr(f)
		if err != nil {
			continue
		}
		a = a.Unmap()
		if (fam == 4 && a.Is4()) || (fam == 6 && a.Is6()) {
			return a, true
		}
	}
	return netip.Addr{}, false
}

var notPublic4 = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), // Carrier-Grade-NAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
}

var global6 = netip.MustParsePrefix("2000::/3")
var doc6 = netip.MustParsePrefix("2001:db8::/32")

// publicAddr: nur weltweit erreichbare Adressen gehoeren ins DNS.
func publicAddr(a netip.Addr) bool {
	if !a.IsValid() || !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	if a.Is4() {
		for _, p := range notPublic4 {
			if p.Contains(a) {
				return false
			}
		}
		return true
	}
	return global6.Contains(a) && !doc6.Contains(a)
}

// prefix64 ist das /64-Praefix einer IPv6-Adresse.
func prefix64(a netip.Addr) netip.Prefix {
	if !a.Is6() {
		return netip.Prefix{}
	}
	p, _ := a.Prefix(64)
	return p
}

// sourceList: eigene URL (gueltig, http/https), dann ipv64, dann Rueckfall.
func sourceList(custom string, fam int) []string {
	def := defaultSource4
	if fam == 6 {
		def = defaultSource6
	}
	var out []string
	if validSource(custom) {
		out = append(out, custom)
	}
	return append(out, def, fallbackSource)
}

func validSource(s string) bool {
	u, err := url.Parse(strings.TrimSpace(s))
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// sourceHost ist der Host einer Quelle fuer Anzeige und Protokoll.
func sourceHost(s string) string {
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		return u.Host
	}
	return s
}

func shortErr(err error) error {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return errors.New("timeout")
	}
	var oe *net.OpError
	if errors.As(err, &oe) {
		return oe.Err
	}
	return err
}
