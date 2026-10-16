// Package upstream forwards DNS queries encrypted: DNS-over-HTTPS (RFC 8484, https://), DNS-over-TLS
// (RFC 7858, tls://host[:853]) and DNS-over-QUIC (RFC 9250, quic://host[:853]).
package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type Server struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	// Bootstrap IPs for the URL's host. Without them we would need DNS to
	// reach our DNS upstream - a loop when this machine uses itself as resolver.
	IPs []string `json:"ips"`
}

var DefaultServers = []Server{Presets[0], Presets[1]}

// Presets are the public resolvers offered in the settings (IPv4 first: without IPv6 the v6 addresses fail fast).
var Presets = []Server{
	{Name: "Cloudflare", URL: "https://cloudflare-dns.com/dns-query", IPs: []string{"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"}},
	{Name: "Quad9", URL: "https://dns.quad9.net/dns-query", IPs: []string{"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"}},
	{Name: "Google", URL: "https://dns.google/dns-query", IPs: []string{"8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"}},
	{Name: "AdGuard", URL: "https://dns.adguard-dns.com/dns-query", IPs: []string{"94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"}},
	{Name: "Mullvad", URL: "https://dns.mullvad.net/dns-query", IPs: []string{"194.242.2.2", "2a07:e340::2"}},
	{Name: "Cloudflare", URL: "tls://one.one.one.one", IPs: []string{"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"}},
	{Name: "Quad9", URL: "tls://dns.quad9.net", IPs: []string{"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"}},
	{Name: "Google", URL: "tls://dns.google", IPs: []string{"8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"}},
	{Name: "AdGuard", URL: "tls://dns.adguard-dns.com", IPs: []string{"94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"}},
	{Name: "AdGuard", URL: "quic://dns.adguard-dns.com", IPs: []string{"94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"}},
	{Name: "Mullvad", URL: "tls://dns.mullvad.net", IPs: []string{"194.242.2.2", "2a07:e340::2"}},
}

// Proto is the transport of an upstream URL: doh, dot or doq ("" = not supported).
func Proto(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	switch u.Scheme {
	case "https":
		return "doh"
	case "tls":
		return "dot"
	case "quic":
		return "doq"
	}
	return ""
}

// Modes: parallel = all at once, fastest valid answer wins; ordered = one after another, next on error;
// fastest = only the currently fastest few at once (measured continuously, see fastest.go).
const (
	ModeParallel = "parallel"
	ModeOrdered  = "ordered"
	ModeFastest  = "fastest"
)

const attemptTimeout = 3 * time.Second

// testRoots replaces the system CAs in tests (nil = system).
var testRoots *x509.CertPool

// doh is one upstream with its statistics; client is used for DoH, ex for DoT and DoQ.
type doh struct {
	Server
	client *http.Client
	ex     exchanger

	mu        sync.Mutex
	requests  uint64
	wins      uint64
	errors    uint64
	avgMs     float64 // exponentially weighted moving average
	recentMs  float64 // faster moving average for the ranking (fastest mode)
	lastUsed  time.Time
	lastErr   string
	lastErrAt time.Time
	lastOKAt  time.Time
}

// Resolver races every query against all upstreams in parallel and returns
// the first good answer. That hides the latency spikes of a single provider
// and gives instant failover.
type Resolver struct {
	ups  []*doh
	mode string
	top  int // fastest mode: how many upstreams are asked at once
}

func New(servers []Server, mode string) *Resolver {
	if mode != ModeOrdered && mode != ModeFastest {
		mode = ModeParallel
	}
	r := &Resolver{mode: mode, top: DefaultTop}
	for _, s := range servers {
		u := &doh{Server: s}
		pu, _ := url.Parse(s.URL)
		port := "853"
		if pu != nil && pu.Port() != "" {
			port = pu.Port()
		}
		switch Proto(s.URL) {
		case "dot":
			u.ex = newDoT(pu.Hostname(), port, s.IPs)
		case "doq":
			u.ex = newDoQ(pu.Hostname(), port, s.IPs)
		default:
			u.client = newClient(s.IPs)
		}
		r.ups = append(r.ups, u)
	}
	return r
}

func newClient(ips []string) *http.Client {
	dialer := &net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}
	var pref atomic.Int32 // Familie der letzten erfolgreichen Verbindung (Happy Eyeballs)
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if len(ips) == 0 { // URL with an IP as host
				return dialer.DialContext(ctx, network, addr)
			}
			addrs := make([]string, 0, len(ips))
			for _, ip := range ips {
				addrs = append(addrs, net.JoinHostPort(ip, port))
			}
			return happyDial(ctx, addrs, &pref, func(ctx context.Context, a string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, a)
			}, func(c net.Conn) { _ = c.Close() })
		},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     5 * time.Minute,
		TLSHandshakeTimeout: 3 * time.Second,
		TLSClientConfig:     &tls.Config{RootCAs: testRoots, MinVersion: tls.VersionTLS12},
	}
	return &http.Client{Transport: tr}
}

// Close drops the idle connections to the upstreams (and their goroutines).
func (r *Resolver) Close() {
	for _, u := range r.ups {
		if u.ex != nil {
			u.ex.close()
		} else {
			u.client.CloseIdleConnections()
		}
	}
}

// Exchange resolves req and returns the response and the name of the
// upstream that answered first. A SERVFAIL is only used if no upstream
// has anything better.
func (r *Resolver) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, string, error) {
	switch r.mode {
	case ModeOrdered:
		return r.exchangeOrdered(ctx, req)
	case ModeFastest:
		return r.exchangeFastest(ctx, req)
	}
	return r.race(ctx, req, r.ups, nil, 0)
}

// race asks first at once; rest are reserves: after hedge (0 = never) the next one joins, and when everything
// started so far failed (error or SERVFAIL), all remaining ones are asked.
func (r *Resolver) race(ctx context.Context, req *dns.Msg, first, rest []*doh, hedge time.Duration) (*dns.Msg, string, error) {
	type result struct {
		resp *dns.Msg
		u    *doh
		err  error
	}
	ch := make(chan result, len(first)+len(rest))
	pending := 0
	launch := func(ups []*doh) {
		for _, u := range ups {
			q := req.Copy()
			pending++
			u.use()
			go func() {
				// Losers keep running to completion so their latency is measured;
				// the buffered channel lets them finish without a reader.
				actx, cancel := context.WithTimeout(context.Background(), attemptTimeout)
				defer cancel()
				start := time.Now()
				resp, err := u.exchange(actx, q)
				u.record(time.Since(start), err, false)
				ch <- result{resp, u, err}
			}()
		}
	}
	launch(first)
	var timer <-chan time.Time
	if hedge > 0 && len(rest) > 0 {
		t := time.NewTimer(hedge)
		defer t.Stop()
		timer = t.C
	}

	var errs []error
	var fallback *result
	for pending > 0 {
		select {
		case res := <-ch:
			pending--
			switch {
			case res.err != nil:
				errs = append(errs, fmt.Errorf("%s: %w", res.u.Name, res.err))
			case res.resp.Rcode == dns.RcodeServerFailure:
				if fallback == nil {
					fallback = &res
				}
			default:
				res.u.win()
				return res.resp, res.u.Name, nil
			}
			if pending == 0 && len(rest) > 0 { // alle bisherigen gescheitert: alle Reserven
				launch(rest)
				rest, timer = nil, nil
			}
		case <-timer: // langsam: die naechste Reserve dazu
			launch(rest[:1])
			rest, timer = rest[1:], nil
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	}
	if fallback != nil {
		fallback.u.win()
		return fallback.resp, fallback.u.Name, nil
	}
	return nil, "", errors.Join(errs...)
}

// Mode is parallel or ordered.
func (r *Resolver) Mode() string { return r.mode }

// exchangeOrdered asks the upstreams one after another; the next one only on an error or SERVFAIL.
func (r *Resolver) exchangeOrdered(ctx context.Context, req *dns.Msg) (*dns.Msg, string, error) {
	var errs []error
	var fallback *dns.Msg
	var fallbackUp *doh
	for _, u := range r.ups {
		if ctx.Err() != nil {
			break
		}
		actx, cancel := context.WithTimeout(ctx, attemptTimeout)
		start := time.Now()
		resp, err := u.exchange(actx, req.Copy())
		cancel()
		u.record(time.Since(start), err, false)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: %w", u.Name, err))
		case resp.Rcode == dns.RcodeServerFailure:
			if fallback == nil {
				fallback, fallbackUp = resp, u
			}
		default:
			u.win()
			return resp, u.Name, nil
		}
	}
	if fallback != nil {
		fallbackUp.win()
		return fallback, fallbackUp.Name, nil
	}
	if len(errs) == 0 {
		return nil, "", ctx.Err()
	}
	return nil, "", errors.Join(errs...)
}

// record notes one answer time; probes (fastest mode) only update the times and the health, not the counters.
func (u *doh) record(d time.Duration, err error, probe bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !probe {
		u.requests++
	}
	if err != nil {
		if !probe {
			u.errors++
		}
		u.lastErr = err.Error()
		u.lastErrAt = time.Now()
		return
	}
	ms := float64(d.Microseconds()) / 1000
	if u.avgMs == 0 {
		u.avgMs, u.recentMs = ms, ms
	} else {
		u.avgMs = 0.9*u.avgMs + 0.1*ms
		u.recentMs = 0.7*u.recentMs + 0.3*ms
	}
	u.lastOKAt = time.Now()
}

func (u *doh) use() {
	u.mu.Lock()
	u.lastUsed = time.Now()
	u.mu.Unlock()
}

func (u *doh) win() {
	u.mu.Lock()
	u.wins++
	u.mu.Unlock()
}

type Stats struct {
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Proto     string    `json:"proto"` // doh, dot, doq
	IPs       []string  `json:"ips"`
	Requests  uint64    `json:"requests"`
	Wins      uint64    `json:"wins"`
	Errors    uint64    `json:"errors"`
	AvgMs     float64   `json:"avgMs"`
	Healthy   bool      `json:"healthy"`
	Active    bool      `json:"active"` // fastest mode: currently among the ones asked first
	LastError string    `json:"lastError,omitempty"`
	LastErrAt time.Time `json:"lastErrorAt"`
}

func (r *Resolver) Stats() []Stats {
	out := make([]Stats, 0, len(r.ups))
	active := map[*doh]bool{}
	if r.mode == ModeFastest {
		for _, u := range r.first() {
			active[u] = true
		}
	}
	for _, u := range r.ups {
		u.mu.Lock()
		out = append(out, Stats{
			Name: u.Name, URL: u.URL, Proto: Proto(u.URL), IPs: u.IPs,
			Requests: u.requests, Wins: u.wins, Errors: u.errors, AvgMs: u.avgMs,
			// healthy until an error is newer than the last success
			Healthy:   u.lastErrAt.IsZero() || u.lastOKAt.After(u.lastErrAt),
			LastError: u.lastErr, LastErrAt: u.lastErrAt, Active: active[u],
		})
		u.mu.Unlock()
	}
	return out
}

func (u *doh) exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if u.ex != nil {
		return u.ex.exchange(ctx, req)
	}
	q := req.Copy()
	q.Id = 0 // RFC 8484 §4.1: use ID 0 for cache friendliness
	wire, err := q.Pack()
	if err != nil {
		return nil, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, u.URL, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/dns-message")
	hreq.Header.Set("Accept", "application/dns-message")
	hresp, err := u.client.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer hresp.Body.Close()
	if hresp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, hresp.Body)
		return nil, fmt.Errorf("HTTP %s", hresp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(hresp.Body, dns.MaxMsgSize))
	if err != nil {
		return nil, err
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(body); err != nil {
		return nil, err
	}
	resp.Id = req.Id
	return resp, nil
}
