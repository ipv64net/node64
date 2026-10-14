// Package upstream forwards DNS queries over DNS-over-HTTPS (RFC 8484).
package upstream

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Server struct {
	Name string
	URL  string
	// Bootstrap IPs for the URL's host. Without them we would need DNS to
	// reach our DNS upstream - a loop when this machine uses itself as resolver.
	IPs []string
}

var DefaultServers = []Server{
	{"Cloudflare", "https://cloudflare-dns.com/dns-query", []string{"1.1.1.1", "1.0.0.1"}},
	{"Quad9", "https://dns.quad9.net/dns-query", []string{"9.9.9.9", "149.112.112.112"}},
}

const attemptTimeout = 3 * time.Second

type doh struct {
	Server
	client *http.Client

	mu        sync.Mutex
	requests  uint64
	wins      uint64
	errors    uint64
	avgMs     float64 // exponentially weighted moving average
	lastErr   string
	lastErrAt time.Time
	lastOKAt  time.Time
}

// Resolver races every query against all upstreams in parallel and returns
// the first good answer. That hides the latency spikes of a single provider
// and gives instant failover.
type Resolver struct {
	ups []*doh
}

func New(servers []Server) *Resolver {
	r := &Resolver{}
	for _, s := range servers {
		r.ups = append(r.ups, &doh{Server: s, client: newClient(s.IPs)})
	}
	return r
}

func newClient(ips []string) *http.Client {
	dialer := &net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			var lastErr error
			for _, ip := range ips {
				c, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
				if err == nil {
					return c, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     5 * time.Minute,
		TLSHandshakeTimeout: 3 * time.Second,
	}
	return &http.Client{Transport: tr}
}

// Close drops the idle connections to the upstreams (and their goroutines).
func (r *Resolver) Close() {
	for _, u := range r.ups {
		u.client.CloseIdleConnections()
	}
}

// Exchange resolves req and returns the response and the name of the
// upstream that answered first. A SERVFAIL is only used if no upstream
// has anything better.
func (r *Resolver) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, string, error) {
	type result struct {
		resp *dns.Msg
		u    *doh
		err  error
	}
	ch := make(chan result, len(r.ups))
	for _, u := range r.ups {
		q := req.Copy()
		go func() {
			// Losers keep running to completion so their latency is measured;
			// the buffered channel lets them finish without a reader.
			actx, cancel := context.WithTimeout(context.Background(), attemptTimeout)
			defer cancel()
			start := time.Now()
			resp, err := u.exchange(actx, q)
			u.record(time.Since(start), err)
			ch <- result{resp, u, err}
		}()
	}

	var errs []error
	var fallback *result
	for range r.ups {
		select {
		case res := <-ch:
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

func (u *doh) record(d time.Duration, err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.requests++
	if err != nil {
		u.errors++
		u.lastErr = err.Error()
		u.lastErrAt = time.Now()
		return
	}
	ms := float64(d.Microseconds()) / 1000
	if u.avgMs == 0 {
		u.avgMs = ms
	} else {
		u.avgMs = 0.9*u.avgMs + 0.1*ms
	}
	u.lastOKAt = time.Now()
}

func (u *doh) win() {
	u.mu.Lock()
	u.wins++
	u.mu.Unlock()
}

type Stats struct {
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	IPs       []string  `json:"ips"`
	Requests  uint64    `json:"requests"`
	Wins      uint64    `json:"wins"`
	Errors    uint64    `json:"errors"`
	AvgMs     float64   `json:"avgMs"`
	Healthy   bool      `json:"healthy"`
	LastError string    `json:"lastError,omitempty"`
	LastErrAt time.Time `json:"lastErrorAt"`
}

func (r *Resolver) Stats() []Stats {
	out := make([]Stats, 0, len(r.ups))
	for _, u := range r.ups {
		u.mu.Lock()
		out = append(out, Stats{
			Name: u.Name, URL: u.URL, IPs: u.IPs,
			Requests: u.requests, Wins: u.wins, Errors: u.errors, AvgMs: u.avgMs,
			// healthy until an error is newer than the last success
			Healthy:   u.lastErrAt.IsZero() || u.lastOKAt.After(u.lastErrAt),
			LastError: u.lastErr, LastErrAt: u.lastErrAt,
		})
		u.mu.Unlock()
	}
	return out
}

func (u *doh) exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
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
