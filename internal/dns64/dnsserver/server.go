// Package dnsserver answers DNS queries: local names, blocklist, cache,
// then encrypted upstream.
package dnsserver

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/ipv64net/node64/internal/dns64/cache"
	"github.com/ipv64net/node64/internal/dns64/filter"
	"github.com/ipv64net/node64/internal/dns64/localnet"
	"github.com/ipv64net/node64/internal/dns64/querylog"
	"github.com/ipv64net/node64/internal/dns64/upstream"
)

const blockedTTL = 10

// Reason codes in the query log (translated in the UI).
const ReasonStale = "stale" // served from cache after expiry, refreshed in the background

// ReasonPaused marks a query a list would have blocked while blocking was paused ("paused:<list>").
const ReasonPaused = "paused:"

// Records are own DNS entries from the settings. ok = the name is known (then the answer may be empty).
type Records interface {
	Lookup(name string, qtype uint16) (rrs []dns.RR, ok bool)
}

// SplitFunc answers a name differently inside the home network (split DNS, e.g. CDN64 online names with the
// node's own address); ok = answered (then the answer may be empty).
type SplitFunc func(name string, qtype uint16, client netip.Addr) (rrs []dns.RR, ok bool)

type Server struct {
	Addr     string
	Local    *localnet.Resolver // router DNS for local names
	Filter   *filter.Manager
	Upstream *upstream.Resolver
	Cache    *cache.Cache
	Log      *querylog.Store
	Logger   *slog.Logger

	Records   Records                 // nil = none
	Split     SplitFunc               // answers for the home network before everything else (nil = none)
	BlockNX   bool                    // blocked names answer NXDOMAIN instead of 0.0.0.0 / ::
	ExtraNets []netip.Prefix          // further client networks besides private and attached ones
	Anonymize func(netip.Addr) string // client as stored in the log, nil = full IP
	Paused    func() bool             // blocking switched off for now (nil = never)

	acl        *clientACL
	srv        []*dns.Server
	refreshSem chan struct{} // bounds concurrent background refreshes
	wg         sync.WaitGroup
}

// Start opens the UDP and TCP sockets right away (so a busy port is reported
// to the caller) and serves them in the background until Shutdown.
func (s *Server) Start() error {
	s.acl = newClientACL(s.ExtraNets)
	s.acl.log = s.Logger
	s.refreshSem = make(chan struct{}, 32)
	pc, err := net.ListenPacket("udp", s.Addr)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		pc.Close()
		return err
	}
	s.srv = []*dns.Server{{PacketConn: pc, Net: "udp", Handler: s}, {Listener: ln, Net: "tcp", Handler: s}}
	for _, srv := range s.srv {
		Serve(srv, &s.wg, func(err error) { s.Logger.Debug("dns listener ended", "net", srv.Net, "err", err) })
	}
	return nil
}

// Serve starts srv in the background and returns once it serves, so a Shutdown right afterwards closes the
// socket (miekg/dns ignores a Shutdown before ActivateAndServe ran, and the port would stay bound).
// ended gets the error when serving stops (nil error is not reported).
func Serve(srv *dns.Server, wg *sync.WaitGroup, ended func(error)) {
	ready := make(chan struct{})
	started := sync.OnceFunc(func() { close(ready) })
	srv.NotifyStartedFunc = started
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := srv.ActivateAndServe()
		started() // failed before serving
		if err != nil && ended != nil {
			ended(err)
		}
	}()
	<-ready
}

// Shutdown closes the sockets and waits for running background refreshes.
func (s *Server) Shutdown(ctx context.Context) {
	for _, srv := range s.srv {
		srv.ShutdownContext(ctx)
	}
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	proto := "udp"
	if _, isTCP := w.RemoteAddr().(*net.TCPAddr); isTCP {
		proto = "tcp"
	}
	reply(w, r, s.Answer(r, remoteIP(w.RemoteAddr()), proto))
}

// Handler answers on another transport (DoT) and records proto in the query log.
func (s *Server) Handler(proto string) dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		reply(w, r, s.Answer(r, remoteIP(w.RemoteAddr()), proto))
	})
}

// Answer resolves one query of clientIP; proto (udp, tcp, doh, dot, doq) goes into the query log.
// Clients outside the allowed networks get REFUSED.
func (s *Server) Answer(r *dns.Msg, clientIP netip.Addr, proto string) *dns.Msg {
	start := time.Now()
	if !s.acl.allowed(clientIP) {
		// Never act as an open resolver on the internet.
		return errorMsg(r, dns.RcodeRefused)
	}
	if r.Opcode != dns.OpcodeQuery || len(r.Question) != 1 {
		return errorMsg(r, dns.RcodeFormatError)
	}

	q := r.Question[0]
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	client := clientIP.String()
	if s.Anonymize != nil {
		client = s.Anonymize(clientIP)
	}
	entry := querylog.Entry{
		Time:   start,
		Client: client,
		Domain: name,
		QType:  dns.TypeToString[q.Qtype],
		Proto:  proto,
	}
	if entry.QType == "" {
		entry.QType = dns.Type(q.Qtype).String()
	}

	var resp *dns.Msg
	if s.Split != nil {
		if rrs, ok := s.Split(name, q.Qtype, clientIP); ok {
			entry.Status = querylog.StatusCustom
			resp = s.custom(r, rrs)
		}
	}
	if resp == nil {
		resp = s.resolve(r, name, &entry)
	}
	resp.Id = r.Id
	entry.Rcode = dns.RcodeToString[resp.Rcode]
	entry.Duration = time.Since(start)
	s.Log.Add(entry)
	return resp
}

// Allowed reports whether ip may use this resolver (private, attached or configured networks).
func (s *Server) Allowed(ip netip.Addr) bool { return s.acl.allowed(ip) }

// Refused: queries from outside the allowed networks since start.
func (s *Server) Refused() Refused { return s.acl.stats() }

func (s *Server) resolve(r *dns.Msg, name string, e *querylog.Entry) *dns.Msg {
	q := r.Question[0]

	if s.Records != nil {
		if rrs, ok := s.Records.Lookup(name, q.Qtype); ok {
			e.Status = querylog.StatusCustom
			return s.custom(r, rrs)
		}
	}

	if isLocalName(name) {
		e.Status = querylog.StatusLocal
		if s.Local.Addr() != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if resp, err := s.Local.Exchange(ctx, r); err == nil {
				e.Upstream = "Router"
				return resp
			}
		}
		// Local names must never leak to public resolvers.
		return errorMsg(r, dns.RcodeNameError)
	}

	blocked, reason := s.Filter.Check(name)
	pausedNow := s.Paused != nil && s.Paused()
	if blocked && pausedNow {
		blocked, reason = false, ReasonPaused+reason // wird nur protokolliert
	}
	if blocked {
		e.Status, e.Reason = querylog.StatusBlocked, reason
		return s.blockedMsg(r)
	}
	released := reason != "" || s.Filter.Allow.Contains(name) || pausedNow

	if resp, state, refresh := s.Cache.Get(r); resp != nil {
		e.Status = querylog.StatusCached
		if state == cache.Stale {
			e.Reason = ReasonStale
		}
		if refresh {
			s.refresh(r, released)
		}
		return resp
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	resp, up, err := s.Upstream.Exchange(ctx, r)
	if err != nil {
		s.Logger.Warn("upstream failed", "domain", name, "err", err)
		e.Status = querylog.StatusError
		return errorMsg(r, dns.RcodeServerFailure)
	}
	e.Upstream = up

	if !released {
		if blocked, why := s.cnameBlocked(resp, q.Qtype); blocked {
			e.Status, e.Reason = querylog.StatusBlocked, why
			return s.blockedMsg(r)
		}
	}

	e.Status, e.Reason = querylog.StatusAllowed, reason
	s.Cache.Set(r, resp)
	return resp
}

// cnameBlocked detects CNAME cloaking: trackers hide behind a first-party
// name that points to a blocked domain.
func (s *Server) cnameBlocked(resp *dns.Msg, qtype uint16) (bool, string) {
	if qtype == dns.TypeCNAME {
		return false, ""
	}
	for _, rr := range resp.Answer {
		if c, ok := rr.(*dns.CNAME); ok {
			target := strings.TrimSuffix(strings.ToLower(c.Target), ".")
			if blocked, list := s.Filter.Check(target); blocked {
				return true, list + " (CNAME " + target + ")"
			}
		}
	}
	return false, ""
}

// refresh fetches a new copy of a cached answer in the background, so the
// client that triggered it is answered from the cache without waiting.
func (s *Server) refresh(r *dns.Msg, released bool) {
	select {
	case s.refreshSem <- struct{}{}:
	default:
		return // busy; the cache allows a retry after a short back-off
	}
	req := r.Copy()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() { <-s.refreshSem }()
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		resp, _, err := s.Upstream.Exchange(ctx, req)
		if err != nil {
			s.Cache.RefreshDone(false)
			return
		}
		if blocked, _ := s.cnameBlocked(resp, req.Question[0].Qtype); blocked && !released {
			s.Cache.Delete(req)
			s.Cache.RefreshDone(true)
			return
		}
		s.Cache.Set(req, resp)
		s.Cache.RefreshDone(true)
	}()
}

func reply(w dns.ResponseWriter, req, resp *dns.Msg) {
	size := dns.MinMsgSize
	if _, isTCP := w.RemoteAddr().(*net.TCPAddr); isTCP {
		size = dns.MaxMsgSize
	} else if opt := req.IsEdns0(); opt != nil {
		size = max(int(opt.UDPSize()), dns.MinMsgSize)
	}
	resp.Truncate(size)
	w.WriteMsg(resp)
}

func errorMsg(r *dns.Msg, rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(r, rcode)
	m.RecursionAvailable = true
	copyEdns(r, m)
	return m
}

// custom answers from own records. A CNAME is followed: to further own records, otherwise like any query
// (blocklists, cache, upstream), so the client gets the addresses in one answer.
func (s *Server) custom(r *dns.Msg, rrs []dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true
	m.Authoritative = true
	m.Answer = rrs
	qtype := r.Question[0].Qtype
	for depth := 0; depth < 8 && qtype != dns.TypeCNAME && len(m.Answer) > 0; depth++ {
		c, ok := m.Answer[len(m.Answer)-1].(*dns.CNAME)
		if !ok {
			break
		}
		target := strings.TrimSuffix(strings.ToLower(c.Target), ".")
		if more, ok := s.Records.Lookup(target, qtype); ok {
			m.Answer = append(m.Answer, more...)
			continue
		}
		sub := new(dns.Msg)
		sub.SetQuestion(dns.Fqdn(target), qtype)
		sub.RecursionDesired = true
		resp := s.resolve(sub, target, &querylog.Entry{})
		m.Answer = append(m.Answer, resp.Answer...)
		m.Rcode = resp.Rcode
		break
	}
	copyEdns(r, m)
	return m
}

// blockedMsg answers NXDOMAIN when configured; otherwise A with 0.0.0.0, AAAA with :: and everything else
// with an empty NOERROR, the same behaviour as Pi-hole and AdGuard Home.
func (s *Server) blockedMsg(r *dns.Msg) *dns.Msg {
	if s.BlockNX {
		return errorMsg(r, dns.RcodeNameError)
	}
	return blockedMsg(r)
}

func blockedMsg(r *dns.Msg) *dns.Msg {
	q := r.Question[0]
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true
	hdr := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: blockedTTL}
	switch q.Qtype {
	case dns.TypeA:
		m.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.IPv4zero}}
	case dns.TypeAAAA:
		m.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: net.IPv6zero}}
	}
	copyEdns(r, m)
	return m
}

func copyEdns(req, resp *dns.Msg) {
	if opt := req.IsEdns0(); opt != nil {
		resp.SetEdns0(dns.DefaultMsgSize, opt.Do())
	}
}
