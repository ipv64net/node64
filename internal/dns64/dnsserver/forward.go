package dnsserver

import (
	"context"
	"time"

	"github.com/miekg/dns"

	"github.com/ipv64net/node64/internal/dns64/querylog"
)

// Weiterleitungen und Umschreiben: Namen einer Domain gehen an eigene DNS-Server (z. B. firma.local an den
// VPN-DNS), und ein Name kann wie ein anderer antworten (Domain A -> Domain B). Blocklisten und Gruppenregeln
// gelten weiter, nur lokale Namen und private Reverse-Zonen gehen ungefiltert an die Weiterleitung. Klappt die
// Weiterleitung nicht, antwortet DNS64 mit SERVFAIL; der Name geht nie an die oeffentlichen Upstreams.

const (
	ReasonForward = "forward:" // forward:<Domain>
	ReasonRewrite = "rewrite:" // rewrite:<Ziel>
)

// Forward ist eine Domain mit eigenen DNS-Servern.
type Forward struct {
	Domain   string
	Exchange func(ctx context.Context, req *dns.Msg) (*dns.Msg, string, error)
}

// ForwardFunc liefert die Weiterleitung fuer einen Namen (laengste passende Domain), nil = keine.
type ForwardFunc func(name string) *Forward

// RewriteFunc liefert das Ziel, wenn der Name wie ein anderer antworten soll.
type RewriteFunc func(name string) (target string, ok bool)

// ZoneFunc beantwortet Namen lokaler Zonen (Antwort, Authority mit SOA, Rcode); ok=false: nicht zustaendig.
type ZoneFunc func(name string, qtype uint16) (ans, ns []dns.RR, rcode int, ok bool)

// forward fragt die Server der Weiterleitung (kein Cache: die Antwort gehoert nur zu dieser Weiterleitung).
func (s *Server) forward(r *dns.Msg, f *Forward, e *querylog.Entry, status querylog.Status) *dns.Msg {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	resp, up, err := f.Exchange(ctx, r)
	e.Reason = ReasonForward + f.Domain
	if err != nil {
		s.Logger.Warn("forward failed", "domain", f.Domain, "name", r.Question[0].Name, "err", err)
		e.Status = querylog.StatusError
		return errorMsg(r, dns.RcodeServerFailure)
	}
	e.Status, e.Upstream = status, up
	resp.Id = r.Id
	return resp
}

// rewrite beantwortet name mit den Antworten fuer target (unter dem gefragten Namen, ohne CNAME). Fuer das Ziel
// gelten dieselben Regeln wie fuer den Client (gesperrtes Ziel = gesperrt; Anfrage des Routers: lokales Ziel nicht an ihn).
func (s *Server) rewrite(r *dns.Msg, name, target string, e *querylog.Entry, p *Policy, fromRouter bool, depth int) *dns.Msg {
	q := r.Question[0]
	for i := 0; ; i++ { // Ziel, das selbst umgeschrieben wird: bis zum letzten, Schleife = SERVFAIL
		next, ok := s.Rewrite(target)
		if !ok {
			break
		}
		if i >= 8 || next == name {
			e.Status, e.Reason = querylog.StatusError, ReasonRewrite+target
			return errorMsg(r, dns.RcodeServerFailure)
		}
		target = next
	}
	sub := new(dns.Msg)
	sub.SetQuestion(dns.Fqdn(target), q.Qtype)
	sub.RecursionDesired = true
	var te querylog.Entry
	resp := s.resolve(sub, target, &te, p, fromRouter, depth+1)
	e.Reason, e.Upstream = ReasonRewrite+target, te.Upstream
	if te.Status == querylog.StatusBlocked {
		e.Status = querylog.StatusBlocked
		e.Reason = te.Reason
		return s.blockedMsg(r)
	}
	e.Status = querylog.StatusCustom
	out := new(dns.Msg)
	out.SetReply(r)
	out.RecursionAvailable = true
	out.Rcode = resp.Rcode
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype != q.Qtype {
			continue // CNAME-Kette des Ziels faellt weg
		}
		c := dns.Copy(rr)
		c.Header().Name = dns.Fqdn(name)
		out.Answer = append(out.Answer, c)
	}
	if len(out.Answer) > 0 {
		out.Rcode = dns.RcodeSuccess
	}
	copyEdns(r, out)
	return out
}
