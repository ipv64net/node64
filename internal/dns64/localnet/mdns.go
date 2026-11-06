package localnet

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// mDNS-Bruecke (RFC 6762): Namen unter .local und Rueckwaertssuchen fragt DNS64 bei Bedarf per Multicast im eigenen
// Netz nach und gibt die Antwort als normales DNS weiter (auch an Geraete in anderen Netzen oder im VPN). Einmalige
// Anfragen von einem freien Port: die Geraete antworten per Unicast an diesen Port (Abschnitt 6.7), daher braucht es
// weder Port 5353 noch dauerndes Mithoeren, und es geht kein Multicast in andere Netze. Nur IPv4-Multicast, die
// Antworten enthalten auch AAAA. Wirkt nur, wenn die Node direkt im LAN haengt (Host-Netz, macvlan), nicht hinter
// der Docker-Bridge.

const (
	mdnsWait      = 400 * time.Millisecond // so lange auf Antworten warten (danach der Router)
	mdnsProbeWait = 1500 * time.Millisecond
	mdnsProbeEach = 10 * time.Minute
	mdnsHitTTL    = 10 * time.Second // Antworten auf einmalige Anfragen gelten hoechstens 10 s (RFC 6762 6.7)
	mdnsMissTTL   = 30 * time.Second
	mdnsServices  = "_services._dns-sd._udp.local."
	maxDomains    = 4
)

// mdnsDst: Ziel der Anfragen (Variable fuer Tests).
var mdnsDst = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

// MDNSStatus ist der Stand der mDNS-Bruecke fuer die Anzeige.
type MDNSStatus struct {
	On         bool      `json:"on"`
	Queries    int64     `json:"queries"`    // Anfragen seit Start
	Answered   int64     `json:"answered"`   // davon beantwortet
	Responders int       `json:"responders"` // Geraete bei der letzten Pruefung, -1 = noch nicht geprueft
	ProbedAt   time.Time `json:"probed_at,omitzero"`
}

type mdnsState struct {
	on                atomic.Bool
	queries, answered atomic.Int64
	kick              chan struct{}

	mu         sync.Mutex
	cache      map[string]mdnsEntry
	responders int
	probedAt   time.Time
	domains    map[string]time.Time // vom Router gelernte Endungen (aus Rueckwaertssuchen)
}

type mdnsEntry struct {
	rrs     []dns.RR
	expires time.Time
}

// SetMDNS schaltet die mDNS-Bruecke (Einstellung dns64.mdns); an = gleich einmal pruefen, wer antwortet.
func (r *Resolver) SetMDNS(on bool) {
	r.md.on.Store(on)
	if on {
		select {
		case r.md.kick <- struct{}{}:
		default:
		}
	}
}

// MDNS: Stand fuer Einstellungen und Uebersicht.
func (r *Resolver) MDNS() MDNSStatus {
	r.md.mu.Lock()
	defer r.md.mu.Unlock()
	return MDNSStatus{On: r.md.on.Load(), Queries: r.md.queries.Load(), Answered: r.md.answered.Load(), Responders: r.md.responders, ProbedAt: r.md.probedAt}
}

// RunMDNS prueft regelmaessig, wie viele Geraete im Netz per mDNS antworten (nur wenn eingeschaltet).
func (r *Resolver) RunMDNS(ctx context.Context) {
	t := time.NewTicker(mdnsProbeEach)
	defer t.Stop()
	for {
		if r.md.on.Load() {
			pctx, cancel := context.WithTimeout(ctx, mdnsProbeWait)
			_, from, _ := mdnsQuery(pctx, dns.Question{Name: mdnsServices, Qtype: dns.TypePTR, Qclass: dns.ClassINET}, false)
			cancel()
			r.md.mu.Lock()
			r.md.responders, r.md.probedAt = from, time.Now()
			r.md.mu.Unlock()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-r.md.kick:
		}
	}
}

// MDNSName: der Name gehoert zur mDNS-Bruecke (.local; Rueckwaertssuchen fragt sie erst, wenn der Router keinen
// Namen kennt). name ohne Punkt am Ende, klein geschrieben.
func MDNSName(name string) bool { return strings.HasSuffix(name, ".local") }

// ExchangeMDNS fragt die Frage aus req per mDNS; nil, wenn sie aus ist oder niemand antwortet.
func (r *Resolver) ExchangeMDNS(ctx context.Context, req *dns.Msg) *dns.Msg {
	if !r.md.on.Load() || len(req.Question) != 1 {
		return nil
	}
	q := req.Question[0]
	q.Name = strings.ToLower(q.Name)
	rrs := r.mdnsLookup(ctx, q)
	if len(rrs) == 0 {
		return nil
	}
	m := new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true
	m.Answer = rrs
	return m
}

func (r *Resolver) mdnsLookup(ctx context.Context, q dns.Question) []dns.RR {
	key := q.Name + "/" + dns.TypeToString[q.Qtype]
	now := time.Now()
	r.md.mu.Lock()
	if e, ok := r.md.cache[key]; ok && now.Before(e.expires) {
		r.md.mu.Unlock()
		return copyRRs(e.rrs, e.expires)
	}
	r.md.mu.Unlock()
	r.md.queries.Add(1)
	qctx, cancel := context.WithTimeout(ctx, mdnsWait)
	rrs, _, _ := mdnsQuery(qctx, q, true)
	cancel()
	exp := now.Add(mdnsMissTTL)
	if len(rrs) > 0 {
		r.md.answered.Add(1)
		exp = now.Add(mdnsHitTTL)
	}
	r.md.mu.Lock()
	if r.md.cache == nil || len(r.md.cache) > 4096 {
		r.md.cache = map[string]mdnsEntry{}
	}
	r.md.cache[key] = mdnsEntry{rrs, exp}
	r.md.mu.Unlock()
	return copyRRs(rrs, exp)
}

// copyRRs: Kopien mit der restlichen Gueltigkeit als TTL (die Eintraege im Cache bleiben unveraendert).
func copyRRs(rrs []dns.RR, exp time.Time) []dns.RR {
	ttl := uint32(max(1, int(time.Until(exp).Seconds())))
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		c := dns.Copy(rr)
		c.Header().Ttl = min(c.Header().Ttl, ttl)
		out = append(out, c)
	}
	return out
}

// mdnsQuery schickt eine einmalige Anfrage und sammelt die Antworten bis zum Ende von ctx (first: bei der ersten
// passenden Antwort aufhoeren). Rueckgabe: passende Eintraege (ohne Cache-Flush-Bit, TTL hoechstens 10 s) und die Zahl
// der Geraete, die geantwortet haben.
func mdnsQuery(ctx context.Context, q dns.Question, first bool) ([]dns.RR, int, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	req := new(dns.Msg)
	req.Id = dns.Id()
	req.Question = []dns.Question{{Name: q.Name, Qtype: q.Qtype, Qclass: dns.ClassINET}}
	b, err := req.Pack()
	if err != nil {
		return nil, 0, err
	}
	if _, err := conn.WriteToUDP(b, mdnsDst); err != nil {
		return nil, 0, err
	}
	if d, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(d)
	} else {
		_ = conn.SetReadDeadline(time.Now().Add(mdnsWait))
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()
	var out []dns.RR
	seen, from := map[string]bool{}, map[string]bool{}
	buf := make([]byte, 9000)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		var resp dns.Msg
		if resp.Unpack(buf[:n]) != nil || !resp.Response {
			continue
		}
		from[src.IP.String()] = true
		for _, rr := range resp.Answer {
			h := rr.Header()
			h.Class &^= 1 << 15 // Cache-Flush-Bit, nur in mDNS
			if h.Class != dns.ClassINET || !strings.EqualFold(h.Name, q.Name) || (h.Rrtype != q.Qtype && h.Rrtype != dns.TypeCNAME && q.Qtype != dns.TypeANY) {
				continue
			}
			h.Name = q.Name
			h.Ttl = min(h.Ttl, uint32(mdnsHitTTL/time.Second))
			if k := rr.String(); !seen[k] {
				seen[k] = true
				out = append(out, rr)
			}
		}
		if first && len(out) > 0 {
			break
		}
	}
	return out, len(from), nil
}

// mdnsPTR: Geraetename per mDNS-Rueckwaertssuche ("" = keiner).
func (r *Resolver) mdnsPTR(ctx context.Context, arpa string) string {
	if !r.md.on.Load() {
		return ""
	}
	for _, rr := range r.mdnsLookup(ctx, dns.Question{Name: arpa, Qtype: dns.TypePTR, Qclass: dns.ClassINET}) {
		if p, ok := rr.(*dns.PTR); ok {
			return strings.TrimSuffix(p.Ptr, ".")
		}
	}
	return ""
}

// learnDomain merkt sich die Endung eines Geraetenamens, den der Router fuer eine private Adresse liefert (z. B.
// nas.zuhause -> zuhause). Nur Endungen ohne oeffentliche Domain (kein ICANN-Name), damit nie eine echte Domain am
// Internet vorbei an den Router geht; .fritz.box, .lan & Co. kennt DNS64 ohnehin.
func (r *Resolver) learnDomain(ip netip.Addr, name string) {
	if !(ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
		return
	}
	_, suffix, ok := strings.Cut(strings.ToLower(strings.TrimSuffix(name, ".")), ".")
	if !ok || suffix == "" || strings.HasSuffix(suffix, "arpa") || MDNSName("x."+suffix) || suffix == "local" {
		return
	}
	if _, icann := publicsuffix.PublicSuffix(suffix); icann {
		return
	}
	r.md.mu.Lock()
	defer r.md.mu.Unlock()
	if r.md.domains == nil {
		r.md.domains = map[string]time.Time{}
	}
	if _, ok := r.md.domains[suffix]; !ok && len(r.md.domains) >= maxDomains {
		return
	}
	r.md.domains[suffix] = time.Now()
}

// LearnedLocal: name liegt unter einer vom Router gelernten Endung (geht wie .lan an den Router, nie ins Internet).
func (r *Resolver) LearnedLocal(name string) bool {
	r.md.mu.Lock()
	defer r.md.mu.Unlock()
	for d := range r.md.domains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// Domains: vom Router gelernte Endungen (sortiert, fuer die Anzeige).
func (r *Resolver) Domains() []string {
	r.md.mu.Lock()
	defer r.md.mu.Unlock()
	out := make([]string, 0, len(r.md.domains))
	for d := range r.md.domains {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}
