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
	"golang.org/x/time/rate"
)

// mDNS-Bruecke (RFC 6762): Namen unter .local und Rueckwaertssuchen fuer Adressen im eigenen Netz fragt DNS64 bei
// Bedarf per Multicast nach und gibt die Antwort als normales DNS weiter (auch an Geraete in anderen Netzen oder im
// VPN). Einmalige Anfragen von einem freien Port: die Geraete antworten per Unicast an diesen Port (Abschnitt 6.7),
// daher braucht es weder Port 5353 noch dauerndes Mithoeren, und es geht kein Multicast in andere Netze. Angenommen
// werden nur Antworten mit der Kennung der Anfrage, von Port 5353 und aus einem direkt angeschlossenen Netz
// (Abschnitt 11). Nur IPv4-Multicast, die Antworten enthalten auch AAAA. Wirkt nur, wenn die Node direkt im LAN
// haengt (Host-Netz, macvlan), nicht hinter der Docker-Bridge. Mit dem Schalter lernt DNS64 ausserdem die eigene
// Endung des Routers aus dessen Rueckwaertssuchen (learnDomain).

const (
	mdnsWait      = 400 * time.Millisecond // so lange auf Antworten warten (danach der Router)
	mdnsProbeWait = 1500 * time.Millisecond
	mdnsProbeEach = 10 * time.Minute
	mdnsHitTTL    = 10 * time.Second // Antworten auf einmalige Anfragen gelten hoechstens 10 s (RFC 6762 6.7)
	mdnsMissTTL   = 30 * time.Second
	mdnsServices  = "_services._dns-sd._udp.local."
	mdnsRate      = 10 // Multicast-Anfragen je Sekunde (Spitze mdnsBurst), darueber gleich der Router
	mdnsBurst     = 30
	maxDomains    = 4
	domainTTL     = 7 * 24 * time.Hour // gelernte Endung ohne neue Bestaetigung so lange behalten
)

// mdnsDst: Ziel der Anfragen (Variable fuer Tests); Antworten muessen von diesem Port kommen.
var mdnsDst = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

// MDNSStatus ist der Stand der mDNS-Bruecke fuer die Anzeige.
type MDNSStatus struct {
	On         bool      `json:"on"`
	Queries    int64     `json:"queries"`    // Multicast-Anfragen seit Start
	Answered   int64     `json:"answered"`   // davon beantwortet
	Responders int       `json:"responders"` // Geraete bei der letzten Pruefung, -1 = noch nicht geprueft
	ProbedAt   time.Time `json:"probed_at,omitzero"`
}

type mdnsState struct {
	on                atomic.Bool
	queries, answered atomic.Int64
	kick              chan struct{}
	lim               *rate.Limiter

	mu         sync.Mutex
	cache      map[string]mdnsEntry
	known      map[string]time.Time     // Namen, die es laut mDNS gibt (fuer NODATA statt NXDOMAIN), bis
	flight     map[string]chan struct{} // laufende Anfragen je Schluessel (gleiche Anfragen warten mit)
	responders int
	probedAt   time.Time
	domains    map[string]time.Time // vom Router gelernte Endungen, zuletzt gesehen
	nets       []netip.Prefix       // direkt angeschlossene Netze (Absender der Antworten)
	netsAt     time.Time

	OnDomains func(map[string]time.Time) // gelernte Endungen geaendert (Speichern ueber Neustarts), unter mu
}

type mdnsEntry struct {
	rrs     []dns.RR
	exists  bool // Name bekannt, auch ohne Eintrag dieser Art (NSEC)
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
			res, _ := mdnsQuery(pctx, dns.Question{Name: mdnsServices, Qtype: dns.TypePTR, Qclass: dns.ClassINET}, false, r.onLink)
			cancel()
			r.md.mu.Lock()
			r.md.responders, r.md.probedAt = res.from, time.Now()
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

// ExchangeMDNS fragt die Frage aus req per mDNS: nil, wenn sie aus ist, niemand antwortet oder die Adresse einer
// Rueckwaertssuche nicht im eigenen Netz liegt; eine leere Antwort (NODATA), wenn es den Namen gibt, aber keinen
// Eintrag dieser Art. Eigenes Zeitbudget (mdnsWait), unabhaengig von dem des Aufrufers.
func (r *Resolver) ExchangeMDNS(ctx context.Context, req *dns.Msg) *dns.Msg {
	if !r.md.on.Load() || len(req.Question) != 1 {
		return nil
	}
	q := req.Question[0]
	q.Name = strings.ToLower(q.Name)
	if ip, ok := arpaAddr(q.Name); ok && !r.onLink(ip) {
		return nil // Geraete ausserhalb des eigenen Netzes antworten nicht per mDNS
	} else if !ok && strings.HasSuffix(q.Name, ".arpa.") {
		return nil
	}
	rrs, exists := r.mdnsLookup(ctx, q)
	if len(rrs) == 0 && !exists {
		return nil
	}
	m := new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true
	m.Answer = rrs
	return m
}

func (r *Resolver) mdnsLookup(ctx context.Context, q dns.Question) ([]dns.RR, bool) {
	key := q.Name + "/" + dns.TypeToString[q.Qtype]
	for {
		r.md.mu.Lock()
		now := time.Now()
		if e, ok := r.md.cache[key]; ok && now.Before(e.expires) {
			r.md.mu.Unlock()
			return copyRRs(e.rrs, e.expires), e.exists || r.isKnown(q.Name)
		}
		if ch, busy := r.md.flight[key]; busy { // dieselbe Anfrage laeuft schon: auf sie warten
			r.md.mu.Unlock()
			select {
			case <-ch:
				continue
			case <-ctx.Done():
				return nil, false
			}
		}
		if !r.md.lim.Allow() { // Bremse (z. B. Netzwerk-Scanner): nicht fragen, nichts merken
			known := r.knownLocked(q.Name)
			r.md.mu.Unlock()
			return nil, known
		}
		if r.md.flight == nil {
			r.md.flight = map[string]chan struct{}{}
		}
		ch := make(chan struct{})
		r.md.flight[key] = ch
		r.md.mu.Unlock()

		r.md.queries.Add(1)
		// eigenes Budget: ein langsamer Router vorher darf die Nachfrage nicht leer laufen lassen
		qctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mdnsWait)
		res, err := mdnsQuery(qctx, q, uniqueType(q), r.onLink)
		cancel()
		now = time.Now()
		r.md.mu.Lock()
		delete(r.md.flight, key)
		close(ch)
		if err != nil { // nicht gefragt (kein Socket, keine Route): nichts merken
			known := r.knownLocked(q.Name)
			r.md.mu.Unlock()
			return nil, known
		}
		exp := now.Add(mdnsMissTTL)
		if len(res.rrs) > 0 {
			r.md.answered.Add(1)
			exp = now.Add(mdnsHitTTL)
		}
		if res.exists {
			if r.md.known == nil {
				r.md.known = map[string]time.Time{}
			}
			r.md.known[q.Name] = now.Add(mdnsHitTTL)
		}
		if r.md.cache == nil {
			r.md.cache = map[string]mdnsEntry{}
		}
		if len(r.md.cache) > 4096 { // abgelaufene raus, erst wenn das nicht reicht alles
			for k, e := range r.md.cache {
				if now.After(e.expires) {
					delete(r.md.cache, k)
				}
			}
			if len(r.md.cache) > 4096 {
				clear(r.md.cache)
			}
			for k, t := range r.md.known {
				if now.After(t) {
					delete(r.md.known, k)
				}
			}
		}
		r.md.cache[key] = mdnsEntry{res.rrs, res.exists, exp}
		known := res.exists || r.knownLocked(q.Name)
		r.md.mu.Unlock()
		return copyRRs(res.rrs, exp), known
	}
}

func (r *Resolver) isKnown(name string) bool {
	r.md.mu.Lock()
	defer r.md.mu.Unlock()
	return r.knownLocked(name)
}

func (r *Resolver) knownLocked(name string) bool {
	t, ok := r.md.known[name]
	return ok && time.Now().Before(t)
}

// uniqueType: Antwort von genau einem Geraet (Adresse, Rueckwaertssuche) - nach der ersten aufhoeren. Gemeinsame
// Eintraege (DNS-SD-Dienste, ANY) sammeln bis zum Ende der Wartezeit.
func uniqueType(q dns.Question) bool {
	switch q.Qtype {
	case dns.TypeA, dns.TypeAAAA:
		return true
	case dns.TypePTR:
		return strings.HasSuffix(q.Name, ".arpa.")
	}
	return false
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

type mdnsResult struct {
	rrs    []dns.RR
	exists bool // Name kommt in einer Antwort vor (Eintrag anderer Art oder NSEC): es gibt ihn
	from   int  // Geraete, die geantwortet haben
}

// mdnsQuery schickt eine einmalige Anfrage und sammelt die Antworten bis zum Ende von ctx (first: bei der ersten
// passenden Antwort aufhoeren). Angenommen werden nur Antworten mit der Kennung der Anfrage, vom Port des Ziels (5353)
// und von einer Adresse, fuer die onLink zutrifft. Eintraege ohne Cache-Flush-Bit, TTL hoechstens 10 s.
func mdnsQuery(ctx context.Context, q dns.Question, first bool, onLink func(netip.Addr) bool) (mdnsResult, error) {
	var res mdnsResult
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return res, err
	}
	defer conn.Close()
	req := new(dns.Msg)
	req.Id = dns.Id()
	req.Question = []dns.Question{{Name: q.Name, Qtype: q.Qtype, Qclass: dns.ClassINET}}
	b, err := req.Pack()
	if err != nil {
		return res, err
	}
	if _, err := conn.WriteToUDP(b, mdnsDst); err != nil {
		return res, err
	}
	if d, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(d)
	} else {
		_ = conn.SetReadDeadline(time.Now().Add(mdnsWait))
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()
	seen, from := map[string]bool{}, map[netip.Addr]bool{}
	buf := make([]byte, 9000)
	for {
		n, src, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			break
		}
		ip := src.Addr().Unmap()
		if int(src.Port()) != mdnsDst.Port || !onLink(ip) {
			continue // nur Geraete im eigenen Netz, von Port 5353 (RFC 6762 6.7, 11)
		}
		var resp dns.Msg
		if resp.Unpack(buf[:n]) != nil || !resp.Response || resp.Id != req.Id {
			continue
		}
		from[ip] = true
		for i, rr := range append(resp.Answer, resp.Extra...) {
			h := rr.Header()
			h.Class &^= 1 << 15 // Cache-Flush-Bit, nur in mDNS
			if h.Class != dns.ClassINET || !strings.EqualFold(h.Name, q.Name) {
				continue
			}
			res.exists = true // auch ein NSEC oder ein Eintrag anderer Art: den Namen gibt es
			if i >= len(resp.Answer) || (h.Rrtype != q.Qtype && h.Rrtype != dns.TypeCNAME && q.Qtype != dns.TypeANY) || h.Rrtype == dns.TypeNSEC {
				continue
			}
			h.Name = q.Name
			h.Ttl = min(h.Ttl, uint32(mdnsHitTTL/time.Second))
			if k := rr.String(); !seen[k] {
				seen[k] = true
				res.rrs = append(res.rrs, rr)
			}
		}
		if first && len(res.rrs) > 0 {
			break
		}
	}
	res.from = len(from)
	return res, nil
}

// onLink: ip liegt in einem direkt angeschlossenen Netz (Schnittstellen der Node, eine Minute zwischengespeichert).
func (r *Resolver) onLink(ip netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	r.md.mu.Lock()
	if r.md.nets == nil || time.Since(r.md.netsAt) > time.Minute {
		r.md.nets, r.md.netsAt = localNets(), time.Now()
	}
	nets := r.md.nets
	r.md.mu.Unlock()
	for _, p := range nets {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func localNets() []netip.Prefix {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return []netip.Prefix{}
	}
	out := make([]netip.Prefix, 0, len(addrs))
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if p, err := netip.ParsePrefix(n.String()); err == nil {
				out = append(out, p.Masked())
			}
		}
	}
	return out
}

// arpaAddr: Adresse einer Rueckwaertssuche (1.2.168.192.in-addr.arpa., Nibbles unter ip6.arpa.).
func arpaAddr(name string) (netip.Addr, bool) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if v4, ok := strings.CutSuffix(name, ".in-addr.arpa"); ok {
		p := strings.Split(v4, ".")
		if len(p) != 4 {
			return netip.Addr{}, false
		}
		a, err := netip.ParseAddr(p[3] + "." + p[2] + "." + p[1] + "." + p[0])
		return a, err == nil
	}
	if v6, ok := strings.CutSuffix(name, ".ip6.arpa"); ok {
		p := strings.Split(v6, ".")
		if len(p) != 32 {
			return netip.Addr{}, false
		}
		var sb strings.Builder
		for i := 31; i >= 0; i-- {
			if len(p[i]) != 1 {
				return netip.Addr{}, false
			}
			sb.WriteString(p[i])
			if i%4 == 0 && i > 0 {
				sb.WriteByte(':')
			}
		}
		a, err := netip.ParseAddr(sb.String())
		return a, err == nil
	}
	return netip.Addr{}, false
}

// mdnsPTR: Geraetename per mDNS-Rueckwaertssuche ("" = keiner).
func (r *Resolver) mdnsPTR(ctx context.Context, arpa string) string {
	req := new(dns.Msg)
	req.SetQuestion(arpa, dns.TypePTR)
	if m := r.ExchangeMDNS(ctx, req); m != nil {
		for _, rr := range m.Answer {
			if p, ok := rr.(*dns.PTR); ok {
				return strings.TrimSuffix(p.Ptr, ".")
			}
		}
	}
	return ""
}

// LearnPTR: Antwort des Routers auf eine Rueckwaertssuche (arpa -> ptr), fuer die Endung des Routers (learnDomain).
func (r *Resolver) LearnPTR(arpa, ptr string) {
	if ip, ok := arpaAddr(arpa); ok {
		r.learnDomain(ip, ptr)
	}
}

// learnDomain merkt sich die Endung eines Geraetenamens, den der Router fuer eine private Adresse liefert (z. B.
// nas.zuhause -> zuhause), nur mit eingeschalteter mDNS-Bruecke. Nur Endungen, deren letzter Teil keine Endung des
// Internets ist (weder ICANN noch privater Teil der Public Suffix List wie duckdns.org), damit nie eine echte Domain
// am Internet vorbei an den Router geht; Endungen, die DNS64 ohnehin lokal behandelt (IsBuiltin), auch nicht.
func (r *Resolver) learnDomain(ip netip.Addr, name string) {
	if !r.md.on.Load() || !(ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
		return
	}
	_, suffix, ok := strings.Cut(strings.ToLower(strings.TrimSuffix(name, ".")), ".")
	if !ok || suffix == "" || strings.HasSuffix(suffix, "arpa") || (r.IsBuiltin != nil && r.IsBuiltin(suffix)) {
		return
	}
	tld := suffix[strings.LastIndexByte(suffix, '.')+1:]
	if ps, icann := publicsuffix.PublicSuffix(suffix); icann || strings.Contains(ps, ".") || tldExists(tld) {
		return
	}
	now := time.Now()
	r.md.mu.Lock()
	if r.md.domains == nil {
		r.md.domains = map[string]time.Time{}
	}
	_, had := r.md.domains[suffix]
	r.expireDomainsLocked(now)
	if !had && len(r.md.domains) >= maxDomains { // voll: die am laengsten nicht gesehene weicht
		oldest := ""
		for d, t := range r.md.domains {
			if oldest == "" || t.Before(r.md.domains[oldest]) {
				oldest = d
			}
		}
		delete(r.md.domains, oldest)
	}
	refresh := !had || now.Sub(r.md.domains[suffix]) > time.Hour
	r.md.domains[suffix] = now
	snap, save := mapsClone(r.md.domains), r.md.OnDomains
	r.md.mu.Unlock()
	if refresh && save != nil {
		save(snap)
	}
}

// tldExists: die oberste Endung ist im Internet vergeben (auch ohne eigene Regel in der Liste, z. B. "box").
func tldExists(tld string) bool {
	_, icann := publicsuffix.PublicSuffix("x." + tld)
	return icann
}

func (r *Resolver) expireDomainsLocked(now time.Time) {
	for d, t := range r.md.domains {
		if now.Sub(t) > domainTTL {
			delete(r.md.domains, d)
		}
	}
}

func mapsClone(m map[string]time.Time) map[string]time.Time {
	out := make(map[string]time.Time, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// LoadDomains: gespeicherte Endungen (beim Start), abgelaufene fallen weg.
func (r *Resolver) LoadDomains(d map[string]time.Time) {
	r.md.mu.Lock()
	defer r.md.mu.Unlock()
	r.md.domains = map[string]time.Time{}
	for k, t := range d {
		if len(r.md.domains) < maxDomains {
			r.md.domains[k] = t
		}
	}
	r.expireDomainsLocked(time.Now())
}

// SetOnDomains: Rueckruf, wenn sich die gelernten Endungen aendern (Speichern).
func (r *Resolver) SetOnDomains(f func(map[string]time.Time)) {
	r.md.mu.Lock()
	r.md.OnDomains = f
	r.md.mu.Unlock()
}

// LearnedLocal: name liegt unter einer vom Router gelernten Endung (geht wie .lan an den Router, nie ins Internet).
// Nur mit eingeschalteter mDNS-Bruecke.
func (r *Resolver) LearnedLocal(name string) bool {
	if !r.md.on.Load() {
		return false
	}
	r.md.mu.Lock()
	defer r.md.mu.Unlock()
	now := time.Now()
	for d, t := range r.md.domains {
		if now.Sub(t) <= domainTTL && (name == d || strings.HasSuffix(name, "."+d)) {
			return true
		}
	}
	return false
}

// Domains: vom Router gelernte Endungen (sortiert, fuer die Anzeige; leer bei ausgeschalteter Bruecke).
func (r *Resolver) Domains() []string {
	out := []string{}
	if !r.md.on.Load() {
		return out
	}
	r.md.mu.Lock()
	defer r.md.mu.Unlock()
	now := time.Now()
	for d, t := range r.md.domains {
		if now.Sub(t) <= domainTTL {
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}
