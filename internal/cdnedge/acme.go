package cdnedge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/acme"
)

// Bestellung bei Let's Encrypt (oder acme_directory) fuer "name" und "*.name" per DNS-01. Den TXT-Eintrag setzt
// ipv64 (POST /cdn64o/edge/acme-txt, nur fuer Modus-2-Namen); auf den Servern liegt kein PowerDNS- und kein
// API-Key eines Nutzers. Vor der Pruefung wartet der Server, bis alle Nameserver der Zone den Eintrag liefern.
// Scheitert DNS-01, gibt es per HTTP-01 ein Zertifikat nur fuer "name" (der DNS des Namens zeigt auf die Server; den
// Token bekommt auch der Nachbar, weil Let's Encrypt einen der beiden fragt). Fuer Wildcard-Namen versucht der
// Server DNS-01 danach alle paar Stunden erneut (certWildRetry); bis dahin enden Unternamen nicht hier (covers).

// obtain: Zertifikat und Schluessel (PEM) fuer name und *.name, sonst nur name. Zertifizierungsstelle nach
// acmeca.go (Let's Encrypt, an der Grenze bzw. nach "rateLimited" ZeroSSL).
func (s *Server) obtain(ctx context.Context, name string) ([]byte, []byte, error) {
	renewal := !s.certs.notAfter(name).IsZero()
	ca, err := s.pickCA(name, renewal)
	if err != nil {
		return nil, nil, err
	}
	cp, kp, err := s.obtainWith(ctx, ca, name)
	if err != nil && ca == caLE && rateLimited(err) {
		d := regDomain(name)
		s.ca.mu.Lock()
		s.ca.cooldown[d] = time.Now().Add(leCooldown)
		s.ca.mu.Unlock()
		s.log.Warn("let's encrypt rate limit reached", "domain", d, "fallback", s.fallbackName(), "err", err)
		if s.fallbackName() == caZeroSSL {
			ca = caZeroSSL
			cp, kp, err = s.obtainWith(ctx, ca, name)
		}
	}
	if err != nil {
		s.mx.certErr[caIndex(ca)].Add(1)
	} else {
		s.mx.certOK[caIndex(ca)].Add(1)
	}
	s.ca.mu.Lock()
	if err != nil {
		s.ca.lastErr[ca] = time.Now().UTC().Format(time.RFC3339) + " " + name + ": " + err.Error()
	} else {
		delete(s.ca.lastErr, ca)
	}
	s.ca.mu.Unlock()
	if err != nil {
		return nil, nil, err
	}
	d, now := regDomain(name), time.Now()
	s.ca.record(issuance{Name: name, Domain: d, CA: ca, At: now, Renewal: renewal})
	if ca == caLE && !renewal {
		s.ca.mu.Lock()
		n := s.ca.leCount(d, now)
		s.ca.mu.Unlock()
		if n*5 >= s.leLimit()*4 {
			s.log.Warn("let's encrypt: domain close to the weekly limit", "domain", d, "count", n, "limit", s.leLimit(), "fallback", s.fallbackName())
		}
	}
	if ca != caLE {
		s.log.Info("certificate from fallback CA", "name", name, "ca", ca)
	}
	return cp, kp, nil
}

// obtainWith: bei einer Zertifizierungsstelle, DNS-01 und als Ausweg HTTP-01 (nicht nach "rateLimited").
func (s *Server) obtainWith(ctx context.Context, ca, name string) ([]byte, []byte, error) {
	if s.obtainHook != nil { // Tests
		return s.obtainHook(ctx, ca+":"+name)
	}
	cl, err := s.acmeClientFor(ctx, ca)
	if err != nil {
		return nil, nil, err
	}
	dnsT, httpT := 5*time.Minute, 3*time.Minute
	if ca == caZeroSSL { // ZeroSSL stellt deutlich langsamer aus (Minuten im Zustand "processing")
		dnsT, httpT = 15*time.Minute, 10*time.Minute
	}
	cp, kp, err := s.obtainDNS(ctx, cl, name, dnsT)
	if err == nil {
		return cp, kp, nil
	}
	if rateLimited(err) {
		return nil, nil, err
	}
	if time.Until(s.certs.notAfter(name)) > certRenewBefore { // frueher Versuch fuer *.name (certs.go): das vorhandene bleibt
		return nil, nil, err
	}
	s.log.Warn("dns-01 failed, trying http-01 (name only, no wildcard)", "name", name, "ca", ca, "err", err)
	cp, kp, herr := s.obtainHTTP(ctx, cl, name, httpT)
	if herr != nil {
		return nil, nil, fmt.Errorf("dns-01: %v; http-01: %w", err, herr)
	}
	return cp, kp, nil
}

func (s *Server) obtainDNS(ctx context.Context, cl *acme.Client, name string, limit time.Duration) ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	names := []string{name, "*." + name}
	order, err := cl.AuthorizeOrder(ctx, acme.DomainIDs(names...))
	if err != nil {
		return nil, nil, fmt.Errorf("order: %w", err)
	}
	var auths []*acme.Authorization
	var chals []*acme.Challenge
	var vals []string
	for _, u := range order.AuthzURLs {
		z, err := cl.GetAuthorization(ctx, u)
		if err != nil {
			return nil, nil, fmt.Errorf("authorization: %w", err)
		}
		if z.Status == acme.StatusValid {
			continue
		}
		var ch *acme.Challenge
		for _, c := range z.Challenges {
			if c.Type == "dns-01" {
				ch = c
			}
		}
		if ch == nil {
			return nil, nil, errors.New("no dns-01 challenge offered")
		}
		v, err := cl.DNS01ChallengeRecord(ch.Token)
		if err != nil {
			return nil, nil, err
		}
		auths, chals, vals = append(auths, z), append(chals, ch), append(vals, v)
	}
	fqdn := "_acme-challenge." + name
	var added []string
	defer func() { // TXT wieder weg, auch bei Fehlern
		dctx, dcancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer dcancel()
		for _, v := range added {
			if err := s.acmeTXT(dctx, fqdn, v, true); err != nil {
				s.log.Warn("acme TXT not removed", "fqdn", fqdn, "err", err)
			}
		}
	}()
	for _, v := range vals {
		if err := s.acmeTXT(ctx, fqdn, v, false); err != nil {
			return nil, nil, fmt.Errorf("TXT at ipv64: %w", err)
		}
		added = append(added, v)
	}
	if len(vals) > 0 {
		if err := waitTXT(ctx, name, fqdn, vals); err != nil {
			return nil, nil, err
		}
	}
	for i := range auths {
		if _, err := cl.Accept(ctx, chals[i]); err != nil {
			return nil, nil, fmt.Errorf("accept: %w", err)
		}
	}
	for _, z := range auths {
		if _, err := cl.WaitAuthorization(ctx, z.URI); err != nil {
			return nil, nil, fmt.Errorf("validation: %w", err)
		}
	}
	return finishOrder(ctx, cl, order, names)
}

// obtainHTTP: Ausweg ueber HTTP-01 fuer den Namen allein.
func (s *Server) obtainHTTP(ctx context.Context, cl *acme.Client, name string, limit time.Duration) ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	order, err := cl.AuthorizeOrder(ctx, acme.DomainIDs(name))
	if err != nil {
		return nil, nil, fmt.Errorf("order: %w", err)
	}
	for _, u := range order.AuthzURLs {
		z, err := cl.GetAuthorization(ctx, u)
		if err != nil {
			return nil, nil, fmt.Errorf("authorization: %w", err)
		}
		if z.Status == acme.StatusValid {
			continue
		}
		var ch *acme.Challenge
		for _, c := range z.Challenges {
			if c.Type == "http-01" {
				ch = c
			}
		}
		if ch == nil {
			return nil, nil, errors.New("no http-01 challenge offered")
		}
		ka, err := cl.HTTP01ChallengeResponse(ch.Token)
		if err != nil {
			return nil, nil, err
		}
		s.acmeTokens.set(ch.Token, ka)
		s.sharePeerToken(ctx, ch.Token, ka)
		_, err = cl.Accept(ctx, ch)
		if err == nil {
			_, err = cl.WaitAuthorization(ctx, z.URI)
		}
		s.acmeTokens.del(ch.Token)
		if err != nil {
			return nil, nil, fmt.Errorf("http-01 validation: %w", err)
		}
	}
	return finishOrder(ctx, cl, order, []string{name})
}

// finishOrder: Auftrag fertig, Schluessel erzeugen, Zertifikat abholen (PEM).
func finishOrder(ctx context.Context, cl *acme.Client, order *acme.Order, names []string) ([]byte, []byte, error) {
	order, err := cl.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, nil, fmt.Errorf("order: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, key)
	if err != nil {
		return nil, nil, err
	}
	ders, _, err := cl.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, nil, fmt.Errorf("certificate: %w", err)
	}
	var certPEM []byte
	for _, d := range ders {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), nil
}

// ---------------------------------------------------------------- HTTP-01-Token (hier und beim Nachbarn)

type tokenStore struct {
	mu sync.Mutex
	m  map[string]tokenEntry
}

type tokenEntry struct {
	ka  string
	exp time.Time
}

func (t *tokenStore) set(tok, ka string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = map[string]tokenEntry{}
	}
	now := time.Now()
	for k, e := range t.m {
		if now.After(e.exp) {
			delete(t.m, k)
		}
	}
	if len(t.m) < 1000 {
		t.m[tok] = tokenEntry{ka: ka, exp: now.Add(10 * time.Minute)}
	}
}

func (t *tokenStore) del(tok string) {
	t.mu.Lock()
	delete(t.m, tok)
	t.mu.Unlock()
}

func (t *tokenStore) get(tok string) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.m[tok]
	if !ok || time.Now().After(e.exp) {
		return "", false
	}
	return e.ka, true
}

// sharePeerToken gibt den Token an die Nachbarn (Let's Encrypt fragt einen der beiden Server).
func (s *Server) sharePeerToken(ctx context.Context, tok, ka string) {
	if pc := s.dialPeer(ctx, "acme", tok, 0, ka, nil); pc != nil { // Host = Token, Client = Key-Authorization
		_ = pc.Close()
	} else if len(s.cfg.Peers) > 0 {
		s.log.Warn("acme token not shared, no peer reachable")
	}
}

// serveToken beantwortet /.well-known/acme-challenge/<token> auf Port 80, wenn der Token hier bekannt ist.
func (s *Server) serveToken(c net.Conn, data []byte) bool {
	line, _, _ := strings.Cut(string(data), "\r\n")
	f := strings.Fields(line)
	if len(f) < 2 || f[0] != http.MethodGet {
		return false
	}
	tok, ok := strings.CutPrefix(f[1], "/.well-known/acme-challenge/")
	if !ok {
		return false
	}
	ka, found := s.acmeTokens.get(tok)
	if !found {
		return false
	}
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(ka), ka)
	_ = c.Close()
	return true
}

// acmeTXT setzt bzw. loescht den TXT-Eintrag ueber ipv64.
func (s *Server) acmeTXT(ctx context.Context, fqdn, value string, del bool) error {
	body, _ := json.Marshal(map[string]any{"fqdn": fqdn, "value": value, "delete": del})
	resp, err := s.apiRequest(ctx, http.MethodPost, "/cdn64o/edge/acme-txt", body)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	return nil
}

// waitTXT wartet, bis jeder Nameserver der Zone alle Werte liefert (hoechstens 3 Minuten).
var waitTXT = func(ctx context.Context, name, fqdn string, want []string) error {
	var servers [][]string
	for z := name; strings.Count(z, ".") >= 1; z = z[strings.IndexByte(z, '.')+1:] {
		ns, err := net.DefaultResolver.LookupNS(ctx, z)
		if err != nil || len(ns) == 0 {
			continue
		}
		for _, n := range ns {
			addrs, _ := net.DefaultResolver.LookupHost(ctx, strings.TrimSuffix(n.Host, "."))
			var list []string
			for _, a := range addrs {
				list = append(list, net.JoinHostPort(a, "53"))
			}
			if len(list) > 0 {
				servers = append(servers, list)
			}
		}
		break
	}
	if len(servers) == 0 {
		return errors.New("no nameservers found for " + name)
	}
	return waitTXTOn(ctx, servers, fqdn, want, 3*time.Minute)
}

// txtStableRounds: so viele Runden hintereinander muessen alle erreichbaren Adressen aller Nameserver alle Werte
// liefern. ns1/ns2.ipv64.net liefern kurz nach dem Anlegen abwechselnd alt/leer und neu; ein einzelner Treffer
// genuegte nicht (wie internal/certs, Test 2026-10-29). Variablen fuer Tests.
var (
	txtStableRounds = 3
	txtEvery        = 3 * time.Second
)

// waitTXTOn: ein Nameserver gilt, wenn eine seiner Adressen alle Werte liefert und keine erreichbare Adresse ohne sie
// antwortet (nicht erreichbare Adressen bzw. Familien zaehlen nicht).
func waitTXTOn(ctx context.Context, servers [][]string, fqdn string, want []string, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	stable := 0
	for {
		ok := 0
		for _, addrs := range servers {
			found, missing := false, false
			for _, a := range addrs {
				switch txtState(ctx, a, fqdn, want) {
				case txtAll:
					found = true
				case txtNotAll:
					missing = true
				}
			}
			if found && !missing {
				ok++
			}
		}
		if ok == len(servers) {
			if stable++; stable >= txtStableRounds {
				return nil
			}
		} else {
			stable = 0
		}
		// Frist um: laeuft gerade eine stabile Folge, wird sie noch zu Ende geprueft (hoechstens txtStableRounds-1 Runden)
		if time.Now().After(deadline) && stable == 0 {
			return fmt.Errorf("TXT not visible on %d of %d nameservers", len(servers)-ok, len(servers))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(txtEvery):
		}
	}
}

const (
	txtNoAnswer = iota // Adresse nicht erreichbar oder keine zustaendige Antwort
	txtNotAll          // zustaendige Antwort ohne alle Werte
	txtAll             // alle Werte da
)

// txtState fragt einen Nameserver direkt (ohne Rekursion). Nur eine zustaendige Antwort (AA, NOERROR/NXDOMAIN) zaehlt
// als „Wert fehlt“; REFUSED, SERVFAIL oder eine nicht zustaendige Antwort (umgeleitet) zaehlen wie keine Antwort, sonst
// hielte eine einzelne falsch eingerichtete Adresse den Nameserver bis zur Frist auf. Abgeschnitten: per TCP nochmal.
func txtState(ctx context.Context, server, fqdn string, want []string) int {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(fqdn), dns.TypeTXT)
	q.RecursionDesired = false
	c := &dns.Client{Timeout: 3 * time.Second}
	r, _, err := c.ExchangeContext(ctx, q, server)
	if err == nil && r != nil && r.Truncated {
		c.Net = "tcp"
		r, _, err = c.ExchangeContext(ctx, q, server)
	}
	if err != nil || r == nil || r.Truncated || !r.Authoritative || r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError {
		return txtNoAnswer
	}
	have := map[string]bool{}
	for _, rr := range r.Answer {
		if t, ok := rr.(*dns.TXT); ok {
			have[strings.Join(t.Txt, "")] = true
		}
	}
	for _, w := range want {
		if !have[w] {
			return txtNotAll
		}
	}
	return txtAll
}
