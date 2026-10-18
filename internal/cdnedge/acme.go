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
	"os"
	"path/filepath"
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
// Token bekommt auch der Nachbar, weil Let's Encrypt einen der beiden fragt). Die naechste Erneuerung versucht
// wieder DNS-01.

// obtain: Zertifikat und Schluessel (PEM) fuer name und *.name, sonst nur name.
func (s *Server) obtain(ctx context.Context, name string) ([]byte, []byte, error) {
	if s.obtainHook != nil { // Tests
		return s.obtainHook(ctx, name)
	}
	cp, kp, err := s.obtainDNS(ctx, name)
	if err == nil {
		return cp, kp, nil
	}
	s.log.Warn("dns-01 failed, trying http-01 (name only, no wildcard)", "name", name, "err", err)
	cp, kp, herr := s.obtainHTTP(ctx, name)
	if herr != nil {
		return nil, nil, fmt.Errorf("dns-01: %v; http-01: %w", err, herr)
	}
	return cp, kp, nil
}

func (s *Server) obtainDNS(ctx context.Context, name string) ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cl, err := s.acmeClient(ctx)
	if err != nil {
		return nil, nil, err
	}
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
func (s *Server) obtainHTTP(ctx context.Context, name string) ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	cl, err := s.acmeClient(ctx)
	if err != nil {
		return nil, nil, err
	}
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

// acmeClient: Konto des Servers (Schluessel in data_dir/acme-account.pem), einmal registriert und dann behalten.
func (s *Server) acmeClient(ctx context.Context) (*acme.Client, error) {
	s.acmeMu.Lock()
	defer s.acmeMu.Unlock()
	if s.acmeCl != nil {
		return s.acmeCl, nil
	}
	path := filepath.Join(s.cfg.DataDir, "acme-account.pem")
	var key *ecdsa.PrivateKey
	if b, err := os.ReadFile(path); err == nil {
		if blk, _ := pem.Decode(b); blk != nil {
			key, _ = x509.ParseECPrivateKey(blk.Bytes)
		}
	}
	if key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		kb, _ := x509.MarshalECPrivateKey(k)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
			return nil, err
		}
		key = k
	}
	dir := s.cfg.ACMEDir
	if dir == "" {
		dir = acme.LetsEncryptURL
	}
	cl := &acme.Client{Key: key, DirectoryURL: dir, UserAgent: "cdn64-edge/" + s.version}
	acct := &acme.Account{}
	if s.cfg.ACMEEmail != "" {
		acct.Contact = []string{"mailto:" + s.cfg.ACMEEmail}
	}
	if _, err := cl.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("account: %w", err)
	}
	s.acmeCl = cl
	return cl, nil
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
	deadline := time.Now().Add(3 * time.Minute)
	for {
		ok := 0
		for _, addrs := range servers {
			for _, a := range addrs {
				if hasAllTXT(ctx, a, fqdn, want) {
					ok++
					break
				}
			}
		}
		if ok == len(servers) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("TXT not visible on %d of %d nameservers", len(servers)-ok, len(servers))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

func hasAllTXT(ctx context.Context, server, fqdn string, want []string) bool {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(fqdn), dns.TypeTXT)
	q.RecursionDesired = false
	r, _, err := (&dns.Client{Timeout: 3 * time.Second}).ExchangeContext(ctx, q, server)
	if err != nil || r == nil {
		return false
	}
	have := map[string]bool{}
	for _, rr := range r.Answer {
		if t, ok := rr.(*dns.TXT); ok {
			have[strings.Join(t.Txt, "")] = true
		}
	}
	for _, w := range want {
		if !have[w] {
			return false
		}
	}
	return true
}
