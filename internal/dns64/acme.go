package dns64

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/acme"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/notify"
)

// Oeffentlich gueltiges Zertifikat von Let's Encrypt fuer einen Namen unter einer ipv64-Domain (cert_mode acme).
// Bestaetigt wird per DNS-01: der TXT-Record _acme-challenge.<name> wird ueber die ipv64-API v2 mit dem zentralen
// API-Key angelegt, DNS64 wartet, bis die ipv64-Nameserver ihn ausliefern, und loescht ihn danach wieder. Der Name
// muss im Internet nicht erreichbar sein; im Heimnetz zeigt ein eigener Eintrag auf die Node. Verlaengert wird
// 30 Tage vor Ablauf; das neue Zertifikat gilt sofort, ohne Neustart der Dienste.

const (
	certACME     = "acme"
	acmeStaging  = "https://acme-staging-v02.api.letsencrypt.org/directory"
	acmeTOS      = "https://letsencrypt.org/repository/"
	acmeRenew    = 30 * 24 * time.Hour
	acmeWaitDNS  = 3 * time.Minute
	setACMEDom   = "dns64.acme_domain"  // ipv64-Domain
	setACMEPre   = "dns64.acme_prefix"  // Praefix darunter ("" = Domain selbst)
	setACMEMail  = "dns64.acme_email"   // optional, fuer Hinweise von Let's Encrypt
	setACMEStage = "dns64.acme_staging" // 1 = Testumgebung (Zertifikat ohne Vertrauen)
	setACMETOS   = "dns64.acme_tos"     // Nutzungsbedingungen akzeptiert (Datum)
)

// SetKey installiert den zentralen ipv64-API-Key (Domains, TXT-Records fuer DNS-01).
func (m *Module) SetKey(k *ipv64api.Key) { m.key = k }

// acmeState ist der Stand des letzten Abrufs (fuer die Seite).
type acmeState struct {
	mu      sync.Mutex
	running bool
	step    string
	err     string
	at      time.Time
}

type acmeView struct {
	Running  bool
	Step     string
	Err      string
	At       time.Time
	Name     string
	NotAfter time.Time
	Staging  bool
	Issuer   string
}

func (m *Module) acmeDir() string { return filepath.Join(m.dir(), "acme") }

// acmeName ist der Name fuer das Zertifikat (Praefix + Domain).
func acmeName(c config) string {
	if c.ACMEDomain == "" {
		return ""
	}
	if c.ACMEPrefix == "" {
		return c.ACMEDomain
	}
	return c.ACMEPrefix + "." + c.ACMEDomain
}

// acmeCert laedt das gespeicherte Zertifikat (nil = keins oder fuer einen anderen Namen).
func (m *Module) acmeCert(name string) (*tls.Certificate, *x509.Certificate) {
	crt, err := tls.LoadX509KeyPair(filepath.Join(m.acmeDir(), "cert.pem"), filepath.Join(m.acmeDir(), "key.pem"))
	if err != nil {
		return nil, nil
	}
	leaf, err := x509.ParseCertificate(crt.Certificate[0])
	if err != nil || !slices.Contains(leaf.DNSNames, name) || time.Now().After(leaf.NotAfter) {
		return nil, nil
	}
	return &crt, leaf
}

func (m *Module) acmeView(c config) acmeView {
	s := &m.acme
	s.mu.Lock()
	v := acmeView{Running: s.running, Step: s.step, Err: s.err, At: s.at, Name: acmeName(c), Staging: c.ACMEStaging}
	s.mu.Unlock()
	if _, leaf := m.acmeCert(v.Name); leaf != nil {
		v.NotAfter = leaf.NotAfter
		v.Issuer = leaf.Issuer.CommonName
	}
	return v
}

func (m *Module) acmeStep(step string) {
	m.acme.mu.Lock()
	m.acme.step = step
	m.acme.mu.Unlock()
	m.log.Info("acme", "step", step)
}

// startACME holt bzw. erneuert das Zertifikat im Hintergrund (hoechstens ein Lauf gleichzeitig).
func (m *Module) startACME(reason string) bool {
	s := &m.acme
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return false
	}
	s.running, s.err, s.step = true, "", reason
	s.mu.Unlock()
	m.mu.Lock()
	bgCtx := m.bgCtx
	if bgCtx == nil || bgCtx.Err() != nil || m.life == nil { // Modul aus
		m.mu.Unlock()
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
		return false
	}
	m.bg.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.bg.Done()
		ctx, cancel := context.WithTimeout(bgCtx, 10*time.Minute)
		defer cancel()
		err := m.obtain(ctx)
		s.mu.Lock()
		s.running, s.at = false, time.Now()
		if err != nil {
			s.err = err.Error()
		} else {
			s.step = "ok"
		}
		s.mu.Unlock()
		if err != nil {
			m.log.Error("acme failed", "err", err)
			if m.notifier != nil {
				m.alertACME(err)
			}
		}
	}()
	return true
}

// obtain fuehrt den kompletten Ablauf aus: Konto, Auftrag, DNS-01 ueber ipv64, Zertifikat.
func (m *Module) obtain(ctx context.Context) error {
	c := m.loadConfig(ctx)
	name := acmeName(c)
	if name == "" {
		return errors.New("no domain configured")
	}
	if m.core.SettingOr(ctx, setACMETOS, "") == "" {
		return errors.New("terms of service of Let's Encrypt not accepted")
	}
	if m.key == nil || m.key.Get(ctx) == "" {
		return errors.New("no ipv64 API key (settings)")
	}
	apiKey, api := m.key.Get(ctx), m.key.Client()
	if err := os.MkdirAll(m.acmeDir(), 0o700); err != nil {
		return err
	}
	accKey, err := loadOrCreateKey(filepath.Join(m.acmeDir(), "account.key"))
	if err != nil {
		return err
	}
	cl := &acme.Client{Key: accKey, UserAgent: "Node64-DNS64/" + version}
	if c.ACMEStaging {
		cl.DirectoryURL = acmeStaging
	}
	m.acmeStep("account")
	acct := &acme.Account{}
	if c.ACMEEmail != "" {
		acct.Contact = []string{"mailto:" + c.ACMEEmail}
	}
	if _, err := cl.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return fmt.Errorf("account: %w", err)
	}
	m.acmeStep("order")
	order, err := cl.AuthorizeOrder(ctx, acme.DomainIDs(name))
	if err != nil {
		return fmt.Errorf("order: %w", err)
	}
	txtPrefix := "_acme-challenge"
	if c.ACMEPrefix != "" {
		txtPrefix += "." + c.ACMEPrefix
	}
	for _, u := range order.AuthzURLs {
		z, err := cl.GetAuthorization(ctx, u)
		if err != nil {
			return fmt.Errorf("authorization: %w", err)
		}
		if z.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, ch := range z.Challenges {
			if ch.Type == "dns-01" {
				chal = ch
			}
		}
		if chal == nil {
			return errors.New("no dns-01 challenge offered")
		}
		val, err := cl.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return err
		}
		m.acmeStep("txt")
		if _, err := api.AddRecord(ctx, apiKey, c.ACMEDomain, "TXT", txtPrefix, val); err != nil {
			return fmt.Errorf("ipv64 TXT record: %w", err)
		}
		cleanup := func() {
			dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
			defer cancel()
			if err := api.DeleteRecordByContent(dctx, apiKey, c.ACMEDomain, "TXT", txtPrefix, val); err != nil {
				m.log.Warn("acme TXT record not removed", "err", err)
			}
		}
		m.acmeStep("dns")
		if err := waitTXT(ctx, "_acme-challenge."+name, val, c.ACMEDomain); err != nil {
			cleanup()
			return err
		}
		m.acmeStep("validate")
		if _, err := cl.Accept(ctx, chal); err != nil {
			cleanup()
			return fmt.Errorf("accept: %w", err)
		}
		_, err = cl.WaitAuthorization(ctx, z.URI)
		cleanup()
		if err != nil {
			return fmt.Errorf("validation: %w", err)
		}
	}
	m.acmeStep("certificate")
	order, err = cl.WaitOrder(ctx, order.URI)
	if err != nil {
		return fmt.Errorf("order: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{name}}, key)
	if err != nil {
		return err
	}
	ders, _, err := cl.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("certificate: %w", err)
	}
	var chain []byte
	for _, d := range ders {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(m.acmeDir(), "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(m.acmeDir(), "cert.pem"), chain, 0o644); err != nil {
		return err
	}
	crt, leaf := m.acmeCert(name)
	if crt == nil {
		return errors.New("certificate could not be loaded")
	}
	m.cur.Store(crt) // gilt sofort fuer DoH/DoT/DoQ
	m.log.Info("acme certificate issued", "name", name, "until", leaf.NotAfter, "issuer", leaf.Issuer.CommonName)
	return nil
}

func loadOrCreateKey(path string) (crypto.Signer, error) {
	if raw, err := os.ReadFile(path); err == nil {
		if b, _ := pem.Decode(raw); b != nil {
			if k, err := x509.ParseECPrivateKey(b.Bytes); err == nil {
				return k, nil
			}
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	return k, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
}

// lookupNS findet die Nameserver der Zone (Domain oder eine Ebene darueber), als ip:53.
var lookupNS = func(ctx context.Context, domain string) ([]string, error) {
	name := domain
	var hosts []string
	for strings.Count(name, ".") >= 1 {
		if ns, err := net.DefaultResolver.LookupNS(ctx, name); err == nil && len(ns) > 0 {
			for _, n := range ns {
				hosts = append(hosts, strings.TrimSuffix(n.Host, "."))
			}
			break
		}
		name = name[strings.Index(name, ".")+1:]
	}
	var out []string
	for _, h := range hosts {
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", h)
		if err == nil && len(ips) > 0 {
			out = append(out, net.JoinHostPort(ips[0].String(), "53"))
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no nameserver for " + domain)
	}
	return out, nil
}

// waitTXT wartet, bis alle Nameserver der Zone den TXT-Record ausliefern (ipv64 schreibt nach einigen Sekunden).
func waitTXT(ctx context.Context, fqdn, want, zone string) error {
	servers, err := lookupNS(ctx, zone)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(acmeWaitDNS)
	for {
		ok := 0
		for _, s := range servers {
			if hasTXT(ctx, s, fqdn, want) {
				ok++
			}
		}
		if ok == len(servers) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("TXT record not visible on %d of %d nameservers after %s", len(servers)-ok, len(servers), acmeWaitDNS)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

func hasTXT(ctx context.Context, server, fqdn, want string) bool {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(fqdn), dns.TypeTXT)
	q.RecursionDesired = false
	c := &dns.Client{Timeout: 3 * time.Second}
	r, _, err := c.ExchangeContext(ctx, q, server)
	if err != nil || r == nil {
		return false
	}
	for _, rr := range r.Answer {
		if t, ok := rr.(*dns.TXT); ok && strings.Join(t.Txt, "") == want {
			return true
		}
	}
	return false
}

// acmeDue startet Abruf bzw. Verlaengerung, wenn noetig (aus der Ueberwachung, alle 30 s geprueft, nach einem
// Fehler erst wieder nach 6 Stunden).
func (m *Module) acmeDue(ctx context.Context) {
	c := m.loadConfig(ctx)
	name := acmeName(c)
	if c.CertMode != certACME || name == "" || m.core.SettingOr(ctx, setACMETOS, "") == "" {
		return
	}
	s := &m.acme
	s.mu.Lock()
	busy, failedRecently := s.running, s.err != "" && time.Since(s.at) < 6*time.Hour
	s.mu.Unlock()
	if busy || failedRecently {
		return
	}
	if _, leaf := m.acmeCert(name); leaf != nil && time.Until(leaf.NotAfter) > acmeRenew {
		return
	}
	m.startACME("renew")
}

// alertACME meldet einen gescheiterten Abruf (Standardkanaele).
func (m *Module) alertACME(err error) {
	ctx := context.Background()
	now := time.Now().UTC()
	m.notifier(notify.Alert{EventID: "dns64-cert-" + now.Format("20060102150405"), Kind: notify.KindDNS64Cert, Time: now,
		Check:  notify.CheckInfo{Name: acmeName(m.loadConfig(ctx)), NotifyDown: true, NotifyUp: true, Local: true},
		Reason: err.Error()})
}
