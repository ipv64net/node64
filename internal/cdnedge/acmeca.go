package cdnedge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/net/publicsuffix"
)

// Zwei Zertifizierungsstellen: Let's Encrypt zuerst, ZeroSSL als Ausweg. Let's Encrypt stellt je registrierter
// Domain (z. B. any64.de - steht nicht auf der Public Suffix List, also teilen sich alle Kunden-Namen darunter die
// Grenze) hoechstens 50 neue Zertifikate je Woche aus. Der Server zaehlt seine Bestellungen (data_dir/acme-issued.json):
// ab acme_le_week_limit (Standard 40) neuen Zertifikaten einer Domain in 7 Tagen geht es zu ZeroSSL, ebenso nach
// einer Ablehnung "rateLimited" von Let's Encrypt (dann 24 h). Erneuerungen zaehlen bei Let's Encrypt nicht gegen die
// Grenze, werden aber mitgeschrieben. ZeroSSL braucht ein Konto mit EAB: aus der Konfiguration oder - mit acme_email -
// einmal bei ZeroSSL abgerufen und in data_dir gespeichert.

const (
	caLE              = "letsencrypt"
	caZeroSSL         = "zerossl"
	zeroSSLDir        = "https://acme.zerossl.com/v2/DV90"
	zeroSSLEABByEmail = "https://api.zerossl.com/acme/eab-credentials-email"
	leWeek            = 7 * 24 * time.Hour
	leCooldown        = 24 * time.Hour
)

// issuance: eine Bestellung (fuer die Zaehlung und /health).
type issuance struct {
	Name    string    `json:"name"`
	Domain  string    `json:"domain"` // registrierte Domain (eTLD+1)
	CA      string    `json:"ca"`
	At      time.Time `json:"at"`
	Renewal bool      `json:"renewal"`
}

type caState struct {
	mu       sync.Mutex
	path     string
	log      []issuance
	cooldown map[string]time.Time // Domain -> Let's Encrypt bis dahin nicht fragen (rateLimited)
	lastErr  map[string]string    // CA -> letzter Fehler
	clients  map[string]*acme.Client
}

func newCAState(dataDir string) *caState {
	c := &caState{path: filepath.Join(dataDir, "acme-issued.json"), cooldown: map[string]time.Time{}, lastErr: map[string]string{}, clients: map[string]*acme.Client{}}
	if b, err := os.ReadFile(c.path); err == nil {
		_ = json.Unmarshal(b, &c.log)
	}
	return c
}

// pslExtra: Eintraege der Public Suffix List, die die in Go eingebaute (aeltere) Liste noch nicht kennt.
var pslExtra = []string{"ipv64.net", "ipv64.de", "home64.de"}

// regDomain: registrierte Domain nach der Public Suffix List (Grenze von Let's Encrypt).
func regDomain(name string) string {
	n := strings.TrimPrefix(normName(name), "*.")
	for _, sfx := range pslExtra {
		if rest, ok := strings.CutSuffix(n, "."+sfx); ok {
			return rest[strings.LastIndexByte(rest, '.')+1:] + "." + sfx
		}
	}
	d, err := publicsuffix.EffectiveTLDPlusOne(n)
	if err != nil {
		return normName(name)
	}
	return d
}

// leCount: neue Zertifikate (ohne Erneuerungen) von Let's Encrypt fuer die Domain in den letzten 7 Tagen.
func (c *caState) leCount(domain string, now time.Time) int {
	n := 0
	for _, x := range c.log {
		if x.CA == caLE && !x.Renewal && x.Domain == domain && now.Sub(x.At) < leWeek {
			n++
		}
	}
	return n
}

// record schreibt eine Bestellung mit (Eintraege aelter als 8 Tage fallen weg).
func (c *caState) record(x issuance) {
	c.mu.Lock()
	defer c.mu.Unlock()
	keep := c.log[:0]
	for _, e := range c.log {
		if x.At.Sub(e.At) < leWeek+24*time.Hour {
			keep = append(keep, e)
		}
	}
	c.log = append(keep, x)
	if b, err := json.Marshal(c.log); err == nil {
		_ = os.WriteFile(c.path+".tmp", b, 0o600)
		_ = os.Rename(c.path+".tmp", c.path)
	}
}

// caInfo fuer /health.
type caInfo struct {
	LEWeekLimit int               `json:"le_week_limit"`
	LEWeek      map[string]int    `json:"le_week"`               // je Domain: neue Zertifikate in 7 Tagen
	Fallback    string            `json:"fallback"`              // zerossl | off
	FallbackWk  int               `json:"fallback_week"`         // bei ZeroSSL in 7 Tagen
	Cooldown    []string          `json:"le_cooldown,omitempty"` // Domains, die gerade zu ZeroSSL gehen
	LastErrors  map[string]string `json:"last_errors,omitempty"`
	Warn        []string          `json:"warn,omitempty"` // Domains ab 80 % der Grenze
}

func (s *Server) caInfo() caInfo {
	c, now := s.ca, time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	in := caInfo{LEWeekLimit: s.leLimit(), LEWeek: map[string]int{}, Fallback: s.fallbackName(), LastErrors: map[string]string{}}
	for _, x := range c.log {
		if now.Sub(x.At) >= leWeek {
			continue
		}
		if x.CA == caLE && !x.Renewal {
			in.LEWeek[x.Domain]++
		} else if x.CA == caZeroSSL {
			in.FallbackWk++
		}
	}
	for d, n := range in.LEWeek {
		if n*5 >= in.LEWeekLimit*4 {
			in.Warn = append(in.Warn, d)
		}
	}
	for d, t := range c.cooldown {
		if now.Before(t) {
			in.Cooldown = append(in.Cooldown, d)
		}
	}
	sort.Strings(in.Warn)
	sort.Strings(in.Cooldown)
	for k, v := range c.lastErr {
		in.LastErrors[k] = v
	}
	return in
}

func (s *Server) leLimit() int {
	if s.cfg.ACMELEWeekLimit > 0 {
		return s.cfg.ACMELEWeekLimit
	}
	return 40
}

// fallbackName: "zerossl", wenn moeglich (EAB in der Konfiguration oder E-Mail fuer den Abruf), sonst "off".
func (s *Server) fallbackName() string {
	if s.cfg.ACMEFallback == "off" || s.cfg.ACMEDir != "" { // eigenes Verzeichnis (z. B. Staging): kein Ausweg
		return "off"
	}
	if s.cfg.ACMEFallbackEABKID != "" || s.cfg.ACMEEmail != "" {
		return caZeroSSL
	}
	return "off"
}

// pickCA: Let's Encrypt, solange die Domain unter der Grenze liegt und nicht gesperrt ist; sonst ZeroSSL (falls da).
func (s *Server) pickCA(name string, renewal bool) (string, error) {
	d, now := regDomain(name), time.Now()
	s.ca.mu.Lock()
	cool := now.Before(s.ca.cooldown[d])
	n := s.ca.leCount(d, now)
	s.ca.mu.Unlock()
	if !cool && s.cfg.ACMELEWeekLimit >= 0 && (renewal || n < s.leLimit()) { // -1: Let's Encrypt aus
		return caLE, nil
	}
	if s.fallbackName() == caZeroSSL {
		return caZeroSSL, nil
	}
	if cool || s.cfg.ACMELEWeekLimit < 0 {
		return "", fmt.Errorf("let's encrypt rate limit for %s or switched off, no fallback configured", d)
	}
	return "", fmt.Errorf("%d new certificates for %s this week (limit %d), no fallback configured", n, d, s.leLimit())
}

// rateLimited: Ablehnung wegen einer Grenze von Let's Encrypt?
func rateLimited(err error) bool {
	var ae *acme.Error
	if errors.As(err, &ae) {
		return strings.HasSuffix(ae.ProblemType, ":rateLimited")
	}
	return err != nil && strings.Contains(err.Error(), "rateLimited")
}

// acmeClientFor: Konto je Zertifizierungsstelle (Schluessel in data_dir), einmal registriert und dann behalten.
func (s *Server) acmeClientFor(ctx context.Context, ca string) (*acme.Client, error) {
	s.ca.mu.Lock()
	cl := s.ca.clients[ca]
	s.ca.mu.Unlock()
	if cl != nil {
		return cl, nil
	}
	s.acmeMu.Lock()
	defer s.acmeMu.Unlock()
	keyFile, dir := "acme-account.pem", s.cfg.ACMEDir
	if dir == "" {
		dir = acme.LetsEncryptURL
	}
	if ca == caZeroSSL {
		keyFile, dir = "acme-account-zerossl.pem", s.cfg.ACMEFallbackDir
		if dir == "" {
			dir = zeroSSLDir
		}
	}
	key, err := loadOrCreateKey(filepath.Join(s.cfg.DataDir, keyFile))
	if err != nil {
		return nil, err
	}
	cl = &acme.Client{Key: key, DirectoryURL: dir, UserAgent: "cdn64-edge/" + s.version}
	acct := &acme.Account{}
	if s.cfg.ACMEEmail != "" {
		acct.Contact = []string{"mailto:" + s.cfg.ACMEEmail}
	}
	if ca == caZeroSSL {
		eab, err := s.zeroSSLEAB(ctx)
		if err != nil {
			return nil, err
		}
		acct.ExternalAccountBinding = eab
	}
	if _, err := cl.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("account %s: %w", ca, err)
	}
	s.ca.mu.Lock()
	s.ca.clients[ca] = cl
	s.ca.mu.Unlock()
	return cl, nil
}

func loadOrCreateKey(path string) (*ecdsa.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		if blk, _ := pem.Decode(b); blk != nil {
			if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
				return k, nil
			}
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	kb, _ := x509.MarshalECPrivateKey(k)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

// zeroSSLEAB: EAB aus der Konfiguration, sonst gespeichert, sonst einmal per E-Mail bei ZeroSSL abgerufen.
func (s *Server) zeroSSLEAB(ctx context.Context) (*acme.ExternalAccountBinding, error) {
	kid, hmac := s.cfg.ACMEFallbackEABKID, s.cfg.ACMEFallbackEABHMAC
	path := filepath.Join(s.cfg.DataDir, "acme-zerossl-eab.json")
	var saved struct {
		KID  string `json:"eab_kid"`
		HMAC string `json:"eab_hmac_key"`
	}
	if kid == "" {
		if b, err := os.ReadFile(path); err == nil && json.Unmarshal(b, &saved) == nil && saved.KID != "" {
			kid, hmac = saved.KID, saved.HMAC
		}
	}
	if kid == "" {
		if s.cfg.ACMEEmail == "" {
			return nil, errors.New("zerossl: no EAB and no acme_email")
		}
		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(rctx, http.MethodPost, zeroSSLEABURL, strings.NewReader(url.Values{"email": {s.cfg.ACMEEmail}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("zerossl eab: %w", err)
		}
		defer resp.Body.Close()
		var r struct {
			Success bool   `json:"success"`
			KID     string `json:"eab_kid"`
			HMAC    string `json:"eab_hmac_key"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&r); err != nil || !r.Success || r.KID == "" {
			return nil, fmt.Errorf("zerossl eab: http %d", resp.StatusCode)
		}
		kid, hmac = r.KID, r.HMAC
		saved.KID, saved.HMAC = kid, hmac
		b, _ := json.Marshal(saved)
		if err := os.WriteFile(path, b, 0o600); err != nil {
			return nil, err
		}
		s.log.Info("zerossl account credentials fetched", "email", s.cfg.ACMEEmail)
	}
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(hmac, "="))
	if err != nil {
		return nil, fmt.Errorf("zerossl eab hmac: %w", err)
	}
	return &acme.ExternalAccountBinding{KID: kid, Key: key}, nil
}

// zeroSSLEABURL (Tests: eigener Server).
var zeroSSLEABURL = zeroSSLEABByEmail
