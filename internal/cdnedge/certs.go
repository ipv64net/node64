package cdnedge

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Zertifikate fuer Modus 2 (Abschnitt 6 der Planung): je Name eins fuer "name" und "*.name" von Let's Encrypt per
// DNS-01 (TXT ueber ipv64, acme.go). Ein Server bestellt (acme_primary, der andere erst, wenn eins 10 Minuten
// fehlt) und legt Zertifikat und Schluessel verschluesselt (AES-256-GCM, cert_key nur auf den Servern) bei ipv64 ab;
// der andere holt es dort. Lokal liegen sie in data_dir/certs (0600). Erneuerung 30 Tage vor Ablauf.

const certRenewBefore = 30 * 24 * time.Hour

type edgeCert struct {
	tls      *tls.Certificate
	notAfter time.Time
}

type certStore struct {
	dir  string
	mu   sync.RWMutex
	m    map[string]*edgeCert
	kick chan struct{}
}

func newCertStore(dir string) *certStore {
	c := &certStore{dir: dir, m: map[string]*edgeCert{}, kick: make(chan struct{}, 1)}
	c.load()
	return c
}

func (c *certStore) kickLoop() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

// has: gueltiges Zertifikat fuer den Namen vorhanden.
func (c *certStore) has(name string) bool { return c.get(name) != nil }

func (c *certStore) get(name string) *tls.Certificate {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if e := c.m[name]; e != nil && time.Now().Before(e.notAfter) {
		return e.tls
	}
	return nil
}

// covers: gueltiges Zertifikat des Namens, das auch host abdeckt. Bei Wildcard-Namen fehlt *.name, wenn es nach
// gescheitertem DNS-01 per HTTP-01 nur fuer den Namen ausgestellt wurde: Unternamen dann nicht hier beenden.
func (c *certStore) covers(name, host string) bool {
	crt := c.get(name)
	if crt == nil {
		return false
	}
	if host = normName(host); host == "" || host == name {
		return true
	}
	return crt.Leaf != nil && crt.Leaf.VerifyHostname(host) == nil
}

// hasWildcard: das Zertifikat des Namens enthaelt *.name.
func (c *certStore) hasWildcard(name string) bool {
	crt := c.get(name)
	return crt != nil && crt.Leaf != nil && slices.Contains(crt.Leaf.DNSNames, "*."+name)
}

func (c *certStore) notAfter(name string) time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if e := c.m[name]; e != nil {
		return e.notAfter
	}
	return time.Time{}
}

// put prueft das Paar (passt zum Namen, Schluessel passt) und legt es ab.
func (c *certStore) put(name string, certPEM, keyPEM []byte) error {
	crt, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(crt.Certificate[0])
	if err != nil {
		return err
	}
	if err := leaf.VerifyHostname(name); err != nil {
		return err
	}
	crt.Leaf = leaf
	if c.dir != "" {
		if err := os.MkdirAll(c.dir, 0o700); err != nil {
			return err
		}
		tmp := filepath.Join(c.dir, name+".pem.tmp")
		if err := os.WriteFile(tmp, append(append([]byte{}, certPEM...), keyPEM...), 0o600); err != nil {
			return err
		}
		if err := os.Rename(tmp, filepath.Join(c.dir, name+".pem")); err != nil {
			return err
		}
	}
	c.mu.Lock()
	c.m[name] = &edgeCert{tls: &crt, notAfter: leaf.NotAfter}
	c.mu.Unlock()
	return nil
}

func (c *certStore) load() {
	if c.dir == "" {
		return
	}
	files, _ := filepath.Glob(filepath.Join(c.dir, "*.pem"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		crt, err := tls.X509KeyPair(b, b)
		if err != nil {
			continue
		}
		if leaf, err := x509.ParseCertificate(crt.Certificate[0]); err == nil {
			crt.Leaf = leaf
			c.m[strings.TrimSuffix(filepath.Base(f), ".pem")] = &edgeCert{tls: &crt, notAfter: leaf.NotAfter}
		}
	}
}

// remove loescht das Zertifikat eines Namens (Speicher und Datei).
func (c *certStore) remove(name string) {
	c.mu.Lock()
	delete(c.m, name)
	c.mu.Unlock()
	if c.dir != "" {
		_ = os.Remove(filepath.Join(c.dir, name+".pem"))
	}
}

func (c *certStore) list() map[string]time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := map[string]time.Time{}
	for n, e := range c.m {
		out[n] = e.notAfter
	}
	return out
}

// ---------------------------------------------------------------- Ablage bei ipv64 (verschluesselt)

type certBlob struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

func (s *Server) certAEAD() (cipher.AEAD, error) {
	k, err := hex.DecodeString(s.cfg.CertKey)
	if err != nil || len(k) != 32 {
		return nil, errors.New("cert_key: 64 hex characters expected")
	}
	b, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func (s *Server) sealCert(name string, certPEM, keyPEM []byte) (string, error) {
	g, err := s.certAEAD()
	if err != nil {
		return "", err
	}
	plain, _ := json.Marshal(certBlob{Cert: string(certPEM), Key: string(keyPEM)})
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(g.Seal(nonce, nonce, plain, []byte(name))), nil
}

func (s *Server) openCert(name, blob string) ([]byte, []byte, error) {
	g, err := s.certAEAD()
	if err != nil {
		return nil, nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil || len(raw) < g.NonceSize() {
		return nil, nil, errors.New("blob unreadable")
	}
	plain, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], []byte(name)) // Name gebunden: kein Vertauschen
	if err != nil {
		return nil, nil, errors.New("blob not decryptable (cert_key?)")
	}
	var b certBlob
	if err := json.Unmarshal(plain, &b); err != nil {
		return nil, nil, err
	}
	return []byte(b.Cert), []byte(b.Key), nil
}

// apiGetCert holt das abgelegte Zertifikat (nil, nil = keins da).
func (s *Server) apiGetCert(ctx context.Context, name string) (certPEM, keyPEM []byte, err error) {
	resp, err := s.apiRequest(ctx, http.MethodGet, "/cdn64o/edge/certs?fqdn="+url.QueryEscape(name), nil)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("cert get: http %d", resp.StatusCode)
	}
	var env struct {
		Data struct {
			Blob string `json:"blob"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&env); err != nil {
		return nil, nil, err
	}
	return s.openCert(name, env.Data.Blob)
}

func (s *Server) apiPutCert(ctx context.Context, name string, certPEM, keyPEM []byte, notAfter time.Time) error {
	blob, err := s.sealCert(name, certPEM, keyPEM)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"fqdn": name, "blob": blob, "not_after": notAfter.UTC().Format(time.RFC3339)})
	resp, err := s.apiRequest(ctx, http.MethodPut, "/cdn64o/edge/certs", body)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("cert put: http %d", resp.StatusCode)
	}
	return nil
}

// ---------------------------------------------------------------- Ablauf

// certKeep: so lange bleibt das Zertifikat eines Namens, der nicht mehr in Modus 2 ist (erneutes Einschalten
// braucht dann keine neue Bestellung, schont die Let's-Encrypt-Limits).
const certKeep = 7 * 24 * time.Hour

// certWildRetry: Wildcard-Name mit Zertifikat nur fuer den Namen (HTTP-01-Ausweg) - so oft (mit Verdopplung bis
// 24 h) wird DNS-01 fuer *.name erneut versucht, statt bis zur Erneuerung zu warten.
const certWildRetry = 6 * time.Hour

type certPlan struct {
	goneSince    map[string]time.Time
	missingSince map[string]time.Time
	nextTry      map[string]time.Time
	backoff      map[string]time.Duration
}

// certLoop: jede Minute und nach neuer Konfiguration pruefen, holen oder bestellen.
func (s *Server) certLoop(ctx context.Context) {
	if s.cfg.APIURL == "" {
		return
	}
	p := newCertPlan()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.certs.kick:
		}
		s.certRound(ctx, p)
	}
}

// certNames: Modus-2-Namen von ipv64 (sortiert, damit die Reihenfolge stabil ist).
func (s *Server) certNames() []string {
	c := s.apiCfg.Load()
	if c == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, h := range c.Hosts {
		if n := normName(h.Name); (h.Mode == 2 || (h.Mode == 3 && h.Target != nil && h.Target.Frontend > 1)) && n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func newCertPlan() *certPlan {
	return &certPlan{goneSince: map[string]time.Time{}, missingSince: map[string]time.Time{}, nextTry: map[string]time.Time{}, backoff: map[string]time.Duration{}}
}

func (s *Server) certRound(ctx context.Context, p *certPlan) {
	now := time.Now()
	names := s.certNames()
	if s.apiCfg.Load() != nil { // ohne Konfiguration nichts loeschen
		want := map[string]bool{}
		for _, n := range names {
			want[n] = true
			delete(p.goneSince, n)
		}
		for _, m := range []map[string]time.Time{p.missingSince, p.nextTry} { // Plan fuer entfernte Namen vergessen
			for n := range m {
				if !want[n] {
					delete(m, n)
				}
			}
		}
		for n := range p.backoff {
			if !want[n] {
				delete(p.backoff, n)
			}
		}
		for n := range s.certs.list() {
			if want[n] {
				continue
			}
			if _, ok := p.goneSince[n]; !ok {
				p.goneSince[n] = now
			} else if now.Sub(p.goneSince[n]) > certKeep {
				s.certs.remove(n)
				delete(p.goneSince, n)
				s.log.Info("certificate removed (name no longer in mode 2)", "name", n)
			}
		}
	}
	for _, name := range names {
		valid := time.Until(s.certs.notAfter(name)) > certRenewBefore
		_, wildName := s.routes.Load().wild[name]
		wild := valid && wildName && !s.certs.hasWildcard(name) // nur per HTTP-01: frueher wieder DNS-01
		if valid && !wild {
			delete(p.missingSince, name)
			continue
		}
		if wild {
			if _, ok := p.nextTry[name]; !ok {
				p.nextTry[name] = now.Add(certWildRetry)
			}
			if now.Before(p.nextTry[name]) {
				continue
			}
		}
		if s.cfg.CertKey != "" { // vielleicht hat der andere Server schon eins
			if cp, kp, err := s.apiGetCert(ctx, name); err != nil {
				s.log.Debug("cert from ipv64", "name", name, "err", err)
			} else if cp != nil {
				if err := s.certs.put(name, cp, kp); err != nil {
					s.log.Warn("cert from ipv64 unusable", "name", name, "err", err)
				} else if time.Until(s.certs.notAfter(name)) > certRenewBefore && (!wildName || s.certs.hasWildcard(name)) {
					s.log.Info("certificate taken from ipv64", "name", name, "not_after", s.certs.notAfter(name))
					delete(p.missingSince, name)
					continue
				}
			}
		}
		if _, ok := p.missingSince[name]; !ok {
			p.missingSince[name] = now
		}
		primary := s.cfg.ACMEPrimary || s.cfg.CertKey == ""
		if wild && !primary { // bestellt nur der erste Server, der andere holt es bei ipv64
			p.nextTry[name] = now.Add(certWildRetry)
			continue
		}
		if !primary && now.Sub(p.missingSince[name]) < 10*time.Minute {
			continue
		}
		if now.Before(p.nextTry[name]) {
			continue
		}
		certPEM, keyPEM, err := s.obtain(ctx, name)
		if err != nil {
			b := max(p.backoff[name]*2, 5*time.Minute)
			p.backoff[name] = min(b, 6*time.Hour)
			if wild {
				p.backoff[name] = min(max(p.backoff[name], certWildRetry), 24*time.Hour)
			}
			p.nextTry[name] = now.Add(p.backoff[name])
			s.log.Warn("certificate not obtained", "name", name, "err", err, "retry", p.nextTry[name].Format(time.RFC3339))
			continue
		}
		delete(p.backoff, name)
		delete(p.nextTry, name)
		if err := s.certs.put(name, certPEM, keyPEM); err != nil {
			s.log.Warn("obtained certificate unusable", "name", name, "err", err)
			continue
		}
		s.log.Info("certificate obtained", "name", name, "not_after", s.certs.notAfter(name))
		if s.cfg.CertKey != "" {
			if err := s.apiPutCert(ctx, name, certPEM, keyPEM, s.certs.notAfter(name)); err != nil {
				s.log.Warn("certificate not stored at ipv64", "name", name, "err", err)
			}
		}
	}
}
