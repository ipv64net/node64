package certs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/ipv64net/node64/internal/store"
)

// Weitere ACME-Stellen neben Let's Encrypt: ZeroSSL, Google Trust Services, SSL.com (mit External Account
// Binding) oder eine eigene step-ca im Netz (mit eigener Root fuer die Verbindung). Das Konto nutzt denselben
// Schluessel wie bei Let's Encrypt; die Nutzungsbedingungen werden beim Anlegen angenommen.

// ACMEPreset ist eine bekannte Stelle (Vorlage im Formular).
type ACMEPreset struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Directory string `json:"directory"`
	EAB       bool   `json:"eab"`  // External Account Binding noetig
	Docs      string `json:"docs"` // wo es KID und HMAC gibt
}

// ACMEPresets: Vorlagen (Buypass hat den kostenlosen ACME-Dienst eingestellt und fehlt deshalb).
var ACMEPresets = []ACMEPreset{
	{ID: "zerossl", Name: "ZeroSSL", Directory: "https://acme.zerossl.com/v2/DV90", EAB: true, Docs: "https://app.zerossl.com/developer (EAB Credentials)"},
	{ID: "google", Name: "Google Trust Services", Directory: "https://dv.acme-v02.api.pki.goog/directory", EAB: true,
		Docs: "gcloud publicca external-account-keys create"},
	{ID: "sslcom", Name: "SSL.com", Directory: "https://acme.ssl.com/sslcom-dv-ecc", EAB: true, Docs: "SSL.com: Account → API Credentials"},
	{ID: "stepca", Name: "step-ca (eigenes Netz)", Directory: "https://ca.lan/acme/acme/directory", Docs: "step ca provisioner add acme --type ACME"},
}

// ACMECA ist eine weitere ACME-Stelle (ohne HMAC).
type ACMECA struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	Directory    string    `json:"directory"`
	EABKID       string    `json:"eab_kid,omitempty"`
	HasEAB       bool      `json:"eab"`
	CustomRoot   bool      `json:"custom_root"`
	Certificates int       `json:"certificates"`
	CreatedAt    time.Time `json:"created_at"`
	hmac         []byte
	root         string
}

// ACMECAInput: neue Stelle.
type ACMECAInput struct {
	Name      string `json:"name"`
	Directory string `json:"directory"`
	EABKID    string `json:"eab_kid"`
	EABHMAC   string `json:"eab_hmac"` // Base64 (URL oder Standard)
	RootPEM   string `json:"root_pem"` // optional: Root der Stelle (step-ca)
	AcceptTOS bool   `json:"accept_tos"`
}

func (m *Manager) loadACMECA(ctx context.Context, id int64) (*ACMECA, error) {
	var a ACMECA
	var hmacSealed, created string
	err := m.r.QueryRowContext(ctx, `SELECT id, name, directory, eab_kid, eab_hmac, root_pem, created_at FROM cert_acme_cas WHERE id = ?`, id).
		Scan(&a.ID, &a.Name, &a.Directory, &a.EABKID, &hmacSealed, &a.root, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.CreatedAt, a.HasEAB, a.CustomRoot = store.ParseTime(created), a.EABKID != "", a.root != ""
	if hmacSealed != "" {
		raw, err := m.d.Box.Decrypt(hmacSealed)
		if err != nil {
			return nil, err
		}
		a.hmac, _ = decodeHMAC(raw)
	}
	_ = m.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM certs WHERE acme_ca = ?`, id).Scan(&a.Certificates)
	return &a, nil
}

// ACMECA liefert eine Stelle.
func (m *Manager) ACMECA(ctx context.Context, id int64) (*ACMECA, error) {
	return m.loadACMECA(ctx, id)
}

// ACMECAs liefert alle weiteren Stellen (ohne HMAC zu entschluesseln, Zaehler in einer Abfrage).
func (m *Manager) ACMECAs(ctx context.Context) ([]*ACMECA, error) {
	counts := map[int64]int{}
	if rows, err := m.r.QueryContext(ctx, `SELECT acme_ca, COUNT(*) FROM certs WHERE acme_ca != 0 GROUP BY acme_ca`); err == nil {
		for rows.Next() {
			var id int64
			var n int
			if rows.Scan(&id, &n) == nil {
				counts[id] = n
			}
		}
		rows.Close()
	}
	rows, err := m.r.QueryContext(ctx, `SELECT id, name, directory, eab_kid, root_pem, created_at FROM cert_acme_cas ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ACMECA
	for rows.Next() {
		var a ACMECA
		var created string
		if err := rows.Scan(&a.ID, &a.Name, &a.Directory, &a.EABKID, &a.root, &created); err != nil {
			return nil, err
		}
		a.CreatedAt, a.HasEAB, a.CustomRoot, a.Certificates = store.ParseTime(created), a.EABKID != "", a.root != "", counts[a.ID]
		out = append(out, &a)
	}
	return out, rows.Err()
}

func decodeHMAC(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) > 0 {
			return b, nil
		}
	}
	return nil, errors.New("HMAC is not base64")
}

// httpClient mit eigener Root (zusaetzlich zu den System-Roots).
func acmeHTTPClient(rootPEM string) (*http.Client, error) {
	if rootPEM == "" {
		return nil, nil
	}
	pool, _ := x509.SystemCertPool()
	if pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM([]byte(rootPEM)) {
		return nil, errors.New("root certificate not readable")
	}
	return &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}, nil
}

// AddACMECA legt eine Stelle an. Das Verzeichnis wird dabei abgefragt (erreichbar? EAB noetig?).
func (m *Manager) AddACMECA(ctx context.Context, in ACMECAInput) (*ACMECA, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 100 {
		return nil, invalid("name", "1 to 100 characters")
	}
	u, err := url.Parse(strings.TrimSpace(in.Directory))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, invalid("directory", "https://… expected")
	}
	if !in.AcceptTOS {
		return nil, invalid("accept_tos", "terms of the CA must be accepted")
	}
	kid := strings.TrimSpace(in.EABKID)
	var hmac []byte
	if kid != "" || strings.TrimSpace(in.EABHMAC) != "" {
		if kid == "" {
			return nil, invalid("eab_kid", "missing")
		}
		if hmac, err = decodeHMAC(in.EABHMAC); err != nil {
			return nil, invalid("eab_hmac", "%v", err)
		}
	}
	root := strings.TrimSpace(in.RootPEM)
	hc, err := acmeHTTPClient(root)
	if err != nil {
		return nil, invalid("root_pem", "%v", err)
	}
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	dir, err := (&acme.Client{DirectoryURL: u.String(), HTTPClient: hc, UserAgent: "Node64/" + m.d.Version}).Discover(dctx)
	if err != nil {
		return nil, invalid("directory", "not reachable: %v", err)
	}
	if dir.ExternalAccountRequired && kid == "" {
		return nil, invalid("eab_kid", "this CA needs External Account Binding (KID and HMAC)")
	}
	sealed := ""
	if len(hmac) > 0 {
		sealed = m.d.Box.Encrypt(base64.RawURLEncoding.EncodeToString(hmac))
	}
	res, err := m.w.ExecContext(ctx, `INSERT INTO cert_acme_cas (name, directory, eab_kid, eab_hmac, root_pem, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		name, u.String(), kid, sealed, root, store.Now())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, invalid("directory", "this CA is already there")
		}
		return nil, err
	}
	id, _ := res.LastInsertId()
	return m.loadACMECA(ctx, id)
}

// DeleteACMECA entfernt eine Stelle, die kein Zertifikat mehr nutzt.
func (m *Manager) DeleteACMECA(ctx context.Context, id int64) error {
	a, err := m.loadACMECA(ctx, id)
	if err != nil {
		return err
	}
	if a.Certificates > 0 {
		return ErrInUse
	}
	_, err = m.w.ExecContext(ctx, `DELETE FROM cert_acme_cas WHERE id = ?`, id)
	m.mu.Lock()
	delete(m.reg, a.Directory)
	m.mu.Unlock()
	return err
}

// clientFor: ACME-Client fuer ein Zertifikat (Let's Encrypt oder eine weitere Stelle mit EAB).
func (m *Manager) clientFor(ctx context.Context, c *Cert) (*acme.Client, error) {
	if c.ACMECA == 0 {
		return m.client(ctx, c.Staging)
	}
	a, err := m.loadACMECA(ctx, c.ACMECA)
	if err != nil {
		return nil, fmt.Errorf("ACME CA: %w", err)
	}
	key, err := m.accountKey(ctx)
	if err != nil {
		return nil, err
	}
	hc, err := acmeHTTPClient(a.root)
	if err != nil {
		return nil, err
	}
	cl := &acme.Client{Key: key, DirectoryURL: a.Directory, HTTPClient: hc, UserAgent: "Node64/" + m.d.Version}
	m.mu.Lock()
	done := m.reg[a.Directory]
	m.mu.Unlock()
	if done {
		return cl, nil
	}
	acct := &acme.Account{}
	if e := m.Account(ctx).Email; e != "" {
		acct.Contact = []string{"mailto:" + e}
	}
	if a.EABKID != "" {
		acct.ExternalAccountBinding = &acme.ExternalAccountBinding{KID: a.EABKID, Key: a.hmac}
	}
	if _, err := cl.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("account at %s: %w", a.Name, err)
	}
	m.mu.Lock()
	m.reg[a.Directory] = true
	m.mu.Unlock()
	return cl, nil
}
