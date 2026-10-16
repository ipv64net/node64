package certs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"html"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/store"
)

// Eigene CAs: fuer Geraete im eigenen Netz, die kein oeffentliches Zertifikat bekommen (Namen wie nas.lan, IP-
// Adressen). Eine CA wird erzeugt oder importiert (auch eine Zwischen-CA unter einer Offline-Root). Standard beim
// Erzeugen: nur private Namen und Adressen (Name Constraints), damit eine gestohlene CA keine Internet-Domains
// faelschen kann. Geraete vertrauen der CA einmal (PEM, .crt, iOS-/macOS-Profil).

const (
	defaultCADays = 397 // wie oeffentliche Zertifikate; Browser akzeptieren bei privaten CAs auch mehr
	maxCADays     = 825 // Grenze von Apple
	caYears       = 10
)

// Private Namen, die eine eingeschraenkte CA bestaetigen darf (dazu eigene Domains).
var privateDomains = []string{"lan", "home.arpa", "internal", "local", "localdomain", "home", "intranet", "corp", "private", "localhost"}

func privateRanges() []*net.IPNet {
	var out []*net.IPNet
	for _, s := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"fc00::/7", "fe80::/10", "::1/128"} {
		_, n, _ := net.ParseCIDR(s)
		out = append(out, n)
	}
	return out
}

// CA ist eine eigene CA (ohne Schluessel).
type CA struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	Subject      string    `json:"subject"`
	NotAfter     time.Time `json:"not_after"`
	Imported     bool      `json:"imported"`
	Root         bool      `json:"root"` // selbst signiert (sonst Zwischen-CA)
	PermittedDNS []string  `json:"permitted_dns,omitempty"`
	PermittedIP  []string  `json:"permitted_ip,omitempty"`
	Fingerprint  string    `json:"fingerprint_sha256"`
	Certificates int       `json:"certificates"` // davon ausgestellte Zertifikate
	CreatedAt    time.Time `json:"created_at"`
	cert         *x509.Certificate
	chainPEM     string // CA mit uebergeordneten (ohne selbst signierte Root, fuer die Kette der Zertifikate)
	allPEM       string
	key          crypto.Signer
}

// CAInput: neue CA.
type CAInput struct {
	Name        string   `json:"name"`
	KeyType     string   `json:"key_type"`    // ecdsa (Standard) oder rsa
	Constrained *bool    `json:"constrained"` // nur private Namen/IPs (Standard an)
	Domains     []string `json:"domains"`     // zusaetzlich erlaubte Domains bei Einschraenkung
}

func parseCA(id int64, name, certPEM, keySealed string, imported bool, created string, box interface {
	Decrypt(string) (string, error)
}) (*CA, error) {
	keyPEM, err := box.Decrypt(keySealed)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, err
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("CA key cannot sign")
	}
	ca := &CA{ID: id, Name: name, Imported: imported, CreatedAt: store.ParseTime(created), cert: pair.Leaf, key: signer, allPEM: certPEM}
	ca.fill()
	for _, der := range pair.Certificate {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		if c.CheckSignatureFrom(c) == nil && c.Subject.String() == c.Issuer.String() {
			continue // Root gehoert nicht in die Kette des Servers
		}
		ca.chainPEM += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	return ca, nil
}

func (ca *CA) fill() {
	c := ca.cert
	ca.Subject, ca.NotAfter = c.Subject.CommonName, c.NotAfter.UTC()
	ca.Root = c.Subject.String() == c.Issuer.String() && c.CheckSignatureFrom(c) == nil
	ca.PermittedDNS = c.PermittedDNSDomains
	ca.PermittedIP = nil
	for _, n := range c.PermittedIPRanges {
		ca.PermittedIP = append(ca.PermittedIP, n.String())
	}
	sum := sha256.Sum256(c.Raw)
	ca.Fingerprint = hex.EncodeToString(sum[:])
}

// permits prueft Namen und IPs gegen die Name Constraints der CA.
func (ca *CA) permits(names []string) error {
	c := ca.cert
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			if len(c.PermittedIPRanges) == 0 {
				continue
			}
			ok := false
			for _, r := range c.PermittedIPRanges {
				ok = ok || r.Contains(ip)
			}
			if !ok {
				return fmt.Errorf("%s is not allowed by the CA (only private addresses)", n)
			}
			continue
		}
		if len(c.PermittedDNSDomains) == 0 {
			continue
		}
		base := strings.TrimPrefix(n, "*.")
		ok := false
		for _, d := range c.PermittedDNSDomains {
			d = strings.ToLower(d)
			if strings.HasPrefix(d, ".") {
				ok = ok || strings.HasSuffix(base, d)
			} else {
				ok = ok || base == d || strings.HasSuffix(base, "."+d)
			}
		}
		if !ok {
			return fmt.Errorf("%s is not allowed by the CA (allowed: %s)", n, strings.Join(c.PermittedDNSDomains, ", "))
		}
	}
	return nil
}

const caCols = `id, name, cert_pem, key_pem, imported, created_at`

func (m *Manager) loadCA(ctx context.Context, id int64) (*CA, error) {
	var name, certPEM, key, created string
	var imported bool
	err := m.r.QueryRowContext(ctx, `SELECT `+caCols+` FROM cert_cas WHERE id = ?`, id).Scan(&id, &name, &certPEM, &key, &imported, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return parseCA(id, name, certPEM, key, imported, created, m.d.Box)
}

// CAs liefert alle eigenen CAs.
func (m *Manager) CAs(ctx context.Context) ([]*CA, error) {
	rows, err := m.r.QueryContext(ctx, `SELECT `+caCols+` FROM cert_cas ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*CA
	for rows.Next() {
		var id int64
		var name, certPEM, key, created string
		var imported bool
		if err := rows.Scan(&id, &name, &certPEM, &key, &imported, &created); err != nil {
			return nil, err
		}
		ca, err := parseCA(id, name, certPEM, key, imported, created, m.d.Box)
		if err != nil {
			m.log.Error("CA not readable", "id", id, "err", err)
			continue
		}
		out = append(out, ca)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, ca := range out {
		_ = m.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM certs WHERE source = ? AND ca_id = ?`, SourceCA, ca.ID).Scan(&ca.Certificates)
	}
	return out, nil
}

// GetCA liefert eine CA.
func (m *Manager) GetCA(ctx context.Context, id int64) (*CA, error) {
	ca, err := m.loadCA(ctx, id)
	if err != nil {
		return nil, err
	}
	_ = m.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM certs WHERE source = ? AND ca_id = ?`, SourceCA, id).Scan(&ca.Certificates)
	return ca, nil
}

func caName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return "", invalid("name", "1 to 100 characters")
	}
	return name, nil
}

// CreateCA erzeugt eine neue CA (10 Jahre).
func (m *Manager) CreateCA(ctx context.Context, in CAInput) (*CA, error) {
	name, err := caName(in.Name)
	if err != nil {
		return nil, err
	}
	var key crypto.Signer
	switch in.KeyType {
	case "", "ecdsa":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "rsa":
		key, err = rsa.GenerateKey(rand.Reader, 3072)
	default:
		return nil, invalid("key_type", "ecdsa or rsa")
	}
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serialNumber(),
		Subject:               pkix.Name{CommonName: name, Organization: []string{"Node64"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(caYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	if in.Constrained == nil || *in.Constrained {
		domains := append([]string{}, privateDomains...)
		for _, d := range in.Domains {
			d = strings.TrimPrefix(strings.TrimSpace(d), "*.")
			if d == "" {
				continue
			}
			nd, err := edge.NormalizeName(d)
			if err != nil || strings.Contains(nd, "*") {
				return nil, invalid("domains", "%s is not a domain", d)
			}
			domains = append(domains, nd)
		}
		tpl.PermittedDNSDomainsCritical = true
		tpl.PermittedDNSDomains = domains
		tpl.PermittedIPRanges = privateRanges()
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	keyPEM, err := marshalKey(key)
	if err != nil {
		return nil, err
	}
	return m.insertCA(ctx, name, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), keyPEM, false)
}

// ImportCA uebernimmt eine vorhandene CA (Zertifikat, bei einer Zwischen-CA mit Kette, und Schluessel als PEM).
func (m *Manager) ImportCA(ctx context.Context, name, certPEM, keyPEM string) (*CA, error) {
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, invalid("cert", "certificate and key do not fit: %v", err)
	}
	c := pair.Leaf
	if !c.IsCA || (c.KeyUsage != 0 && c.KeyUsage&x509.KeyUsageCertSign == 0) {
		return nil, invalid("cert", "not a CA certificate (CA:TRUE and keyCertSign needed)")
	}
	if time.Now().After(c.NotAfter) {
		return nil, invalid("cert", "CA expired on %s", c.NotAfter.UTC().Format(time.DateOnly))
	}
	if _, ok := pair.PrivateKey.(crypto.Signer); !ok {
		return nil, invalid("key", "key cannot sign")
	}
	if strings.TrimSpace(name) == "" {
		name = c.Subject.CommonName
	}
	if name, err = caName(name); err != nil {
		return nil, err
	}
	var chain []byte
	for _, der := range pair.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyOut, err := marshalKey(pair.PrivateKey)
	if err != nil {
		return nil, invalid("key", "%v", err)
	}
	var exists int
	sum := sha256.Sum256(c.Raw)
	if rows, err := m.r.QueryContext(ctx, `SELECT cert_pem FROM cert_cas`); err == nil {
		for rows.Next() {
			var p string
			if rows.Scan(&p) == nil {
				if b, _ := pem.Decode([]byte(p)); b != nil && sha256.Sum256(b.Bytes) == sum {
					exists++
				}
			}
		}
		rows.Close()
	}
	if exists > 0 {
		return nil, invalid("cert", "this CA is already there")
	}
	return m.insertCA(ctx, name, string(chain), keyOut, true)
}

func (m *Manager) insertCA(ctx context.Context, name, certPEM, keyPEM string, imported bool) (*CA, error) {
	res, err := m.w.ExecContext(ctx, `INSERT INTO cert_cas (name, cert_pem, key_pem, imported, created_at) VALUES (?, ?, ?, ?, ?)`,
		name, certPEM, m.d.Box.Encrypt(keyPEM), imported, store.Now())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return m.GetCA(ctx, id)
}

// RenameCA aendert den Anzeigenamen.
func (m *Manager) RenameCA(ctx context.Context, id int64, name string) error {
	name, err := caName(name)
	if err != nil {
		return err
	}
	res, err := m.w.ExecContext(ctx, `UPDATE cert_cas SET name = ? WHERE id = ?`, name, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteCA entfernt eine CA, die kein Zertifikat mehr ausstellt.
func (m *Manager) DeleteCA(ctx context.Context, id int64) error {
	ca, err := m.GetCA(ctx, id)
	if err != nil {
		return err
	}
	if ca.Certificates > 0 {
		return ErrInUse
	}
	_, err = m.w.ExecContext(ctx, `DELETE FROM cert_cas WHERE id = ?`, id)
	return err
}

// CAFile liefert das CA-Zertifikat zum Verteilen: pem (mit Kette), crt (DER, Windows/Android) oder mobileconfig
// (iOS/macOS).
func (m *Manager) CAFile(ctx context.Context, id int64, format string) (data []byte, filename, contentType string, err error) {
	ca, err := m.loadCA(ctx, id)
	if err != nil {
		return nil, "", "", err
	}
	base := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, ca.Name)
	switch format {
	case "", "pem":
		return []byte(ca.allPEM), base + ".pem", "application/x-pem-file", nil
	case "crt":
		return ca.cert.Raw, base + ".crt", "application/x-x509-ca-cert", nil
	case "mobileconfig":
		return []byte(caProfile(ca)), base + ".mobileconfig", "application/x-apple-aspen-config", nil
	}
	return nil, "", "", invalid("format", "pem, crt or mobileconfig")
}

func caProfile(ca *CA) string {
	x := html.EscapeString
	uid := func(kind string) string {
		h := sha256.Sum256([]byte(kind + ca.Fingerprint))
		s := strings.ToUpper(hex.EncodeToString(h[:16]))
		return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key><string>%s.cer</string>
			<key>PayloadContent</key><data>%s</data>
			<key>PayloadDisplayName</key><string>%s</string>
			<key>PayloadIdentifier</key><string>net.ipv64.node64.ca.%s</string>
			<key>PayloadType</key><string>com.apple.security.root</string>
			<key>PayloadUUID</key><string>%s</string>
			<key>PayloadVersion</key><integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key><string>CA von Node64 fuer Geraete im eigenen Netz</string>
	<key>PayloadDisplayName</key><string>%s</string>
	<key>PayloadIdentifier</key><string>net.ipv64.node64.ca-profile.%s</string>
	<key>PayloadRemovalDisallowed</key><false/>
	<key>PayloadType</key><string>Configuration</string>
	<key>PayloadUUID</key><string>%s</string>
	<key>PayloadVersion</key><integer>1</integer>
</dict>
</plist>
`, x(ca.Name), base64.StdEncoding.EncodeToString(ca.cert.Raw), x(ca.Name), ca.Fingerprint[:16], uid("ca"), x(ca.Name), ca.Fingerprint[:16], uid("profile"))
}

func serialNumber() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n.Add(n, big.NewInt(1))
}

// issueFromCA stellt ein Zertifikat mit der eigenen CA aus (statt ACME).
func (m *Manager) issueFromCA(ctx context.Context, c *Cert) error {
	m.step(c.ID, "certificate")
	ca, err := m.loadCA(ctx, c.CAID)
	if err != nil {
		return fmt.Errorf("CA: %w", err)
	}
	if err := ca.permits(c.Names); err != nil {
		return err
	}
	days := c.Days
	if days <= 0 {
		days = defaultCADays
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tpl := &x509.Certificate{
		SerialNumber: serialNumber(),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	if tpl.NotAfter.After(ca.cert.NotAfter) {
		tpl.NotAfter = ca.cert.NotAfter
	}
	for _, n := range c.Names {
		if ip := net.ParseIP(n); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, n)
		}
	}
	tpl.Subject.CommonName = c.Names[0]
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return fmt.Errorf("certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	chain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + ca.chainPEM
	return m.storeIssued(ctx, c.ID, chain, leaf, key)
}

// storeIssued speichert ein neues Zertifikat und laedt es sofort.
func (m *Manager) storeIssued(ctx context.Context, id int64, chain string, leaf *x509.Certificate, key crypto.PrivateKey) error {
	keyPEM, err := marshalKey(key)
	if err != nil {
		return err
	}
	now := store.Now()
	if _, err := m.w.ExecContext(ctx, `UPDATE certs SET cert_pem = ?, key_pem = ?, not_before = ?, not_after = ?, issuer = ?, status = ?, last_error = '',
		last_attempt = ?, warned = '', updated_at = ? WHERE id = ?`, chain, m.d.Box.Encrypt(keyPEM), store.FormatTime(leaf.NotBefore),
		store.FormatTime(leaf.NotAfter), issuerName(leaf), StatusValid, now, now, id); err != nil {
		return err
	}
	return m.reload(ctx) // gilt sofort, ohne Neustart
}
