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
	chain        []*x509.Certificate // die CA und ihre uebergeordneten (wie gespeichert)
	chainPEM     string              // CA mit uebergeordneten (ohne selbst signierte Root, fuer die Kette der Zertifikate)
	allPEM       string
	key          crypto.Signer // nur nach loadCA(..., true)
}

// CAInput: neue CA.
type CAInput struct {
	Name        string   `json:"name"`
	KeyType     string   `json:"key_type"`    // ecdsa (Standard) oder rsa
	Constrained *bool    `json:"constrained"` // nur private Namen/IPs (Standard an)
	Domains     []string `json:"domains"`     // zusaetzlich erlaubte Domains bei Einschraenkung
}

func selfSigned(c *x509.Certificate) bool {
	return c.Subject.String() == c.Issuer.String() && c.CheckSignatureFrom(c) == nil
}

// parseCAInfo liest das CA-Zertifikat samt Kette, ohne den Schluessel zu entschluesseln (Listen, Pruefungen,
// Download).
func parseCAInfo(id int64, name, certPEM string, imported bool, created string) (*CA, error) {
	ca := &CA{ID: id, Name: name, Imported: imported, CreatedAt: store.ParseTime(created), allPEM: certPEM}
	rest := []byte(certPEM)
	for {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		ca.chain = append(ca.chain, c)
		if !selfSigned(c) { // Root gehoert nicht in die Kette des Servers
			ca.chainPEM += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
		}
	}
	if len(ca.chain) == 0 {
		return nil, errors.New("CA certificate not readable")
	}
	ca.cert = ca.chain[0]
	ca.fill()
	return ca, nil
}

// attachKey entschluesselt den Schluessel (nur zum Ausstellen).
func (ca *CA) attachKey(keySealed string, box interface {
	Decrypt(string) (string, error)
}) error {
	keyPEM, err := box.Decrypt(keySealed)
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair([]byte(ca.allPEM), []byte(keyPEM))
	if err != nil {
		return err
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return errors.New("CA key cannot sign")
	}
	ca.key = signer
	return nil
}

func (ca *CA) fill() {
	c := ca.cert
	ca.Subject, ca.NotAfter = c.Subject.CommonName, c.NotAfter.UTC()
	ca.Root = selfSigned(c)
	ca.PermittedDNS = c.PermittedDNSDomains
	ca.PermittedIP = nil
	for _, n := range c.PermittedIPRanges {
		ca.PermittedIP = append(ca.PermittedIP, n.String())
	}
	sum := sha256.Sum256(c.Raw)
	ca.Fingerprint = hex.EncodeToString(sum[:])
}

// anchor: das Zertifikat, dem Geraete vertrauen sollen (die Root der Kette, falls mit importiert, sonst die CA).
func (ca *CA) anchor() *x509.Certificate {
	for i := len(ca.chain) - 1; i >= 0; i-- {
		if selfSigned(ca.chain[i]) {
			return ca.chain[i]
		}
	}
	return ca.cert
}

func matchDomain(name, constraint string) bool {
	constraint = strings.ToLower(constraint)
	if strings.HasPrefix(constraint, ".") {
		return strings.HasSuffix(name, constraint)
	}
	return name == constraint || strings.HasSuffix(name, "."+constraint)
}

// permits prueft Namen und IPs gegen die Name Constraints der CA und ihrer uebergeordneten CAs (erlaubt und
// ausgeschlossen), wie es die Clients beim Pruefen tun.
func (ca *CA) permits(names []string) error {
	for _, n := range names {
		ip := net.ParseIP(n)
		base := strings.TrimPrefix(n, "*.")
		for _, c := range ca.chain {
			if ip != nil {
				for _, r := range c.ExcludedIPRanges {
					if r.Contains(ip) {
						return fmt.Errorf("%s is excluded by %s", n, c.Subject.CommonName)
					}
				}
				if len(c.PermittedIPRanges) > 0 {
					ok := false
					for _, r := range c.PermittedIPRanges {
						ok = ok || r.Contains(ip)
					}
					if !ok {
						return fmt.Errorf("%s is not allowed by the CA %s (only private addresses)", n, c.Subject.CommonName)
					}
				}
				continue
			}
			for _, d := range c.ExcludedDNSDomains {
				if matchDomain(base, d) {
					return fmt.Errorf("%s is excluded by %s", n, c.Subject.CommonName)
				}
			}
			if len(c.PermittedDNSDomains) > 0 {
				ok := false
				for _, d := range c.PermittedDNSDomains {
					ok = ok || matchDomain(base, d)
				}
				if !ok {
					return fmt.Errorf("%s is not allowed by the CA %s (allowed: %s)", n, c.Subject.CommonName, strings.Join(c.PermittedDNSDomains, ", "))
				}
			}
		}
	}
	return nil
}

const caCols = `id, name, cert_pem, key_pem, imported, created_at`

// loadCA liest eine CA; withKey entschluesselt den Schluessel (nur zum Ausstellen).
func (m *Manager) loadCA(ctx context.Context, id int64, withKey bool) (*CA, error) {
	var name, certPEM, key, created string
	var imported bool
	err := m.r.QueryRowContext(ctx, `SELECT `+caCols+` FROM cert_cas WHERE id = ?`, id).Scan(&id, &name, &certPEM, &key, &imported, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	ca, err := parseCAInfo(id, name, certPEM, imported, created)
	if err != nil {
		return nil, err
	}
	if withKey {
		if err := ca.attachKey(key, m.d.Box); err != nil {
			return nil, err
		}
	}
	return ca, nil
}

// caCounts: ausgestellte Zertifikate je CA (eine Abfrage fuer alle).
func (m *Manager) caCounts(ctx context.Context) map[int64]int {
	out := map[int64]int{}
	rows, err := m.r.QueryContext(ctx, `SELECT ca_id, COUNT(*) FROM certs WHERE source = ? GROUP BY ca_id`, SourceCA)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var n int
		if rows.Scan(&id, &n) == nil {
			out[id] = n
		}
	}
	return out
}

// CAs liefert alle eigenen CAs.
func (m *Manager) CAs(ctx context.Context) ([]*CA, error) {
	rows, err := m.r.QueryContext(ctx, `SELECT id, name, cert_pem, imported, created_at FROM cert_cas ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*CA
	for rows.Next() {
		var id int64
		var name, certPEM, created string
		var imported bool
		if err := rows.Scan(&id, &name, &certPEM, &imported, &created); err != nil {
			return nil, err
		}
		ca, err := parseCAInfo(id, name, certPEM, imported, created)
		if err != nil {
			m.log.Error("CA not readable", "id", id, "err", err)
			continue
		}
		out = append(out, ca)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	counts := m.caCounts(ctx)
	for _, ca := range out {
		ca.Certificates = counts[ca.ID]
	}
	return out, nil
}

// GetCA liefert eine CA.
func (m *Manager) GetCA(ctx context.Context, id int64) (*CA, error) {
	ca, err := m.loadCA(ctx, id, false)
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
	m.changed(ctx, ItemCAs, id)
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
	m.changed(ctx, ItemCAs, id)
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
	uid := m.deleting(ctx, ItemCAs, id)
	if _, err = m.w.ExecContext(ctx, `DELETE FROM cert_cas WHERE id = ?`, id); err == nil {
		m.changedUID(ctx, ItemCAs, uid, true)
	}
	return err
}

// CAFile liefert das CA-Zertifikat zum Verteilen: pem (mit Kette), crt (DER, Windows/Android) oder mobileconfig
// (iOS/macOS).
func (m *Manager) CAFile(ctx context.Context, id int64, format string) (data []byte, filename, contentType string, err error) {
	ca, err := m.loadCA(ctx, id, false)
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
	case "crt": // Vertrauensanker: bei einer Zwischen-CA die mit importierte Root
		return ca.anchor().Raw, base + ".crt", "application/x-x509-ca-cert", nil
	case "mobileconfig":
		return []byte(caProfile(ca)), base + ".mobileconfig", "application/x-apple-aspen-config", nil
	}
	return nil, "", "", invalid("format", "pem, crt or mobileconfig")
}

func caProfile(ca *CA) string {
	x := html.EscapeString
	root := ca.anchor()
	sum := sha256.Sum256(root.Raw)
	fp := hex.EncodeToString(sum[:])
	uid := func(kind string) string {
		h := sha256.Sum256([]byte(kind + fp))
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
`, x(ca.Name), base64.StdEncoding.EncodeToString(root.Raw), x(ca.Name), fp[:16], uid("ca"), x(ca.Name), fp[:16], uid("profile"))
}

func serialNumber() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n.Add(n, big.NewInt(1))
}

// issueFromCA stellt ein Zertifikat mit der eigenen CA aus (statt ACME).
func (m *Manager) issueFromCA(ctx context.Context, c *Cert) error {
	m.step(c.ID, "certificate")
	ca, err := m.loadCA(ctx, c.CAID, true)
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
	return m.storeIssued(ctx, c.ID, c.Names, chain, leaf, key)
}

// storeIssued speichert ein neues Zertifikat samt den Namen, auf die es ausgestellt ist, und laedt es sofort.
func (m *Manager) storeIssued(ctx context.Context, id int64, names []string, chain string, leaf *x509.Certificate, key crypto.PrivateKey) error {
	keyPEM, err := marshalKey(key)
	if err != nil {
		return err
	}
	now := store.Now()
	if _, err := m.w.ExecContext(ctx, `UPDATE certs SET names = ?, cert_pem = ?, key_pem = ?, not_before = ?, not_after = ?, issuer = ?, status = ?, last_error = '',
		last_attempt = ?, warned = '', renewer = '', updated_at = ? WHERE id = ?`, strings.Join(names, ","), chain, m.d.Box.Encrypt(keyPEM), store.FormatTime(leaf.NotBefore),
		store.FormatTime(leaf.NotAfter), issuerName(leaf), StatusValid, now, now, id); err != nil {
		return err
	}
	if err := m.reload(ctx); err != nil { // gilt sofort, ohne Neustart
		return err
	}
	m.issued(id)
	m.changed(ctx, ItemCertificates, id) // wer ausstellt, erneuert ab jetzt (renewer '')
	return nil
}

// issued meldet ein neues Zertifikat an die Abnehmer (OnChange).
func (m *Manager) issued(id int64) {
	m.mu.Lock()
	fs := append([]func(int64){}, m.onChg...)
	m.mu.Unlock()
	for _, f := range fs {
		go f(id)
	}
}

// OnChange meldet jede neue Ausstellung bzw. Erneuerung (Kennung) an f, ausserhalb aller Sperren. Abnehmer, die
// das Zertifikat zwischenspeichern (DNS64: m.cur), tauschen es damit ohne Neustart.
func (m *Manager) OnChange(f func(id int64)) {
	m.mu.Lock()
	m.onChg = append(m.onChg, f)
	m.mu.Unlock()
}
