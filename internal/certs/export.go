package certs

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// Export: Zertifikate zum Weiterverwenden auf anderen Geraeten (NAS, Router, Server). Formate wie bei certbot
// (cert, chain, fullchain, privkey), dazu alles in einer Datei (HAProxy, Fritzbox), ZIP und PKCS#12.

// Formate fuer Download und API.
const (
	FormatFullchain = "fullchain" // Zertifikat + Zwischenzertifikate
	FormatCert      = "cert"      // nur das Zertifikat
	FormatChain     = "chain"     // nur die Zwischenzertifikate
	FormatKey       = "key"       // privater Schluessel
	FormatPEM       = "pem"       // fullchain + Schluessel in einer Datei
	FormatZIP       = "zip"       // alle Dateien
)

// ErrNoCert: das Zertifikat ist noch nicht ausgestellt.
var ErrNoCert = errors.New("certificate not issued yet")

// HasKey: das Format enthaelt den privaten Schluessel (Download wird im Audit vermerkt).
func HasKey(format string) bool {
	return format == FormatKey || format == FormatPEM || format == FormatZIP || format == "p12"
}

// Bundle ist ein ausgestelltes Zertifikat mit Schluessel.
type Bundle struct {
	ID          int64
	Name        string // Hauptname (fuer Dateinamen)
	CertPEM     string
	ChainPEM    string
	KeyPEM      string
	Fingerprint string // SHA-256 des Zertifikats, hex
	Leaf        *x509.Certificate
	chain       []*x509.Certificate
	key         any
}

// Bundle laedt ein Zertifikat samt Schluessel.
func (m *Manager) Bundle(ctx context.Context, id int64) (*Bundle, error) {
	var names, certPEM, keySealed string
	err := m.r.QueryRowContext(ctx, `SELECT names, cert_pem, key_pem FROM certs WHERE id = ?`, id).Scan(&names, &certPEM, &keySealed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if certPEM == "" {
		return nil, ErrNoCert
	}
	keyPEM, err := m.d.Box.Decrypt(keySealed)
	if err != nil {
		return nil, err
	}
	crt, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, err
	}
	b := &Bundle{ID: id, Name: strings.Split(names, ",")[0], KeyPEM: keyPEM, Leaf: crt.Leaf, key: crt.PrivateKey}
	sum := sha256.Sum256(crt.Certificate[0])
	b.Fingerprint = hex.EncodeToString(sum[:])
	b.CertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt.Certificate[0]}))
	for _, der := range crt.Certificate[1:] {
		b.ChainPEM += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		if c, err := x509.ParseCertificate(der); err == nil {
			b.chain = append(b.chain, c)
		}
	}
	return b, nil
}

// FileBase ist der Dateiname ohne Endung (Wildcard-Stern ersetzt).
func (b *Bundle) FileBase() string {
	return strings.ReplaceAll(strings.TrimPrefix(b.Name, "*."), "*", "_")
}

// File liefert ein Format als Dateiinhalt mit Dateiname und Typ.
func (b *Bundle) File(format string) (data []byte, filename, contentType string, err error) {
	base := b.FileBase()
	switch format {
	case FormatFullchain, "":
		return []byte(b.CertPEM + b.ChainPEM), base + ".fullchain.pem", "application/pem-certificate-chain", nil
	case FormatCert:
		return []byte(b.CertPEM), base + ".cert.pem", "application/x-pem-file", nil
	case FormatChain:
		return []byte(b.ChainPEM), base + ".chain.pem", "application/pem-certificate-chain", nil
	case FormatKey:
		return []byte(b.KeyPEM), base + ".privkey.pem", "application/x-pem-file", nil
	case FormatPEM:
		return []byte(b.CertPEM + b.ChainPEM + b.KeyPEM), base + ".pem", "application/x-pem-file", nil
	case FormatZIP:
		z, err := b.zip()
		return z, base + ".zip", "application/zip", err
	}
	return nil, "", "", invalid("format", "unknown format %q", format)
}

func (b *Bundle) zip() ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	mod := b.Leaf.NotBefore
	for _, f := range []struct{ name, data string }{
		{"fullchain.pem", b.CertPEM + b.ChainPEM}, {"cert.pem", b.CertPEM}, {"chain.pem", b.ChainPEM}, {"privkey.pem", b.KeyPEM},
	} {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: f.name, Method: zip.Deflate, Modified: mod})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(f.data)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// P12 liefert eine PKCS#12-Datei (Zertifikat, Kette, Schluessel) mit Passwort. legacy = alte Verschluesselung
// (3DES/RC2) fuer aeltere Geraete und Windows-Versionen, sonst AES-256.
func (b *Bundle) P12(password string, legacy bool) ([]byte, error) {
	if len(password) < 4 || len(password) > 128 {
		return nil, invalid("password", "4 to 128 characters")
	}
	enc := pkcs12.Modern2023
	if legacy {
		enc = pkcs12.LegacyDES
	}
	return enc.WithRand(rand.Reader).Encode(b.key, b.Leaf, b.chain, password)
}

// Meta sind die Angaben zu einem ausgestellten Zertifikat fuer Skripte (ohne Schluessel).
type Meta struct {
	ID          int64     `json:"id"`
	Names       []string  `json:"names"`
	Issuer      string    `json:"issuer"`
	Serial      string    `json:"serial"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	DaysLeft    int       `json:"days_left"`
	Fingerprint string    `json:"fingerprint_sha256"`
}

// Meta liefert die Angaben zum Zertifikat.
func (b *Bundle) Meta() Meta {
	return Meta{ID: b.ID, Names: certNames(b.Leaf), Issuer: issuerName(b.Leaf), Serial: strings.ToUpper(b.Leaf.SerialNumber.Text(16)),
		NotBefore: b.Leaf.NotBefore.UTC(), NotAfter: b.Leaf.NotAfter.UTC(), DaysLeft: int(time.Until(b.Leaf.NotAfter).Hours() / 24), Fingerprint: b.Fingerprint}
}
