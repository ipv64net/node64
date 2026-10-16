package certs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"time"
)

// Selbst signierte Zertifikate: ohne Let's Encrypt und ohne eigene CA, z. B. fuer node64.home.local oder den Zugriff
// per IP. Browser warnen, bis man dem Zertifikat vertraut; fuer mehrere Geraete ist eine eigene CA bequemer (nur
// die CA muss man einmal vertrauen). Erneuert wird wie bei der eigenen CA (30 Tage vor Ablauf, bei kurzer Laufzeit
// im letzten Drittel) - nach einer Erneuerung muss man dem neuen Zertifikat erneut vertrauen.

// SourceSelf: selbst signiert (Namen und IPs, ohne Voraussetzung).
const SourceSelf = "self"

// Schluessel fuer selbst signierte Zertifikate.
const (
	KeyECDSA = "ecdsa" // P-256 (Standard)
	KeyRSA   = "rsa"   // 2048 Bit, fuer sehr alte Geraete
)

func selfKey(kind string) (crypto.Signer, error) {
	if kind == KeyRSA {
		return rsa.GenerateKey(rand.Reader, 2048)
	}
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// issueSelfSigned stellt das Zertifikat aus, sofort und ohne ACME.
func (m *Manager) issueSelfSigned(ctx context.Context, c *Cert) error {
	m.step(c.ID, "certificate")
	days := c.Days
	if days <= 0 {
		days = defaultCADays
	}
	key, err := selfKey(c.KeyType)
	if err != nil {
		return err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serialNumber(),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, // CA:FALSE
	}
	if _, isRSA := key.(*rsa.PrivateKey); isRSA {
		tpl.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	for _, n := range c.Names {
		if ip := net.ParseIP(n); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, n)
		}
	}
	tpl.Subject.CommonName = c.Names[0]
	tpl.Subject.Organization = []string{"Node64 (selbst signiert)"}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		return fmt.Errorf("certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	return m.storeIssued(ctx, c.ID, c.Names, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), leaf, key)
}
