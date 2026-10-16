package dns64

import (
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
	"slices"
	"time"
)

// Frueher holte DNS64 selbst ein Zertifikat von Let's Encrypt (cert_mode acme, DNS-01 ueber die ipv64-API).
// Das macht jetzt die zentrale Zertifikatsverwaltung; hier bleibt nur, was der einmalige Umzug braucht (central.go):
// die Einstellungen und das gespeicherte Zertifikat unter acme/. Bis zum Umzug wird es weiter ausgeliefert, aber
// nicht mehr erneuert.

const (
	certACME     = "acme"
	setACMEDom   = "dns64.acme_domain"  // ipv64-Domain
	setACMEPre   = "dns64.acme_prefix"  // Praefix darunter ("" = Domain selbst)
	setACMEMail  = "dns64.acme_email"   // Mail fuer Let's Encrypt
	setACMEStage = "dns64.acme_staging" // 1 = Testumgebung
	setACMETOS   = "dns64.acme_tos"     // Nutzungsbedingungen akzeptiert (Datum)
)

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

// acmeCert laedt das gespeicherte Zertifikat (nil = keins, abgelaufen oder fuer einen anderen Namen).
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
