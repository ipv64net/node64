package dns64

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"
)

// Zertifikate fuer die verschluesselten Dienste (DoH, DoT, DoQ). Standard: eine eigene kleine CA fuer das
// Heimnetz (10 Jahre) und ein davon ausgestelltes Server-Zertifikat mit allen Namen und IPs der Node
// (800 Tage, Apple erlaubt hoechstens 825). Geraete vertrauen einmal der CA (Download / iOS-Profil); aendern
// sich Namen oder IPs, wird nur das Server-Zertifikat neu ausgestellt. Die CA darf nur private Adressen
// bestaetigen (Name Constraints). Alternativ das Zertifikat der Weboberflaeche (NODE64_TLS_CERT).

const (
	certSelf   = "self"   // eigene CA (Standard)
	certNode64 = "node64" // Zertifikat der Weboberflaeche
	leafDays   = 800
	renewDays  = 30
)

// SetWebCert setzt die Dateien des Zertifikats der Weboberflaeche (fuer cert_mode node64).
func (m *Module) SetWebCert(certFile, keyFile string) { m.webCert, m.webKey = certFile, keyFile }

func (m *Module) tlsDir() string { return filepath.Join(m.dir(), "tls") }

// CACertFile ist die CA zum Herunterladen.
func (m *Module) caFile() string { return filepath.Join(m.tlsDir(), "ca.pem") }

// serverCert liefert das Zertifikat fuer DoH/DoT/DoQ und die Namen, auf die es lautet.
func (m *Module) serverCert(c config) (tls.Certificate, []string, error) {
	if c.CertMode == certNode64 {
		if m.webCert == "" {
			return tls.Certificate{}, nil, errors.New("no web certificate")
		}
		crt, err := tls.LoadX509KeyPair(m.webCert, m.webKey)
		if err != nil {
			return crt, nil, err
		}
		leaf, err := x509.ParseCertificate(crt.Certificate[0])
		if err != nil {
			return crt, nil, err
		}
		return crt, certNames(leaf), nil
	}
	ca, caKey, err := m.loadOrCreateCA()
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	dnsNames, ips := wantedNames(c.Names)
	certFile, keyFile := filepath.Join(m.tlsDir(), "server.pem"), filepath.Join(m.tlsDir(), "server.key")
	if crt, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil {
		if leaf, err := x509.ParseCertificate(crt.Certificate[0]); err == nil && covers(leaf, dnsNames, ips) &&
			time.Until(leaf.NotAfter) > renewDays*24*time.Hour && leaf.CheckSignatureFrom(ca) == nil {
			return crt, certNames(leaf), nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: firstOr(dnsNames, "node64-dns64"), Organization: []string{"Node64 DNS64"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(leafDays * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	if err := writeKeyPair(certFile, keyFile, der, key); err != nil {
		return tls.Certificate{}, nil, err
	}
	m.log.Info("dns64 server certificate issued", "names", dnsNames, "ips", len(ips))
	crt, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return crt, nil, err
	}
	leaf, _ := x509.ParseCertificate(crt.Certificate[0])
	return crt, certNames(leaf), nil
}

func (m *Module) loadOrCreateCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certFile, keyFile := m.caFile(), filepath.Join(m.tlsDir(), "ca.key")
	if crt, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil {
		ca, err := x509.ParseCertificate(crt.Certificate[0])
		key, ok := crt.PrivateKey.(*ecdsa.PrivateKey)
		if err == nil && ok && time.Until(ca.NotAfter) > leafDays*24*time.Hour {
			return ca, key, nil
		}
	}
	if err := os.MkdirAll(m.tlsDir(), 0o700); err != nil {
		return nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	host, _ := os.Hostname()
	tpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "Node64 DNS64 CA " + host, Organization: []string{"Node64 DNS64 (Heimnetz)"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		// nur private Adressen; Namen bleiben frei (eigene Namen wie nas.home.lan oder eine ipv64-Domain)
		PermittedIPRanges: privateRanges(),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	if err := writeKeyPair(certFile, keyFile, der, key); err != nil {
		return nil, nil, err
	}
	m.log.Info("dns64 home CA created", "file", certFile)
	ca, err := x509.ParseCertificate(der)
	return ca, key, err
}

func privateRanges() []*net.IPNet {
	var out []*net.IPNet
	for _, s := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"fc00::/7", "fe80::/10", "::1/128"} {
		_, n, _ := net.ParseCIDR(s)
		out = append(out, n)
	}
	return out
}

// wantedNames: eingestellte Namen, Rechnername, localhost und alle privaten Adressen der Node.
func wantedNames(extra []string) ([]string, []net.IP) {
	names := append([]string{}, extra...)
	if h, err := os.Hostname(); err == nil && h != "" {
		names = append(names, h)
	}
	names = append(names, "localhost")
	ips := []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.IPv6loopback}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			// private und CGNAT-Adressen; keine Link-Local-Adressen (169.254.x, fe80::), die wechseln und nutzt niemand
			if !ok || n.IP.IsLoopback() || n.IP.IsLinkLocalUnicast() || !(n.IP.IsPrivate() || isCGNAT(n.IP)) {
				continue
			}
			if v4 := n.IP.To4(); v4 != nil {
				ips = append(ips, v4)
			} else {
				ips = append(ips, n.IP)
			}
		}
	}
	sort.Strings(names)
	names = slices.Compact(names)
	return names, ips
}

func isCGNAT(ip net.IP) bool {
	_, n, _ := net.ParseCIDR("100.64.0.0/10")
	return n.Contains(ip)
}

// covers: das Zertifikat enthaelt alle gewuenschten Namen und Adressen.
func covers(c *x509.Certificate, names []string, ips []net.IP) bool {
	for _, n := range names {
		if !slices.Contains(c.DNSNames, n) {
			return false
		}
	}
	for _, ip := range ips {
		if !slices.ContainsFunc(c.IPAddresses, ip.Equal) {
			return false
		}
	}
	return true
}

func certNames(c *x509.Certificate) []string {
	out := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

func writeKeyPair(certFile, keyFile string, der []byte, key *ecdsa.PrivateKey) error {
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}

func firstOr(s []string, def string) string {
	if len(s) > 0 {
		return s[0]
	}
	return def
}
