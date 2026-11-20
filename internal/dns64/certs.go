package dns64

import (
	"context"
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
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/dns64/dnsserver"
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
	m.certInUse.Store(0)
	var pending int64 // "central", aber noch nicht ausgestellt: kommt per OnChange
	if c.CertMode == certCentral {
		if m.certs != nil {
			if crt := m.certs.ByID(c.CertID); crt != nil {
				m.certInUse.Store(c.CertID)
				return *crt, certNames(crt.Leaf), nil
			}
			pending = c.CertID
			m.certInUse.Store(c.CertID)
		}
		c.CertMode = certSelf // bis dahin mit der Heimnetz-CA
	}
	if c.CertMode == certACME {
		if crt, leaf := m.acmeCert(acmeName(c)); crt != nil {
			return *crt, certNames(leaf), nil
		}
		// noch kein Zertifikat: bis zum Abruf mit der eigenen CA (Dienste laufen trotzdem)
		c.CertMode = certSelf
		if n := acmeName(c); n != "" && !slices.Contains(c.Names, n) {
			c.Names = append(c.Names, n)
		}
	}
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
	if m.certs != nil { // Heimnetz-CA in der Verwaltung
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		crt, id, err := m.centralSelf(ctx, c)
		cancel()
		if err == nil {
			if pending == 0 {
				m.certInUse.Store(id)
			}
			return *crt, certNames(crt.Leaf), nil
		}
		m.log.Warn("dns64 certificate from the certificate management failed, using the local CA", "err", err)
	}
	ca, caKey, err := m.loadOrCreateCA(m.caPermitted(c))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	dnsNames, ips := wantedNames(c.Names)
	dnsNames = permittedNames(ca.PermittedDNSDomains, dnsNames)
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

// caPermitted: Namen, auf die eine neue Heimnetz-CA beschraenkt wird (Review DN-1) - lokale Endungen, die
// eingestellten Namen fuer DoH/DoT, die lokalen Zonen und der Rechnername. Ohne Beschraenkung koennte, wer den
// CA-Schluessel hat, fuer Geraete mit installiertem Profil Zertifikate fuer jede Domain ausstellen.
func (m *Module) caPermitted(c config) []string {
	out := dnsserver.LocalNames() // Endungen, die nur im eigenen Netz gelten
	for _, n := range c.Names {
		if n = strings.TrimPrefix(hostName(n), "*."); n != "" && net.ParseIP(n) == nil && validName(n) {
			out = append(out, n)
		}
	}
	if zt := m.zns.Load(); zt != nil {
		for z := range zt.byName {
			out = append(out, z)
		}
	}
	if h, err := os.Hostname(); err == nil && validName(hostName(h)) {
		out = append(out, hostName(h))
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// permitsName: name liegt unter einer der Beschraenkungen (leer = keine Beschraenkung, alles erlaubt).
func permitsName(permitted []string, name string) bool {
	if len(permitted) == 0 {
		return true
	}
	for _, d := range permitted {
		if d = strings.TrimPrefix(d, "."); name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// permittedNames: nur die Namen, die die CA ausstellen darf (sonst lehnen Geraete das ganze Zertifikat ab).
func permittedNames(permitted, names []string) []string {
	out := names[:0:0]
	for _, n := range names {
		if permitsName(permitted, n) {
			out = append(out, n)
		}
	}
	return out
}

// homeCA: die Heimnetz-CA aus tls/ca.pem (nil = keine).
func (m *Module) homeCA() *x509.Certificate {
	der := m.caDER()
	if der == nil {
		return nil
	}
	ca, _ := x509.ParseCertificate(der)
	return ca
}

// renewCA legt eine neue, beschraenkte Heimnetz-CA an (Knopf in der Oberflaeche). Die alte bleibt als ca-<Zeit>.pem
// liegen und in der Zertifikatsverwaltung; Geraete brauchen danach die neue CA bzw. das neue Profil.
func (m *Module) renewCA(ctx context.Context) error {
	stamp := time.Now().UTC().Format("20060102-150405")
	for _, f := range []string{"ca.pem", "ca.key"} {
		old := filepath.Join(m.tlsDir(), f)
		if _, err := os.Stat(old); err == nil {
			if err := os.Rename(old, filepath.Join(m.tlsDir(), strings.Replace(f, "ca.", "ca-"+stamp+".", 1)+".old")); err != nil {
				return err
			}
		}
	}
	for _, f := range []string{"server.pem", "server.key"} {
		_ = os.Remove(filepath.Join(m.tlsDir(), f))
	}
	if _, _, err := m.loadOrCreateCA(m.caPermitted(m.loadConfig(ctx))); err != nil {
		return err
	}
	return m.core.SetSetting(ctx, setCAID, "") // die Verwaltung uebernimmt die neue CA beim naechsten Zertifikat
}

func (m *Module) loadOrCreateCA(permitted []string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
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
		// nur private Adressen und die Namen aus caPermitted (lokale Endungen, eigene DoH/DoT-Namen, Zonen)
		PermittedIPRanges:           certs.PrivateRanges(),
		PermittedDNSDomains:         permitted,
		PermittedDNSDomainsCritical: len(permitted) > 0,
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

// covers: das Zertifikat enthaelt genau die gewuenschten Adressen und alle gewuenschten Namen (eine Adresse, die
// die Node nicht mehr hat, fuehrt zu einem neuen Zertifikat).
func covers(c *x509.Certificate, names []string, ips []net.IP) bool {
	if len(c.IPAddresses) != len(ips) {
		return false
	}
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
