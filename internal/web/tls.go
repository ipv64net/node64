package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/ipv64net/node64/internal/config"
)

// loadOrCreateCertificate laedt das eigene Zertifikat aus der Konfiguration
// oder erzeugt beim ersten Start ein selbstsigniertes unter DataDir/tls.
func loadOrCreateCertificate(cfg *config.Config, log *slog.Logger) (tls.Certificate, error) {
	certFile, keyFile := cfg.TLSCertFile, cfg.TLSKeyFile
	if certFile == "" {
		certFile = filepath.Join(cfg.TLSDir(), "cert.pem")
		keyFile = filepath.Join(cfg.TLSDir(), "key.pem")
		if _, err := os.Stat(certFile); errors.Is(err, os.ErrNotExist) {
			if err := createSelfSigned(certFile, keyFile); err != nil {
				return tls.Certificate{}, err
			}
			log.Info("self-signed certificate created", "file", certFile)
		}
	}
	return tls.LoadX509KeyPair(certFile, keyFile)
}

func createSelfSigned(certFile, keyFile string) error {
	if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Node64", Organization: []string{"Node64 (self-signed)"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	if host != "" {
		tmpl.DNSNames = append(tmpl.DNSNames, host)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
}
