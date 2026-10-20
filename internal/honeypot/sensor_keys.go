package honeypot

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
)

// Dateien im Datenverzeichnis (beim ersten Start erzeugt, danach wiederverwendet: gleicher Fingerabdruck wie ein
// echter Server, der nicht bei jedem Neustart einen neuen Schluessel hat).
const (
	sensorHostKeyFile = "ssh_host_ed25519"
	sensorCertFile    = "tls.crt"
	sensorKeyFile     = "tls.key"
)

// sshSigner liefert den SSH-Host-Schluessel (ed25519). Ohne Datenverzeichnis nur im Speicher.
func (s *Sensor) sshSigner() (ssh.Signer, error) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	if s.signer != nil {
		return s.signer, nil
	}
	path := filepath.Join(s.dir, sensorHostKeyFile)
	if s.dir != "" {
		if b, err := os.ReadFile(path); err == nil {
			if sg, err := ssh.ParsePrivateKey(b); err == nil {
				s.signer = sg
				return sg, nil
			}
			s.log.Warn("honeypot ssh host key unreadable, generating a new one", "file", path)
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sg, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	if s.dir != "" {
		blk, err := ssh.MarshalPrivateKey(priv, "")
		if err != nil {
			return nil, err
		}
		if err := sensorWriteFile(path, pem.EncodeToMemory(blk)); err != nil {
			return nil, err
		}
	}
	s.signer = sg
	return sg, nil
}

// tlsCert liefert das selbst signierte Zertifikat fuer HTTPS (ECDSA P-256, 10 Jahre).
func (s *Sensor) tlsCert() (*tls.Certificate, error) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	if s.cert != nil {
		return s.cert, nil
	}
	crtPath, keyPath := filepath.Join(s.dir, sensorCertFile), filepath.Join(s.dir, sensorKeyFile)
	if s.dir != "" {
		if c, err := tls.LoadX509KeyPair(crtPath, keyPath); err == nil {
			s.cert = &c
			return &c, nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})
	if s.dir != "" {
		if err := sensorWriteFile(keyPath, keyPEM); err != nil {
			return nil, err
		}
		if err := sensorWriteFile(crtPath, crtPEM); err != nil {
			return nil, err
		}
	}
	c, err := tls.X509KeyPair(crtPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	s.cert = &c
	return &c, nil
}

// sensorWriteFile schreibt atomar mit 0600 (Verzeichnis 0700).
func sensorWriteFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
