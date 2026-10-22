package honeypot

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
)

// Dateien im Datenverzeichnis (beim ersten Start erzeugt, danach wiederverwendet: gleicher Fingerabdruck wie ein
// echter Server, der nicht bei jedem Neustart einen neuen Schluessel hat).
const (
	sensorHostKeyFile  = "ssh_host_ed25519"
	sensorHostKeyECDSA = "ssh_host_ecdsa"
	sensorHostKeyRSA   = "ssh_host_rsa"
	sensorCertFile     = "tls.crt"
	sensorKeyFile      = "tls.key"
)

// sshSigner liefert den SSH-Host-Schluessel (ed25519). Ohne Datenverzeichnis nur im Speicher.
func (s *Sensor) sshSigner() (ssh.Signer, error) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	return s.sshSignerLocked()
}

func (s *Sensor) sshSignerLocked() (ssh.Signer, error) {
	if s.signer != nil {
		return s.signer, nil
	}
	sg, err := s.sshKeyFile(sensorHostKeyFile, func() (crypto.Signer, error) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	})
	if err != nil {
		return nil, err
	}
	s.signer = sg
	return sg, nil
}

// sshKeyFile laedt einen Host-Schluessel aus dem Datenverzeichnis oder erzeugt ihn (Aufrufer haelt keyMu).
func (s *Sensor) sshKeyFile(name string, gen func() (crypto.Signer, error)) (ssh.Signer, error) {
	path := filepath.Join(s.dir, name)
	if s.dir != "" {
		if b, err := os.ReadFile(path); err == nil {
			if sg, err := ssh.ParsePrivateKey(b); err == nil {
				return sg, nil
			}
			s.log.Warn("honeypot ssh host key unreadable, generating a new one", "file", path)
		}
	}
	priv, err := gen()
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
	return sg, nil
}

// sensorSSHKeys sind die Host-Schluessel wie bei einem frisch installierten OpenSSH (RSA 3072, ECDSA P-256, Ed25519).
type sensorSSHKeys struct {
	rsa, ecdsa, ed25519 ssh.Signer
}

// sshHostKeys liefert alle Host-Schluessel (Dateien ssh_host_rsa, ssh_host_ecdsa, ssh_host_ed25519).
func (s *Sensor) sshHostKeys() (*sensorSSHKeys, error) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	if s.sshKeys != nil {
		return s.sshKeys, nil
	}
	ed, err := s.sshSignerLocked()
	if err != nil {
		return nil, err
	}
	ec, err := s.sshKeyFile(sensorHostKeyECDSA, func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) })
	if err != nil {
		return nil, err
	}
	rs, err := s.sshKeyFile(sensorHostKeyRSA, func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 3072) })
	if err != nil {
		return nil, err
	}
	s.sshKeys = &sensorSSHKeys{rsa: rs, ecdsa: ec, ed25519: ed}
	return s.sshKeys, nil
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

// Zertifikat je Profil (HTTPS): selbst signiert wie der nachgeahmte Dienst, RSA 2048, Seriennummer zufaellig,
// Ausstellung je Sensor verschieden weit zurueck. Dateien tls-<art>.crt/.key; neu erzeugt, wenn der Hostname
// nicht mehr passt oder das Zertifikat abgelaufen ist.
const (
	certGeneric = "generic" // wie das Snakeoil-Zertifikat von Debian/Ubuntu (CN = Hostname)
	certPVE     = "pve"     // wie pve-ssl.pem (von der Cluster-CA signiert)
	certWebmin  = "webmin"  // wie das selbst erzeugte Zertifikat von Webmin
)

// certStyle: Zertifikat zum Profil.
func certStyle(persona string) string {
	switch persona {
	case PersonaPVE:
		return certPVE
	case PersonaWebmin:
		return certWebmin
	}
	return certGeneric
}

// httpsCert liefert das Zertifikat fuer den aktuellen Stand des Profils eines HTTPS-Dienstes.
func (s *Sensor) httpsCert(k sensorKey) (*tls.Certificate, error) {
	p := s.personas()
	return s.personaCert(certStyle(p.of(k)), p.id)
}

// personaCert laedt oder erzeugt das Zertifikat einer Art fuer die Identitaet des Sensors.
func (s *Sensor) personaCert(style string, id *sensorIdent) (*tls.Certificate, error) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	subj := certSubject(style, id).String()
	ok := func(c *tls.Certificate) bool {
		return c != nil && c.Leaf != nil && c.Leaf.Subject.String() == subj && time.Now().Before(c.Leaf.NotAfter)
	}
	if c := s.certs[style]; ok(c) {
		return c, nil
	}
	crtPath, keyPath := filepath.Join(s.dir, "tls-"+style+".crt"), filepath.Join(s.dir, "tls-"+style+".key")
	if s.dir != "" {
		if c, err := tls.LoadX509KeyPair(crtPath, keyPath); err == nil && ok(&c) {
			s.setCert(style, &c)
			return &c, nil
		}
	}
	crtPEM, keyPEM, err := certCreate(style, id, time.Now())
	if err != nil {
		return nil, err
	}
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
	s.setCert(style, &c)
	return &c, nil
}

func (s *Sensor) setCert(style string, c *tls.Certificate) {
	if s.certs == nil {
		s.certs = map[string]*tls.Certificate{}
	}
	s.certs[style] = c
}

// certSubject: Inhaber wie beim nachgeahmten Dienst.
func certSubject(style string, id *sensorIdent) pkix.Name {
	switch style {
	case certPVE:
		return pkix.Name{OrganizationalUnit: []string{"PVE Cluster Node"}, Organization: []string{"Proxmox Virtual Environment"}, CommonName: id.fqdn()}
	case certWebmin:
		return pkix.Name{Organization: []string{"Webmin Webserver on " + id.host}, CommonName: "*"}
	}
	return pkix.Name{CommonName: id.host}
}

// certCreate erzeugt Zertifikat und Schluessel (PEM). Ausgestellt 1 bis 600 Tage vor now (je Sensor stabil),
// gueltig wie beim Original: PVE 2 Jahre (Cluster-CA 10 Jahre), Webmin 5 Jahre, Snakeoil 10 Jahre.
func certCreate(style string, id *sensorIdent, now time.Time) (crtPEM, keyPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	age := time.Duration(1+id.pick("cert-age", 600))*24*time.Hour + time.Duration(id.pick("cert-sec", 86400))*time.Second
	from := now.Add(-age).UTC().Truncate(time.Second)
	tpl := &x509.Certificate{SerialNumber: serial, Subject: certSubject(style, id), NotBefore: from, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	parent, signKey := tpl, crypto.Signer(key)
	switch style {
	case certPVE:
		tpl.NotAfter = from.AddDate(2, 0, 0)
		tpl.DNSNames = []string{"localhost", id.host, id.fqdn()}
		tpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
		caKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
		u := id.hex("pve-ca", 32)
		parent = &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: from.Add(-time.Minute), NotAfter: from.AddDate(10, 0, 0),
			Subject: pkix.Name{CommonName: "Proxmox Virtual Environment", Organization: []string{"PVE Cluster Manager CA"},
				OrganizationalUnit: []string{u[:8] + "-" + u[8:12] + "-" + u[12:16] + "-" + u[16:20] + "-" + u[20:]}},
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		signKey = caKey
	case certWebmin:
		tpl.NotAfter = from.AddDate(5, 0, 0)
		tpl.DNSNames = []string{id.host}
	default:
		tpl.NotAfter = from.AddDate(10, 0, 0)
		tpl.DNSNames = []string{id.host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, signKey)
	if err != nil {
		return nil, nil, err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), nil
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
