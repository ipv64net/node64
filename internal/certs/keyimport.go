package certs

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"

	"github.com/youmark/pkcs8"
	"software.sslmate.com/src/go-pkcs12"
)

// Import gekaufter Zertifikate: der private Schluessel ist oft mit einem Passwort verschluesselt. Unterstuetzt
// werden PKCS#8 ("ENCRYPTED PRIVATE KEY", PBES2 mit PBKDF2/scrypt, AES/3DES), klassisches PEM mit DEK-Info
// ("Proc-Type: 4,ENCRYPTED") und PKCS#12 (.pfx/.p12). Gespeichert wird der entschluesselte Schluessel in der
// verschluesselten Ablage, das Passwort nicht.

// ErrKeyPassword: der Schluessel ist verschluesselt, es fehlt das Passwort.
var ErrKeyPassword = errors.New("private key is encrypted: password needed")

func wrongPassword() error { return invalid("password", "wrong password or unsupported encryption") }

func isPEM(b []byte) bool { return bytes.Contains(b, []byte("-----BEGIN ")) }

// PrepareUpload macht aus den hochgeladenen Daten Zertifikat (PEM mit Kette) und unverschluesselten Schluessel
// (PEM). certData darf PEM oder PKCS#12 sein; keyData darf leer sein, wenn der Schluessel in certData steckt
// (PKCS#12 oder eine PEM-Datei mit beidem). password entschluesselt Schluessel bzw. PKCS#12.
func PrepareUpload(certData, keyData []byte, password string) (certPEM, keyPEM string, err error) {
	certData, keyData = bytes.TrimSpace(certData), bytes.TrimSpace(keyData)
	if len(certData) == 0 {
		return "", "", invalid("cert", "certificate missing")
	}
	if !isPEM(certData) { // binaer: PKCS#12
		return fromP12(certData, password)
	}
	if len(keyData) == 0 { // eine Datei mit Zertifikat und Schluessel
		keyData = certData
	}
	key, err := DecryptKey(string(keyData), password)
	if err != nil {
		return "", "", err
	}
	var certs []byte
	rest := certData
	for {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			certs = append(certs, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.Bytes})...)
		}
	}
	if len(certs) == 0 {
		return "", "", invalid("cert", "no certificate in the file")
	}
	return string(certs), key, nil
}

// DecryptKey liefert den ersten privaten Schluessel aus keyPEM unverschluesselt als PKCS#8-PEM.
func DecryptKey(keyPEM, password string) (string, error) {
	rest := []byte(keyPEM)
	for {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			return "", invalid("key", "no private key in the file")
		}
		if !strings.Contains(b.Type, "PRIVATE KEY") {
			continue
		}
		var key any
		var err error
		switch {
		case b.Type == "ENCRYPTED PRIVATE KEY": // PKCS#8 mit Passwort
			if password == "" {
				return "", ErrKeyPassword
			}
			if key, err = pkcs8.ParsePKCS8PrivateKey(b.Bytes, []byte(password)); err != nil {
				return "", wrongPassword()
			}
		case x509.IsEncryptedPEMBlock(b): //nolint:staticcheck // klassisches PEM mit DEK-Info, fuer alte Dateien noetig
			if password == "" {
				return "", ErrKeyPassword
			}
			der, err := x509.DecryptPEMBlock(b, []byte(password)) //nolint:staticcheck // s. o.
			if err != nil {
				return "", wrongPassword()
			}
			if key, err = parseKeyDER(b.Type, der); err != nil {
				return "", wrongPassword() // falsches Passwort ergibt bei CBC oft ein "gueltiges" Padding
			}
		default:
			if key, err = parseKeyDER(b.Type, b.Bytes); err != nil {
				return "", invalid("key", "%v", err)
			}
		}
		return marshalKey(key)
	}
}

func parseKeyDER(typ string, der []byte) (any, error) {
	switch typ {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(der)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(der)
	}
	return x509.ParsePKCS8PrivateKey(der)
}

func fromP12(data []byte, password string) (certPEM, keyPEM string, err error) {
	key, leaf, chain, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		if errors.Is(err, pkcs12.ErrIncorrectPassword) {
			if password == "" {
				return "", "", ErrKeyPassword
			}
			return "", "", wrongPassword()
		}
		return "", "", invalid("cert", "PKCS#12 not readable: %v", err)
	}
	if keyPEM, err = marshalKey(key); err != nil {
		return "", "", invalid("key", "%v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
	for _, c := range chain {
		certPEM += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return certPEM, keyPEM, nil
}
