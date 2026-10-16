package certs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/youmark/pkcs8"
	"software.sslmate.com/src/go-pkcs12"
)

func keyAndCert(t *testing.T, name string) (*ecdsa.PrivateKey, *x509.Certificate, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	leaf, _ := x509.ParseCertificate(der)
	return key, leaf, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// Verschluesselte Schluessel (PKCS#8, klassisches PEM mit DEK-Info, PKCS#12): richtig, falsch, ohne Passwort.
func TestPrepareUploadEncryptedKeys(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	key, leaf, certPEM := keyAndCert(t, "shop.example.com")

	p8, err := pkcs8.MarshalPrivateKey(key, []byte("geheim"), &pkcs8.Opts{Cipher: pkcs8.AES256CBC,
		KDFOpts: pkcs8.PBKDF2Opts{SaltSize: 16, IterationCount: 2048, HMACHash: crypto.SHA256}})
	if err != nil {
		t.Fatal(err)
	}
	p8PEM := string(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: p8}))
	ecDER, _ := x509.MarshalECPrivateKey(key)
	legacy, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", ecDER, []byte("geheim"), x509.PEMCipherAES256) //nolint:staticcheck // Testdatei im alten Format
	if err != nil {
		t.Fatal(err)
	}
	legacyPEM := string(pem.EncodeToMemory(legacy))
	p12, err := pkcs12.Modern2023.Encode(key, leaf, nil, "geheim")
	if err != nil {
		t.Fatal(err)
	}
	p12Legacy, _ := pkcs12.LegacyDES.Encode(key, leaf, nil, "geheim")

	cases := map[string]struct{ cert, key string }{
		"pkcs8":      {certPEM, p8PEM},
		"legacy-pem": {certPEM, legacyPEM},
		"p12":        {string(p12), ""},
		"p12-3des":   {string(p12Legacy), ""},
		"one-file":   {certPEM + p8PEM, ""}, // Zertifikat und Schluessel in einer Datei
	}
	for name, c := range cases {
		if _, _, err := PrepareUpload([]byte(c.cert), []byte(c.key), ""); !errors.Is(err, ErrKeyPassword) {
			t.Errorf("%s without password: %v", name, err)
		}
		var ve *ValidationError
		if _, _, err := PrepareUpload([]byte(c.cert), []byte(c.key), "falsch"); !errors.As(err, &ve) || ve.Field != "password" {
			t.Errorf("%s wrong password: %v", name, err)
		}
		cp, kp, err := PrepareUpload([]byte(c.cert), []byte(c.key), "geheim")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		up, err := e.m.Upload(ctx, cp, kp)
		if err != nil {
			t.Fatalf("%s upload: %v", name, err)
		}
		b, _ := e.m.Bundle(ctx, up.ID)
		if sum := sha256.Sum256(leaf.Raw); b.Fingerprint == "" || sha256.Sum256(b.Leaf.Raw) != sum {
			t.Fatalf("%s: other certificate stored", name)
		}
		if err := e.m.Delete(ctx, up.ID, true); err != nil {
			t.Fatal(err)
		}
	}
	// unverschluesselt geht wie bisher, auch ohne Passwort
	plain, _ := marshalKey(key)
	if _, _, err := PrepareUpload([]byte(certPEM), []byte(plain), ""); err != nil {
		t.Fatal(err)
	}
}
