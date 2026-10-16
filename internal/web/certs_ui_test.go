package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/secrets"
)

// Die Seite „Zertifikate“ gehoert zum Kern: eigener Menuepunkt, ohne CDN64 erreichbar.
func TestCertificatesPage(t *testing.T) {
	ctx := context.Background()
	var mgr *certs.Manager
	a := newTestAppDeps(t, func(d *Deps) {
		ms, _ := certs.Migrations()
		if err := d.Store.Migrate(ctx, "certs", ms); err != nil {
			t.Fatal(err)
		}
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		box, _ := secrets.New(key)
		m, err := certs.New(ctx, certs.Deps{Store: d.Store, Box: box})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(m.Close)
		d.Certs, mgr = m, m
	})
	loginAs(t, a, "admin", "sehr geheimes passwort")

	resp, body := a.get(t, "/")
	if resp.StatusCode != 200 || !strings.Contains(body, `href="/certificates"`) {
		t.Fatalf("nav entry missing: %d", resp.StatusCode)
	}
	resp, body = a.get(t, "/certificates")
	if resp.StatusCode != 200 || !strings.Contains(body, "Zertifikate") || strings.Contains(body, "/cdn64/") {
		t.Fatalf("certificates page: %d", resp.StatusCode)
	}
	resp, body = a.get(t, "/certificates/new")
	if resp.StatusCode != 200 || !strings.Contains(body, `action="/certificates/upload"`) {
		t.Fatalf("new page: %d", resp.StatusCode)
	}
	certPEM, keyPEM := testCertPEM(t, "files.example.org")
	resp, _ = a.post(t, "/certificates/upload", url.Values{"_csrf": {csrfOf(t, body)}, "cert": {certPEM}, "key": {keyPEM}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/certificates" {
		t.Fatalf("upload: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	list, _ := mgr.List(ctx)
	if len(list) != 1 {
		t.Fatalf("uploaded: %d", len(list))
	}
	_, body = a.get(t, "/certificates")
	if !strings.Contains(body, "files.example.org") {
		t.Fatal("uploaded certificate not listed")
	}
	if resp, body = a.get(t, "/certificates/1/chain.pem"); resp.StatusCode != 200 || !strings.Contains(body, "BEGIN CERTIFICATE") {
		t.Fatalf("chain: %d", resp.StatusCode)
	}
	if resp, _ = a.get(t, "/certificates/dns-accounts/new"); resp.StatusCode != 200 {
		t.Fatalf("dns new: %d", resp.StatusCode)
	}
	if resp, _ = a.get(t, "/certificates/dns-accounts/99/edit"); resp.StatusCode != 404 {
		t.Fatalf("dns unknown: %d", resp.StatusCode)
	}
}

func testCertPEM(t *testing.T, name string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(60 * 24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	kd, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}))
}
