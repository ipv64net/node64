package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
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
	// Downloads auf der Seite: ohne Schluessel kein Audit, mit Schluessel schon
	if resp, body = a.get(t, "/certificates/1/download?f=fullchain"); resp.StatusCode != 200 || !strings.Contains(body, "BEGIN CERTIFICATE") || strings.Contains(body, "PRIVATE") {
		t.Fatalf("fullchain: %d", resp.StatusCode)
	}
	etag := resp.Header.Get("ETag")
	if resp, body = a.get(t, "/certificates/1/download?f=key"); resp.StatusCode != 200 || !strings.Contains(body, "PRIVATE KEY") ||
		!strings.Contains(resp.Header.Get("Content-Disposition"), "files.example.org.privkey.pem") {
		t.Fatalf("key: %d %s", resp.StatusCode, resp.Header.Get("Content-Disposition"))
	}
	if resp, _ = a.get(t, "/certificates/1/download?f=exe"); resp.StatusCode != 400 {
		t.Fatalf("unknown format: %d", resp.StatusCode)
	}
	_, page := a.get(t, "/certificates")
	if !strings.Contains(page, `id="p12modal"`) || !strings.Contains(page, `data-p12="1"`) || !strings.Contains(page, "/certificates/1/download?f=zip") {
		t.Fatal("download menu or p12 dialog missing")
	}
	resp, body = a.post(t, "/certificates/1/p12", url.Values{"_csrf": {csrfOf(t, page)}, "password": {"geheim12"}})
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/x-pkcs12" || len(body) < 100 {
		t.Fatalf("p12: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}

	// API mit API-Key: meta, bundle mit ETag/304, p12 per POST
	u, _ := a.store.UserByName(ctx, "admin")
	apiKey, _, err := a.store.NewAPIKey(ctx, u.ID, "nas")
	if err != nil {
		t.Fatal(err)
	}
	api := func(method, path, body string, hdr map[string]string) (*http.Response, string) {
		req, _ := http.NewRequest(method, a.srv.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+apiKey)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(b)
	}
	resp, body = api("GET", "/api/certs/1/meta", "", nil)
	if resp.StatusCode != 200 || !strings.Contains(body, `"fingerprint_sha256"`) || resp.Header.Get("ETag") != etag {
		t.Fatalf("meta: %d %s", resp.StatusCode, body)
	}
	resp, body = api("GET", "/api/certs/1/bundle", "", nil)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/zip" {
		t.Fatalf("bundle zip: %d", resp.StatusCode)
	}
	for _, f := range []string{"fullchain", "key"} { // 304 mit Schluessel-Format: kein Audit
		if resp, _ = api("GET", "/api/certs/1/bundle?format="+f, "", map[string]string{"If-None-Match": etag}); resp.StatusCode != http.StatusNotModified {
			t.Fatalf("if-none-match %s: %d", f, resp.StatusCode)
		}
	}
	if resp, body = api("POST", "/api/certs/1/p12", `{"password":"abc"}`, nil); resp.StatusCode != 422 {
		t.Fatalf("p12 short password: %d %s", resp.StatusCode, body)
	}
	if resp, _ = api("POST", "/api/certs/1/p12", `{"password":"geheim12","legacy":true}`, nil); resp.StatusCode != 200 {
		t.Fatalf("p12 api: %d", resp.StatusCode)
	}
	if resp, _ = api("GET", "/api/certs/99/meta", "", nil); resp.StatusCode != 404 {
		t.Fatalf("meta unknown: %d", resp.StatusCode)
	}
	entries, _ := a.store.AuditList(ctx, 50, 0)
	var downloads []string
	for _, e := range entries {
		if e.Action == "cert.download" {
			downloads = append(downloads, e.Details)
		}
	}
	// key, p12 (Seite), zip (API), p12 (API); fullchain und 304 zaehlen nicht
	if len(downloads) != 4 || strings.Contains(strings.Join(downloads, " "), "PRIVATE") {
		t.Fatalf("audit downloads: %v", downloads)
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
