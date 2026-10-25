package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/secrets"
)

// Die Seite „Zertifikate“ gehoert zum Kern: eigener Menuepunkt, ohne CDN64 erreichbar.
// newCertsApp: Testserver mit Zertifikatsverwaltung, angemeldet als admin.
func newCertsApp(t *testing.T) (*testApp, *certs.Manager) {
	t.Helper()
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
	return a, mgr
}

func TestCertificatesPage(t *testing.T) {
	ctx := context.Background()
	a, mgr := newCertsApp(t)

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
	// selbst signiert: immer waehlbar, ohne Voraussetzung
	if !strings.Contains(body, `id="src-self" value="self"`) || strings.Contains(body, `data-why="self"`) || !strings.Contains(body, `name="self_days"`) {
		t.Fatal("self-signed option missing or disabled")
	}
	// ausgegraute Wege nennen direkt den Grund samt Link (ohne API-Key, DNS-Zugang, CA)
	for _, why := range []string{`data-why="ipv64"`, `data-why="alias"`, `data-why="dns"`, `data-why="ca"`, `data-why="http"`} {
		if !strings.Contains(body, why) {
			t.Fatalf("reason missing: %s", why)
		}
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
	_, body = a.get(t, "/certificates/new")
	resp, _ = a.post(t, "/certificates", url.Values{"_csrf": {csrfOf(t, body)}, "names": {"node64.home.local 192.168.10.30"}, "source": {"self"},
		"self_days": {"100"}, "days": {"397"}, "key_type": {"rsa"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("self-signed via form: %d", resp.StatusCode)
	}
	for i := 0; i < 100; i++ {
		l, _ := mgr.List(ctx)
		for _, c := range l {
			if c.Source == certs.SourceSelf && c.Status == certs.StatusValid {
				if c.Days != 100 || c.KeyType != certs.KeyRSA || strings.Join(c.Names, ",") != "node64.home.local,192.168.10.30" {
					t.Fatalf("self-signed: %+v", c)
				}
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("self-signed certificate not issued")
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

// Eigene CA: anlegen, Zertifikat fuer Name und IP ausstellen, CA verteilen; ACME-Stellen-Formular.
func TestCertificatesCA(t *testing.T) {
	ctx := context.Background()
	a, mgr := newCertsApp(t)
	resp, body := a.get(t, "/certificates/ca/new")
	if resp.StatusCode != 200 || !strings.Contains(body, `action="/certificates/ca/import"`) {
		t.Fatalf("ca new: %d", resp.StatusCode)
	}
	resp, _ = a.post(t, "/certificates/ca", url.Values{"_csrf": {csrfOf(t, body)}, "name": {"Heimnetz"}, "key_type": {"ecdsa"}, "constrained": {"on"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("ca create: %d", resp.StatusCode)
	}
	cas, _ := mgr.CAs(ctx)
	if len(cas) != 1 || len(cas[0].PermittedIP) == 0 {
		t.Fatalf("cas: %+v", cas)
	}
	_, body = a.get(t, "/certificates")
	if !strings.Contains(body, "Heimnetz") || !strings.Contains(body, "/certificates/ca/1/file?f=mobileconfig") {
		t.Fatal("CA card missing")
	}
	resp, body = a.get(t, "/certificates/new")
	if !strings.Contains(body, `value="ca"`) || !strings.Contains(body, `name="ca_id"`) || !strings.Contains(body, `name="acme_ca"`) {
		t.Fatal("ca source missing in form")
	}
	resp, _ = a.post(t, "/certificates", url.Values{"_csrf": {csrfOf(t, body)}, "names": {"nas.lan\n192.168.1.5"}, "source": {"ca"}, "ca_id": {"1"}, "days": {"100"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("issue: %d", resp.StatusCode)
	}
	var c *certs.Cert
	for i := 0; i < 100; i++ {
		list, _ := mgr.List(ctx)
		if len(list) == 1 && list[0].Status == certs.StatusValid {
			c = list[0]
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if c == nil || c.Source != certs.SourceCA || c.Days != 100 || strings.Join(c.Names, ",") != "nas.lan,192.168.1.5" {
		t.Fatalf("issued: %+v", c)
	}
	// oeffentlicher Name: abgelehnt, Formular zeigt den Fehler
	_, body = a.get(t, "/certificates/new")
	if resp, body = a.post(t, "/certificates", url.Values{"_csrf": {csrfOf(t, body)}, "names": {"example.com"}, "source": {"ca"}, "ca_id": {"1"}}); resp.StatusCode != 422 ||
		!strings.Contains(body, "alert-danger") {
		t.Fatalf("public name: %d", resp.StatusCode)
	}
	for _, f := range []string{"pem", "crt", "mobileconfig"} {
		if resp, _ = a.get(t, "/certificates/ca/1/file?f="+f); resp.StatusCode != 200 {
			t.Fatalf("ca file %s: %d", f, resp.StatusCode)
		}
	}
	if resp, body = a.get(t, "/api/cas"); resp.StatusCode != 200 || !strings.Contains(body, `"certificates":1`) {
		t.Fatalf("api cas: %d %s", resp.StatusCode, body)
	}
	if resp, body = a.get(t, "/certificates/acme/new"); resp.StatusCode != 200 || !strings.Contains(body, "acme.zerossl.com") {
		t.Fatalf("acme new: %d", resp.StatusCode)
	}
	if resp, body = a.get(t, "/api/acme-cas/presets"); resp.StatusCode != 200 || !strings.Contains(body, "zerossl") {
		t.Fatalf("presets: %d", resp.StatusCode)
	}
	_, body = a.get(t, "/certificates")
	if resp, _ = a.post(t, "/certificates/ca/1/delete", url.Values{"_csrf": {csrfOf(t, body)}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if cas, _ := mgr.CAs(ctx); len(cas) != 1 { // benutzt: bleibt
		t.Fatal("used CA must stay")
	}
	if _, body = a.get(t, "/certificates"); !strings.Contains(body, "stellt noch Zertifikate aus") {
		t.Fatal("in-use message for the CA missing")
	}
	if !strings.Contains(body, `data-bs-popper-config='{"strategy":"fixed"}'`) && !strings.Contains(body, `data-bs-popper-config="{&#34;strategy&#34;:&#34;fixed&#34;}"`) {
		t.Fatal("dropdown would be clipped by the table")
	}
}

// Zertifikat der Oberflaeche: automatisch nach Namen, fest gewaehlt, selbst signiert; NODE64_TLS_CERT gewinnt.
func TestUICertificate(t *testing.T) {
	ctx := context.Background()
	a, mgr := newCertsApp(t)
	s := a.s
	fallback := &tls.Certificate{}
	s.fallbackCert = fallback
	certPEM, keyPEM := testCertPEM(t, "node.test")
	c, err := mgr.Upload(ctx, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	hello := func(name string) *tls.Certificate {
		crt, err := s.uiCertificate(&tls.ClientHelloInfo{ServerName: name})
		if err != nil {
			t.Fatal(err)
		}
		return crt
	}
	if hello("node.test") == fallback || hello("other.test") != fallback || hello("") != fallback {
		t.Fatal("auto: matching name only")
	}
	req := httptest.NewRequest("POST", "/", nil).WithContext(ctx)
	if err := s.saveUICert(req, strconv.FormatInt(c.ID, 10)); err != nil {
		t.Fatal(err)
	}
	if hello("other.test") == fallback || s.Store.SettingOr(ctx, setUICert, "") != strconv.FormatInt(c.ID, 10) {
		t.Fatal("fixed certificate not used")
	}
	if got, _ := mgr.Get(ctx, c.ID); len(got.UsedBy) != 1 || got.UsedBy[0] != "Node64 UI" {
		t.Fatalf("used by: %v", got.UsedBy)
	}
	if err := s.saveUICert(req, "999"); err == nil {
		t.Fatal("unknown certificate must be refused")
	}
	if err := s.saveUICert(req, "self"); err != nil || hello("node.test") != fallback {
		t.Fatalf("self: %v", err)
	}
	_ = s.saveUICert(req, "auto")
	s.Cfg.TLSCertFile = "/data/own.pem"
	if hello("node.test") != fallback {
		t.Fatal("NODE64_TLS_CERT must win")
	}
	// fest gewaehlt bleibt es fuer den Namen am Eingang benutzt, auch mit NODE64_TLS_CERT
	if err := s.saveUICert(req, strconv.FormatInt(c.ID, 10)); err != nil {
		t.Fatal(err)
	}
	if got, _ := mgr.Get(ctx, c.ID); len(got.UsedBy) != 1 {
		t.Fatalf("used by with NODE64_TLS_CERT: %v", got.UsedBy)
	}
	_ = s.saveUICert(req, "auto")
	s.Cfg.TLSCertFile = ""
	s.loadUICert(ctx) // nach Neustart: gespeicherter Wert
	if s.uiCertSel.Load() != 0 {
		t.Fatal("reload")
	}
}

// DNS-01-Pruefung: Link im Konto-Kasten, eigene Resolver speichern (falsche Eingabe abgelehnt), Seite ohne Test.
func TestCertificatesDNSCheck(t *testing.T) {
	a, mgr := newCertsApp(t)
	_, body := a.get(t, "/certificates")
	if !strings.Contains(body, `href="/certificates/dns-check"`) {
		t.Fatal("link missing")
	}
	csrf := csrfOf(t, body)
	resp, page := a.get(t, "/certificates/dns-check")
	if resp.StatusCode != 200 || !strings.Contains(page, `href="/certificates/dns-check?run=1"`) || !strings.Contains(page, `name="resolvers"`) || strings.Contains(page, "certs.dnscheck") {
		t.Fatalf("page: %d", resp.StatusCode)
	}
	a.post(t, "/certificates/dns-check", url.Values{"_csrf": {csrf}, "resolvers": {"dns.example"}})
	if got := mgr.CheckResolvers(context.Background()); len(got) != 0 {
		t.Fatalf("bad input saved: %v", got)
	}
	resp, _ = a.post(t, "/certificates/dns-check", url.Values{"_csrf": {csrf}, "resolvers": {"192.0.2.53\nhttps://dns.quad9.net/dns-query"}})
	if resp.StatusCode != 303 || resp.Header.Get("Location") != "/certificates/dns-check?run=1" {
		t.Fatalf("save: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if got := mgr.CheckResolvers(context.Background()); strings.Join(got, "|") != "192.0.2.53:53|https://dns.quad9.net/dns-query" {
		t.Fatalf("saved: %v", got)
	}
	if _, page = a.get(t, "/certificates/dns-check"); !strings.Contains(page, "192.0.2.53:53\nhttps://dns.quad9.net/dns-query</textarea>") {
		t.Fatal("not shown")
	}
}
