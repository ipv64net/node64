package web

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// Zertifikate stehen nur im Export mit Passwort (verschluesselt) und kommen beim Import mit Schluessel an.
func TestExportImportCertificates(t *testing.T) {
	ctx := context.Background()
	a, mgr := newCertsApp(t)
	certPEM, keyPEM := testCertPEM(t, "export.example.org")
	if _, err := mgr.Upload(ctx, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	_, page := a.get(t, "/settings")
	csrf := csrfOf(t, page)
	_, none := a.post(t, "/settings/export", url.Values{"_csrf": {csrf}, "secrets": {"none"}})
	if strings.Contains(none, `"certs"`) || strings.Contains(none, "PRIVATE KEY") {
		t.Fatal("certificates in export without password")
	}
	_, body := a.post(t, "/settings/export", url.Values{"_csrf": {csrf}, "secrets": {"password"}, "password": {"export-passwort"}})
	var cf configFile
	if err := json.Unmarshal([]byte(body), &cf); err != nil || !strings.HasPrefix(cf.Certs, "enc:") || strings.Contains(body, "PRIVATE KEY") {
		t.Fatalf("certs not encrypted in export: %v %q", err, cf.Certs[:min(len(cf.Certs), 10)])
	}

	b, mgr2 := newCertsApp(t)
	if _, _, err := b.s.applyImport(ctx, []byte(body), "falsches-passwort"); err != errPasswordWrong {
		t.Fatalf("wrong password: %v", err)
	}
	if list, _ := mgr2.List(ctx); len(list) != 0 {
		t.Fatal("imported despite wrong password")
	}
	n, problems, err := b.s.applyImport(ctx, []byte(body), "export-passwort")
	if err != nil || len(problems) != 0 || n == 0 {
		t.Fatalf("import: %d %v %v", n, problems, err)
	}
	list, _ := mgr2.List(ctx)
	if len(list) != 1 || list[0].Names[0] != "export.example.org" {
		t.Fatalf("imported certs: %+v", list)
	}
	if bundle, err := mgr2.Bundle(ctx, list[0].ID); err != nil || !strings.Contains(bundle.KeyPEM, "PRIVATE KEY") {
		t.Fatalf("key not imported: %v", err)
	}
}
