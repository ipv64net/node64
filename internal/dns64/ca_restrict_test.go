package dns64

import (
	"context"
	"crypto/x509"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Heimnetz-CA (Review DN-1): neue CAs nur fuer lokale Endungen, eigene DoH/DoT-Namen und Zonen; Namen ausserhalb
// fehlen im Zertifikat und werden angezeigt; eine alte CA ohne Beschraenkung bleibt, bis der Knopf eine neue anlegt.
func TestHomeCARestricted(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	c := m.loadConfig(ctx)
	c.CertMode, c.Names = certSelf, []string{"dns.home.lan", "dns.mein.example"}
	if err := m.saveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}

	// alte CA ohne Beschraenkung (vor 1.41.1)
	if _, _, err := m.loadOrCreateCA(nil); err != nil {
		t.Fatal(err)
	}
	v := m.encView(httptest.NewRequest("GET", "/dns64/encrypted", nil), c)
	if !v.CAOld || len(v.CAMiss) != 0 {
		t.Fatalf("old CA view: %+v", v)
	}
	crt, names, err := m.serverCert(c)
	if err != nil || !slices.Contains(names, "dns.mein.example") {
		t.Fatalf("old CA certificate: %v %v", names, err)
	}
	_ = crt

	// neue beschraenkte CA
	if err := m.renewCA(ctx); err != nil {
		t.Fatal(err)
	}
	if olds, _ := filepath.Glob(filepath.Join(m.tlsDir(), "ca-*.pem.old")); len(olds) != 1 {
		t.Fatalf("old CA not kept: %v", olds)
	}
	ca := m.homeCA()
	if ca == nil || !ca.PermittedDNSDomainsCritical || !slices.Contains(ca.PermittedDNSDomains, "dns.mein.example") ||
		!slices.Contains(ca.PermittedDNSDomains, "home.arpa") || slices.Contains(ca.PermittedDNSDomains, "example") {
		t.Fatalf("permitted: %v", ca.PermittedDNSDomains)
	}
	crt, names, err = m.serverCert(c)
	if err != nil || !slices.Contains(names, "dns.home.lan") || !slices.Contains(names, "dns.mein.example") {
		t.Fatalf("restricted certificate: %v %v", names, err)
	}
	leaf, _ := x509.ParseCertificate(crt.Certificate[0])
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "dns.mein.example"}); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// spaeter ein Name ausserhalb: fehlt im Zertifikat, Hinweis auf der Seite
	c.Names = append(c.Names, "dns.fremd.example")
	if v := m.encView(httptest.NewRequest("GET", "/dns64/encrypted", nil), c); v.CAOld || !slices.Equal(v.CAMiss, []string{"dns.fremd.example"}) {
		t.Fatalf("missing names: %+v", v)
	}
	_ = os.Remove(filepath.Join(m.tlsDir(), "server.pem"))
	crt, names, err = m.serverCert(c)
	if err != nil || slices.Contains(names, "dns.fremd.example") || !slices.Contains(names, "dns.mein.example") {
		t.Fatalf("certificate with foreign name: %v %v", names, err)
	}
	leaf, _ = x509.ParseCertificate(crt.Certificate[0])
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "dns.home.lan"}); err != nil {
		t.Fatalf("verify after foreign name: %v", err)
	}
}
