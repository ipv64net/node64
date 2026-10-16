package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestOwnCA(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	ca, err := e.m.CreateCA(ctx, CAInput{Name: "Heimnetz", Domains: []string{"home.example.org"}})
	if err != nil {
		t.Fatal(err)
	}
	if !ca.Root || len(ca.PermittedDNS) == 0 || len(ca.PermittedIP) == 0 || ca.NotAfter.Before(time.Now().AddDate(9, 0, 0)) {
		t.Fatalf("ca: %+v", ca)
	}
	// ohne Let's-Encrypt-Bedingungen: die eigene CA braucht sie nicht
	c, err := e.m.Create(ctx, Request{Names: []string{"nas.lan", "192.168.1.5", "*.home.example.org"}, Source: SourceCA, CAID: ca.ID, Days: 30})
	if err != nil {
		t.Fatal(err)
	}
	c = wait(t, e.m, c.ID)
	if c.Status != StatusValid || c.Days != 30 || c.DaysLeft() < 29 {
		t.Fatalf("issued: %+v", c)
	}
	b, err := e.m.Bundle(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if b.ChainPEM != "" { // Root gehoert nicht in die Kette
		t.Fatal("root in chain")
	}
	pool := x509.NewCertPool()
	data, _, _, _ := e.m.CAFile(ctx, ca.ID, "pem")
	pool.AppendCertsFromPEM(data)
	for _, n := range []string{"nas.lan", "192.168.1.5", "x.home.example.org"} {
		opts := x509.VerifyOptions{Roots: pool, DNSName: n}
		if _, err := b.Leaf.Verify(opts); err != nil {
			t.Fatalf("verify %s: %v", n, err)
		}
	}
	if e.m.ForName("nas.lan") == nil {
		t.Fatal("not served")
	}
	// Einschraenkung: keine oeffentlichen Namen und Adressen
	for _, n := range []string{"example.com", "8.8.8.8", "lan.example.com"} {
		var ve *ValidationError
		if _, err := e.m.Create(ctx, Request{Names: []string{n}, Source: SourceCA, CAID: ca.ID}); !errors.As(err, &ve) {
			t.Fatalf("%s must be refused: %v", n, err)
		}
	}
	if _, err := e.m.Create(ctx, Request{Names: []string{"a.lan"}, Source: SourceCA, CAID: ca.ID, Days: 900}); err == nil {
		t.Fatal("days > 825 must be refused")
	}
	if _, err := e.m.Create(ctx, Request{Names: []string{"1.2.3.4"}, Source: SourceIPv64}); err == nil {
		t.Fatal("IPs only with the own CA")
	}
	// ohne Einschraenkung: alles
	off := false
	free, err := e.m.CreateCA(ctx, CAInput{Name: "Frei", KeyType: "rsa", Constrained: &off})
	if err != nil || len(free.PermittedDNS) != 0 {
		t.Fatalf("free CA: %v %+v", err, free)
	}
	if _, err := e.m.Create(ctx, Request{Names: []string{"example.com"}, Source: SourceCA, CAID: free.ID}); err != nil {
		t.Fatal(err)
	}
	// Dateien zum Verteilen
	for _, f := range []string{"pem", "crt", "mobileconfig"} {
		data, name, ctype, err := e.m.CAFile(ctx, ca.ID, f)
		if err != nil || len(data) == 0 || !strings.HasPrefix(name, "Heimnetz.") || ctype == "" {
			t.Fatalf("ca file %s: %v %s", f, err, name)
		}
		if f == "mobileconfig" && !strings.Contains(string(data), "com.apple.security.root") {
			t.Fatal("profile")
		}
	}
	// benutzt: nicht loeschbar
	if err := e.m.DeleteCA(ctx, ca.ID); !errors.Is(err, ErrInUse) {
		t.Fatalf("delete used CA: %v", err)
	}
	if err := e.m.Delete(ctx, c.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := e.m.DeleteCA(ctx, ca.ID); err != nil {
		t.Fatal(err)
	}
	if list, _ := e.m.CAs(ctx); len(list) != 1 || list[0].Certificates != 1 {
		t.Fatalf("cas: %+v", list)
	}
}

func TestImportCA(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	// Root offline, Zwischen-CA wird importiert
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Offline Root"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	root, _ := x509.ParseCertificate(rootDER)
	subKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	subTpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Haus-CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().AddDate(3, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, PermittedIPRanges: privateRanges()}
	subDER, _ := x509.CreateCertificate(rand.Reader, subTpl, root, &subKey.PublicKey, rootKey)
	kd, _ := x509.MarshalECPrivateKey(subKey)
	chainPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subDER})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}))
	ca, err := e.m.ImportCA(ctx, "", chainPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if ca.Name != "Haus-CA" || ca.Root || !ca.Imported {
		t.Fatalf("imported: %+v", ca)
	}
	if _, err := e.m.ImportCA(ctx, "nochmal", chainPEM, keyPEM); err == nil {
		t.Fatal("duplicate must be refused")
	}
	leafPEM, leafKey := selfSignedPEM(t, 30, "x.lan")
	if _, err := e.m.ImportCA(ctx, "kein CA", leafPEM, leafKey); err == nil {
		t.Fatal("leaf is not a CA")
	}
	c, err := e.m.Create(ctx, Request{Names: []string{"10.0.0.7", "drucker"}, Source: SourceCA, CAID: ca.ID})
	if err != nil {
		t.Fatal(err)
	}
	c = wait(t, e.m, c.ID)
	b, err := e.m.Bundle(ctx, c.ID)
	if err != nil || c.Status != StatusValid {
		t.Fatalf("issued: %v %+v", err, c)
	}
	if !strings.Contains(b.ChainPEM, "CERTIFICATE") { // Zwischen-CA in der Kette, Root nicht
		t.Fatal("intermediate missing in chain")
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	inter := x509.NewCertPool()
	inter.AppendCertsFromPEM([]byte(b.ChainPEM))
	if _, err := b.Leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, DNSName: "10.0.0.7"}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ip := net.ParseIP(b.Meta().Names[len(b.Meta().Names)-1]); ip == nil {
		t.Fatalf("meta names: %v", b.Meta().Names)
	}
}

func TestOtherACMECA(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	ca2 := newFakeCA(t)
	ca2.txt = e.dns.lookup
	ca2.eab = true
	var ve *ValidationError
	in := ACMECAInput{Name: "ZeroSSL-Test", Directory: ca2.url("/dir")}
	if _, err := e.m.AddACMECA(ctx, in); !errors.As(err, &ve) || ve.Field != "accept_tos" {
		t.Fatalf("tos: %v", err)
	}
	in.AcceptTOS = true
	if _, err := e.m.AddACMECA(ctx, in); !errors.As(err, &ve) || ve.Field != "eab_kid" {
		t.Fatalf("eab required: %v", err)
	}
	in.EABKID, in.EABHMAC = "kid-123", base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	a, err := e.m.AddACMECA(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if !a.HasEAB || a.EABKID != "kid-123" {
		t.Fatalf("acme ca: %+v", a)
	}
	if _, err := e.m.AddACMECA(ctx, in); err == nil {
		t.Fatal("duplicate directory")
	}
	// ohne Let's-Encrypt-Bedingungen, die Stelle hat eigene
	c, err := e.m.Create(ctx, Request{Names: []string{"a.home.ipv64.de"}, Source: SourceIPv64, ACMECA: a.ID, Staging: true})
	if err != nil {
		t.Fatal(err)
	}
	c = wait(t, e.m, c.ID)
	if c.Status != StatusValid || c.ACMECA != a.ID || c.Staging {
		t.Fatalf("issued: %+v", c)
	}
	ca2.mu.Lock()
	kid, issued := ca2.eabKID, ca2.issued
	ca2.mu.Unlock()
	e.ca.mu.Lock()
	le := e.ca.issued
	e.ca.mu.Unlock()
	if kid != "kid-123" || issued != 1 || le != 0 {
		t.Fatalf("kid=%q issued=%d le=%d", kid, issued, le)
	}
	if err := e.m.DeleteACMECA(ctx, a.ID); !errors.Is(err, ErrInUse) {
		t.Fatalf("delete used: %v", err)
	}
	if _, err := e.m.Create(ctx, Request{Names: []string{"b.home.ipv64.de"}, Source: SourceIPv64, ACMECA: 99}); err == nil {
		t.Fatal("unknown acme ca")
	}
}
