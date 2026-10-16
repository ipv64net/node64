package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sync/atomic"
	"testing"
	"time"
)

// CA wie die von DNS64: nur private IPs eingeschraenkt, Namen frei, MaxPathLenZero.
func dns64LikeCA(t *testing.T) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "Node64 DNS64 CA box", Organization: []string{"Node64 DNS64 (Heimnetz)"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature, PermittedIPRanges: privateRanges()}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	kd, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}))
}

func TestHandoverCAAndOwned(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	caPEM, caKey := dns64LikeCA(t)
	ca, err := e.m.EnsureCA(ctx, "DNS64 Heimnetz-CA", caPEM, caKey)
	if err != nil {
		t.Fatal(err)
	}
	again, err := e.m.EnsureCA(ctx, "anders", caPEM, caKey)
	if err != nil || again.ID != ca.ID {
		t.Fatalf("EnsureCA twice: %v %d %d", err, again.ID, ca.ID)
	}
	if len(ca.PermittedDNS) != 0 || len(ca.PermittedIP) == 0 {
		t.Fatalf("constraints changed: %+v", ca)
	}
	var changed atomic.Int64
	e.m.OnChange(func(id int64) { changed.Store(id) })
	names := []string{"pfsense.ipv64.de", "debian-int01", "localhost", "192.168.10.30", "127.0.0.1"}
	c, err := e.m.EnsureIssued(ctx, "dns64", ca.ID, names, 800)
	if err != nil {
		t.Fatal(err)
	}
	if c.Status != StatusValid || c.Days != 800 || c.DaysLeft() < 790 {
		t.Fatalf("issued: %+v", c)
	}
	b1, _ := e.m.Bundle(ctx, c.ID)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(caPEM))
	if _, err := b1.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "192.168.10.30"}); err != nil {
		t.Fatalf("verify with the DNS64 CA: %v", err)
	}
	for i := 0; i < 50 && changed.Load() != c.ID; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if changed.Load() != c.ID {
		t.Fatal("OnChange not called")
	}
	// gleiche Namen (andere Reihenfolge): kein neues Zertifikat
	c2, err := e.m.EnsureIssued(ctx, "dns64", ca.ID, []string{"127.0.0.1", "localhost", "debian-int01", "192.168.10.30", "pfsense.ipv64.de"}, 800)
	b2, _ := e.m.Bundle(ctx, c2.ID)
	if err != nil || c2.ID != c.ID || b2.Fingerprint != b1.Fingerprint {
		t.Fatalf("idempotent: %v", err)
	}
	// weniger Namen bei gleichen IPs: deckt ab, bleibt
	c3, _ := e.m.EnsureIssued(ctx, "dns64", ca.ID, []string{"pfsense.ipv64.de", "192.168.10.30", "127.0.0.1"}, 800)
	if b3, _ := e.m.Bundle(ctx, c3.ID); b3.Fingerprint != b1.Fingerprint {
		t.Fatal("covered names must not reissue")
	}
	// neue IP: neu ausgestellt, gleiche Kennung
	c4, err := e.m.EnsureIssued(ctx, "dns64", ca.ID, append(names, "192.168.20.1"), 800)
	b4, _ := e.m.Bundle(ctx, c4.ID)
	if err != nil || c4.ID != c.ID || b4.Fingerprint == b1.Fingerprint || len(b4.Leaf.IPAddresses) != 3 {
		t.Fatalf("reissue on new IP: %v", err)
	}
	// ein laufender ACME-Abruf (Sperre gehalten) blockiert die eigene CA nicht
	e.m.acme.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := e.m.EnsureIssued(ctx, "dns64", ca.ID, append(names, "192.168.30.1"), 800)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("EnsureIssued waits for the ACME lock")
	}
	e.m.acme.Unlock()
	if own, err := e.m.Owned(ctx, "dns64"); err != nil || own.ID != c.ID {
		t.Fatalf("owned: %v", err)
	}
	// oeffentliche IP geht mit dieser CA nicht
	if _, err := e.m.EnsureIssued(ctx, "dns64", ca.ID, []string{"8.8.8.8"}, 800); err == nil {
		t.Fatal("public IP must be refused")
	}
}

func TestHandoverImportIssued(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	_ = e.m.SetAccount(ctx, "", true)
	e.m.loopFirst, e.m.loopEvery = 10*time.Millisecond, 20*time.Millisecond // vor dem ersten Zertifikat
	certPEM, keyPEM := selfSignedPEM(t, 20, "pfsense.home.ipv64.de")        // wie ein altes LE-Zertifikat, bald faellig
	c, err := e.m.ImportIssued(ctx, ImportRequest{Source: SourceIPv64, CertPEM: certPEM, KeyPEM: keyPEM})
	if err != nil {
		t.Fatal(err)
	}
	if c.Source != SourceIPv64 || !c.AutoRenew || c.Status != StatusValid || e.m.ForName("pfsense.home.ipv64.de") == nil {
		t.Fatalf("imported: %+v", c)
	}
	if again, err := e.m.ImportIssued(ctx, ImportRequest{Source: SourceIPv64, CertPEM: certPEM, KeyPEM: keyPEM}); err != nil || again.ID != c.ID {
		t.Fatalf("twice: %v", err)
	}
	if _, err := e.m.ImportIssued(ctx, ImportRequest{Source: SourceUpload, CertPEM: certPEM, KeyPEM: keyPEM}); err == nil {
		t.Fatal("upload is not renewable")
	}
	// die Zentrale erneuert ab jetzt (ipv64 DNS-01 ueber die Fake-CA)
	for i := 0; i < 200; i++ {
		if got, _ := e.m.Get(ctx, c.ID); got.DaysLeft() > 80 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("imported certificate was not renewed")
}
