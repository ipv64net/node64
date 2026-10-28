package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

// Regressionstests zum Review der Zertifikatsverwaltung (Z0–Z5).

func TestImportIssuedNeedsRenewalData(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	certPEM, keyPEM := selfSignedPEM(t, 60, "shop.example.com")
	var ve *ValidationError
	if _, err := e.m.ImportIssued(ctx, ImportRequest{Source: SourceAlias, CertPEM: certPEM, KeyPEM: keyPEM}); !errors.As(err, &ve) || ve.Field != "alias_zone" {
		t.Fatalf("alias without zone: %v", err)
	}
	if _, err := e.m.ImportIssued(ctx, ImportRequest{Source: SourceDNS, DNSAccount: 42, CertPEM: certPEM, KeyPEM: keyPEM}); !errors.As(err, &ve) || ve.Field != "dns_account" {
		t.Fatalf("dns without account: %v", err)
	}
	c, err := e.m.ImportIssued(ctx, ImportRequest{Source: SourceAlias, AliasZone: "Home.IPv64.de.", AliasPrefix: "le", CertPEM: certPEM, KeyPEM: keyPEM})
	if err != nil {
		t.Fatal(err)
	}
	if c.AliasZone != "home.ipv64.de" || c.AliasPrefix != "le" {
		t.Fatalf("alias data not stored: %+v", c)
	}
}

// Die eigene CA stellt aus, auch wenn gerade ein ACME-Abruf die Sperre haelt.
func TestOwnCANotBehindACMELock(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	ca, err := e.m.CreateCA(ctx, CAInput{Name: "Heim"})
	if err != nil {
		t.Fatal(err)
	}
	e.m.acme.Lock()
	defer e.m.acme.Unlock()
	c, err := e.m.Create(ctx, Request{Names: []string{"nas.lan"}, Source: SourceCA, CAID: ca.ID})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if got, _ := e.m.Get(ctx, c.ID); got.Status == StatusValid {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("own CA waits for the ACME lock")
}

// Laeuft gerade eine Ausstellung, wartet EnsureIssued und stellt dann mit den neuen Namen aus; Eintrag und
// Zertifikat stimmen danach ueberein.
func TestEnsureIssuedWaitsAndKeepsNamesInSync(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	ca, _ := e.m.CreateCA(ctx, CAInput{Name: "Heim"})
	c, err := e.m.EnsureIssued(ctx, "dns64", ca.ID, []string{"node.lan", "192.168.1.2"}, 800)
	if err != nil {
		t.Fatal(err)
	}
	e.m.mu.Lock()
	e.m.steps[c.ID] = "certificate" // eine Erneuerung laeuft
	e.m.mu.Unlock()
	done := make(chan *Cert, 1)
	go func() {
		got, err := e.m.EnsureIssued(ctx, "dns64", ca.ID, []string{"node.lan", "192.168.1.2", "192.168.2.2"}, 800)
		if err != nil {
			t.Error(err)
		}
		done <- got
	}()
	time.Sleep(300 * time.Millisecond)
	e.m.mu.Lock()
	delete(e.m.steps, c.ID)
	e.m.mu.Unlock()
	got := <-done
	b, _ := e.m.Bundle(ctx, got.ID)
	if len(b.Leaf.IPAddresses) != 2 || !strings.Contains(strings.Join(got.Names, ","), "192.168.2.2") {
		t.Fatalf("new IP missing: %v %v", got.Names, b.Leaf.IPAddresses)
	}
	if strings.Join(got.Names, ",") != strings.Join(certNames(b.Leaf), ",") {
		t.Fatalf("db names %v differ from certificate %v", got.Names, certNames(b.Leaf))
	}
}

// Kurze Laufzeit: kein neues Zertifikat bei jedem Aufruf.
func TestEnsureIssuedShortDays(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	ca, _ := e.m.CreateCA(ctx, CAInput{Name: "Heim"})
	c1, err := e.m.EnsureIssued(ctx, "x", ca.ID, []string{"a.lan"}, 20)
	if err != nil {
		t.Fatal(err)
	}
	c2, _ := e.m.EnsureIssued(ctx, "x", ca.ID, []string{"a.lan"}, 20)
	b1, _ := e.m.Bundle(ctx, c1.ID)
	b2, _ := e.m.Bundle(ctx, c2.ID)
	if b1.Fingerprint != b2.Fingerprint {
		t.Fatal("reissued although 20 days are left")
	}
}

// Gleichzeitiges Anlegen und Loeschen darf die Erneuerung nicht anhalten, solange Zertifikate da sind.
func TestRefreshHoldConcurrent(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	certPEM, keyPEM := selfSignedPEM(t, 60, "keep.example.org")
	if _, err := e.m.Upload(ctx, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p, k := selfSignedPEM(t, 60, fmt.Sprintf("tmp%d.example.org", i))
			c, err := e.m.Upload(ctx, p, k)
			if err == nil {
				_ = e.m.Delete(ctx, c.ID, true)
			}
		}(i)
	}
	wg.Wait()
	e.m.mu.Lock()
	running := e.m.stopLp != nil
	e.m.mu.Unlock()
	if !running {
		t.Fatal("renewal loop stopped although a certificate is left")
	}
}

func caCert(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, mod func(*x509.Certificate)) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().AddDate(3, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	if mod != nil {
		mod(tpl)
	}
	if parent == nil {
		parent, parentKey = tpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key
}

// Einschraenkungen der uebergeordneten Root und Ausschluesse gelten auch; der Download liefert die Root.
func TestPermitsChainAndExcluded(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	root, rootKey := caCert(t, "Root", nil, nil, func(c *x509.Certificate) { c.PermittedDNSDomains = []string{"corp.example"} })
	sub, subKey := caCert(t, "Sub", root, rootKey, func(c *x509.Certificate) { c.ExcludedDNSDomains = []string{"printer.corp.example"} })
	kd, _ := x509.MarshalECPrivateKey(subKey)
	chainPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sub.Raw})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}))
	ca, err := e.m.ImportCA(ctx, "", chainPEM, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})))
	if err != nil {
		t.Fatal(err)
	}
	for name, ok := range map[string]bool{"a.corp.example": true, "nas.lan": false, "printer.corp.example": false, "x.printer.corp.example": false} {
		_, err := e.m.Create(ctx, Request{Names: []string{name}, Source: SourceCA, CAID: ca.ID})
		if (err == nil) != ok {
			t.Errorf("%s: allowed=%v err=%v", name, ok, err)
		}
	}
	data, _, _, err := e.m.CAFile(ctx, ca.ID, "crt")
	if err != nil || string(data) != string(root.Raw) {
		t.Fatal("crt must be the root of the chain")
	}
	profile, _, _, _ := e.m.CAFile(ctx, ca.ID, "mobileconfig")
	if !strings.Contains(string(profile), "PayloadContent</key><data>") {
		t.Fatal("profile")
	}
}

func TestIssueNowAfterClose(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	ca, _ := e.m.CreateCA(ctx, CAInput{Name: "Heim"})
	e.m.Close()
	if _, err := e.m.EnsureIssued(ctx, "x", ca.ID, []string{"a.lan"}, 0); err == nil {
		t.Fatal("issuing after Close must fail")
	}
}

// Oeffentlich vertrauenswuerdig vor selbst signiert, auch wenn das selbst signierte laenger gilt.
func TestMatchPrefersPublicTrust(t *testing.T) {
	ctx := context.Background()
	root, rootKey := caCert(t, "Public Root", nil, nil, nil)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	old := trustRoots
	trustRoots = func() (*x509.CertPool, error) { return pool, nil }
	t.Cleanup(func() { trustRoots = old })
	e := newEnv(t, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "web.example.org"}, DNSNames: []string{"web.example.org"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 0, 30), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	pub, err := e.m.Upload(ctx, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})))
	if err != nil {
		t.Fatal(err)
	}
	selfPEM, selfKey := selfSignedPEM(t, 300, "web.example.org")
	self, err := e.m.Upload(ctx, selfPEM, selfKey)
	if err != nil {
		t.Fatal(err)
	}
	if id := e.m.MatchID("web.example.org"); id != pub.ID {
		t.Fatalf("matched %d, want public %d (self-signed %d)", id, pub.ID, self.ID)
	}
}

// Wartet ein Abruf auf die ACME-Sperre, laeuft sein Zeitlimit noch nicht; ein Zeitlimit beim Abruf selbst haelt
// den Fehler fest, meldet aber nichts und laesst den Status (naechster Lauf versucht es wieder).
func TestQueuedIssueNotTimedOut(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	_ = e.m.SetAccount(ctx, "", true)
	e.m.issueTimeout = time.Second
	e.m.acme.Lock()
	c, err := e.m.Create(ctx, Request{Names: []string{"q.home.ipv64.de"}, Source: SourceIPv64})
	if err != nil {
		e.m.acme.Unlock()
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond) // laenger als das Zeitlimit in der Warteschlange
	e.m.acme.Unlock()
	if got := wait(t, e.m, c.ID); got.Status != StatusValid {
		t.Fatalf("queued issue: %s %s", got.Status, got.LastError)
	}
	e.m.issueTimeout = 200 * time.Millisecond
	e.m.txtVisible = func(ctx context.Context, _, _, _ string) error { <-ctx.Done(); return ctx.Err() }
	c2, err := e.m.Create(ctx, Request{Names: []string{"t.home.ipv64.de"}, Source: SourceIPv64})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		got, _ := e.m.Get(ctx, c2.ID)
		if got.Step == "" && got.LastError != "" {
			if got.Status != StatusPending || !strings.Contains(got.LastError, "deadline") {
				t.Fatalf("timeout: %s %s", got.Status, got.LastError)
			}
			if k := e.kinds(); len(k) != 0 {
				t.Fatalf("no alert expected on timeout: %v", k)
			}
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("timeout not recorded")
}
