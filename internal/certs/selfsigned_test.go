package certs

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/store"
)

// Selbst signiert: ohne Let's-Encrypt-Bedingungen, Namen, Wildcards und IPs, ECDSA oder RSA, Erneuerung.
func TestSelfSigned(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil) // ohne SetAccount: Bedingungen nicht angenommen
	c, err := e.m.Create(ctx, Request{Names: []string{"node64.home.local", "*.home.local", "192.168.10.30"}, Source: SourceSelf})
	if err != nil {
		t.Fatal(err)
	}
	c = wait(t, e.m, c.ID)
	if c.Status != StatusValid || c.Days != 397 || c.KeyType != KeyECDSA || c.DaysLeft() < 395 {
		t.Fatalf("issued: %+v", c)
	}
	b, _ := e.m.Bundle(ctx, c.ID)
	if b.Leaf.CheckSignature(b.Leaf.SignatureAlgorithm, b.Leaf.RawTBSCertificate, b.Leaf.Signature) != nil || b.Leaf.IsCA || b.ChainPEM != "" ||
		b.Leaf.Issuer.String() != b.Leaf.Subject.String() {
		t.Fatal("must be a self-signed end-entity certificate")
	}
	pool := x509.NewCertPool()
	pool.AddCert(b.Leaf)
	for _, n := range []string{"node64.home.local", "nas.home.local", "192.168.10.30"} {
		if _, err := b.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: n}); err != nil {
			t.Fatalf("verify %s: %v", n, err)
		}
	}
	if e.m.ForName("node64.home.local") == nil {
		t.Fatal("not usable by name")
	}
	r, err := e.m.Create(ctx, Request{Names: []string{"alt.home.local"}, Source: SourceSelf, KeyType: KeyRSA, Days: 30})
	if err != nil {
		t.Fatal(err)
	}
	r = wait(t, e.m, r.ID)
	rb, _ := e.m.Bundle(ctx, r.ID)
	if pub, ok := rb.Leaf.PublicKey.(*rsa.PublicKey); !ok || pub.N.BitLen() != 2048 || r.Days != 30 {
		t.Fatalf("rsa: %+v", r)
	}
	var ve *ValidationError
	if _, err := e.m.Create(ctx, Request{Names: []string{"x.local"}, Source: SourceSelf, KeyType: "dsa"}); !errors.As(err, &ve) || ve.Field != "key_type" {
		t.Fatalf("key type: %v", err)
	}
	if _, err := e.m.Create(ctx, Request{Names: []string{"x.local"}, Source: SourceSelf, Days: 900}); !errors.As(err, &ve) || ve.Field != "days" {
		t.Fatalf("days: %v", err)
	}
	// faellig: erneuert sich selbst, auch ohne Let's-Encrypt-Bedingungen
	if err := e.m.Renew(ctx, c.ID); err != nil {
		t.Fatalf("renew without TOS: %v", err)
	}
	_ = wait(t, e.m, c.ID)
	if _, err := e.m.w.ExecContext(ctx, `UPDATE certs SET not_after = ? WHERE id = ?`, store.FormatTime(time.Now().Add(5*24*time.Hour)), c.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.m.Get(ctx, c.ID); !needsRenewal(got) {
		t.Fatal("must be due 5 days before expiry")
	}
}
