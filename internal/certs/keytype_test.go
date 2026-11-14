package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"testing"
)

// #62: Schluesselart fuer Let's-Encrypt-Zertifikate waehlbar (ECDSA P-256, RSA 2048, RSA 4096) und nachtraeglich
// aenderbar - das vorhandene Zertifikat bleibt, die naechste Erneuerung nimmt die neue Art.
func TestKeyTypeLetsEncrypt(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	if err := e.m.SetAccount(ctx, "admin@example.test", true); err != nil {
		t.Fatal(err)
	}
	bits := func(id int64) int {
		t.Helper()
		b, err := e.m.Bundle(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		switch k := b.Leaf.PublicKey.(type) {
		case *rsa.PublicKey:
			return k.N.BitLen()
		case *ecdsa.PublicKey:
			return 256
		}
		return 0
	}
	c, err := e.m.Create(ctx, Request{Names: []string{"nas.home.ipv64.de"}, Source: SourceIPv64, KeyType: KeyRSA4096})
	if err != nil {
		t.Fatal(err)
	}
	c = wait(t, e.m, c.ID)
	if c.Status != StatusValid || c.KeyType != KeyRSA4096 || bits(c.ID) != 4096 || c.KeyTypeName() != "RSA 4096" {
		t.Fatalf("rsa4096: %+v (%d bit)", c, bits(c.ID))
	}

	d, err := e.m.Create(ctx, Request{Names: []string{"dsm.home.ipv64.de"}, Source: SourceIPv64})
	if err != nil {
		t.Fatal(err)
	}
	d = wait(t, e.m, d.ID)
	if d.KeyType != "" || bits(d.ID) != 256 || d.KeyTypeName() != "ECDSA P-256" {
		t.Fatalf("default: %+v", d)
	}
	// aendern: das vorhandene Zertifikat bleibt ECDSA, die Erneuerung holt RSA 2048
	if err := e.m.SetKeyType(ctx, d.ID, KeyRSA); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.m.Get(ctx, d.ID); got.KeyType != KeyRSA || bits(d.ID) != 256 {
		t.Fatalf("after change: %+v (%d bit)", got, bits(d.ID))
	}
	if err := e.m.Renew(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	if d = wait(t, e.m, d.ID); bits(d.ID) != 2048 {
		t.Fatalf("renewed: %d bit", bits(d.ID))
	}
	// zurueck auf ECDSA: gespeichert wie beim Anlegen (leer)
	if err := e.m.SetKeyType(ctx, d.ID, KeyECDSA); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.m.Get(ctx, d.ID); got.KeyType != "" {
		t.Fatalf("ecdsa: %q", got.KeyType)
	}
	var ve *ValidationError
	if err := e.m.SetKeyType(ctx, d.ID, "dsa"); !errors.As(err, &ve) || ve.Field != "key_type" {
		t.Fatalf("invalid: %v", err)
	}
	if _, err := e.m.Create(ctx, Request{Names: []string{"x.home.ipv64.de"}, Source: SourceIPv64, KeyType: "rsa1024"}); !errors.As(err, &ve) {
		t.Fatalf("create invalid: %v", err)
	}
	// hochgeladen: keine Wahl
	certPEM, keyPEM := selfSignedPEM(t, 30, "up.example.org")
	up, err := e.m.Upload(ctx, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if up.KeyTypeChangeable() || e.m.SetKeyType(ctx, up.ID, KeyRSA) == nil {
		t.Fatal("upload must not change key type")
	}
	// selbst signiert: RSA 4096 und Wechsel
	s, err := e.m.Create(ctx, Request{Names: []string{"a.home.local"}, Source: SourceSelf, KeyType: KeyRSA4096})
	if err != nil {
		t.Fatal(err)
	}
	if s = wait(t, e.m, s.ID); bits(s.ID) != 4096 {
		t.Fatalf("self rsa4096: %d", bits(s.ID))
	}
	if err := e.m.SetKeyType(ctx, s.ID, ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.m.Get(ctx, s.ID); got.KeyType != KeyECDSA {
		t.Fatalf("self ecdsa: %q", got.KeyType)
	}
}
