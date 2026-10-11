package totp

import (
	"strings"
	"testing"
	"time"
)

func TestRFC6238Vector(t *testing.T) {
	// RFC 6238, Anhang B: Geheimnis "12345678901234567890", SHA1, T=59 -> 94287082 (8 Stellen); 6 Stellen = 287082
	secret := enc.EncodeToString([]byte("12345678901234567890"))
	code, err := Code(secret, time.Unix(59, 0))
	if err != nil || code != "287082" {
		t.Fatalf("got %s %v", code, err)
	}
	if c, _ := Code(secret, time.Unix(1111111109, 0)); c != "081804" {
		t.Fatalf("second vector: %s", c)
	}
	now := time.Unix(1111111109, 0)
	if !Verify(secret, "081804", now) || !Verify(secret, "081804", now.Add(29*time.Second)) || Verify(secret, "000000", now) {
		t.Fatal("verify")
	}
	if !Verify(secret, "081804", now.Add(20*time.Second)) {
		t.Fatal("window of one period must be accepted")
	}
	if Verify(secret, "081804", now.Add(91*time.Second)) {
		t.Fatal("outside window must fail")
	}
}

func TestSecretAndRecovery(t *testing.T) {
	s := NewSecret()
	if len(s) != 32 || !strings.HasPrefix(URL("Node64", "admin", s), "otpauth://totp/Node64:admin?") {
		t.Fatalf("secret/url: %s %s", s, URL("Node64", "admin", s))
	}
	if _, err := Code(s, time.Now()); err != nil {
		t.Fatal(err)
	}
	codes, hashes := NewRecoveryCodes(8)
	if len(codes) != 8 || len(codes[0]) != 11 {
		t.Fatalf("codes: %v", codes)
	}
	rest, ok := UseRecovery(strings.ToUpper(codes[3]), hashes)
	if !ok || len(rest) != 7 {
		t.Fatal("recovery code must work once, case-insensitive")
	}
	if _, ok := UseRecovery(codes[3], rest); ok {
		t.Fatal("used code must not work again")
	}
}
