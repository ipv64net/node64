package healthchecks

import "testing"

func TestCertNotAfter(t *testing.T) {
	if tm, ok := certNotAfter([]byte(`{"cert_not_after":"2026-12-01T00:00:00Z"}`)); !ok || tm.Day() != 1 {
		t.Fatalf("top level: %v %v", tm, ok)
	}
	tm, ok := certNotAfter([]byte(`{"ipv4":{"cert_not_after":"2026-12-05T00:00:00Z"},"ipv6":{"cert_not_after":"2026-12-03T00:00:00Z"}}`))
	if !ok || tm.Day() != 3 {
		t.Fatalf("families: %v %v", tm, ok)
	}
	if _, ok := certNotAfter([]byte(`{"status":200}`)); ok {
		t.Fatal("no cert expected")
	}
}

func TestCertFromMessage(t *testing.T) {
	tm, ok := CertFromMessage("ipv4: HTTP 200, cert valid until 2026-12-08 (57 days) | ipv6: HTTP 200, cert valid until 2026-12-06 (55 days)")
	if !ok || tm.Day() != 6 {
		t.Fatalf("%v %v", tm, ok)
	}
	if _, ok := CertFromMessage("HTTP 200"); ok {
		t.Fatal("no date expected")
	}
}
