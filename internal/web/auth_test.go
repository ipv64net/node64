package web

import (
	"strings"
	"testing"
	"time"
)

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$") {
		t.Fatalf("unexpected format: %s", h)
	}
	if !VerifyPassword(h, "correct horse battery") {
		t.Fatal("valid password rejected")
	}
	if VerifyPassword(h, "wrong") || VerifyPassword("garbage", "x") || VerifyPassword("", "") {
		t.Fatal("invalid password accepted")
	}
	h2, _ := HashPassword("correct horse battery")
	if h == h2 {
		t.Fatal("salt must differ")
	}
}

func TestLoginLimiter(t *testing.T) {
	l := newLoginLimiter()
	for i := 0; i < 5; i++ {
		if l.retryAfter("ip:1") != 0 {
			t.Fatalf("attempt %d should be allowed", i)
		}
		l.fail("ip:1")
	}
	wait := l.retryAfter("ip:1")
	if wait <= 0 || wait > 31*time.Second {
		t.Fatalf("expected wait of up to 30s, got %v", wait)
	}
	if l.retryAfter("ip:2") != 0 {
		t.Fatal("other key must not be affected")
	}
}

func TestSafeNext(t *testing.T) {
	cases := map[string]string{"": "/", "/settings": "/settings", "//evil.com": "/", "https://evil.com": "/", "/a\r\nb": "/",
		"/\t/evil.example": "/", "/ /evil.example": "/", "/\\evil.example": "/", "/a\x7fb": "/", "/settings?tab=1#x": "/settings?tab=1#x"}
	for in, want := range cases {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIPKey(t *testing.T) {
	if ipKey("192.0.2.7") != "192.0.2.7" {
		t.Fatal("ipv4 must stay unchanged")
	}
	if a, b := ipKey("2001:db8:1:2:aaaa::1"), ipKey("2001:db8:1:2:bbbb::9"); a != b || a != "2001:db8:1:2::/64" {
		t.Fatalf("ipv6 must map to /64: %s %s", a, b)
	}
	if ipKey("not an ip") != "not an ip" {
		t.Fatal("garbage must pass through")
	}
}
