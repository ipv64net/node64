package notify

import (
	"strings"
	"testing"
)

func TestRedactSecrets(t *testing.T) {
	in := `duckdns: update failed: Get "https://www.duckdns.org/update?domains=x&token=0f1e2d3c-aaaa-bbbb-cccc-123456789abc&txt=abc": EOF; ` +
		`provider said apikey=SECRET123 Authorization: Bearer abcdefghijklmnop password=hunter2`
	out := RedactSecrets(in)
	for _, bad := range []string{"0f1e2d3c", "SECRET123", "abcdefghijklmnop", "hunter2", "domains=x"} {
		if strings.Contains(out, bad) {
			t.Fatalf("not redacted (%s): %s", bad, out)
		}
	}
	if !strings.Contains(out, "https://www.duckdns.org/…") || !strings.Contains(out, "duckdns: update failed") {
		t.Fatalf("too much removed: %s", out)
	}
	if RedactSecrets("") != "" || RedactSecrets("plain error") != "plain error" {
		t.Fatal("plain text changed")
	}
}

// Schluessel mit Vor-/Nachsilbe, JSON-Paare, Authorization mit beliebigem Schema; "basic constraints" bleibt.
func TestRedactSecretsForms(t *testing.T) {
	for _, c := range []struct{ in, secret, keep string }{
		{"client_secret=s3cr3tV4lue", "s3cr3tV4lue", "client_secret=***"},
		{"auth_token=abc123xyz&x=1", "abc123xyz", "auth_token=***"},
		{"api_token: tk-998877", "tk-998877", "api_token: ***"},
		{"secret_key=AKIAxyz", "AKIAxyz", "secret_key=***"},
		{"X-Api-Key: 1234abcd", "1234abcd", "X-Api-Key: ***"},
		{`password="hunter2"`, "hunter2", `password="***"`},
		{`{"password":"hunter2","user":"bob"}`, "hunter2", `"user":"bob"`},
		{`{"api_key": "k-1\"2"}`, `k-1`, `"api_key": "***"`},
		{"Authorization: Token xyz", "xyz", "Authorization: Token ***"},
		{"authorization: Bot MTk4NjIy.abc", "MTk4NjIy", "authorization: Bot ***"},
		{"Authorization: rawkey123", "rawkey123", "Authorization: ***"},
		{"Basic dXNlcjpwYXNz", "dXNlcjpwYXNz", "Basic ***"},
		{"x509: invalid basic constraints a", "", "invalid basic constraints a"},
		{"use Basic Authentication please", "", "Basic Authentication"},
		{"see https://h.example#access_token=abc", "abc", "https://h.example/…"},
		{"dial http://[2001:db8::1]:8443/api?k=v failed", "k=v", "http://[2001:db8::1]:8443/… failed"},
	} {
		out := RedactSecrets(c.in)
		if (c.secret != "" && strings.Contains(out, c.secret)) || !strings.Contains(out, c.keep) {
			t.Errorf("%q -> %q", c.in, out)
		}
		if again := RedactSecrets(out); again != out {
			t.Errorf("not stable: %q -> %q", out, again)
		}
	}
}
