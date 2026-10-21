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
