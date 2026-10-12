package hubnotify

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSMSText(t *testing.T) {
	if got := smsText("✅ IPv64.net Testbenachrichtigung - Dies ist ein Test für „x“ 🔴"); got != "IPv64.net Testbenachrichtigung - Dies ist ein Test für „x“" {
		t.Errorf("smsText = %q", got)
	}
	long := strings.Repeat("a", 299) + "ü" // 301 Bytes, das ü beginnt bei Byte 299
	if got := truncRunes(long, 300); !utf8.ValidString(got) || len(got) != 299 {
		t.Errorf("truncRunes cut a rune: len %d valid %v", len(got), utf8.ValidString(got))
	}
}
