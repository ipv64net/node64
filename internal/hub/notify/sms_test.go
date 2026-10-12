package hubnotify

import "testing"

func TestSMSNumber(t *testing.T) {
	cases := map[string]string{"491771234567": "00491771234567", "+49 177 1234567": "00491771234567", "00491771234567": "00491771234567",
		"01771234567": "00491771234567", "43 660 123": "0043660123", "": ""}
	for in, want := range cases {
		if got := smsNumber(in); got != want {
			t.Errorf("smsNumber(%q) = %q, want %q", in, got, want)
		}
	}
	if got := smsText("✅ IPv64.net Testbenachrichtigung - Dies ist ein Test für „x“ 🔴"); got != "IPv64.net Testbenachrichtigung - Dies ist ein Test für „x“" {
		t.Errorf("smsText = %q", got)
	}
}
