package notify

import "testing"

func TestSMSNumber(t *testing.T) {
	ok := map[string]string{"491771234567": "00491771234567", "+49 177 1234567": "00491771234567", "00491771234567": "00491771234567", "43 660 1234567": "00436601234567"}
	for in, want := range ok {
		if got, err := SMSNumber(in); err != nil || got != want {
			t.Errorf("SMSNumber(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "01771234567", "0660 1234567", "12"} {
		if got, err := SMSNumber(bad); err == nil {
			t.Errorf("SMSNumber(%q) = %q, want error", bad, got)
		}
	}
}
