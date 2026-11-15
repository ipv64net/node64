package module

import "testing"

func TestCSVCell(t *testing.T) {
	for in, want := range map[string]string{"=1+1": "'=1+1", "-1+1": "'-1+1", "+x": "'+x", "@x": "'@x", "\tx": "'\tx", "\rx": "'\rx", "ok": "ok", "": "", "a=b": "a=b"} {
		if got := CSVCell(in); got != want {
			t.Errorf("CSVCell(%q) = %q, want %q", in, got, want)
		}
	}
}
