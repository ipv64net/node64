package checks

import "testing"

func TestTokenHint(t *testing.T) {
	for in, want := range map[string]string{"": "", "12": "12", "abcdefgh": "abcdefgh", "zhM2nMLHabcdefghijklmnopqrstuvwx": "zhM2nM…"} {
		if got := TokenHint(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}
