package m64proto

import (
	"strings"
	"testing"
)

func TestHint(t *testing.T) {
	if got := Hint(HintMissing, "smartctl"); got != "{m64:missing=smartctl}" {
		t.Fatalf("Hint = %q", got)
	}
	if got := Hint(HintTooLarge, "5000000", "4194304"); got != "{m64:too_large=5000000;4194304}" {
		t.Fatalf("zwei Werte = %q", got)
	}
	// Klammern und Semikolon in Werten zerstoeren den Code nicht
	args := []string{"a{b};c"}
	if got := Hint("x", args...); got != "{m64:x=a(b),c}" || args[0] != "a{b};c" {
		t.Fatalf("Sonderzeichen = %q %q", got, args)
	}
	if HintReading != Hint("reading") {
		t.Fatalf("Konstante und Hint verschieden: %q", HintReading)
	}
}

func TestReplaceHints(t *testing.T) {
	known := func(code string, args []string) (string, bool) {
		if code == "neu" {
			return "", false // unbekannter Code einer neueren Version bleibt stehen
		}
		return "<" + code + ":" + strings.Join(args, "|") + ">", true
	}
	upper := strings.ToUpper
	for in, want := range map[string]string{
		"":                                     "",
		"smartctl fehlt":                       "SMARTCTL FEHLT", // alter Agent: freier Text
		HintReading:                            "<reading:>",
		"smartctl: " + HintTimeout:             "SMARTCTL: <timeout:>",
		"statfs /mnt: {m64:hung=5s}":           "STATFS /MNT: <hung:5s>",
		Hint(HintTooLarge, "1", "2") + " ende": "<too_large:1|2> ENDE",
		HintSecUnknown + ": exit 1; " + Hint(HintExitCode, "3"): "<sec_unknown:>: EXIT 1; <exit_code:3>",
		"vor {m64:neu=1} nach": "VOR {M64:NEU=1} NACH",
		"{m64:kaputt":          "{M64:KAPUTT",
		"{m64:GROSS}":          "{M64:GROSS}",
	} {
		if got := ReplaceHints(in, known, upper); got != want {
			t.Errorf("%q = %q, erwartet %q", in, got, want)
		}
	}
	if got := ReplaceHints("x "+HintTimeout, known, nil); got != "x <timeout:>" {
		t.Errorf("ohne Textfunktion = %q", got)
	}
}

// Localize wendet die Funktion genau einmal an (MapReport darf denselben Bericht mehrfach sehen).
func TestLocalizeOnce(t *testing.T) {
	r := &Report{Errors: []SectionErr{{Section: SecSmart, Error: "a"}}, Notes: []SectionNote{{Section: SecUpdates, Note: "b"}}}
	f := func(s string) string { return s + "!" }
	r.Localize(f)
	r.Localize(f)
	if r.Errors[0].Error != "a!" || r.Notes[0].Note != "b!" {
		t.Fatalf("%+v", r)
	}
	var none *Report
	none.Localize(f) // kein Absturz
}
