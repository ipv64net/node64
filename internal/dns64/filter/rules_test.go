package filter

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Eigene Filterregeln im AdGuard/Adblock-Stil (Forum 5162): Sperren, Freigaben, einfache Domains, hosts-Zeilen;
// $client und Regeln nur fuer genau einen Namen werden mit eigenem Fehler abgelehnt.
func TestParseRule(t *testing.T) {
	for _, c := range []struct {
		in    string
		want  Rule
		empty bool
		err   error
	}{
		{in: "||ads.example.com^", want: Rule{Domain: "ads.example.com"}},
		{in: "@@||example.com^", want: Rule{Domain: "example.com", Allow: true}},
		{in: "@@||example.com^$important", want: Rule{Domain: "example.com", Allow: true}},
		{in: "||Tracker.Example.ORG^|", want: Rule{Domain: "tracker.example.org"}},
		{in: "example.net", want: Rule{Domain: "example.net"}},
		{in: "*.example.net", want: Rule{Domain: "example.net"}},
		{in: "example.net^", want: Rule{Domain: "example.net"}},
		{in: "0.0.0.0 ads.example.net # Werbung", want: Rule{Domain: "ads.example.net"}},
		{in: "example.com\t2026-11-14T10:00:00Z", want: Rule{Domain: "example.com"}},
		{in: "bücher.example", want: Rule{Domain: "xn--bcher-kva.example"}},
		{in: "# Kategorie A", empty: true},
		{in: "! AdGuard-Kommentar", empty: true},
		{in: "   ", empty: true},
		{in: "0.0.0.0 localhost", empty: true},
		{in: "@@||example.com^$client='192.168.0.100'", err: ErrRuleClient},
		{in: "||example.com^$client=192.168.0.100", err: ErrRuleClient},
		{in: "|exact.example.com^", err: ErrRuleExact},
		{in: "@@|exact.example.com^", err: ErrRuleExact},
		{in: "||example.com^$third-party", err: ErrInvalidDomain},
		{in: "example.com##.banner", err: ErrInvalidDomain}, // Browser-Regel sperrt nie die ganze Domain
		{in: "||example.com/werbung^", err: ErrInvalidDomain},
		{in: "192.168.1.1", err: ErrInvalidDomain},
		{in: "@@0.0.0.0 example.com", err: ErrInvalidDomain},
	} {
		r, tok, err := ParseRule(c.in)
		if c.empty {
			if tok != "" || err != nil {
				t.Fatalf("%q: tok=%q err=%v, want nothing to do", c.in, tok, err)
			}
			continue
		}
		if tok == "" {
			t.Fatalf("%q: tok empty", c.in)
		}
		if c.err != nil {
			if !errors.Is(err, c.err) {
				t.Fatalf("%q: err=%v, want %v", c.in, err, c.err)
			}
			continue
		}
		if err != nil || r != c.want {
			t.Fatalf("%q: %+v %v, want %+v", c.in, r, err, c.want)
		}
	}
}

// Textfeld "Eigene Filterregeln": Sperren in die Sperrliste, Freigaben in die Freigaben; ungueltige Zeilen gemeldet,
// nur ungueltige Zeilen aendern nichts. Die Listen-Dateien lesen auch von Hand eingetragene Regeln.
func TestReplaceRules(t *testing.T) {
	dir := t.TempDir()
	allow, _ := LoadAllowlist(filepath.Join(dir, "allowlist.txt"))
	deny, _ := LoadDenylist(filepath.Join(dir, "denylist.txt"))
	if _, err := allow.Add("alt.example"); err != nil {
		t.Fatal(err)
	}
	res, err := ReplaceRules(allow, deny, []string{
		"# Werbung", "||ads.example.com^", "tracker.example.org", "||ads.example.com^",
		"", "! Freigaben", "@@||example.com^", "@@||cdn.example.net^$important",
		"@@||kind.example^$client='192.168.0.100'", "|genau.example^", "kaputt!",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Deny != 2 || res.Allow != 2 || res.Duplicates != 1 || len(res.Invalid) != 3 || res.Client != 1 || res.Exact != 1 || res.Removed != 1 || res.Added != 4 {
		t.Fatalf("result: %+v", res)
	}
	if !deny.Contains("x.ads.example.com") || !allow.Contains("example.com") || allow.Contains("alt.example") {
		t.Fatalf("lists: deny=%q allow=%q", deny.Text(), allow.Text())
	}
	want := "||ads.example.com^\n||tracker.example.org^\n@@||cdn.example.net^\n@@||example.com^"
	if got := RulesText(allow, deny); got != want {
		t.Fatalf("text:\n%s\nwant:\n%s", got, want)
	}
	if _, err := ReplaceRules(allow, deny, []string{"kaputt!", "|x.example^"}); !errors.Is(err, ErrInvalidDomain) || deny.Len() != 2 {
		t.Fatalf("only invalid lines: %v, deny %d", err, deny.Len())
	}

	// Einzelfelder: Adblock-Stil erlaubt; eine Freigabe-Regel gehoert nicht in die Sperrliste
	if d, err := deny.Add("||werbung.example^"); err != nil || d != "werbung.example" {
		t.Fatalf("deny add: %q %v", d, err)
	}
	if _, err := deny.Add("@@||example.com^"); !errors.Is(err, ErrRuleAllow) {
		t.Fatalf("deny add @@: %v", err)
	}
	if d, err := allow.Add("@@||frei.example^"); err != nil || d != "frei.example" {
		t.Fatalf("allow add: %q %v", d, err)
	}

	// von Hand in die Datei geschrieben (z. B. /data/dns64/allowlist.txt)
	p := filepath.Join(dir, "hand.txt")
	_ = os.WriteFile(p, []byte("# eigene\n@@||example.com^\n||example.net^\nexample.org\t2026-11-14T10:00:00Z\n"), 0o644)
	h, err := LoadAllowlist(p)
	if err != nil || !h.Contains("www.example.com") || !h.Contains("example.net") || !h.Contains("example.org") {
		t.Fatalf("hand-written allowlist: %q %v", h.Text(), err)
	}
	hd, _ := LoadDenylist(p) // @@ in der Sperrliste zaehlt nicht
	if hd.Contains("example.com") || !strings.Contains(hd.Text(), "example.net") {
		t.Fatalf("hand-written denylist: %q", hd.Text())
	}
}

// Suche "In welcher Liste steht diese Domain?": alle Listen mit einer Regel (auch fuer eine Elterndomain), nicht nur
// die erste wie beim Sperren.
func TestMatcherLists(t *testing.T) {
	m := newMatcher([]string{"A", "B", "C"})
	_, _ = m.load(0, strings.NewReader("||example.com^\n"))
	_, _ = m.load(1, strings.NewReader("ads.example.com\n"))
	_, _ = m.load(2, strings.NewReader("@@||ads.example.com^\nother.example\n"))
	mask, exc := m.Lists("ads.example.com")
	if got := m.ListNames(mask); len(got) != 2 || got[0] != "A" || got[1] != "B" || !exc {
		t.Fatalf("lists = %v excepted = %v", got, exc)
	}
	if mask, exc := m.Lists("example.com"); len(m.ListNames(mask)) != 1 || exc {
		t.Fatalf("example.com: %v %v", m.ListNames(mask), exc)
	}
	if mask, _ := m.Lists("nothing.example"); mask != 0 {
		t.Fatal("unexpected hit")
	}
}
