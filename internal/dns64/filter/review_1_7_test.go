package filter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Code-Review 1.7: hosts-Zeile mit Tab in der Datei der eigenen Sperrliste geht beim Laden und naechsten Speichern
// nicht verloren.
func TestDenylistHostsTab(t *testing.T) {
	p := filepath.Join(t.TempDir(), "denylist.txt")
	if err := os.WriteFile(p, []byte("# Eigene Sperrliste\n0.0.0.0\tads.example.com\nold.example.org\t2026-11-01T10:00:00Z\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := LoadDenylist(p)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Contains("ads.example.com") || !d.Contains("old.example.org") {
		t.Fatalf("loaded %v", d.domains())
	}
	if _, err := d.Add("new.example.net"); err != nil {
		t.Fatal(err)
	}
	d2, err := LoadDenylist(p)
	if err != nil {
		t.Fatal(err)
	}
	if !d2.Contains("ads.example.com") || !d2.Contains("old.example.org") || !d2.Contains("new.example.net") {
		t.Fatalf("after save %v", d2.domains())
	}
}

// Eigene Regeln lesen hosts-Zeilen wie die Blocklisten: nur Sperr-Adressen (eine Zuordnung "192.168.1.10 nas.lan"
// sperrt nicht) und ein Name je Zeile (sonst Meldung statt nur den ersten Namen zu sperren).
func TestRuleHostsLikeLists(t *testing.T) {
	for _, line := range []string{"192.168.1.10 nas.lan", "0.0.0.0 a.example.com b.example.com"} {
		if _, kind := parseLine(line); kind != ruleNone {
			t.Fatalf("list %q: %v", line, kind)
		}
		if r, tok, err := ParseRule(line); tok == "" || err == nil {
			t.Fatalf("rule %q blocks %+v", line, r)
		}
	}
	for _, line := range []string{"0.0.0.0 ads.example.com", "127.0.0.1\tads.example.com", ":: ads.example.com"} {
		if d, kind := parseLine(line); kind != ruleExact || d != "ads.example.com" {
			t.Fatalf("list %q: %q %v", line, d, kind)
		}
		if r, _, err := ParseRule(line); err != nil || r.Domain != "ads.example.com" || r.Allow {
			t.Fatalf("rule %q: %+v %v", line, r, err)
		}
	}
	if _, tok, _ := ParseRule("::1 localhost ip6-localhost ip6-loopback"); tok != "" {
		t.Fatalf("hosts default names: %q", tok)
	}
}

// Reine IP-Adressen sind keine Domain: in Blocklisten zaehlen sie nicht als Eintrag; nicht erkannte Zeilen werden
// gezaehlt (Listenstatus), Kommentare und Leerzeilen nicht.
func TestListIPNotDomain(t *testing.T) {
	for _, line := range []string{"1.2.3.4", "||10.0.0.1^", "0.0.0.0 192.168.1.1"} {
		if d, kind := parseLine(line); kind != ruleNone {
			t.Fatalf("%q counted as %q", line, d)
		}
	}
	m := newMatcher([]string{"a"})
	n, err := m.load(0, strings.NewReader("# Kommentar\n\n1.2.3.4\nads.example.com\nexample.com##.banner\n! adblock\n"))
	if err != nil || n != 1 {
		t.Fatalf("rules %d %v", n, err)
	}
	if m.Skipped(0) != 2 {
		t.Fatalf("skipped %d", m.Skipped(0))
	}
}
