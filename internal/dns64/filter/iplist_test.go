package filter

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #164: Eine Liste mit IP-Adressen (z. B. Honeypot-Liste fuer Firewalls) ergab "0 Eintraege" ohne Erklaerung.
func TestListIPHint(t *testing.T) {
	dir := t.TempDir()
	ipl := List{Name: "Honeypot", URL: "https://example.com/honeypot.txt"}
	dom := List{Name: "Domains", URL: "https://example.com/domains.txt"}
	empty := List{Name: "Leer", URL: "https://example.com/empty.txt"}
	for l, body := range map[List]string{
		ipl:   "# ipv64 blocklist\n192.0.2.1\n198.51.100.0/24\n2001:db8::/32\n",
		dom:   "ads.example.com\n",
		empty: "# nichts\n",
	} {
		if err := os.WriteFile(fileFor(dir, l.URL), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	a, _ := LoadAllowlist(filepath.Join(dir, "allow.txt"))
	m, err := NewManager(dir, []List{ipl, dom, empty}, time.Hour, a, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	st, _ := m.Status()
	want := map[string]string{"Honeypot": HintIPList, "Domains": "", "Leer": ""}
	for _, s := range st {
		if s.Hint != want[s.Name] {
			t.Errorf("%s: hint %q, want %q (rules %d)", s.Name, s.Hint, want[s.Name], s.Rules)
		}
	}
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"1.2.3.4\n5.6.7.8 # Kommentar\n", true},
		{"0.0.0.0 ads.example.com\n0.0.0.0 b.example.com\n", false}, // hosts-Datei
		{"; Kommentar\n10.0.0.0/8\nfoo bar\n", false},
		{"", false},
		{"irgendwas\n", false},
	} {
		if got := ipList(strings.NewReader(c.in)); got != c.want {
			t.Errorf("ipList(%q) = %v", c.in, got)
		}
	}
}
