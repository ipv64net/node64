package filter

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// Textfeld mit hosts-Zeilen: die Domain kommt aus dem zweiten Feld, IP-Adressen sind nie ein Eintrag, Standardnamen
// einer hosts-Datei werden uebergangen; New nennt die neu aufgenommenen Domains.
func TestReplaceHosts(t *testing.T) {
	d, _ := LoadDenylist(filepath.Join(t.TempDir(), "deny.txt"))
	if _, err := d.Add("alt.example"); err != nil {
		t.Fatal(err)
	}
	res, err := d.Replace([]string{"0.0.0.0 ads.example", "127.0.0.1 localhost", "::1 ip6-localhost", "0.0.0.0 0.0.0.0",
		"0.0.0.0", "1.2.3.4", "alt.example", "*.Neu.Example\t2026-01-01T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 3 || res.Added != 2 || !slices.Equal(res.Invalid, []string{"0.0.0.0", "1.2.3.4"}) {
		t.Fatalf("replace: %+v", res)
	}
	slices.Sort(res.New)
	if !slices.Equal(res.New, []string{"ads.example", "neu.example"}) {
		t.Fatalf("new: %v", res.New)
	}
	if !d.Contains("ads.example") || d.Contains("0.0.0.0") {
		t.Fatalf("list: %s", d.Text())
	}
	if _, err := d.Add("0.0.0.0"); err != ErrInvalidDomain {
		t.Fatalf("Add IP: %v", err)
	}
}

// Freigabe-Listen ohne Liste bauen keinen Matcher; mit einer kleinen Liste bleibt der Speicher klein (frueher zwei
// auf 2^18 vorbelegte Maps, knapp 19 MB).
func TestReleaseManagerSmall(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	empty, err := NewReleaseManager(dir, nil, 0, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	if empty.Matcher() != nil {
		t.Fatal("matcher without lists")
	}
	if _, ok := empty.Released("x.example"); ok {
		t.Fatal("empty manager releases")
	}

	l := List{Name: "ok", URL: "https://allow.example/ok.txt"}
	if err := os.WriteFile(fileFor(dir, l.URL), []byte("@@||cdn.example^\nshop.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	m, err := NewReleaseManager(dir, []List{l}, 0, nil, log)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > 2<<20 {
		t.Fatalf("release manager allocated %d bytes", got)
	}
	if name, ok := m.Released("img.cdn.example"); !ok || name != "ok" {
		t.Fatalf("Released: %q %v", name, ok)
	}
}

// Exempt: eigene Freigabe oder Freigabe-Liste (auch ohne Freigabe-Listen und ohne Freigaben).
func TestExempt(t *testing.T) {
	dir := t.TempDir()
	a, _ := LoadAllowlist(filepath.Join(dir, "allow.txt"))
	if _, err := a.Add("own.example"); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Allow: a}
	if !m.Exempt("x.own.example") || m.Exempt("shop.example") {
		t.Fatal("Exempt without release lists")
	}
	rel := &Manager{lists: []List{{Name: "ok", URL: "https://x.example/ok.txt"}}, release: true}
	rm := newMatcher([]string{"ok"})
	rm.loadAs(0, strings.NewReader("shop.example\n"), true)
	rel.cur.Store(rm)
	m.Release = rel
	if !m.Exempt("shop.example") || m.Exempt("other.example") {
		t.Fatal("Exempt with release lists")
	}
	if (&Manager{}).Exempt("own.example") {
		t.Fatal("Exempt on empty manager")
	}
}
