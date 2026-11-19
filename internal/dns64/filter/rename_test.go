package filter

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// #224: Umbenennen wirkt sofort auf Grund und Status, ohne die Liste neu zu laden.
func TestManagerRename(t *testing.T) {
	dir := t.TempDir()
	l := List{Name: "raw.githubusercontent.com · malware", URL: "https://example.com/malware.txt"}
	if err := os.WriteFile(fileFor(dir, l.URL), []byte("ads.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, _ := LoadAllowlist(filepath.Join(dir, "allow.txt"))
	m, err := NewManager(dir, []List{l}, time.Hour, a, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if b, why := m.Check("ads.example.com"); !b || why != l.Name {
		t.Fatalf("before: %v %q", b, why)
	}
	if !m.Rename(l.URL, "Malware") || m.Rename("https://example.com/other.txt", "x") {
		t.Fatal("rename result")
	}
	if b, why := m.Check("ads.example.com"); !b || why != "Malware" {
		t.Fatalf("after: %v %q", b, why)
	}
	if st, _ := m.Status(); len(st) != 1 || st[0].Name != "Malware" || st[0].Rules != 1 {
		t.Fatalf("status: %+v", st)
	}
}
