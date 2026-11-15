package cdn64

import (
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Review: Der Schreiber las "Adressen kuerzen" fuer die Zugriffslog-Datei nur, wenn die Datei beim Start schon an war
// (accessFileApply laeuft erst danach) bzw. nach einem Takt mit eingeschalteter Datei. Bis dahin standen volle
// Client-Adressen in access.log, obwohl Kuerzen an war.
func TestAccessFileAnonFromStart(t *testing.T) {
	dir := t.TempDir()
	s, err := openStats(dir, slog.New(slog.NewTextHandler(io.Discard, nil)), func() int { return 7 }, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	s.afOn.Store(true) // wie accessFileApply nach openStats
	s.add(hit{time: time.Now(), client: netip.MustParseAddr("203.0.113.77"), method: "GET", host: "cloud.example.com", path: "/", status: 200, proto: "HTTP/1.1"})
	s.close()
	b, err := os.ReadFile(filepath.Join(dir, accessFileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "203.0.113.77") || !strings.Contains(string(b), "203.0.113.0") {
		t.Fatalf("full address in access.log: %q", b)
	}
}
