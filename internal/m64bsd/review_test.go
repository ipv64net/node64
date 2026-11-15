package m64bsd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
)

// Review 13 (#159 auch fuer FreeBSD/OPNsense): Aendert sich die Paketdatenbank (pkg upgrade, pkg update), liest der
// Agent die Updates neu, statt bis zu einer Stunde den alten Stand zu melden - fruehestens eine Minute nach dem
// letzten Lauf.
func TestReviewUpdatesPkgChange(t *testing.T) {
	db := filepath.Join(t.TempDir(), "local.sqlite")
	write := func(s string, mt time.Time) {
		t.Helper()
		if err := os.WriteFile(db, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(db, mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	base := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	write("a", base.Add(-time.Hour))
	var mu sync.Mutex
	now := base
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	ex := &fakeExec{out: map[string]ExecResult{"/usr/local/sbin/pkg version -U -R -l <": {}, "/usr/local/sbin/pkg audit": {}}}
	opt := Options{Sections: []string{m64proto.SecUpdates}, Exec: ex.exec, Has: func(n string) bool { return n == "/usr/local/sbin/pkg" },
		Sysctl: fakeSysctl{}.fn(), Cache: NewCache(), PkgFiles: []string{db},
		Now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now }}
	count := func() int {
		ex.mu.Lock()
		defer ex.mu.Unlock()
		n := 0
		for _, c := range ex.calls {
			if strings.HasPrefix(c, "/usr/local/sbin/pkg version") {
				n++
			}
		}
		return n
	}
	run := func() { Collect(context.Background(), opt); opt.Cache.Wait() }
	run()
	advance(10 * time.Minute)
	run()
	if count() != 1 {
		t.Fatalf("ohne Aenderung neu gelesen: %d", count())
	}
	write("ab", base.Add(10*time.Minute))
	advance(30 * time.Second)
	run()
	if count() != 2 {
		t.Fatalf("Aenderung nicht erkannt: %d", count())
	}
	write("abc", base.Add(11*time.Minute))
	advance(30 * time.Second)
	run()
	if count() != 2 {
		t.Fatalf("zu frueh neu gelesen: %d", count())
	}
	advance(time.Minute)
	run()
	if count() != 3 {
		t.Fatalf("zweite Aenderung nicht erkannt: %d", count())
	}
}
