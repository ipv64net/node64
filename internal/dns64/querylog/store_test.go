package querylog

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"
)

// Ein grosser Rueckstand wird in Stuecken geloescht, neue Eintraege bleiben, und Schreiben laeuft dazwischen weiter.
func TestPruneInBatches(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "q.db"), 24*time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	old := make([]Entry, 0, 2*pruneBatch+10)
	for i := 0; i < cap(old); i++ {
		old = append(old, Entry{Time: time.Now().Add(-48 * time.Hour), Client: "192.168.1.2", Domain: "old.example", QType: "A"})
	}
	s.write(old)
	s.write([]Entry{{Time: time.Now(), Client: "192.168.1.2", Domain: "new.example", QType: "A"}})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)
	s.Add(Entry{Time: time.Now(), Client: "fd00::2", Domain: "during.example", QType: "AAAA"})
	count := func(where string) int {
		var n int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM queries WHERE ` + where).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for i := 0; i < 200 && (count("domain = 'old.example'") > 0 || count("domain = 'during.example'") == 0); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if n := count("domain = 'old.example'"); n != 0 {
		t.Fatalf("%d old rows left", n)
	}
	if count("domain = 'new.example'") != 1 || count("domain = 'during.example'") != 1 {
		t.Fatal("new entries lost")
	}
	cancel()
	_ = s.Close()
}
