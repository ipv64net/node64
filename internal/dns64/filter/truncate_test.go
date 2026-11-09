package filter

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Liste groesser als die Grenze: an der letzten ganzen Zeile gekuerzt und gemeldet statt still abgeschnitten (Forum 5057).
func TestDownloadTruncate(t *testing.T) {
	old := maxListSize
	maxListSize = 15
	defer func() { maxListSize = old }()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/small" {
			_, _ = io.WriteString(w, "a.example\n")
			return
		}
		_, _ = io.WriteString(w, "a.example\nbb.example\nccc.example\n")
	}))
	defer srv.Close()
	m := &Manager{client: srv.Client(), log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	dst := filepath.Join(t.TempDir(), "l.txt")
	cut, err := m.download(context.Background(), srv.URL+"/big", dst)
	b, _ := os.ReadFile(dst)
	if err != nil || !cut || string(b) != "a.example\n" {
		t.Fatalf("big: cut=%v err=%v %q", cut, err, b)
	}
	cut, err = m.download(context.Background(), srv.URL+"/small", dst)
	b, _ = os.ReadFile(dst)
	if err != nil || cut || string(b) != "a.example\n" {
		t.Fatalf("small: cut=%v err=%v %q", cut, err, b)
	}
}
