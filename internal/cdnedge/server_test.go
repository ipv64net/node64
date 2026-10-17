package cdnedge

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("name: srv07\nlocation: nbg\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(p)
	if err != nil || c.Name != "srv07" || c.ListenHTTP != ":80" || c.DataDir != "/var/lib/cdn64-edge" {
		t.Fatalf("%+v %v", c, err)
	}
	if err := os.WriteFile(p, []byte("location: nbg\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("name is required")
	}
}

// /health liefert lokal Einzelheiten, andere Pfade eine neutrale 404, Beenden ist sauber.
func TestHealthAndShutdown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	s := New(&Config{Name: "srv07", Location: "nbg", ListenHTTP: addr}, slog.New(slog.NewTextHandler(io.Discard, nil)), "0.1.0")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	var resp *http.Response
	for i := 0; i < 50; i++ {
		if resp, err = http.Get("http://" + addr + "/health"); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	var h Health
	_ = json.NewDecoder(resp.Body).Decode(&h)
	resp.Body.Close()
	if h.Status != "ok" || h.Name != "srv07" || h.Version != "0.1.0" || h.Location != "nbg" || h.Go == "" {
		t.Fatalf("health: %+v", h)
	}
	r2, err := http.Get("http://" + addr + "/irgendwas")
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if r2.StatusCode != http.StatusNotFound || r2.Header.Get("Server") != "" {
		t.Fatalf("neutral 404: %d %q", r2.StatusCode, r2.Header.Get("Server"))
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no clean shutdown")
	}
}
