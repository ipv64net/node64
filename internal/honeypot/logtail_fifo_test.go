//go:build linux

package honeypot

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Eine FIFO wird nicht geoeffnet (Open wuerde ohne Schreiber blockieren, unter dem Lock des Lesers).
func TestLogTailSkipsFIFO(t *testing.T) {
	p := filepath.Join(t.TempDir(), "auth.log")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	tt := newTailTest(t)
	done := make(chan struct{})
	go func() { tt.setFiles([]LogFile{{Path: p}}); tt.poll(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("poll blockiert an der FIFO")
	}
	st := tt.status()
	if len(st) != 1 || st[0].OK || st[0].Error != "not a regular file" {
		t.Fatalf("status %+v", st)
	}
}
