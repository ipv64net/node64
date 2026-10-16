//go:build loadtest

package certs

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/store"
)

// Lasttest der Verwaltung: viele Zertifikate der eigenen CA, die Haelfte faellig. Misst Ausstellen, Liste und
// einen Erneuerungslauf. Aufruf: go test -tags loadtest -run TestLoadCerts -v ./internal/certs/
func TestLoadCerts(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	e.m.loopFirst, e.m.loopEvery = time.Hour, time.Hour // Lauf von Hand
	ca, err := e.m.CreateCA(ctx, CAInput{Name: "Last"})
	if err != nil {
		t.Fatal(err)
	}
	const n = 500
	start := time.Now()
	for i := 0; i < n; i++ {
		days := 397
		names := []string{fmt.Sprintf("host%03d.lan", i), fmt.Sprintf("10.1.%d.%d", i/250, i%250+1)}
		if _, err := e.m.EnsureIssued(ctx, fmt.Sprintf("load%d", i), ca.ID, names, days); err != nil {
			t.Fatal(err)
		}
	}
	issued := time.Since(start)
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	t.Logf("%d Zertifikate ausgestellt in %v (%.1f ms je Zertifikat), Heap %d MB", n, issued.Round(time.Millisecond),
		float64(issued.Microseconds())/1000/n, ms.HeapAlloc>>20)

	start = time.Now()
	list, err := e.m.List(ctx)
	if err != nil || len(list) != n {
		t.Fatalf("list: %v %d", err, len(list))
	}
	t.Logf("Liste mit %d Eintraegen: %v", n, time.Since(start).Round(time.Microsecond))
	start = time.Now()
	for i := 0; i < 1000; i++ {
		if e.m.ForName(fmt.Sprintf("host%03d.lan", i%n)) == nil {
			t.Fatal("ForName")
		}
	}
	t.Logf("1000 Handshake-Suchen (ForName): %v", time.Since(start).Round(time.Microsecond))

	// die Haelfte laeuft in 5 Tagen ab: faellig
	if _, err := e.m.w.ExecContext(ctx, `UPDATE certs SET not_after = ? WHERE id % 2 = 0`, store.FormatTime(time.Now().Add(5*24*time.Hour))); err != nil {
		t.Fatal(err)
	}
	list, _ = e.m.List(ctx)
	due := 0
	for _, c := range list {
		if needsRenewal(c) {
			due++
		}
	}
	if due != n/2 {
		t.Fatalf("due: %d", due)
	}
	start = time.Now()
	e.m.due(ctx) // ein Lauf der Erneuerung: startet die faelligen im Hintergrund
	for i := 0; i < 600; i++ {
		left := 0
		list, _ = e.m.List(ctx)
		for _, c := range list {
			if needsRenewal(c) || c.Step != "" {
				left++
			}
		}
		if left == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	runtime.GC()
	runtime.ReadMemStats(&ms)
	t.Logf("Erneuerung von %d faelligen: %v, Heap danach %d MB, Goroutinen %d", due, time.Since(start).Round(time.Millisecond), ms.HeapAlloc>>20,
		runtime.NumGoroutine())
	for _, c := range list {
		if needsRenewal(c) {
			t.Fatalf("still due: %v", c.Names)
		}
	}
}
