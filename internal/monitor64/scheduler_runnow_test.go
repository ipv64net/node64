package monitor64

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// #225: "jetzt abfragen" waehrend eines laufenden Durchgangs geht nicht verloren - direkt danach folgt ein weiterer.
func TestSchedulerRunNowWhileRunning(t *testing.T) {
	s := NewScheduler(2)
	var runs atomic.Int64
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	s.Set("host:a", time.Hour, func(context.Context) {
		n := runs.Add(1)
		started <- struct{}{}
		if n == 1 {
			<-release
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	s.RunNow("host:a")
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first run did not start")
	}
	s.RunNow("host:a") // laeuft gerade
	close(release)
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatalf("no second run after RunNow during a run (runs=%d)", runs.Load())
	}
}

// Der Lauf, den "again" nach dem ersten startet, gilt als laufend: das Zuruecksetzen des ersten Laufs darf ihn nicht
// als "laeuft nicht" markieren (sonst startete ein weiterer gleichzeitiger Lauf desselben Hosts).
func TestSchedulerAgainRunStaysRunning(t *testing.T) {
	s := NewScheduler(4)
	var runs, active, overlap atomic.Int64
	started := make(chan struct{}, 8)
	release := make(chan struct{})
	s.Set("host:a", time.Hour, func(context.Context) {
		if active.Add(1) > 1 {
			overlap.Add(1)
		}
		defer active.Add(-1)
		n := runs.Add(1)
		started <- struct{}{}
		if n <= 2 {
			<-release
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	wait := func(what string) {
		t.Helper()
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s did not start (runs=%d)", what, runs.Load())
		}
	}
	s.RunNow("host:a")
	wait("first run")
	s.RunNow("host:a") // laeuft: again
	release <- struct{}{}
	wait("second run")
	time.Sleep(50 * time.Millisecond) // erster Lauf ist sicher beendet
	if st, _ := s.Job("host:a"); !st.Running {
		t.Fatal("second run not marked as running")
	}
	s.RunNow("host:a") // laeuft: again statt eines gleichzeitigen Laufs
	time.Sleep(50 * time.Millisecond)
	if overlap.Load() != 0 {
		t.Fatal("two runs of the same job at the same time")
	}
	close(release)
	wait("third run")
}
