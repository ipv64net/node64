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
