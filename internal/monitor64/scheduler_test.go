package monitor64

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOffsetStableAndSpread(t *testing.T) {
	iv := time.Minute
	if offset("a", iv) != offset("a", iv) {
		t.Fatal("offset not stable")
	}
	// 1000 Schluessel verteilen sich ueber das Intervall (keine Haeufung in einer Sekunde)
	buckets := map[int64]int{}
	for i := 0; i < 1000; i++ {
		buckets[int64(offset(string(rune('a'+i%26))+time.Duration(i).String(), iv)/time.Second)]++
	}
	for s, n := range buckets {
		if n > 60 {
			t.Fatalf("second %d has %d jobs", s, n)
		}
	}
}

func TestFirstRunOnGrid(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 30, 0, time.UTC)
	f := firstRun(now, "host1", time.Minute)
	if !f.After(now) || f.Sub(now) > time.Minute {
		t.Fatalf("first run %v not within next interval after %v", f, now)
	}
	if f.Sub(now.Truncate(time.Minute))%time.Minute != offset("host1", time.Minute) {
		t.Fatalf("first run not on grid")
	}
}

func TestClampAndTimeout(t *testing.T) {
	if clampInterval(time.Second) != minInterval || clampInterval(time.Hour) != maxInterval {
		t.Fatal("clamp")
	}
	if jobTimeout(time.Minute) != 30*time.Second || jobTimeout(30*time.Second) != 24*time.Second {
		t.Fatal("timeout")
	}
}

func TestSchedulerRunsAndSkipsLate(t *testing.T) {
	old := minInterval
	minInterval = 20 * time.Millisecond
	defer func() { minInterval = old }()
	s := NewScheduler(4)
	ctx, cancel := context.WithCancel(context.Background())
	var fast, slow atomic.Int64
	block := make(chan struct{})
	s.Set("fast", 20*time.Millisecond, func(context.Context) { fast.Add(1) })
	s.Set("slow", 20*time.Millisecond, func(context.Context) { // haelt sich nicht an das Zeitlimit
		slow.Add(1)
		<-block
	})
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	time.Sleep(300 * time.Millisecond)
	close(block)
	cancel()
	<-done
	if fast.Load() < 5 {
		t.Fatalf("fast ran %d times", fast.Load())
	}
	st, _ := s.Job("slow")
	if st.Late == 0 || slow.Load() != 1 {
		t.Fatalf("slow job should have been skipped while running (runs=%d late=%d)", slow.Load(), st.Late)
	}
	if s.Stats().Running != 0 {
		t.Fatal("jobs still running after Run returned")
	}
}

func TestSchedulerWorkerLimitAndPanic(t *testing.T) {
	old := minInterval
	minInterval = 10 * time.Millisecond
	defer func() { minInterval = old }()
	s := NewScheduler(2)
	var mu sync.Mutex
	var cur, peak int
	var panics atomic.Int64
	s.OnPanic = func(string, any) { panics.Add(1) }
	for i := 0; i < 8; i++ {
		s.Set(string(rune('a'+i)), 10*time.Millisecond, func(context.Context) {
			mu.Lock()
			cur++
			if cur > peak {
				peak = cur
			}
			mu.Unlock()
			time.Sleep(5 * time.Millisecond)
			mu.Lock()
			cur--
			mu.Unlock()
		})
	}
	s.Set("boom", 10*time.Millisecond, func(context.Context) { panic("x") })
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	s.Run(ctx)
	if peak > 2 {
		t.Fatalf("peak %d > workers 2", peak)
	}
	if panics.Load() == 0 {
		t.Fatal("panic not reported")
	}
	s.Remove("boom")
	if _, ok := s.Job("boom"); ok {
		t.Fatal("job not removed")
	}
}
