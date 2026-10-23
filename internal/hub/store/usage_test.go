package store

import (
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestDailyUsageGate(t *testing.T) {
	s := &Store{log: slog.New(slog.NewTextHandler(io.Discard, nil)), users: map[string]int64{"tok": 7, "push": 7, "other": 8}}
	var flips []bool
	s.OnUsageFlip = func(uid int64, blocked bool) {
		if uid == 7 {
			flips = append(flips, blocked)
		}
	}
	s.TrackUsage([]int64{7, 8})
	s.use.mu.Lock()
	s.use.limit[7], s.use.limitAt[7] = 3, time.Now() // Klasse mit 3 Online-Messungen am Tag
	s.use.mu.Unlock()

	for i := 0; i < 3; i++ {
		if !s.AllowRun("tok", false) {
			t.Fatalf("run %d blocked too early", i+1)
		}
	}
	if s.AllowRun("tok", false) || s.AllowRun("push", true) {
		t.Fatal("quota used up: measurements and push evaluation must pause")
	}
	if !s.AllowRun("other", false) {
		t.Fatal("other account (no limit known) must not be affected")
	}
	if today, limit, known := s.DailyUsage(7); today != 3 || limit != 3 || !known {
		t.Fatalf("usage = %d/%d known=%v, want 3/3", today, limit, known)
	}
	if len(flips) != 1 || !flips[0] {
		t.Fatalf("flips = %v, want [true]", flips)
	}
	// Push-Auswertung zaehlt nicht
	s.use.mu.Lock()
	s.use.limit[7] = 10
	s.use.blocked[7] = false
	s.use.mu.Unlock()
	s.AllowRun("push", true)
	if today, _, _ := s.DailyUsage(7); today != 3 {
		t.Fatalf("push evaluation counted: %d", today)
	}
	// Tageswechsel gibt frei
	s.use.mu.Lock()
	s.use.day = "2000-01-01"
	s.use.blocked[7] = true
	s.use.mu.Unlock()
	if s.DailyBlocked(7) {
		t.Fatal("rollover must free the account")
	}
	if len(flips) != 2 || flips[1] {
		t.Fatalf("flips after rollover = %v, want [true false]", flips)
	}
}

// Klassenlimit: alle 2 Minuten neu, gesperrte Accounts bei jedem Abgleich (Upgrade gibt sofort frei).
func TestLimitDue(t *testing.T) {
	now := time.Now()
	u := usage{limitAt: map[int64]time.Time{1: now.Add(-time.Minute), 2: now.Add(-3 * time.Minute), 3: now.Add(-time.Minute)}, blocked: map[int64]bool{3: true}}
	if u.limitDue(1, now) || !u.limitDue(2, now) || !u.limitDue(3, now) || !u.limitDue(4, now) {
		t.Fatalf("due: 1=%v 2=%v 3=%v 4=%v", u.limitDue(1, now), u.limitDue(2, now), u.limitDue(3, now), u.limitDue(4, now))
	}
}
