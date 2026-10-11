package store

import (
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/scheduler"
)

func TestEventKind(t *testing.T) {
	cases := []struct {
		from, to scheduler.State
		incident bool
		kind     string
		silent   bool
	}{
		{scheduler.StatePending, scheduler.StateUp, false, "up", true},
		{scheduler.StateUp, scheduler.StateDown, false, "down", false},
		{scheduler.StateDown, scheduler.StateUp, true, "up", false},
		{scheduler.StateUp, scheduler.StateDegraded, false, "degraded", false},
		{scheduler.StateDegraded, scheduler.StateUp, false, "degraded_end", false},
		{scheduler.StateDegraded, scheduler.StateDown, false, "down", false},
		{scheduler.StateDown, scheduler.StateDegraded, true, "degraded", false},
		{scheduler.StateDegraded, scheduler.StateUp, true, "up", false}, // Stoerung endet erst mit up
		{scheduler.StateUp, scheduler.StateFlapping, false, "flapping_start", false},
		{scheduler.StateFlapping, scheduler.StateUp, true, "flapping_end", false},
		{scheduler.StateUp, scheduler.StatePaused, false, "state", true},
	}
	for _, c := range cases {
		k, s := eventKind(c.from, c.to, c.incident)
		if k != c.kind || s != c.silent {
			t.Errorf("%s->%s: got %s/%v want %s/%v", c.from, c.to, k, s, c.kind, c.silent)
		}
	}
}

func TestDiagnosis(t *testing.T) {
	if d := diagnosis([]string{"node:abc"}, []string{"loc:nbg", "loc:fsn"}); d != "innen gestört, außen OK → Heimnetz/Node" {
		t.Errorf("inside: %q", d)
	}
	if d := diagnosis([]string{"loc:nbg", "loc:fsn"}, []string{"node:abc"}); !strings.HasPrefix(d, "außen") {
		t.Errorf("outside: %q", d)
	}
	if d := diagnosis([]string{"loc:nbg"}, []string{"loc:fsn"}); d != "gestört: loc:nbg; OK: loc:fsn" {
		t.Errorf("mixed: %q", d)
	}
	if d := diagnosis([]string{"loc:nbg", "loc:fsn"}, nil); d == "" {
		t.Errorf("all down should mention it")
	}
	if d := diagnosis(nil, []string{"loc:nbg"}); d != "" {
		t.Errorf("all up: %q", d)
	}
}

func TestSlotShare(t *testing.T) {
	s := &Store{location: "nbg", node: "hc-srv02"}
	idx, n := s.SlotShare([]HubInstance{{"hc-srv01", "fsn"}, {"hc-srv02", "nbg"}})
	if idx != 0 || n != 1 {
		t.Fatalf("single node per location: %d/%d", idx, n)
	}
	idx, n = s.SlotShare([]HubInstance{{"hc-srv02", "nbg"}, {"hc-srv03", "nbg"}, {"hc-srv01", "fsn"}})
	if idx != 0 || n != 2 {
		t.Fatalf("two nodes: %d/%d", idx, n)
	}
	s2 := &Store{location: "nbg", node: "hc-srv03"}
	if idx, n = s2.SlotShare([]HubInstance{{"hc-srv02", "nbg"}}); idx != 1 || n != 2 {
		t.Fatalf("self not yet listed: %d/%d", idx, n)
	}
	if !s.IsHousekeeper([]HubInstance{{"hc-srv02", "nbg"}, {"hc-srv03", "nbg"}}) || s.IsHousekeeper([]HubInstance{{"hc-srv01", "fsn"}}) {
		t.Fatal("housekeeper is the alphabetically first live node")
	}
}

func TestMaintenanceCovers(t *testing.T) {
	start := time.Date(2026, 10, 10, 22, 0, 0, 0, time.UTC)
	m := Maintenance{Active: true, StartAt: start, EndAt: start.Add(time.Hour), Repeat: "daily", Tokens: []string{"abc"}}
	if !m.Covers("abc", start.AddDate(0, 0, 3).Add(30*time.Minute)) {
		t.Fatal("daily window should cover three days later")
	}
	if m.Covers("abc", start.AddDate(0, 0, 3).Add(90*time.Minute)) {
		t.Fatal("outside the hour")
	}
	if m.Covers("xyz", start.Add(10*time.Minute)) {
		t.Fatal("other token")
	}
}
