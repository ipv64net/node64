package healthchecks

import (
	"testing"
	"time"
)

func TestMergeEventsAndDuration(t *testing.T) {
	now := time.Now()
	local := []Event{{EventID: "a", Kind: "down", Time: now.Add(-2 * time.Minute)}, {EventID: "b", Kind: "up", Time: now.Add(-time.Minute)}}
	hub := []Event{{EventID: "c", Kind: "unchecked", Time: now, Hub: true}, {EventID: "a", Kind: "down", Time: now.Add(-2 * time.Minute), Hub: true}}
	out := mergeEvents(local, hub, 50)
	if len(out) != 3 || out[0].EventID != "c" || !out[0].Hub || out[2].EventID != "a" || out[2].Hub {
		t.Fatalf("merge: %+v", out)
	}
	if len(mergeEvents(local, hub, 2)) != 2 {
		t.Fatal("limit")
	}
	if (Event{DurationSec: 90}).Length() != 90*time.Second {
		t.Fatal("length")
	}
	if (Event{Kind: "unchecked"}).KindClass() != "text-bg-warning" || (Event{Kind: "rechecked"}).KindClass() != "text-bg-success" {
		t.Fatal("kind class")
	}
}
