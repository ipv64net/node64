package peer

import (
	"strconv"
	"testing"
	"time"
)

// NonceCache: Wiederholung abgelehnt, hart begrenzt (voll = ablehnen), abgelaufene Eintraege machen Platz.
func TestNonceCache(t *testing.T) {
	c := &NonceCache{TTL: time.Minute, Max: 10}
	now := time.Now()
	if !c.Fresh("a", now) || c.Fresh("a", now) {
		t.Fatal("replay")
	}
	for i := range 9 {
		if !c.Fresh("n"+strconv.Itoa(i), now) {
			t.Fatalf("rejected %d", i)
		}
	}
	if c.Fresh("x", now) || len(c.m) != 10 {
		t.Fatalf("not limited: %d", len(c.m))
	}
	if !c.Fresh("x", now.Add(2*time.Minute)) || len(c.m) != 1 {
		t.Fatalf("expired entries not purged: %d", len(c.m))
	}
}
