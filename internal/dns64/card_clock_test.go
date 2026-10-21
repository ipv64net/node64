package dns64

import (
	"testing"
	"time"
)

// Karte „Blockieren pausiert bis“: Uhrzeit in der Zeitzone der Node, an einem anderen Tag mit Datum.
func TestClockText(t *testing.T) {
	loc, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skip("keine Zeitzonen-Daten")
	}
	now := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC) // 12:00 in Berlin
	if got := clockText(now.Add(90*time.Minute), now, loc); got != "13:30" {
		t.Fatalf("heute: %q", got)
	}
	if got := clockText(time.Date(2026, 10, 21, 23, 30, 0, 0, time.UTC), now, loc); got != "22.10. 01:30" {
		t.Fatalf("morgen: %q", got)
	}
}
