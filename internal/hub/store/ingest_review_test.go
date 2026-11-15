package store

import (
	"context"
	"database/sql/driver"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/wire"
)

// Sicherheits-Review HC-2/HC-3: Ereignisse nur fuer eigene Checks und mit Zeitpunkt innerhalb der Aufbewahrung,
// Zustellungen nicht in der Zukunft.
func TestIngestEventsOwnAndTime(t *testing.T) {
	var inserted []string
	var times []any
	s, _ := fakeStore(func(q string, args []driver.NamedValue) fakeResult {
		switch {
		case strings.HasPrefix(q, "SELECT token, userid FROM hc2_checks"):
			return fakeResult{cols: []string{"token", "userid"}, rows: [][]driver.Value{{"own-token-0000000000", int64(9)}, {"foreign-token-000000", int64(5)}}}
		case strings.HasPrefix(q, "INSERT IGNORE INTO hc2_events"):
			inserted = append(inserted, args[1].Value.(string))
			times = append(times, args[5].Value)
			return fakeResult{affected: 1}
		case strings.HasPrefix(q, "INSERT IGNORE INTO hc2_deliveries"):
			times = append(times, args[4].Value)
			return fakeResult{affected: 1}
		}
		return fakeResult{}
	})
	n := &Node{ID: "node-a", UserID: 9}
	now := time.Now().UTC()
	ack, err := s.IngestEvents(context.Background(), n, []wire.Event{
		{EventID: "e1", Token: "own-token-0000000000", Kind: "down", Time: now},
		{EventID: "e2", Token: "foreign-token-000000", Kind: "down", Time: now},
		{EventID: "e3", Token: "own-token-0000000000", Kind: "down", Time: now.AddDate(-2, 0, 0)},
		{EventID: "e4", Token: "own-token-0000000000", Kind: "up", Time: time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(inserted) != 2 || len(ack.Accepted) != 4 {
		t.Fatalf("gespeichert %v, bestaetigt %v", inserted, ack.Accepted)
	}
	for _, tok := range inserted {
		if tok != "own-token-0000000000" {
			t.Errorf("fremder Token gespeichert: %s", tok)
		}
	}
	if s, _ := times[1].(string); strings.HasPrefix(s, "9999") {
		t.Errorf("Zeitpunkt in der Zukunft gespeichert: %v", times[1])
	}
	times = nil
	if err := s.IngestDeliveries(context.Background(), n, []wire.Delivery{
		{EventID: "e1", ChannelID: 1, Time: time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)},
		{EventID: "e1", ChannelID: 2, Time: now.AddDate(0, 0, -200)},
	}); err != nil {
		t.Fatal(err)
	}
	if len(times) != 1 {
		t.Fatalf("Zustellungen: %v", times)
	}
	if s, _ := times[0].(string); strings.HasPrefix(s, "9999") {
		t.Errorf("Zustellung in der Zukunft gespeichert: %v", times[0])
	}
}

// Sicherheits-Review HC-n1: entityData liefert nur Eintraege des eigenen Accounts.
func TestEntityDataOwnAccount(t *testing.T) {
	var queries []string
	s, _ := fakeStore(func(q string, args []driver.NamedValue) fakeResult {
		queries = append(queries, q)
		if strings.HasPrefix(q, "SELECT token, userid FROM hc2_checks") {
			return fakeResult{cols: []string{"token", "userid"}, rows: [][]driver.Value{{"foreign-token-000000", int64(5)}}}
		}
		return fakeResult{cols: []string{"id"}}
	})
	ctx := context.Background()
	if d, err := s.entityData(ctx, "check", "foreign-token-000000", "node-a", 9); err != nil || d != nil {
		t.Fatalf("fremder Check: %s %v", d, err)
	}
	_, _ = s.entityData(ctx, "maintenance", "1", "node-a", 9)
	_, _ = s.entityData(ctx, "channel", "1", "node-a", 9)
	for _, q := range queries {
		if (strings.Contains(q, "FROM hc2_maintenance") || strings.Contains(q, "FROM hc2_channels")) && !strings.Contains(q, "userid = ?") {
			t.Errorf("ohne userid: %s", q)
		}
		if strings.Contains(q, "FROM hc2_checks WHERE token = ?") {
			t.Errorf("fremder Check gelesen: %s", q)
		}
	}
}
