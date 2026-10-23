package querylog

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"
)

func aggStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "q.db"), 8*24*time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.CloseNow() })
	return s
}

func aggEntries(now time.Time) []Entry {
	var b []Entry
	for i := 0; i < 50; i++ {
		b = append(b, Entry{Time: now.Add(-time.Duration(i) * time.Minute), Client: "192.168.1.2", Domain: "a.example", QType: "A", Status: StatusAllowed, Duration: 2 * time.Millisecond})
	}
	for i := 0; i < 20; i++ {
		b = append(b, Entry{Time: now.Add(-time.Duration(i) * time.Minute), Client: "192.168.1.3", Domain: "ads.example", QType: "A", Status: StatusBlocked, Group: "Kinder"})
	}
	for i := 0; i < 10; i++ {
		b = append(b, Entry{Time: now, Client: "192.168.1.3", Domain: "b.example", QType: "AAAA", Status: StatusCached})
	}
	b = append(b, Entry{Time: now.Add(-48 * time.Hour), Client: "192.168.1.9", Domain: "alt.example", QType: "A", Status: StatusAllowed}) // ausserhalb von 24 h
	return b
}

// Summary, Timeline, Top und Geraeteliste kommen aus den Aggregaten und stimmen mit den Einzelzeilen ueberein.
func TestAggregates(t *testing.T) {
	s := aggStore(t)
	now := time.Now()
	s.write(aggEntries(now))
	ctx := context.Background()
	since := now.Add(-24 * time.Hour)
	sum, err := s.Summary(ctx, since)
	if err != nil || sum.Total != 80 || sum.Blocked != 20 || sum.Cached != 10 || sum.Clients != 2 || sum.AvgUpstreamM != 2 {
		t.Fatalf("summary: %+v %v", sum, err)
	}
	top, _ := s.Top(ctx, "blocked", since, 10)
	if len(top) != 1 || top[0].Name != "ads.example" || top[0].Count != 20 {
		t.Fatalf("top blocked: %+v", top)
	}
	top, _ = s.Top(ctx, "allowed", since, 10)
	if len(top) != 2 || top[0].Name != "a.example" || top[0].Count != 50 || top[1].Count != 10 {
		t.Fatalf("top allowed: %+v", top)
	}
	top, _ = s.Top(ctx, "clients", since, 10)
	if len(top) != 2 || top[0].Name != "192.168.1.2" || top[1].Count != 30 || top[1].Blocked != 20 {
		t.Fatalf("top clients: %+v", top)
	}
	cl, _ := s.RecentClients(ctx, since, 10)
	if len(cl) != 2 || cl[1].Group != "Kinder" || cl[0].LastSeen != now.UnixMilli() {
		t.Fatalf("clients: %+v", cl)
	}
	tl, _ := s.Timeline(ctx, now.Add(-time.Hour), 2*time.Minute)
	var tot, blk int64
	for _, b := range tl {
		tot, blk = tot+b.Total, blk+b.Blocked
	}
	if tot != 80 || blk != 20 {
		t.Fatalf("timeline: %d %d", tot, blk)
	}
	if _, err := s.Top(ctx, "nix", since, 10); err == nil {
		t.Fatal("unknown kind accepted")
	}
}

// Update von einer Version ohne Aggregate: einmal aus den vorhandenen Zeilen aufbauen, danach nie wieder.
func TestAggregateBackfill(t *testing.T) {
	s := aggStore(t)
	now := time.Now()
	s.write(aggEntries(now))
	if _, err := s.db.Exec(`DELETE FROM agg_min; DELETE FROM agg_top`); err != nil {
		t.Fatal(err)
	}
	s.backfillAgg()
	sum, _ := s.Summary(context.Background(), now.Add(-24*time.Hour))
	if sum.Total != 80 || sum.Blocked != 20 || sum.Clients != 2 {
		t.Fatalf("backfill: %+v", sum)
	}
	s.backfillAgg() // schon da: nichts doppelt
	if sum2, _ := s.Summary(context.Background(), now.Add(-24*time.Hour)); sum2.Total != 80 {
		t.Fatalf("doppelt: %+v", sum2)
	}
}

// Viele Eintraege: Uebersicht bleibt schnell, die Log-Seite zaehlt gedeckelt.
func TestAggregatesLarge(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	s := aggStore(t)
	now := time.Now()
	batch := make([]Entry, 0, 10000)
	for i := 0; i < 300000; i++ {
		batch = append(batch, Entry{Time: now.Add(-time.Duration(i) * 200 * time.Millisecond), Client: fmt.Sprintf("10.0.%d.%d", i%7, i%250),
			Domain: fmt.Sprintf("%d.in-addr.arpa", i%5000), QType: "PTR", Status: Status(i % 3)})
		if len(batch) == cap(batch) {
			s.write(batch)
			batch = batch[:0]
		}
	}
	ctx := context.Background()
	start := time.Now()
	sum, err := s.Summary(ctx, now.Add(-24*time.Hour))
	if _, err2 := s.Top(ctx, "allowed", now.Add(-24*time.Hour), 10); err != nil || err2 != nil {
		t.Fatal(err, err2)
	}
	_, _ = s.Timeline(ctx, now.Add(-24*time.Hour), 30*time.Minute)
	if took := time.Since(start); sum.Total != 300000 || took > 2*time.Second {
		t.Fatalf("summary %d in %s", sum.Total, took)
	}
	_, total, err := s.Recent(ctx, LogFilter{Limit: 50})
	if err != nil || total != CountCap {
		t.Fatalf("recent total %d %v", total, err)
	}
}
