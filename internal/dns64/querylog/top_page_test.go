package querylog

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TopPage: Seiten, Gesamtzahl, Suche und Sortierung der vollstaendigen Top-Liste (Seite "Alle anzeigen").
func TestTopPage(t *testing.T) {
	s := aggStore(t)
	now := time.Now()
	var b []Entry
	for i := 1; i <= 25; i++ { // d01 1x ... d25 25x
		for j := 0; j < i; j++ {
			b = append(b, Entry{Time: now, Client: "192.168.1.2", Domain: fmt.Sprintf("d%02d.example", i), QType: "A", Status: StatusAllowed})
		}
	}
	s.write(b)
	ctx := context.Background()
	since := now.Add(-time.Hour)
	items, total, err := s.TopPage(ctx, TopFilter{Kind: "allowed", Since: since, Desc: true, Limit: 10, Offset: 10, Total: true})
	if err != nil || total != 25 || len(items) != 10 || items[0].Name != "d15.example" || items[0].Count != 15 {
		t.Fatalf("page 2: %+v total=%d err=%v", items, total, err)
	}
	items, _, _ = s.TopPage(ctx, TopFilter{Kind: "allowed", Since: since, Sort: "name", Limit: 3})
	if len(items) != 3 || items[0].Name != "d01.example" || items[2].Name != "d03.example" {
		t.Fatalf("name asc: %+v", items)
	}
	items, total, _ = s.TopPage(ctx, TopFilter{Kind: "allowed", Since: since, Search: "D2", Desc: true, Limit: 50, Total: true})
	if total != 6 || len(items) != 6 || items[0].Name != "d25.example" { // d20..d25
		t.Fatalf("search: %+v total=%d", items, total)
	}
	if _, _, err := s.TopPage(ctx, TopFilter{Kind: "allowed", Since: since, Sort: "x; DROP TABLE agg_top", Limit: 5}); err != nil {
		t.Fatalf("unknown sort must fall back to count: %v", err)
	}
}
