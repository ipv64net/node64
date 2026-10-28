package store

import (
	"context"
	"database/sql/driver"
	"strings"
	"testing"
	"time"
)

// Gesamtzustand eines lokalen Checks: misst nur die Besitzer-Node und hat sie notify-direct gemeldet, sendet sie
// selbst (DirectNode); sonst, bei mehreren Nodes und bei "nicht geprueft" sendet der hub wie bisher alles.
func TestReverdictDirectNode(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name, nodes, modules string
		updated              time.Time
		wantKind, wantDirect string
	}{
		{"capable node", "a", "healthchecks,notify-direct", now, "down", "a"},
		{"owner only, empty list", "", "healthchecks,notify-direct", now, "down", "a"},
		{"older node", "a", "healthchecks", now, "down", ""},
		{"several nodes", "a,b", "healthchecks,notify-direct", now, "down", ""},
		{"unchecked stays with the hub", "a", "healthchecks,notify-direct", now.Add(-10 * time.Minute), "unchecked", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := fakeStore(func(q string, args []driver.NamedValue) fakeResult {
				switch {
				case strings.HasPrefix(q, "SELECT userid, policy"):
					return fakeResult{cols: []string{"userid", "policy", "state", "name", "interval_sec", "incident_id", "down_since", "type", "target", "critical", "channels",
						"notify_down", "notify_up", "notify_degraded", "execution", "paused", "nodes", "node_id"},
						rows: [][]driver.Value{{int64(7), "all", "up", "Web", int64(60), nil, nil, "http", "https://x/", int64(0), "", int64(1), int64(1), int64(0), "local", int64(0), tc.nodes, "a"}}}
				case strings.Contains(q, "FROM hc2_check_states"):
					var rows [][]driver.Value
					for _, n := range measuringNodes(splitList(tc.nodes), "a") {
						rows = append(rows, []driver.Value{"node:" + n, "down", "down", "timeout", "", 0.0, tc.updated.Format(TimeFormat), tc.updated.Add(-time.Minute).Format(TimeFormat)})
					}
					return fakeResult{cols: []string{"source", "state", "last_status", "last_reason", "last_message", "last_latency_ms", "updated_at", "since"}, rows: rows}
				case strings.HasPrefix(q, "SELECT online, last_seen"):
					return fakeResult{cols: []string{"online", "last_seen"}, rows: [][]driver.Value{{int64(1), now.Format(TimeFormat)}}}
				case strings.HasPrefix(q, "SELECT modules FROM hc2_nodes"):
					if args[0].Value != "a" {
						t.Errorf("capability of node %v", args[0].Value)
					}
					return fakeResult{cols: []string{"modules"}, rows: [][]driver.Value{{tc.modules}}}
				case strings.HasPrefix(q, "SELECT name FROM hc2_nodes"):
					return fakeResult{cols: []string{"name"}, rows: [][]driver.Value{{"Box"}}}
				case strings.HasPrefix(q, "SELECT"):
					return fakeResult{cols: []string{"x"}} // Stellvertreter, letztes Ereignis: keine
				}
				return fakeResult{affected: 1}
			})
			var got []OverallEvent
			s.OnOverall = func(e OverallEvent) { got = append(got, e) }
			if err := s.Reverdict(context.Background(), "tok"); err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 {
				t.Fatalf("events: %+v", got)
			}
			if got[0].Kind != tc.wantKind || got[0].DirectNode != tc.wantDirect {
				t.Fatalf("kind %q direct %q, want %q %q", got[0].Kind, got[0].DirectNode, tc.wantKind, tc.wantDirect)
			}
		})
	}
}

// Erinnerungen: lokale Checks nur mit notify-direct der Node (dann DirectNode: der hub sendet nur die uebrigen
// Portal-Kanaele), Online/Hybrid wie bisher.
func TestDueRemindersDirectNode(t *testing.T) {
	ds := time.Now().UTC().Add(-time.Hour).Format(TimeFormat)
	s, f := fakeStore(func(q string, args []driver.NamedValue) fakeResult {
		if !strings.Contains(q, "FIND_IN_SET('notify-direct', d.modules)") || !strings.Contains(q, "execution = 'local'") {
			t.Errorf("query without capability check: %s", q)
		}
		return fakeResult{cols: []string{"token", "userid", "name", "type", "target", "critical", "channels", "notify_down", "notify_up", "notify_degraded", "repeat_minutes",
			"down_since", "last_reason", "last_message", "execution", "node_id"},
			rows: [][]driver.Value{
				{"loc", int64(7), "Lokal", "http", "", int64(0), "", int64(1), int64(1), int64(0), int64(30), ds, "timeout", "", "local", "a"},
				{"onl", int64(7), "Online", "http", "", int64(0), "4,5", int64(1), int64(1), int64(0), int64(30), ds, "timeout", "", "online", ""},
				{"hyb", int64(7), "Hybrid", "http", "", int64(0), "", int64(1), int64(1), int64(0), int64(30), ds, "timeout", "", "both", "a"},
			}}
	})
	list, err := s.DueReminders(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f.count("SELECT token, userid") != 1 || len(list) != 3 {
		t.Fatalf("reminders: %+v", list)
	}
	want := map[string]string{"loc": "a", "onl": "", "hyb": ""}
	for _, e := range list {
		if e.DirectNode != want[e.Token] {
			t.Errorf("%s: direct node %q", e.Token, e.DirectNode)
		}
	}
	if len(list[1].Channels) != 2 || list[1].Duration != 30*time.Minute {
		t.Fatalf("online reminder: %+v", list[1])
	}
}
