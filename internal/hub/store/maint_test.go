package store

import (
	"context"
	"database/sql/driver"
	"strings"
	"testing"
	"time"
)

// Wartungsfenster im Gesamtzustand (#129): ein Ausfall in der Wartung ist still (mit Wartungs-Flag), die Entwarnung
// eines so verschwiegenen Ausfalls ebenfalls; die eines gemeldeten Ausfalls kommt.
func TestReverdictMaintenance(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name, state, srcState string
		incident              any
		inMaint               bool
		lastFlags             int64
		wantKind              string // leer = still
		wantFlags             int64
	}{
		{"down in maintenance", "up", "down", nil, true, 0, "", FlagSilent | FlagMaintenance},
		{"down without maintenance", "up", "down", nil, false, 0, "down", 0},
		{"recovery of a silenced outage", "down", "up", int64(5), false, FlagSilent | FlagMaintenance, "", FlagSilent},
		{"recovery of an alerted outage", "down", "up", int64(5), false, 0, "up", 0},
		{"recovery in maintenance", "down", "up", int64(5), true, 0, "", FlagSilent | FlagMaintenance},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var flags any
			s, _ := fakeStore(func(q string, args []driver.NamedValue) fakeResult {
				switch {
				case strings.HasPrefix(q, "SELECT userid, policy"):
					return fakeResult{cols: []string{"userid", "policy", "state", "name", "interval_sec", "incident_id", "down_since", "type", "target", "critical", "channels",
						"notify_down", "notify_up", "notify_degraded", "execution", "paused", "nodes", "node_id", "params"},
						rows: [][]driver.Value{{int64(7), "all", tc.state, "Web", int64(60), tc.incident, now.Add(-time.Hour).Format(TimeFormat), "http", "https://x/", int64(0), "",
							int64(1), int64(1), int64(0), "online", int64(0), "", nil, "{}"}}}
				case strings.Contains(q, "FROM hc2_check_states"):
					return fakeResult{cols: []string{"source", "state", "last_status", "last_reason", "last_message", "last_latency_ms", "updated_at", "since"},
						rows: [][]driver.Value{{"loc:fsn", tc.srcState, tc.srcState, "timeout", "", 0.0, now.Format(TimeFormat), now.Add(-time.Minute).Format(TimeFormat)}}}
				case strings.HasPrefix(q, "SELECT flags FROM hc2_events"):
					if !strings.Contains(q, "source = ''") || !strings.Contains(q, "'down','flapping_start'") {
						t.Errorf("last outage query: %s", q)
					}
					return fakeResult{cols: []string{"flags"}, rows: [][]driver.Value{{tc.lastFlags}}}
				case strings.HasPrefix(q, "INSERT INTO hc2_events"):
					flags = args[10].Value
				case strings.HasPrefix(q, "SELECT"):
					return fakeResult{cols: []string{"x"}}
				}
				return fakeResult{affected: 1}
			})
			if tc.inMaint {
				s.maint = []Maintenance{{UserID: 7, StartAt: now.Add(-time.Hour), EndAt: now.Add(time.Hour), Active: true}}
			} else {
				s.maint = []Maintenance{{UserID: 8, StartAt: now.Add(-time.Hour), EndAt: now.Add(time.Hour), Active: true}} // anderer Account
			}
			var got []OverallEvent
			s.OnOverall = func(e OverallEvent) { got = append(got, e) }
			if err := s.Reverdict(context.Background(), "tok"); err != nil {
				t.Fatal(err)
			}
			if tc.wantKind == "" && len(got) != 0 {
				t.Fatalf("must be silent: %+v", got)
			}
			if tc.wantKind != "" && (len(got) != 1 || got[0].Kind != tc.wantKind) {
				t.Fatalf("events %+v, want %s", got, tc.wantKind)
			}
			if flags != tc.wantFlags {
				t.Fatalf("event flags %v, want %d", flags, tc.wantFlags)
			}
		})
	}
}

// Nach der Wartung: andauernde, verschwiegene Ausfaelle werden einmal gemeldet (neues Ereignis ohne Flag); laeuft das
// Fenster noch oder hat sich der Zustand inzwischen geaendert, nicht.
func TestMaintenanceOver(t *testing.T) {
	now := time.Now().UTC()
	since := now.Add(-2 * time.Hour).Format(TimeFormat)
	var inserted []string
	s, _ := fakeStore(func(q string, args []driver.NamedValue) fakeResult {
		switch {
		case strings.HasPrefix(q, "SELECT c.token, c.userid, c.state, c.state_since FROM hc2_checks c"):
			if !strings.Contains(q, "e.flags & 1 <> 0") || !strings.Contains(q, "NOT EXISTS") {
				t.Errorf("candidate query: %s", q)
			}
			return fakeResult{cols: []string{"token", "userid", "state", "state_since"}, rows: [][]driver.Value{
				{"over", int64(7), "down", since}, {"running", int64(7), "down", since}, {"changed", int64(7), "flapping", since}}}
		case strings.HasPrefix(q, "SELECT userid, name, type"):
			tok := args[0].Value.(string)
			if tok == "running" {
				t.Errorf("check still in maintenance was locked")
			}
			state, cur := "down", since
			if tok == "changed" {
				state, cur = "flapping", now.Format(TimeFormat) // Reverdict hat inzwischen entschieden
			}
			return fakeResult{cols: []string{"userid", "name", "type", "target", "critical", "channels", "notify_down", "notify_up", "notify_degraded", "execution", "nodes",
				"node_id", "state", "state_since", "last_reason", "last_message", "incident_id"},
				rows: [][]driver.Value{{int64(7), "Web " + tok, "http", "https://x/", int64(0), "4,5", int64(1), int64(1), int64(0), "online", "", "", state, cur, "timeout", "", int64(9)}}}
		case strings.HasPrefix(q, "INSERT INTO hc2_events"):
			inserted = append(inserted, args[1].Value.(string))
			if !strings.Contains(q, "0,0,0,?)") {
				t.Errorf("event after maintenance must not be silent: %s", q)
			}
		case strings.HasPrefix(q, "SELECT"):
			return fakeResult{cols: []string{"x"}}
		}
		return fakeResult{affected: 1}
	})
	s.maint = []Maintenance{{UserID: 7, StartAt: now.Add(-time.Hour), EndAt: now.Add(time.Hour), Tokens: []string{"running"}, Active: true}}
	list, err := s.MaintenanceOver(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Token != "over" || list[0].Kind != "down" || len(list[0].Channels) != 2 || list[0].Channels[1] != 5 || list[0].UserID != 7 {
		t.Fatalf("alerts: %+v", list)
	}
	if len(inserted) != 1 || inserted[0] != "over" {
		t.Fatalf("events: %v", inserted)
	}
}
