package store

import (
	"context"
	"database/sql/driver"
	"strings"
	"testing"
	"time"
)

// Forum 5181: taegliches Fenster 04:30-04:45 (Zeitzone des Accounts) bleibt nach der Zeitumstellung um 04:30.
func TestMaintenanceCoversAccountTimezone(t *testing.T) {
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skip("keine Zeitzonen-Daten")
	}
	at := func(s string) time.Time {
		v, err := time.ParseInLocation("2006-01-02 15:04:05", s, berlin)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	// im Winter angelegt (04:30 MEZ = 03:30 UTC)
	winter := Maintenance{Active: true, StartAt: at("2026-11-08 04:30:00").UTC(), EndAt: at("2026-11-08 04:45:00").UTC(), Repeat: "daily", Loc: berlin}
	// im Sommer angelegt (04:30 MESZ = 02:30 UTC)
	summer := Maintenance{Active: true, StartAt: at("2026-10-01 04:30:00").UTC(), EndAt: at("2026-10-01 04:45:00").UTC(), Repeat: "daily", Loc: berlin}
	weekly := Maintenance{Active: true, StartAt: at("2026-10-01 04:30:00").UTC(), EndAt: at("2026-10-01 04:45:00").UTC(), Repeat: "weekly", Loc: berlin}
	monthly := Maintenance{Active: true, StartAt: at("2026-10-01 04:30:00").UTC(), EndAt: at("2026-10-01 04:45:00").UTC(), Repeat: "monthly", Loc: berlin}
	cases := []struct {
		name string
		m    Maintenance
		t    string
		want bool
	}{
		{"winter window, incident 12.11.", winter, "2026-11-12 04:35:35", true},
		{"winter window, end 12.11.", winter, "2026-11-12 04:40:08", true},
		{"winter window, before", winter, "2026-11-12 04:29:00", false},
		{"winter window, after", winter, "2026-11-12 04:45:00", false},
		{"winter window in summer", winter, "2027-04-12 04:35:00", true},
		{"winter window in summer, one hour later", winter, "2027-04-12 05:35:00", false},
		{"summer window in winter", summer, "2026-11-12 04:35:35", true},
		{"summer window in winter, one hour earlier", summer, "2026-11-12 03:35:35", false},
		{"day of the change", summer, "2026-10-25 04:35:00", true},
		{"weekly after the change", weekly, "2026-11-12 04:35:00", true},
		{"weekly other weekday", weekly, "2026-11-11 04:35:00", false},
		{"monthly after the change", monthly, "2026-12-01 04:35:00", true},
		{"monthly one hour earlier", monthly, "2026-12-01 03:35:00", false},
	}
	for _, tc := range cases {
		if got := tc.m.Covers("x", at(tc.t).UTC()); got != tc.want {
			t.Errorf("%s (%s): got %v", tc.name, tc.t, got)
		}
	}
}

// Die Zeitzone kommt aus den Einstellungen des Accounts (notify.quiet_tz), sonst Europe/Berlin.
func TestReloadMaintenanceTimezone(t *testing.T) {
	s, _ := fakeStore(func(q string, args []driver.NamedValue) fakeResult {
		if strings.Contains(q, "FROM hc2_maintenance") {
			if !strings.Contains(q, "notify.quiet_tz") {
				t.Errorf("Zeitzone nicht gelesen: %s", q)
			}
			return fakeResult{cols: []string{"id", "userid", "start_at", "end_at", "repeat", "repeat_until", "tokens", "value"}, rows: [][]driver.Value{
				{int64(1), int64(7), "2026-11-08 03:30:00.000", "2026-11-08 03:45:00.000", "daily", nil, nil, nil},
				{int64(2), int64(8), "2026-11-08 03:30:00.000", "2026-11-08 03:45:00.000", "daily", nil, "abc,def", "Asia/Tokyo"},
				{int64(3), int64(9), "2026-11-08 03:30:00.000", "2026-11-08 03:45:00.000", "daily", nil, nil, "Kein/Ort"},
			}}
		}
		return fakeResult{}
	})
	if err := s.ReloadMaintenance(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(s.maint) != 3 {
		t.Fatalf("Fenster: %d", len(s.maint))
	}
	for i, want := range []string{"Europe/Berlin", "Asia/Tokyo", "Europe/Berlin"} {
		if s.maint[i].Loc == nil || s.maint[i].Loc.String() != want {
			t.Errorf("Fenster %d: Zeitzone %v, erwartet %s", i+1, s.maint[i].Loc, want)
		}
	}
	if got := s.maint[1].Tokens; len(got) != 2 || got[0] != "abc" {
		t.Errorf("Tokens: %v", got)
	}
	// 12.11.2026 04:35:35 MEZ liegt im Fenster des Accounts 7, nicht in dem eines anderen Accounts
	at := time.Date(2026, 11, 12, 3, 35, 35, 0, time.UTC)
	if !s.InMaintenanceOf(7, "any", at) || s.InMaintenanceOf(10, "any", at) {
		t.Error("Wartung des Accounts nicht erkannt")
	}
	// nach der Zeitumstellung: 04:35 MESZ = 02:35 UTC
	if !s.InMaintenanceOf(7, "any", time.Date(2027, 4, 12, 2, 35, 0, 0, time.UTC)) || s.InMaintenanceOf(7, "any", time.Date(2027, 4, 12, 3, 35, 0, 0, time.UTC)) {
		t.Error("Wiederholung nach der Zeitumstellung nicht zur selben Uhrzeit")
	}
}
