package store

import (
	"context"
	"database/sql"
	"time"
)

// Maintenance ist ein Wartungsfenster aus hc2_maintenance (Logik wie im Node).
type Maintenance struct {
	ID          int64
	UserID      int64
	StartAt     time.Time
	EndAt       time.Time
	Repeat      string
	RepeatUntil time.Time
	Tokens      []string
	Active      bool
	// Loc: Zeitzone des Accounts (notify.quiet_tz); Wiederholungen bleiben nach der Zeitumstellung zur selben
	// Uhrzeit wie auf der Node (nil = UTC)
	Loc *time.Location
}

// Covers sagt, ob das Fenster zum Zeitpunkt t den Check betrifft.
func (m Maintenance) Covers(token string, t time.Time) bool {
	if !m.Active || !m.EndAt.After(m.StartAt) {
		return false
	}
	if len(m.Tokens) > 0 {
		found := false
		for _, x := range m.Tokens {
			if x == token {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if !m.RepeatUntil.IsZero() && t.After(m.RepeatUntil) {
		return false
	}
	dur := m.EndAt.Sub(m.StartAt)
	loc := m.Loc
	if loc == nil {
		loc = time.UTC
	}
	switch m.Repeat {
	case "daily", "weekly":
		days := 1
		if m.Repeat == "weekly" {
			days = 7
		}
		if t.Before(m.StartAt) {
			return false
		}
		// feste Schritte als Naeherung; die Zeitumstellung verschiebt hoechstens um eine Stunde, daher Nachbarn pruefen
		k := int(t.Sub(m.StartAt) / (time.Duration(days) * 24 * time.Hour))
		for _, n := range []int{k + 1, k, k - 1} {
			if n < 0 {
				continue
			}
			start := m.StartAt.In(loc).AddDate(0, 0, n*days)
			if !t.Before(start) && t.Before(start.Add(dur)) {
				return true
			}
		}
		return false
	case "monthly":
		if t.Before(m.StartAt) {
			return false
		}
		for k := 0; k < 1200; k++ {
			start := m.StartAt.In(loc).AddDate(0, k, 0)
			if start.After(t) {
				return false
			}
			if t.Before(start.Add(dur)) {
				return true
			}
		}
		return false
	default:
		return !t.Before(m.StartAt) && t.Before(m.EndAt)
	}
}

// defaultMaintTZ: Zeitzone ohne Einstellung des Accounts (wie Portal und Benachrichtigungen).
const defaultMaintTZ = "Europe/Berlin"

// ReloadMaintenance laedt alle aktiven Wartungsfenster in den Cache, mit der Zeitzone des Accounts.
func (s *Store) ReloadMaintenance(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT m.id, m.userid, m.start_at, m.end_at, m.`+"`repeat`"+`, m.repeat_until, m.tokens, st.`+"`value`"+` FROM hc2_maintenance m
		LEFT JOIN hc2_settings st ON st.userid = m.userid AND st.`+"`key`"+` = 'notify.quiet_tz' WHERE m.active = 1 AND m.deleted_at IS NULL`)
	if err != nil {
		s.Metrics.add(&s.Metrics.DBErrors, 1)
		return err
	}
	defer rows.Close()
	var list []Maintenance
	locs := map[string]*time.Location{}
	for rows.Next() {
		var m Maintenance
		var start, end, until, tokens, tz sql.NullString
		if err := rows.Scan(&m.ID, &m.UserID, &start, &end, &m.Repeat, &until, &tokens, &tz); err != nil {
			return err
		}
		m.StartAt, m.EndAt, m.RepeatUntil, m.Active = pt(start), pt(end), pt(until), true
		m.Tokens = splitList(tokens.String)
		m.Loc = maintLocation(locs, tz.String)
		list = append(list, m)
	}
	s.mu.Lock()
	s.maint = list
	s.mu.Unlock()
	return rows.Err()
}

// maintLocation liefert die Zeitzone (leer oder ungueltig = Europe/Berlin), je Name nur einmal geladen.
func maintLocation(cache map[string]*time.Location, tz string) *time.Location {
	if tz == "" {
		tz = defaultMaintTZ
	}
	if l, ok := cache[tz]; ok {
		return l
	}
	l, err := time.LoadLocation(tz)
	if err != nil {
		if l, err = time.LoadLocation(defaultMaintTZ); err != nil {
			l = time.UTC
		}
	}
	cache[tz] = l
	return l
}

// InMaintenance prueft gegen den Cache; nur Fenster des eigenen Accounts.
func (s *Store) InMaintenance(_ context.Context, token string, at time.Time) bool {
	s.mu.RLock()
	uid := s.users[token]
	s.mu.RUnlock()
	return s.InMaintenanceOf(uid, token, at)
}

// InMaintenanceOf prueft einen Check mit bekanntem Account (auch Checks, die dieser hub nicht misst).
func (s *Store) InMaintenanceOf(uid int64, token string, at time.Time) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, m := range s.maint {
		if m.UserID == uid && m.Covers(token, at) {
			return true
		}
	}
	return false
}
