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
	switch m.Repeat {
	case "daily", "weekly":
		step := 24 * time.Hour
		if m.Repeat == "weekly" {
			step = 7 * 24 * time.Hour
		}
		if t.Before(m.StartAt) {
			return false
		}
		k := t.Sub(m.StartAt) / step
		start := m.StartAt.Add(k * step)
		return !t.Before(start) && t.Before(start.Add(dur))
	case "monthly":
		if t.Before(m.StartAt) {
			return false
		}
		for k := 0; k < 1200; k++ {
			start := m.StartAt.AddDate(0, k, 0)
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

// ReloadMaintenance laedt alle aktiven Wartungsfenster in den Cache.
func (s *Store) ReloadMaintenance(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id, userid, start_at, end_at, `+"`repeat`"+`, repeat_until, tokens FROM hc2_maintenance WHERE active = 1 AND deleted_at IS NULL`)
	if err != nil {
		s.Metrics.add(&s.Metrics.DBErrors, 1)
		return err
	}
	defer rows.Close()
	var list []Maintenance
	for rows.Next() {
		var m Maintenance
		var start, end, until, tokens sql.NullString
		if err := rows.Scan(&m.ID, &m.UserID, &start, &end, &m.Repeat, &until, &tokens); err != nil {
			return err
		}
		m.StartAt, m.EndAt, m.RepeatUntil, m.Active = pt(start), pt(end), pt(until), true
		m.Tokens = splitList(tokens.String)
		list = append(list, m)
	}
	s.mu.Lock()
	s.maint = list
	s.mu.Unlock()
	return rows.Err()
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
