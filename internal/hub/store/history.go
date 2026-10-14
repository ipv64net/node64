package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Verlauf fuer das Nachladen in die Node (nach Zuruecksetzen, neuer Verknuepfung, Offline-Zeit):
// Einzelmessungen (hc2_measurements, 2 Tage) oder Stundenwerte (hc2_hourly, 90 Tage) eines Checks des
// Accounts, alle Messstellen ausser der anfragenden Node selbst. Seitenweise ueber since (inklusive).

// HistoryPoint ist eine Einzelmessung oder ein Stundenwert (gleiches Format wie die Node erwartet).
type HistoryPoint struct {
	Source string    `json:"s"`
	Time   time.Time `json:"t"`
	Status int       `json:"st"`
	MS     float64   `json:"ms"`
	Count  int       `json:"n,omitempty"`
	Up     int       `json:"up,omitempty"`
}

// ErrNotFound: Check gehoert nicht zum Account.
var ErrNotFound = errors.New("not found")

// History liefert hoechstens limit Punkte ab since (bis until), aufsteigend nach Zeit.
func (s *Store) History(ctx context.Context, userID int64, token, exclude string, hourly bool, since, until time.Time, limit int) ([]HistoryPoint, error) {
	var ok int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM hc2_checks WHERE token = ? AND userid = ? AND deleted_at IS NULL`, token, userID).Scan(&ok); err != nil {
		return nil, err
	}
	if ok == 0 {
		return nil, ErrNotFound
	}
	var rows *sql.Rows
	var err error
	if hourly {
		rows, err = s.db.QueryContext(ctx, `SELECT source, hour, count, up_count, avg_ms FROM hc2_hourly WHERE token = ? AND source <> ? AND hour >= ? AND hour < ? ORDER BY hour, source LIMIT ?`,
			token, exclude, since.UTC().Format(TimeFormat), until.UTC().Format(TimeFormat), limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `SELECT source, time, status, latency_ms FROM hc2_measurements WHERE token = ? AND source <> ? AND time >= ? AND time < ? ORDER BY time, source LIMIT ?`,
			token, exclude, since.UTC().Format(TimeFormat), until.UTC().Format(TimeFormat), limit)
	}
	if err != nil {
		s.Metrics.add(&s.Metrics.DBErrors, 1)
		return nil, err
	}
	defer rows.Close()
	out := []HistoryPoint{}
	for rows.Next() {
		var p HistoryPoint
		var t sql.NullString
		if hourly {
			var avg sql.NullFloat64
			if err := rows.Scan(&p.Source, &t, &p.Count, &p.Up, &avg); err != nil {
				return nil, err
			}
			p.MS = avg.Float64
		} else if err := rows.Scan(&p.Source, &t, &p.Status, &p.MS); err != nil {
			return nil, err
		}
		p.Time = pt(t)
		out = append(out, p)
	}
	return out, rows.Err()
}
