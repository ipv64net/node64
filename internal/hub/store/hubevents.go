package store

import (
	"context"
	"database/sql"
)

// HubEvent ist ein Ereignis, das der hub selbst bewertet hat (Gesamtzustand, z. B. nicht ueberwacht, wieder geprueft,
// teilweise gestoert). Die Nodes kennen nur ihre eigenen Ereignisse und zeigen diese zusaetzlich an.
type HubEvent struct {
	EventID     string `json:"event_id"`
	Kind        string `json:"kind"`
	Time        string `json:"time"`
	From        string `json:"from"`
	To          string `json:"to"`
	Reason      string `json:"reason"`
	Message     string `json:"message"`
	DurationSec int64  `json:"duration_seconds"`
	Flags       int    `json:"flags"`
}

// HubEvents liefert die Ereignisse des hubs zu einem Check des Accounts, neueste zuerst.
func (s *Store) HubEvents(ctx context.Context, userID int64, token string, limit int) ([]HubEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT event_id, kind, time, from_state, to_state, reason, message, duration_sec, flags FROM hc2_events
		WHERE userid = ? AND token = ? AND source = '' ORDER BY time DESC LIMIT ?`, userID, token, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HubEvent{}
	for rows.Next() {
		var e HubEvent
		var tm, from, to, reason, msg sql.NullString
		if err := rows.Scan(&e.EventID, &e.Kind, &tm, &from, &to, &reason, &msg, &e.DurationSec, &e.Flags); err != nil {
			return nil, err
		}
		e.From, e.To, e.Reason, e.Message = from.String, to.String, reason.String, msg.String
		if t := pt(tm); !t.IsZero() {
			e.Time = t.UTC().Format("2006-01-02T15:04:05.000Z")
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
