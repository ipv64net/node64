package store

import (
	"context"
	"database/sql"
	"time"
)

// RemoteState ist der Zustand eines Checks, den eine Node nicht selbst misst (Online-Checks,
// Checks anderer Nodes). Die Node zeigt ihn nur an; dazu der letzte Messpunkt fuer die Pillen.
type RemoteState struct {
	UserID    int64     `json:"-"`
	NodeID    string    `json:"-"` // messende Node (leer bei Online-Checks)
	Execution string    `json:"-"`
	Token     string    `json:"token"`
	State     string    `json:"state"` // Gesamtzustand
	Since     time.Time `json:"since"`
	Source    string    `json:"source"` // Messstelle des letzten Messpunkts
	Time      time.Time `json:"time"`   // letzter Messpunkt
	Status    string    `json:"status"`
	LatencyMS float64   `json:"latency_ms"`
	Reason    string    `json:"reason"`
	Message   string    `json:"message"`
}

const remoteCols = `c.userid, COALESCE(c.node_id,''), c.execution, c.token, c.state, c.state_since,
	st.source, st.last_check_at, st.last_status, st.last_latency_ms, st.last_reason, st.last_message`

func scanRemote(rows *sql.Rows) (RemoteState, error) {
	var r RemoteState
	var since, last, ls, reason, msg sql.NullString
	var lat sql.NullFloat64
	err := rows.Scan(&r.UserID, &r.NodeID, &r.Execution, &r.Token, &r.State, &since, &r.Source, &last, &ls, &lat, &reason, &msg)
	r.Since, r.Time, r.Status, r.LatencyMS, r.Reason, r.Message = pt(since), pt(last), ls.String, lat.Float64, reason.String, msg.String
	return r, err
}

// RemoteStatesSince liefert Zustaende aller Messstellen, die seit 'since' aktualisiert wurden (alle Accounts).
func (s *Store) RemoteStatesSince(ctx context.Context, since time.Time) ([]RemoteState, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+remoteCols+` FROM hc2_check_states st JOIN hc2_checks c ON c.token = st.token
		WHERE st.updated_at > ? AND c.deleted_at IS NULL ORDER BY st.updated_at LIMIT 20000`, since.UTC().Format(TimeFormat))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RemoteState
	for rows.Next() {
		r, err := scanRemote(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RemoteStatesOf liefert den aktuellen Stand aller Checks eines Accounts (beim Verbinden).
func (s *Store) RemoteStatesOf(ctx context.Context, userID int64) ([]RemoteState, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+remoteCols+` FROM hc2_checks c JOIN hc2_check_states st ON st.token = c.token
		WHERE c.userid = ? AND c.deleted_at IS NULL ORDER BY st.updated_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RemoteState
	for rows.Next() {
		r, err := scanRemote(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ForNode sagt, ob die Node diesen Zustand angezeigt bekommen soll (nicht ihre eigenen Messungen).
func (r RemoteState) ForNode(nodeID string) bool {
	return r.Source != "node:"+nodeID && !(r.NodeID == nodeID && r.Execution == "local")
}
