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
	// Zustand dieser Messstelle (fuer die Messstellen-Tabelle der Node)
	SourceState string    `json:"source_state,omitempty"`
	SourceSince time.Time `json:"source_since,omitempty"`
	SourceLabel string    `json:"source_label,omitempty"` // Standort- oder Node-Name
}

const remoteCols = `c.userid, COALESCE(c.node_id,''), c.execution, c.token, c.state, c.state_since,
	st.source, st.last_check_at, st.last_status, st.last_latency_ms, st.last_reason, st.last_message,
	st.state, st.since, COALESCE(l.name, n.name, '')`

// remoteJoin liefert die Namen der Messstellen (Standort bzw. Node) mit.
const remoteJoin = ` LEFT JOIN hc2_locations l ON st.source = CONCAT('loc:', l.code)
	LEFT JOIN hc2_nodes n ON n.userid = c.userid AND st.source = CONCAT('node:', n.node_id)`

func scanRemote(rows *sql.Rows) (RemoteState, error) {
	var r RemoteState
	var since, last, ls, reason, msg, sst, ssince sql.NullString
	var lat sql.NullFloat64
	err := rows.Scan(&r.UserID, &r.NodeID, &r.Execution, &r.Token, &r.State, &since, &r.Source, &last, &ls, &lat, &reason, &msg, &sst, &ssince, &r.SourceLabel)
	r.Since, r.Time, r.Status, r.LatencyMS, r.Reason, r.Message = pt(since), pt(last), ls.String, lat.Float64, reason.String, msg.String
	r.SourceState, r.SourceSince = sst.String, pt(ssince)
	return r, err
}

// RemoteStatesSince liefert Zustaende aller Messstellen, die seit 'since' aktualisiert wurden (alle Accounts).
func (s *Store) RemoteStatesSince(ctx context.Context, since time.Time) ([]RemoteState, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+remoteCols+` FROM hc2_check_states st JOIN hc2_checks c ON c.token = st.token`+remoteJoin+`
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
	rows, err := s.db.QueryContext(ctx, `SELECT `+remoteCols+` FROM hc2_checks c JOIN hc2_check_states st ON st.token = c.token`+remoteJoin+`
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
