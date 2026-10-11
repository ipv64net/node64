package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// Testlaeufe beim Umhaengen (Sync-Plan 3.11): das Portal legt eine Zeile in hc2_testruns an,
// jeder Standort traegt sein Ergebnis unter result.<loc> ein, die Node ueber das Kommando
// test_check (args.testrun_id) unter result.node. Sind alle verlangten Messstellen da, wird
// der Status ok/failed; aeltere Laeufe laufen nach 60 s ab.

type Testrun struct {
	ID         int64
	UserID     int64
	Token      string
	Definition json.RawMessage
	Target     string // local, online, both
	NodeID     string
	Locations  []string
	Result     map[string]json.RawMessage
}

// TestrunOutcome ist das Ergebnis einer Messstelle.
type TestrunOutcome struct {
	OK      bool            `json:"ok"`
	Error   string          `json:"error,omitempty"`
	Results json.RawMessage `json:"results,omitempty"`
	Time    time.Time       `json:"time"`
}

// PendingTestruns liefert offene Testlaeufe, zu denen dieser Standort noch kein Ergebnis hat.
func (s *Store) PendingTestruns(ctx context.Context, loc string) ([]Testrun, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, userid, token, definition, target_execution, COALESCE(node_id,''), locations, result
		FROM hc2_testruns WHERE status IN ('pending','running') AND target_execution IN ('online','both') AND FIND_IN_SET(?, locations) > 0 AND created_at > ? ORDER BY id LIMIT 50`,
		loc, time.Now().UTC().Add(-2*time.Minute).Format(TimeFormat))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Testrun
	for rows.Next() {
		var t Testrun
		var def, locs string
		var res sql.NullString
		if err := rows.Scan(&t.ID, &t.UserID, &t.Token, &def, &t.Target, &t.NodeID, &locs, &res); err != nil {
			return nil, err
		}
		t.Definition = json.RawMessage(def)
		t.Locations = splitList(locs)
		t.Result = map[string]json.RawMessage{}
		if res.Valid && res.String != "" {
			_ = json.Unmarshal([]byte(res.String), &t.Result)
		}
		if _, done := t.Result[loc]; done {
			continue
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TestrunResult traegt das Ergebnis einer Messstelle ein und schliesst den Lauf ab, wenn alles da ist.
func (s *Store) TestrunResult(ctx context.Context, id int64, key string, o TestrunOutcome) error {
	b, _ := json.Marshal(o)
	if _, err := s.db.ExecContext(ctx, `UPDATE hc2_testruns SET status = IF(status = 'pending', 'running', status), result = JSON_SET(COALESCE(result, '{}'), ?, CAST(? AS JSON)) WHERE id = ? AND status IN ('pending','running')`,
		"$."+key, string(b), id); err != nil {
		return err
	}
	return s.finalizeTestrun(ctx, id)
}

func (s *Store) finalizeTestrun(ctx context.Context, id int64) error {
	var target, locs string
	var res sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT target_execution, locations, result FROM hc2_testruns WHERE id = ? AND status IN ('pending','running')`, id).Scan(&target, &locs, &res)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	got := map[string]TestrunOutcome{}
	if res.Valid {
		_ = json.Unmarshal([]byte(res.String), &got)
	}
	var need []string
	if target != "local" {
		need = append(need, splitList(locs)...)
	}
	if target != "online" {
		need = append(need, "node")
	}
	ok := true
	for _, k := range need {
		o, present := got[k]
		if !present {
			return nil // noch nicht vollstaendig
		}
		if !o.OK {
			ok = false
		}
	}
	status := "failed"
	if ok {
		status = "ok"
	}
	_, err = s.db.ExecContext(ctx, `UPDATE hc2_testruns SET status = ?, finished_at = ? WHERE id = ? AND status IN ('pending','running')`, status, nowStr(), id)
	return err
}

// ExpireTestruns setzt Laeufe ohne vollstaendiges Ergebnis nach 60 s auf expired.
func (s *Store) ExpireTestruns(ctx context.Context) {
	_, _ = s.db.ExecContext(ctx, `UPDATE hc2_testruns SET status = 'expired', finished_at = ? WHERE status IN ('pending','running') AND created_at < ?`,
		nowStr(), time.Now().UTC().Add(-60*time.Second).Format(TimeFormat))
}

// PrivateTarget sagt, ob ein Ziel fuer Online-Checks unzulaessig ist (RFC 1918, ULA, Loopback, .local ...).
func PrivateTarget(typ, target string) bool { return isPrivateTarget(typ, strings.TrimSpace(target)) }
