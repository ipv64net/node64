package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/wire"
)

// PendingCommands liefert offene Kommandos einer Node (max. 1 h alt).
func (s *Store) PendingCommands(ctx context.Context, nodeID string) ([]wire.Command, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, args FROM hc2_commands WHERE node_id = ? AND done_at IS NULL AND created_at > ? ORDER BY id`, nodeID, time.Now().UTC().Add(-time.Hour).Format(TimeFormat))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []wire.Command
	for rows.Next() {
		var c wire.Command
		var args sql.NullString
		if err := rows.Scan(&c.ID, &c.Name, &args); err != nil {
			return nil, err
		}
		if args.Valid {
			c.Args = json.RawMessage(args.String)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CommandDone traegt das Ergebnis ein. Nur Kommandos der meldenden Node (nodeID) und nur einmal;
// sonst wird die Meldung ignoriert (fremde oder erledigte Kommandos).
func (s *Store) CommandDone(ctx context.Context, nodeID string, r wire.CommandResult) error {
	out := string(r.Output)
	if r.Error != "" {
		out = r.Error
	}
	res, err := s.db.ExecContext(ctx, `UPDATE hc2_commands SET done_at = ?, ok = ?, output = ? WHERE id = ? AND node_id = ? AND done_at IS NULL`, nowStr(), b2i(r.OK), truncate(out, 65000), r.ID, nodeID)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return err
	}
	// Gehoert das Kommando zu einem Testlauf (Umhaengen), Ergebnis dort als Messstelle "node" eintragen
	var args sql.NullString
	var cmdNode string
	if err := s.db.QueryRowContext(ctx, `SELECT args, node_id FROM hc2_commands WHERE id = ? AND node_id = ? AND name = 'test_check'`, r.ID, nodeID).Scan(&args, &cmdNode); err == nil && args.Valid {
		var a struct {
			TestrunID int64 `json:"testrun_id"`
		}
		if json.Unmarshal([]byte(args.String), &a) == nil && a.TestrunID > 0 {
			o := TestrunOutcome{OK: r.OK, Error: r.Error, Time: time.Now().UTC()}
			if json.Valid(r.Output) {
				o.Results = r.Output
			}
			return s.TestrunResult(ctx, a.TestrunID, "node:"+cmdNode, o)
		}
	}
	return nil
}

// AddCommand legt ein Kommando an (Portal/Tests).
// RunCheckOn beauftragt alle messenden Nodes eines Checks (ausser der anfragenden) mit einer sofortigen Messung.
func (s *Store) RunCheckOn(ctx context.Context, userID int64, token, senderNode string) error {
	var nodes, execution string
	var owner sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT nodes, execution, node_id FROM hc2_checks WHERE token = ? AND userid = ? AND deleted_at IS NULL`, token, userID).Scan(&nodes, &execution, &owner)
	if err == sql.ErrNoRows || execution == "online" {
		return nil
	}
	if err != nil {
		return err
	}
	list := measuringNodes(splitList(nodes), owner.String)
	proxies, err := proxySet(ctx, s.db, list)
	if err != nil {
		return err
	}
	for _, id := range list {
		if id != senderNode && !proxies[id] { // Stellvertreter-Nodes haben keine Verbindung (die Gruppe misst selbst)
			if _, err := s.AddCommand(ctx, id, "run_check", map[string]string{"token": token}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) AddCommand(ctx context.Context, nodeID, name string, args any) (int64, error) {
	b, _ := json.Marshal(args)
	res, err := s.db.ExecContext(ctx, `INSERT INTO hc2_commands (node_id, name, args, created_at) VALUES (?,?,?,?)`, nodeID, name, string(b), nowStr())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// PendingSendOrders liefert nicht abgeholte Sendeauftraege einer Node und markiert sie als abgeholt.
func (s *Store) PendingSendOrders(ctx context.Context, nodeID string) ([]wire.SendOrder, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, channel_id, event_id, kind, payload FROM hc2_send_orders WHERE node_id = ? AND done_at IS NULL AND fetched_at IS NULL AND created_at > ? ORDER BY id LIMIT 100`,
		nodeID, time.Now().UTC().Add(-time.Hour).Format(TimeFormat))
	if err != nil {
		return nil, err
	}
	var out []wire.SendOrder
	for rows.Next() {
		var o wire.SendOrder
		var payload string
		if err := rows.Scan(&o.ID, &o.ChannelID, &o.EventID, &o.Kind, &payload); err != nil {
			rows.Close()
			return nil, err
		}
		_ = json.Unmarshal([]byte(payload), &o.Payload)
		out = append(out, o)
	}
	rows.Close()
	for _, o := range out {
		_, _ = s.db.ExecContext(ctx, `UPDATE hc2_send_orders SET fetched_at = ? WHERE id = ?`, nowStr(), o.ID)
	}
	return out, nil
}

// SendOrderDone traegt das Ergebnis eines Sendeauftrags ein (nur Auftraege, die an nodeID gingen).
func (s *Store) SendOrderDone(ctx context.Context, nodeID string, id int64, ok bool, errText string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE hc2_send_orders SET done_at = ?, ok = ?, error = ? WHERE id = ? AND node_id = ?`, nowStr(), b2i(ok), truncate(errText, 500), id, nodeID)
	return err
}

// PushIn nimmt einen Heartbeat am hub an (Messpunkt + last_push_at); der checker bewertet.
func (s *Store) PushIn(ctx context.Context, token string, down bool, msg, from string) (bool, error) {
	return s.PushInFrom(ctx, token, down, msg, from, "", 0)
}

// PushInFrom nimmt einen Heartbeat an und reicht ihn an alle messenden Nodes weiter (ausser der
// Absenderin). userID > 0: nur Checks dieses Accounts (Push, den eine Node lokal empfangen hat).
func (s *Store) PushInFrom(ctx context.Context, token string, down bool, msg, from, senderNode string, userID int64) (bool, error) {
	var t, execution string
	var owner sql.NullString
	var nodes string
	var uid int64
	err := s.db.QueryRowContext(ctx, `SELECT token, userid, execution, node_id, nodes FROM hc2_checks WHERE token = ? AND type = 'push' AND deleted_at IS NULL`, token).Scan(&t, &uid, &execution, &owner, &nodes)
	if err == nil && userID > 0 && uid != userID {
		return false, nil
	}
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if senderNode == "" && execution != "local" { // Push an die Online-Adresse: Tageskontingent
		switch blocked := s.DailyBlocked(uid); {
		case blocked && execution == "online":
			return false, ErrDailyLimit
		case !blocked:
			s.countUse(uid)
		} // Hybrid bei erschoepftem Kontingent: annehmen und an die Nodes weiterreichen (sonst lokal "ueberfaellig")
	}
	details, _ := json.Marshal(map[string]string{"from": from, "via": "hub:" + s.location})
	status, reason := 1, ""
	if down {
		status, reason = 0, "push_down"
	}
	if _, err := s.db.ExecContext(ctx, `INSERT IGNORE INTO hc2_measurements (token, source, node_seq, time, status, latency_ms, reason, message, details, received_at) VALUES (?,'push',0,?,?,0,?,?,?,?)`,
		t, nowStr(), status, reason, truncate(strings.TrimSpace(msg), 500), string(details), nowStr()); err != nil {
		return false, err
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE hc2_checks SET last_push_at = ? WHERE token = ?`, nowStr(), t)
	if execution != "online" {
		args, _ := json.Marshal(map[string]any{"token": t, "down": down, "msg": msg, "from": from, "time": time.Now().UTC().Format(time.RFC3339)})
		for _, id := range measuringNodes(splitList(nodes), owner.String) {
			if id != senderNode {
				_, _ = s.db.ExecContext(ctx, `INSERT INTO hc2_commands (node_id, name, args, created_at) VALUES (?, 'push', ?, ?)`, id, string(args), nowStr())
			}
		}
	}
	return true, nil
}

// NodesSeen schreibt last_seen/online fuer mehrere Nodes gebuendelt.
// GoneNodes liefert aus ids die Nodes, die inzwischen getrennt (Token widerrufen) oder entfernt sind,
// z. B. im Portal; deren Verbindung beendet der gateway (die Node bekommt beim Neuverbinden 401).
func (s *Store) GoneNodes(ctx context.Context, ids []string) ([]string, error) {
	var gone []string
	for len(ids) > 0 {
		n := min(len(ids), 500)
		part := ids[:n]
		ids = ids[n:]
		ph := make([]string, len(part))
		args := make([]any, len(part))
		for i, id := range part {
			ph[i], args[i] = "?", id
		}
		rows, err := s.db.QueryContext(ctx, `SELECT node_id FROM hc2_nodes WHERE node_id IN (`+strings.Join(ph, ",")+`) AND revoked_at IS NULL`, args...)
		if err != nil {
			return gone, err
		}
		live := map[string]bool{}
		for rows.Next() {
			var id string
			if rows.Scan(&id) == nil {
				live[id] = true
			}
		}
		rows.Close()
		for _, id := range part {
			if !live[id] {
				gone = append(gone, id)
			}
		}
	}
	return gone, nil
}

func (s *Store) NodesSeen(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	args := make([]any, 0, len(ids)+2)
	args = append(args, nowStr(), s.node)
	ph := make([]string, len(ids))
	for i, id := range ids {
		ph[i] = "?"
		args = append(args, id)
	}
	_, err := s.db.ExecContext(ctx, `UPDATE hc2_nodes SET last_seen = ?, online = 1, node = ? WHERE node_id IN (`+strings.Join(ph, ",")+`)`, args...)
	for _, id := range ids {
		s.setNodeOnline(id, true)
	}
	return err
}
