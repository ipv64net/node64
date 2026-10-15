package store

import (
	"context"
	"database/sql"
	"regexp"
	"strings"

	"github.com/ipv64net/node64/internal/wire"
)

// Stellvertreter-Nodes: Ein nicht verknuepftes Mitglied einer lokalen Gruppe meldet Messwerte und Zustaende ueber
// die weiterreichende Node der Gruppe (hc2_nodes.proxy_via). Solche Nodes haben keinen Token und keine Verbindung;
// online/last_seen setzt die Meldung der weiterreichenden Node. Ihre Checks zeigt der hub an, benachrichtigt aber
// nicht – das macht die Gruppe selbst (sonst kaeme jede Meldung doppelt).

var proxyIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,32}$`)

// MaxProxies: so viele Stellvertreter-Nodes nimmt der hub je weiterreichender Node an.
const MaxProxies = 50

type rowQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// RegisterProxies uebernimmt die Liste der Stellvertreter-Nodes einer weiterreichenden Node: legt neue an,
// uebernimmt sie von einer anderen weiterreichenden Node, setzt online/last_seen und widerruft die, die nicht mehr
// in der Liste stehen. Verknuepfte Nodes und Nodes anderer Accounts bleiben unberuehrt. Liefert je angenommener
// Node den bestaetigten Messpunkt-Stand.
func (s *Store) RegisterProxies(ctx context.Context, via *Node, items []wire.ProxyNode) (map[string]int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	acks := map[string]int64{}
	online := map[string]bool{}
	changed := false
	now := nowStr()
	var keep []any
	for _, p := range items {
		if !proxyIDRe.MatchString(p.ID) || p.ID == via.ID {
			continue
		}
		if _, dup := acks[p.ID]; dup {
			continue
		}
		name := truncate(strings.TrimSpace(p.Name), 100)
		if name == "" {
			name = "Node " + p.ID[:8]
		}
		loc := truncate(strings.TrimSpace(p.Location), 100)
		var uid, ack int64
		var cur, revoked sql.NullString
		var oldName, oldLoc string
		err := tx.QueryRowContext(ctx, `SELECT userid, proxy_via, revoked_at, name, location, last_ack_seq FROM hc2_nodes WHERE node_id = ? FOR UPDATE`, p.ID).
			Scan(&uid, &cur, &revoked, &oldName, &oldLoc, &ack)
		switch {
		case err == sql.ErrNoRows:
			var seen any
			if p.Online {
				seen = now
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO hc2_nodes (userid, node_id, name, location, version, remote_mgmt, proxy_via, online, last_seen, created_at) VALUES (?,?,?,?,?,'off',?,?,?,?)`,
				via.UserID, p.ID, name, loc, truncate(p.Version, 32), via.ID, b2i(p.Online), seen, now); err != nil {
				return nil, err
			}
			changed = true
		case err != nil:
			return nil, err
		case uid != via.UserID:
			continue // Node eines anderen Accounts
		case !cur.Valid && !revoked.Valid:
			continue // verknuepft: meldet selbst
		default:
			if revoked.Valid || oldName != name || oldLoc != loc || cur.String != via.ID {
				changed = true
			}
			q := `UPDATE hc2_nodes SET proxy_via = ?, revoked_at = NULL, name = ?, location = ?, version = ?, online = 0 WHERE node_id = ?`
			args := []any{via.ID, name, loc, truncate(p.Version, 32), p.ID}
			if p.Online {
				q = `UPDATE hc2_nodes SET proxy_via = ?, revoked_at = NULL, name = ?, location = ?, version = ?, online = 1, last_seen = ? WHERE node_id = ?`
				args = []any{via.ID, name, loc, truncate(p.Version, 32), now, p.ID}
			}
			if _, err := tx.ExecContext(ctx, q, args...); err != nil {
				return nil, err
			}
		}
		acks[p.ID], online[p.ID] = ack, p.Online
		keep = append(keep, p.ID)
	}
	// nicht mehr in der Liste (Mitglied entfernt oder inzwischen selbst verknuepft): widerrufen
	q := `UPDATE hc2_nodes SET revoked_at = ?, online = 0 WHERE proxy_via = ? AND userid = ? AND revoked_at IS NULL`
	args := []any{now, via.ID, via.UserID}
	if len(keep) > 0 {
		q += ` AND node_id NOT IN (` + strings.TrimSuffix(strings.Repeat("?,", len(keep)), ",") + `)`
		args = append(args, keep...)
	}
	res, err := tx.ExecContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		changed = true
	}
	if changed { // die Nodes des Accounts laden ihre Liste der Nodes neu (Auswahl der messenden Nodes)
		rev, err := nextRevision(ctx, tx, via.UserID)
		if err != nil {
			return nil, err
		}
		if err := logChange(ctx, tx, via.UserID, nil, "node", via.ID, "upsert", rev, "node"); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	for id, on := range online {
		s.setNodeOnline(id, on)
	}
	return acks, nil
}

// ProxyOf laedt eine Stellvertreter-Node, die ueber via meldet (nil: keine solche).
func (s *Store) ProxyOf(ctx context.Context, via *Node, id string) (*Node, error) {
	n, err := s.NodeByID(ctx, id)
	if err != nil || n == nil {
		return nil, err
	}
	if n.UserID != via.UserID || n.ProxyVia != via.ID || !n.RevokedAt.IsZero() {
		return nil, nil
	}
	return n, nil
}

// proxySet liefert die Stellvertreter-Nodes unter ids.
func proxySet(ctx context.Context, q rowQuerier, ids []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(ids) == 0 {
		return out, nil
	}
	args := make([]any, 0, len(ids))
	for _, id := range ids {
		args = append(args, id)
	}
	rows, err := q.QueryContext(ctx, `SELECT node_id FROM hc2_nodes WHERE proxy_via IS NOT NULL AND revoked_at IS NULL AND node_id IN (`+strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			out[id] = true
		}
	}
	return out, rows.Err()
}
