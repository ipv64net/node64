package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/wire"
)

// Testlauf von den Standorten, den eine Node vor dem Umhaengen auf online/hybrid anfragt (wie das Portal in
// hc2_testrun_create, nur der Online-Teil): die Checker der Standorte messen einmal, die Node fragt das Ergebnis ab
// und haengt dann selbst um (normaler Sync).

var (
	ErrTestrunPrivate = errors.New("online checks cannot target private addresses")
	ErrTestrunType    = errors.New("this check type runs only locally")
)

// NodeTestrunResult ist der Stand eines Testlaufs fuer die Node.
type NodeTestrunResult struct {
	ID      int64                     `json:"id"`
	Status  string                    `json:"status"` // pending, running, ok, failed, expired
	Results map[string]TestrunOutcome `json:"results"`
}

// CreateNodeTestrun legt einen Online-Testlauf an; Standorte auf die bekannten und die Klasse begrenzt.
func (s *Store) CreateNodeTestrun(ctx context.Context, userID int64, def wire.Check, locations []string) (int64, []string, error) {
	if def.Type == "docker" || def.Type == "proxmox" || def.Type == "push" {
		return 0, nil, ErrTestrunType
	}
	if isPrivateTarget(def.Type, def.Target) || (def.Type == "dns" && checks.DNSNeedsNode(def.Params)) {
		return 0, nil, ErrTestrunPrivate
	}
	known := map[string]bool{"nbg": true, "fsn": true}
	var locs []string
	for _, l := range locations {
		if known[l] && !slices.Contains(locs, l) {
			locs = append(locs, l)
		}
	}
	if len(locs) == 0 {
		locs = []string{"nbg", "fsn"}
	}
	if acc, err := s.Account(ctx, userID); err == nil && acc.HCLocation > 0 && len(locs) > acc.HCLocation {
		locs = locs[:acc.HCLocation]
	}
	raw, err := json.Marshal(def)
	if err != nil {
		return 0, nil, err
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO hc2_testruns (userid, token, definition, target_execution, node_id, nodes, locations, status, created_at)
		VALUES (?, ?, ?, 'online', NULL, '', ?, 'pending', ?)`, userID, def.Token, string(raw), strings.Join(locs, ","), nowStr())
	if err != nil {
		return 0, nil, err
	}
	id, _ := res.LastInsertId()
	return id, locs, nil
}

// NodeTestrun liefert den Stand eines Testlaufs des Accounts; ErrNotFound, wenn es ihn nicht gibt.
func (s *Store) NodeTestrun(ctx context.Context, userID, id int64) (*NodeTestrunResult, error) {
	var status string
	var res sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT status, result FROM hc2_testruns WHERE id = ? AND userid = ?`, id, userID).Scan(&status, &res)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	out := &NodeTestrunResult{ID: id, Status: status, Results: map[string]TestrunOutcome{}}
	if res.Valid && res.String != "" {
		var all map[string]json.RawMessage
		if json.Unmarshal([]byte(res.String), &all) == nil {
			for k, v := range all {
				var o TestrunOutcome
				if k != "applied" && json.Unmarshal(v, &o) == nil {
					out.Results[k] = o
				}
			}
		}
	}
	return out, nil
}
