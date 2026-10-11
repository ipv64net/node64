package store

import (
	"context"
	"sort"
	"time"
)

// Heartbeat traegt diese Instanz in hc2_hubs ein bzw. erneuert sie.
func (s *Store) Heartbeat(ctx context.Context, roles, version string, connections int, started time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO hc2_hubs (name, location, roles, version, connections, started_at, heartbeat) VALUES (?,?,?,?,?,?,?)
		ON DUPLICATE KEY UPDATE location=VALUES(location), roles=VALUES(roles), version=VALUES(version), connections=VALUES(connections), started_at=VALUES(started_at), heartbeat=VALUES(heartbeat)`,
		s.node, s.location, roles, version, connections, ft(started), nowStr())
	if err != nil {
		s.Metrics.add(&s.Metrics.DBErrors, 1)
	}
	return err
}

// Leave entfernt die Instanz beim sauberen Herunterfahren.
func (s *Store) Leave(ctx context.Context) {
	_, _ = s.db.ExecContext(ctx, `DELETE FROM hc2_hubs WHERE name = ?`, s.node)
}

// Node ist eine lebende hub-Instanz.
type Node struct {
	Name, Location string
}

// LiveNodes liefert alle Instanzen mit Heartbeat in den letzten 30 s, sortiert.
func (s *Store) LiveNodes(ctx context.Context) ([]Node, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, location FROM hc2_hubs WHERE heartbeat > ? ORDER BY name`, time.Now().UTC().Add(-30*time.Second).Format(TimeFormat))
	if err != nil {
		s.Metrics.add(&s.Metrics.DBErrors, 1)
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.Name, &n.Location); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// SlotShare berechnet aus den lebenden Instanzen des eigenen Standorts, welche
// Slots diese Instanz bearbeitet: Index i von n (slot % n == i). Ist die
// eigene Instanz (noch) nicht in der Liste, zaehlt sie sich dazu.
func (s *Store) SlotShare(nodes []Node) (idx, n int) {
	var names []string
	seen := false
	for _, x := range nodes {
		if x.Location == s.location {
			names = append(names, x.Name)
			if x.Name == s.node {
				seen = true
			}
		}
	}
	if !seen {
		names = append(names, s.node)
	}
	sort.Strings(names)
	for i, nm := range names {
		if nm == s.node {
			return i, len(names)
		}
	}
	return 0, 1
}

// IsHousekeeper sagt, ob diese Instanz die standortuebergreifenden Aufgaben
// (Partitionen, Aufraeumen, Tageswerte) uebernimmt: die alphabetisch erste
// lebende Instanz.
func (s *Store) IsHousekeeper(nodes []Node) bool {
	first := s.node
	for _, x := range nodes {
		if x.Name < first {
			first = x.Name
		}
	}
	return first == s.node
}
