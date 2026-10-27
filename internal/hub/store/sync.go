package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/notify"
	"hash/crc32"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/scheduler"
	"github.com/ipv64net/node64/internal/wire"
)

// ---------------------------------------------------------------- Revisionen / Log

// NextRevision vergibt die naechste Revision eines Accounts (in tx).
func nextRevision(ctx context.Context, tx *sql.Tx, userID int64) (int64, error) {
	if _, err := tx.ExecContext(ctx, `INSERT INTO hc2_revisions (userid, next) VALUES (?, 2) ON DUPLICATE KEY UPDATE next = next + 1`, userID); err != nil {
		return 0, err
	}
	var next int64
	if err := tx.QueryRowContext(ctx, `SELECT next - 1 FROM hc2_revisions WHERE userid = ?`, userID).Scan(&next); err != nil {
		return 0, err
	}
	return next, nil
}

func logChange(ctx context.Context, tx *sql.Tx, userID int64, nodeID any, entity, id, op string, rev int64, origin string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO hc2_config_log (userid, node_id, entity, entity_id, op, revision, origin, time) VALUES (?,?,?,?,?,?,?,?)`,
		userID, nodeID, entity, id, op, rev, origin, nowStr())
	return err
}

// CurrentRevision liefert die hoechste vergebene Revision eines Accounts.
func (s *Store) CurrentRevision(ctx context.Context, userID int64) int64 {
	var next sql.NullInt64
	_ = s.db.QueryRowContext(ctx, `SELECT next FROM hc2_revisions WHERE userid = ?`, userID).Scan(&next)
	if !next.Valid || next.Int64 <= 1 {
		return 0
	}
	return next.Int64 - 1
}

// ---------------------------------------------------------------- Checks <-> wire

const wireCheckCols = `token, node_id, execution, locations, policy, notify_degraded, type, name, target, params, interval_sec, retry_interval_sec, retries,
	connect_timeout_ms, total_timeout_ms, invert, stabilize, ip_mode, tags, description, paused, parent_token, critical, notify_down, notify_up, channels, repeat_minutes, revision, deleted_at, group_name, nodes`

func scanWireCheck(row interface{ Scan(...any) error }) (*wire.Check, bool, error) {
	var c wire.Check
	var nodeID, parent, deleted, description sql.NullString
	var locations, tags, channels, params, nodes string
	var iv, riv, cto, tto int64
	var invert, paused, critical, nd, nu, ndeg int
	if err := row.Scan(&c.Token, &nodeID, &c.Execution, &locations, &c.Policy, &ndeg, &c.Type, &c.Name, &c.Target, &params, &iv, &riv, &c.Retries,
		&cto, &tto, &invert, &c.Stabilize, &c.IPMode, &tags, &description, &paused, &parent, &critical, &nd, &nu, &channels, &c.RepeatMinutes, &c.Revision, &deleted, &c.Group, &nodes); err != nil {
		return nil, false, err
	}
	c.NodeID, c.Parent, c.Description = nodeID.String, parent.String, description.String
	if c.Execution != "online" {
		c.Nodes = measuringNodes(splitList(nodes), c.NodeID)
	}
	c.Params = json.RawMessage(params)
	if strings.TrimSpace(params) == "" {
		c.Params = json.RawMessage("{}")
	}
	c.Locations, c.Tags = splitList(locations), splitList(tags)
	if c.Locations == nil {
		c.Locations = []string{}
	}
	if c.Tags == nil {
		c.Tags = []string{}
	}
	c.Channels = []int64{}
	for _, ch := range splitList(channels) {
		var id int64
		if _, err := fmtSscan(ch, &id); err == nil {
			c.Channels = append(c.Channels, id)
		}
	}
	c.IntervalSeconds, c.RetryIntervalSeconds = int(iv), int(riv)
	c.ConnectTimeoutSeconds, c.TimeoutSeconds = float64(cto)/1000, float64(tto)/1000
	c.Invert, c.Paused, c.Critical, c.NotifyDown, c.NotifyUp, c.NotifyDegraded = invert == 1, paused == 1, critical == 1, nd == 1, nu == 1, ndeg == 1
	return &c, deleted.Valid, nil
}

func joinInts(ids []int64) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprint(id))
	}
	return strings.Join(parts, ",")
}

func slotOf(token string) int { return int(crc32.ChecksumIEEE([]byte(token)) % 1024) }

// WireCheck laedt einen Check in Wire-Form (auch geloeschte: deleted = true).
func (s *Store) WireCheck(ctx context.Context, token string) (*wire.Check, bool, error) {
	c, del, err := scanWireCheck(s.db.QueryRowContext(ctx, `SELECT `+wireCheckCols+` FROM hc2_checks WHERE token = ?`, token))
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	return c, del, err
}

// ownerOf setzt die Sicht der Node: self (eigener), other (andere Node), online.
func ownerOf(c *wire.Check, nodeID string) string {
	switch {
	case c.Execution == "online":
		return "online"
	case c.NodeID == nodeID:
		return "self"
	default:
		return "other"
	}
}

// ---------------------------------------------------------------- Vollabgleich

// FullConfig liefert die gesamte Konfiguration eines Accounts aus Sicht einer Node.
func (s *Store) FullConfig(ctx context.Context, userID int64, nodeID string) (*wire.FullConfig, error) {
	out := &wire.FullConfig{Revision: s.CurrentRevision(ctx, userID), Checks: []wire.Check{}, Maintenance: []wire.Maintenance{}, Channels: []wire.Channel{}, Settings: map[string]string{}}
	rows, err := s.db.QueryContext(ctx, `SELECT `+wireCheckCols+` FROM hc2_checks WHERE userid = ? AND deleted_at IS NULL ORDER BY name`, userID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		c, _, err := scanWireCheck(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		c.Owner = ownerOf(c, nodeID)
		out.Checks = append(out.Checks, *c)
	}
	rows.Close()
	mrows, err := s.db.QueryContext(ctx, `SELECT id, name, start_at, end_at, `+"`repeat`"+`, repeat_until, tokens, active, revision, node_id FROM hc2_maintenance WHERE userid = ? AND deleted_at IS NULL`, userID)
	if err != nil {
		return nil, err
	}
	for mrows.Next() {
		m, err := scanWireMaint(mrows)
		if err != nil {
			mrows.Close()
			return nil, err
		}
		out.Maintenance = append(out.Maintenance, *m)
	}
	mrows.Close()
	crows, err := s.db.QueryContext(ctx, `SELECT id, type, name, config_enc, enabled, is_default, lang, notify_down, notify_up, revision, node_id, secret_only_local FROM hc2_channels WHERE userid = ? AND deleted_at IS NULL ORDER BY name`, userID)
	if err != nil {
		return nil, err
	}
	for crows.Next() {
		ch, err := s.scanWireChannel(crows, nodeID)
		if err != nil {
			crows.Close()
			return nil, err
		}
		out.Channels = append(out.Channels, *ch)
	}
	crows.Close()
	srows, err := s.db.QueryContext(ctx, "SELECT `key`, `value` FROM hc2_settings WHERE userid = ?", userID)
	if err == nil {
		for srows.Next() {
			var k, v string
			if srows.Scan(&k, &v) == nil {
				out.Settings[k] = v
			}
		}
		srows.Close()
	}
	return out, nil
}

func scanWireMaint(row interface{ Scan(...any) error }) (*wire.Maintenance, error) {
	var m wire.Maintenance
	var start, end, until, tokens, nodeID sql.NullString
	var active int
	if err := row.Scan(&m.ID, &m.Name, &start, &end, &m.Repeat, &until, &tokens, &active, &m.Revision, &nodeID); err != nil {
		return nil, err
	}
	m.StartAt, m.EndAt, m.RepeatUntil, m.Active, m.NodeID = pt(start), pt(end), pt(until), active == 1, nodeID.String
	m.Tokens = splitList(tokens.String)
	if m.Tokens == nil {
		m.Tokens = []string{}
	}
	return &m, nil
}

func (s *Store) scanWireChannel(row interface{ Scan(...any) error }, nodeID string) (*wire.Channel, error) {
	var ch wire.Channel
	var cfg string
	var enabled, def, nd, nu, sol int
	var owner sql.NullString
	if err := row.Scan(&ch.ID, &ch.Type, &ch.Name, &cfg, &enabled, &def, &ch.Lang, &nd, &nu, &ch.Revision, &owner, &sol); err != nil {
		return nil, err
	}
	ch.Enabled, ch.Default, ch.NotifyDown, ch.NotifyUp, ch.NodeID = enabled == 1, def == 1, nd == 1, nu == 1, owner.String
	// Konfiguration nur fuer die Besitzer-Node (verschluesselt, wie gespeichert; die Node hat denselben Schluessel nicht,
	// daher liefert der Server bei secret_only_local gar nichts und sonst den Klartext)
	if !(owner.Valid && owner.String == nodeID) && sol == 0 && cfg != "" {
		// Kanal des Portals: die nicht geheimen Werte (Adresse, Nummer, URL ...) zum Anzeigen und Bearbeiten
		m := map[string]string{}
		if json.Unmarshal([]byte(cfg), &m) == nil {
			ch.Config = map[string]string{}
			for k, v := range m {
				if !isSecretField(k) && !strings.HasPrefix(v, "enc:v1:") {
					ch.Config[k] = v
				}
			}
		}
	}
	if owner.Valid && owner.String == nodeID && sol == 0 && cfg != "" {
		m := map[string]string{}
		if json.Unmarshal([]byte(cfg), &m) == nil {
			for k, v := range m {
				if strings.HasPrefix(v, "enc:v1:") {
					if s.box != nil {
						if plain, err := s.box.Decrypt(v); err == nil {
							v = plain
						}
					}
				}
				m[k] = v
			}
			ch.Config = m
		}
	}
	return &ch, nil
}

// ConfigSince liefert die Log-Eintraege eines Accounts nach einer Revision mit den vollstaendigen Entitaeten.
// gap = true, wenn das Log die Revision nicht mehr enthaelt (Node muss den Vollabgleich machen).
func (s *Store) ConfigSince(ctx context.Context, userID int64, nodeID string, since int64) (changes []wire.Change, gap bool, err error) {
	if since > 0 {
		var minRev sql.NullInt64
		_ = s.db.QueryRowContext(ctx, `SELECT MIN(revision) FROM hc2_config_log WHERE userid = ?`, userID).Scan(&minRev)
		if minRev.Valid && minRev.Int64 > since+1 {
			return nil, true, nil
		}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT entity, entity_id, op, revision, node_id FROM hc2_config_log WHERE userid = ? AND revision > ? ORDER BY revision, id`, userID, since)
	if err != nil {
		return nil, false, err
	}
	type raw struct {
		entity, id, op string
		rev            int64
		target         sql.NullString
	}
	var list []raw
	for rows.Next() {
		var r raw
		if err := rows.Scan(&r.entity, &r.id, &r.op, &r.rev, &r.target); err != nil {
			rows.Close()
			return nil, false, err
		}
		list = append(list, r)
	}
	rows.Close()
	seen := map[string]bool{}
	for i := len(list) - 1; i >= 0; i-- { // nur die letzte Aenderung je Entitaet
		r := list[i]
		if r.target.Valid && r.target.String != nodeID {
			continue
		}
		key := r.entity + ":" + r.id
		if seen[key] {
			continue
		}
		seen[key] = true
		ch := wire.Change{Entity: r.entity, ID: r.id, Op: r.op, Revision: r.rev}
		if r.op == "upsert" {
			data, err := s.entityData(ctx, r.entity, r.id, nodeID, userID)
			if err != nil {
				return nil, false, err
			}
			if data == nil {
				ch.Op = "delete"
			} else {
				ch.Data = data
			}
		}
		changes = append([]wire.Change{ch}, changes...)
	}
	return changes, false, nil
}

func (s *Store) entityData(ctx context.Context, entity, id, nodeID string, userID int64) (json.RawMessage, error) {
	switch entity {
	case "check":
		c, deleted, err := s.WireCheck(ctx, id)
		if err != nil || c == nil || deleted {
			return nil, err
		}
		c.Owner = ownerOf(c, nodeID)
		return json.Marshal(c)
	case "maintenance":
		m, err := scanWireMaint(s.db.QueryRowContext(ctx, `SELECT id, name, start_at, end_at, `+"`repeat`"+`, repeat_until, tokens, active, revision, node_id FROM hc2_maintenance WHERE id = ? AND deleted_at IS NULL`, id))
		if err == sql.ErrNoRows {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return json.Marshal(m)
	case "channel":
		ch, err := s.scanWireChannel(s.db.QueryRowContext(ctx, `SELECT id, type, name, config_enc, enabled, is_default, lang, notify_down, notify_up, revision, node_id, secret_only_local FROM hc2_channels WHERE id = ? AND deleted_at IS NULL`, id), nodeID)
		if err == sql.ErrNoRows {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return json.Marshal(ch)
	case "settings":
		kv, err := s.AccountSettings(ctx, userID) // Einstellungen dieses Accounts
		if err != nil {
			return nil, err
		}
		return json.Marshal(kv)
	}
	return nil, nil
}

// ---------------------------------------------------------------- Vorschlaege der Node

// Propose wendet einen Aenderungsvorschlag an (Sync-Plan 3.4). base_revision -1 = ohne Pruefung (system).
func (s *Store) Propose(ctx context.Context, userID int64, nodeID string, p wire.Propose, origin string) (*wire.ProposeResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	res := &wire.ProposeResult{}
	switch p.Entity {
	case "check":
		err = s.proposeCheck(ctx, tx, userID, nodeID, p, origin, res)
	case "maintenance":
		err = s.proposeMaintenance(ctx, tx, userID, nodeID, p, origin, res)
	case "channel":
		err = s.proposeChannel(ctx, tx, userID, nodeID, p, origin, res)
	default:
		return nil, fmt.Errorf("unknown entity %q", p.Entity)
	}
	if err != nil {
		return nil, err
	}
	if res.Error != "" && !strings.Contains(res.Error, "another account") {
		// Ablehnung: aktuellen Stand des Eintrags mitschicken (leer = hier nicht vorhanden), damit die Node beide
		// Fassungen zeigen und den Server-Stand wiederherstellen kann statt den Eintrag zu loeschen
		_ = tx.Rollback()
		if d, err := s.entityData(ctx, p.Entity, p.ID, nodeID, userID); err == nil && len(d) > 0 {
			var x struct {
				Revision int64 `json:"revision"`
			}
			_ = json.Unmarshal(d, &x)
			res.Server, res.Revision = d, x.Revision
		}
	}
	if res.Conflict || res.Error != "" {
		return res, nil
	}
	return res, tx.Commit()
}

func (s *Store) proposeCheck(ctx context.Context, tx *sql.Tx, userID int64, nodeID string, p wire.Propose, origin string, res *wire.ProposeResult) error {
	var cur sql.NullInt64
	var owner sql.NullString
	var deleted, updated sql.NullString
	var ownerUser sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT revision, node_id, deleted_at, userid, updated_at FROM hc2_checks WHERE token = ? FOR UPDATE`, p.ID).Scan(&cur, &owner, &deleted, &ownerUser, &updated)
	exists := err == nil
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if exists && ownerUser.Int64 != userID {
		res.Error = "token belongs to another account"
		return nil
	}
	if exists && deleted.Valid && p.Op != "delete" && p.BaseRevision > 0 && !p.ChangedAt.After(pt(deleted)) {
		// nach der Aenderung an der Node geloescht: bleibt geloescht (leere Server-Fassung = loeschen)
		res.Conflict, res.Revision = true, cur.Int64
		return nil
	}
	if exists && p.BaseRevision >= 0 && cur.Int64 != p.BaseRevision && !deleted.Valid && !p.ChangedAt.After(pt(updated)) {
		res.Conflict = true
		res.Revision = cur.Int64
		if c, _, err := s.WireCheck(ctx, p.ID); err == nil && c != nil {
			c.Owner = ownerOf(c, nodeID)
			res.Server, _ = json.Marshal(c)
		}
		return nil
	}
	// Checks einer anderen Node darf jede Node des Accounts aendern, pausieren und loeschen;
	// nur die Messstelle eines Docker-Checks bleibt bei der Container-Node (siehe unten)
	rev, err := nextRevision(ctx, tx, userID)
	if err != nil {
		return err
	}
	if p.Op == "delete" {
		if exists {
			if _, err := tx.ExecContext(ctx, `UPDATE hc2_checks SET deleted_at = ?, revision = ?, updated_at = ?, updated_by = ?, incident_id = NULL WHERE token = ?`, nowStr(), rev, nowStr(), origin, p.ID); err != nil {
				return err
			}
			// offene Stoerung endet mit dem Loeschen (die Node loescht ihre Stoerungen mit dem Check)
			if _, err := tx.ExecContext(ctx, `UPDATE hc2_incidents SET ended_at = ? WHERE token = ? AND ended_at IS NULL`, nowStr(), p.ID); err != nil {
				return err
			}
		}
		res.Revision = rev
		return logChange(ctx, tx, userID, nil, "check", p.ID, "delete", rev, origin)
	}
	var c wire.Check
	if err := json.Unmarshal(p.Data, &c); err != nil {
		res.Error = "invalid check: " + err.Error()
		return nil
	}
	c.Token = p.ID
	if err := validateWireCheck(&c); err != nil {
		res.Error = err.Error()
		return nil
	}
	if exists {
		// Kanaele anderer Nodes sieht die vorschlagende Node nicht (nicht synchronisiert): beibehalten
		var cur string
		_ = tx.QueryRowContext(ctx, `SELECT channels FROM hc2_checks WHERE token = ?`, p.ID).Scan(&cur)
		if cur != "" {
			rows, err := tx.QueryContext(ctx, `SELECT id FROM hc2_channels WHERE userid = ? AND node_id IS NOT NULL AND node_id <> ? AND deleted_at IS NULL AND FIND_IN_SET(id, ?)`, userID, nodeID, cur)
			if err != nil {
				return err
			}
			have := map[int64]bool{}
			for _, id := range c.Channels {
				have[id] = true
			}
			for rows.Next() {
				var id int64
				if rows.Scan(&id) == nil && !have[id] {
					c.Channels = append(c.Channels, id)
				}
			}
			rows.Close()
		}
	}
	// Ausfuehrungsort und Standorte: Node-Checks gehoeren der Node; Standorte auf die Klasse begrenzen
	if c.Execution == "" {
		c.Execution = "local"
	}
	nodeRef := any(nil)
	if c.Execution == "local" || c.Execution == "both" {
		if c.NodeID == "" && exists && owner.Valid && owner.String != "" {
			c.NodeID = owner.String // Besitzerin bleibt, auch wenn eine andere Node aendert
		}
		if c.NodeID == "" {
			c.NodeID = nodeID
		}
		if c.NodeID != "" {
			nodeRef = c.NodeID
		}
	} else if c.NodeID != "" {
		nodeRef = c.NodeID
	}
	// Messende Nodes: nur aktive Nodes des Accounts; Docker/Proxmox bleiben bei ihrer Besitzer-Node (im Cluster der
	// Node messen weitere Nodes mit, die das System kennen - die Liste kommt von der Node)
	var nodeList []string
	if c.Execution != "online" {
		owner0 := ""
		if v, ok := nodeRef.(string); ok {
			owner0 = v
		}
		if singleNodeType(c.Type) && exists && owner.Valid && owner.String != "" && owner0 != owner.String {
			res.Error = c.Type + " checks belong to the node that runs them and cannot be moved"
			return nil
		}
		nodeList = measuringNodes(c.Nodes, owner0)
		if singleNodeType(c.Type) && owner0 != "" && !inList(nodeList, owner0) {
			nodeList = append([]string{owner0}, nodeList...) // Besitzerin bleibt vorn
		}
		if len(nodeList) > 20 {
			res.Error = "at most 20 measuring nodes"
			return nil
		}
		for _, id := range nodeList {
			var ok int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM hc2_nodes WHERE userid = ? AND node_id = ? AND revoked_at IS NULL`, userID, id).Scan(&ok); err != nil {
				return err
			}
			if ok == 0 {
				res.Error = "unknown or unlinked node " + id
				return nil
			}
		}
		// Besitzerin misst nicht mehr mit: Besitz an die erste messende Node (wie im Portal und beim Trennen)
		if len(nodeList) > 0 && !inList(nodeList, owner0) {
			nodeRef, c.NodeID = nodeList[0], nodeList[0]
		}
	}
	acc, _ := s.Account(ctx, userID)
	locs := c.Locations
	if len(locs) == 0 {
		locs = []string{"nbg", "fsn"}
	}
	if acc.HCLocation == 1 && len(locs) > 1 {
		locs = locs[:1]
	}
	if c.Execution != "local" {
		// Limit: Online-Messstellen (Check x Standorte) gegen healthcheck_limit
		var used int
		_ = tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(LENGTH(locations) - LENGTH(REPLACE(locations, ',', '')) + 1), 0) FROM hc2_checks WHERE userid = ? AND deleted_at IS NULL AND execution IN ('online','both') AND token <> ?`, userID, p.ID).Scan(&used)
		if lim := acc.Limits["healthchecks_online"]; lim > 0 && used+len(locs) > lim {
			res.Error = fmt.Sprintf("online limit reached (%d of %d measuring points)", used, lim)
			return nil
		}
		if singleNodeType(c.Type) {
			res.Error = c.Type + " checks run only locally on a node and cannot be moved"
			return nil
		}
		if isPrivateTarget(c.Type, c.Target) || (c.Type == "dns" && checks.DNSNeedsNode(c.Params)) {
			res.Error = "online checks cannot target private addresses"
			return nil
		}
	}
	params := string(c.Params)
	if strings.TrimSpace(params) == "" {
		params = "{}"
	}
	paused := b2i(c.Paused)
	if exists {
		_, err = tx.ExecContext(ctx, `UPDATE hc2_checks SET node_id=?, execution=?, locations=?, policy=?, notify_degraded=?, slot=?, type=?, name=?, target=?, params=?,
			interval_sec=?, retry_interval_sec=?, retries=?, connect_timeout_ms=?, total_timeout_ms=?, invert=?, stabilize=?, ip_mode=?, tags=?, description=?, paused=?,
			parent_token=?, critical=?, notify_down=?, notify_up=?, channels=?, repeat_minutes=?, revision=?, updated_at=?, updated_by=?, deleted_at=NULL, group_name=?, nodes=? WHERE token=?`,
			nodeRef, c.Execution, strings.Join(locs, ","), orDefault(c.Policy, "all"), b2i(c.NotifyDegraded), slotOf(c.Token), c.Type, truncate(c.Name, 200), truncate(c.Target, 500), params,
			c.IntervalSeconds, c.RetryIntervalSeconds, c.Retries, int(c.ConnectTimeoutSeconds*1000), int(c.TimeoutSeconds*1000), b2i(c.Invert), c.Stabilize, orDefault(c.IPMode, "auto"),
			truncate(strings.Join(c.Tags, ","), 255), c.Description, paused, nullStr(c.Parent), b2i(c.Critical), b2i(c.NotifyDown), b2i(c.NotifyUp), joinInts(c.Channels), c.RepeatMinutes,
			rev, nowStr(), origin, truncate(c.Group, 100), strings.Join(nodeList, ","), c.Token)
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO hc2_checks (token, userid, node_id, execution, locations, policy, notify_degraded, slot, type, name, target, params,
			interval_sec, retry_interval_sec, retries, connect_timeout_ms, total_timeout_ms, invert, stabilize, ip_mode, tags, description, paused,
			parent_token, critical, notify_down, notify_up, channels, repeat_minutes, revision, created_at, updated_at, updated_by, group_name, nodes)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?, ?,?,?,?,?,?,?,?,?,?,?, ?,?,?,?,?,?,?,?,?,?,?,?)`,
			c.Token, userID, nodeRef, c.Execution, strings.Join(locs, ","), orDefault(c.Policy, "all"), b2i(c.NotifyDegraded), slotOf(c.Token), c.Type, truncate(c.Name, 200), truncate(c.Target, 500), params,
			c.IntervalSeconds, c.RetryIntervalSeconds, c.Retries, int(c.ConnectTimeoutSeconds*1000), int(c.TimeoutSeconds*1000), b2i(c.Invert), c.Stabilize, orDefault(c.IPMode, "auto"),
			truncate(strings.Join(c.Tags, ","), 255), c.Description, paused,
			nullStr(c.Parent), b2i(c.Critical), b2i(c.NotifyDown), b2i(c.NotifyUp), joinInts(c.Channels), c.RepeatMinutes, rev, nowStr(), nowStr(), origin, truncate(c.Group, 100), strings.Join(nodeList, ","))
	}
	if err != nil {
		return err
	}
	if err := logChange(ctx, tx, userID, nil, "check", c.Token, "upsert", rev, origin); err != nil {
		return err
	}
	res.Revision = rev
	c.Revision, c.Locations = rev, locs
	c.Owner = ownerOf(&c, nodeID)
	res.Data, _ = json.Marshal(c)
	return nil
}

func (s *Store) proposeMaintenance(ctx context.Context, tx *sql.Tx, userID int64, nodeID string, p wire.Propose, origin string, res *wire.ProposeResult) error {
	var id int64
	fmt.Sscan(p.ID, &id)
	var cur int64
	var ownerUser int64
	var updated sql.NullString
	if gone, err := deletedAfterChange(ctx, tx, "hc2_maintenance", id, userID, p); err != nil || gone {
		res.Conflict = gone
		return err
	}
	err := tx.QueryRowContext(ctx, `SELECT revision, userid, updated_at FROM hc2_maintenance WHERE id = ? AND deleted_at IS NULL FOR UPDATE`, id).Scan(&cur, &ownerUser, &updated)
	exists := err == nil
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if exists && ownerUser != userID {
		res.Error = "maintenance belongs to another account"
		return nil
	}
	if exists && p.BaseRevision >= 0 && cur != p.BaseRevision && !p.ChangedAt.After(pt(updated)) {
		res.Conflict, res.Revision = true, cur
		if d, err := s.entityData(ctx, "maintenance", p.ID, nodeID, userID); err == nil {
			res.Server = d
		}
		return nil
	}
	rev, err := nextRevision(ctx, tx, userID)
	if err != nil {
		return err
	}
	if p.Op == "delete" {
		if exists {
			if _, err := tx.ExecContext(ctx, `UPDATE hc2_maintenance SET deleted_at = ?, revision = ?, updated_at = ? WHERE id = ?`, nowStr(), rev, nowStr(), id); err != nil {
				return err
			}
		}
		res.Revision = rev
		return logChange(ctx, tx, userID, nil, "maintenance", p.ID, "delete", rev, origin)
	}
	var m wire.Maintenance
	if err := json.Unmarshal(p.Data, &m); err != nil {
		res.Error = "invalid maintenance: " + err.Error()
		return nil
	}
	if m.Name == "" || !m.EndAt.After(m.StartAt) {
		res.Error = "maintenance needs a name and end after start"
		return nil
	}
	if m.Repeat == "" {
		m.Repeat = "none"
	}
	if exists {
		_, err = tx.ExecContext(ctx, "UPDATE hc2_maintenance SET name=?, start_at=?, end_at=?, `repeat`=?, repeat_until=?, tokens=?, active=?, revision=?, updated_at=? WHERE id=?",
			truncate(m.Name, 200), ft(m.StartAt), ft(m.EndAt), m.Repeat, ft(m.RepeatUntil), strings.Join(m.Tokens, ","), b2i(m.Active), rev, nowStr(), id)
	} else {
		var r sql.Result
		r, err = tx.ExecContext(ctx, "INSERT INTO hc2_maintenance (userid, node_id, name, start_at, end_at, `repeat`, repeat_until, tokens, active, revision, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
			userID, nullStr(nodeID), truncate(m.Name, 200), ft(m.StartAt), ft(m.EndAt), m.Repeat, ft(m.RepeatUntil), strings.Join(m.Tokens, ","), b2i(m.Active), rev, nowStr(), nowStr())
		if err == nil {
			id, _ = r.LastInsertId()
		}
	}
	if err != nil {
		return err
	}
	m.ID, m.Revision, m.NodeID = id, rev, nodeID
	if err := logChange(ctx, tx, userID, nil, "maintenance", fmt.Sprint(id), "upsert", rev, origin); err != nil {
		return err
	}
	res.Revision = rev
	res.Data, _ = json.Marshal(m)
	return nil
}

func (s *Store) proposeChannel(ctx context.Context, tx *sql.Tx, userID int64, nodeID string, p wire.Propose, origin string, res *wire.ProposeResult) error {
	var id int64
	fmt.Sscan(p.ID, &id)
	var cur, ownerUser int64
	var owner, updated sql.NullString
	if gone, err := deletedAfterChange(ctx, tx, "hc2_channels", id, userID, p); err != nil || gone {
		res.Conflict = gone
		return err
	}
	err := tx.QueryRowContext(ctx, `SELECT revision, userid, node_id, updated_at FROM hc2_channels WHERE id = ? AND deleted_at IS NULL FOR UPDATE`, id).Scan(&cur, &ownerUser, &owner, &updated)
	exists := err == nil
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if exists && ownerUser != userID {
		res.Error = "channel belongs to another account"
		return nil
	}
	// Kanal des Portals oder einer anderen Node: jede Node darf ihn aendern und loeschen, die Zugangsdaten
	// (config_enc) und die Besitzer-Node bleiben dabei unveraendert
	foreign := exists && (!owner.Valid || owner.String != nodeID)
	if exists && p.BaseRevision >= 0 && cur != p.BaseRevision && !p.ChangedAt.After(pt(updated)) {
		res.Conflict, res.Revision = true, cur
		if d, err := s.entityData(ctx, "channel", p.ID, nodeID, userID); err == nil {
			res.Server = d
		}
		return nil
	}
	rev, err := nextRevision(ctx, tx, userID)
	if err != nil {
		return err
	}
	if p.Op == "delete" {
		if exists {
			if _, err := tx.ExecContext(ctx, `UPDATE hc2_channels SET deleted_at = ?, revision = ?, updated_at = ? WHERE id = ?`, nowStr(), rev, nowStr(), id); err != nil {
				return err
			}
		}
		res.Revision = rev
		return logChange(ctx, tx, userID, nil, "channel", p.ID, "delete", rev, origin)
	}
	var ch wire.Channel
	if err := json.Unmarshal(p.Data, &ch); err != nil {
		res.Error = "invalid channel: " + err.Error()
		return nil
	}
	if ch.Type == "" || ch.Name == "" {
		res.Error = "channel needs type and name"
		return nil
	}
	// Konfiguration der Node-Kanaele: Geheimnisse mit dem Server-Schluessel ablegen (secret_only_local = 0),
	// damit Sendeauftraege spaeter auch serverseitig verstanden werden; ohne Schluessel nur Typ/Name
	cfg := map[string]string{}
	for k, v := range ch.Config {
		if s.box != nil && v != "" && isSecretField(k) {
			v = s.box.Encrypt(v)
		}
		cfg[k] = v
	}
	cfgJSON, _ := json.Marshal(cfg)
	if ch.Lang == "" {
		ch.Lang = "de"
	}
	if foreign && !owner.Valid && len(ch.Config) > 0 {
		// Kanal des Portals mit geaenderten Werten: einmischen (leere = unveraendert), Geheimnisse verschluesselt;
		// eine neue Adresse/Nummer gilt erst nach Bestaetigung im Portal (wie dort)
		var curCfg string
		var verified int
		if err := tx.QueryRowContext(ctx, `SELECT config_enc, verified FROM hc2_channels WHERE id = ?`, id).Scan(&curCfg, &verified); err != nil {
			return err
		}
		merged := map[string]string{}
		_ = json.Unmarshal([]byte(curCfg), &merged)
		for k, v := range ch.Config {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			switch {
			case ch.Type == "ipv64_mail" && k == "email":
				if a, err := mail.ParseAddress(v); err != nil || a.Address != v {
					res.Error = "email: invalid address"
					return nil
				}
			case ch.Type == "ipv64_sms" && k == "number":
				n, err := notify.SMSNumber(v)
				if err != nil {
					res.Error = "number: " + err.Error()
					return nil
				}
				v = n
			}
			if (k == "email" || k == "number") && !sameAddress(k, merged[k], v) {
				verified = 0
			}
			if isSecretField(k) && s.box != nil {
				v = s.box.Encrypt(v)
			}
			merged[k] = v
		}
		cfgMerged, _ := json.Marshal(merged)
		_, err = tx.ExecContext(ctx, `UPDATE hc2_channels SET name=?, config_enc=?, verified=?, enabled=?, is_default=?, lang=?, notify_down=?, notify_up=?, revision=?, updated_at=? WHERE id=?`,
			truncate(ch.Name, 100), string(cfgMerged), verified, b2i(ch.Enabled), b2i(ch.Default), ch.Lang, b2i(ch.NotifyDown), b2i(ch.NotifyUp), rev, nowStr(), id)
	} else if foreign {
		_, err = tx.ExecContext(ctx, `UPDATE hc2_channels SET name=?, enabled=?, is_default=?, lang=?, notify_down=?, notify_up=?, revision=?, updated_at=? WHERE id=?`,
			truncate(ch.Name, 100), b2i(ch.Enabled), b2i(ch.Default), ch.Lang, b2i(ch.NotifyDown), b2i(ch.NotifyUp), rev, nowStr(), id)
	} else if exists {
		_, err = tx.ExecContext(ctx, `UPDATE hc2_channels SET type=?, name=?, config_enc=?, enabled=?, is_default=?, lang=?, notify_down=?, notify_up=?, revision=?, updated_at=? WHERE id=?`,
			ch.Type, truncate(ch.Name, 100), string(cfgJSON), b2i(ch.Enabled), b2i(ch.Default), ch.Lang, b2i(ch.NotifyDown), b2i(ch.NotifyUp), rev, nowStr(), id)
	} else {
		var r sql.Result
		r, err = tx.ExecContext(ctx, `INSERT INTO hc2_channels (userid, node_id, type, name, config_enc, enabled, is_default, lang, notify_down, notify_up, verified, revision, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,1,?,?,?)`,
			userID, nodeID, ch.Type, truncate(ch.Name, 100), string(cfgJSON), b2i(ch.Enabled), b2i(ch.Default), ch.Lang, b2i(ch.NotifyDown), b2i(ch.NotifyUp), rev, nowStr(), nowStr())
		if err == nil {
			id, _ = r.LastInsertId()
		}
	}
	if err != nil {
		return err
	}
	ch.ID, ch.Revision, ch.NodeID = id, rev, nodeID
	if foreign {
		ch.NodeID, ch.Config = owner.String, nil
	}
	if err := logChange(ctx, tx, userID, nil, "channel", fmt.Sprint(id), "upsert", rev, origin); err != nil {
		return err
	}
	res.Revision = rev
	res.Data, _ = json.Marshal(ch)
	return nil
}

// deletedAfterChange: Wartung/Kanal wurde geloescht, nachdem die Node ihn geaendert hat -> bleibt geloescht
// (Konflikt ohne Server-Fassung, die Node loescht ihre Kopie). Eine juengere Aenderung legt ihn neu an.
func deletedAfterChange(ctx context.Context, tx *sql.Tx, table string, id, userID int64, p wire.Propose) (bool, error) {
	if id <= 0 || p.Op == "delete" || p.BaseRevision <= 0 {
		return false, nil
	}
	var deleted sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT deleted_at FROM `+table+` WHERE id = ? AND userid = ? AND deleted_at IS NOT NULL`, id, userID).Scan(&deleted)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return !p.ChangedAt.After(pt(deleted)), nil
}

func isSecretField(k string) bool {
	switch k {
	case "bot_token", "webhook_url", "token", "password", "app_token", "user_key", "headers", "device_token", "webhook_id":
		return true
	}
	return false
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func validateWireCheck(c *wire.Check) error {
	switch c.Type {
	case "http", "keyword", "json", "dns", "icmp", "tcp", "port", "cert", "push", "docker", "proxmox", "whois":
	default:
		return fmt.Errorf("unknown type %q", c.Type)
	}
	if strings.TrimSpace(c.Name) == "" {
		return errors.New("name is required")
	}
	if c.Type != "push" && strings.TrimSpace(c.Target) == "" {
		return errors.New("target is required")
	}
	if c.Type != "push" {
		minIv := 20 // online und hybrid; nur lokal ab 5 s
		if c.Execution == "" || c.Execution == "local" {
			minIv = 5
		}
		if c.Type == "whois" { // WHOIS/RDAP-Server begrenzen Abfragen
			minIv = max(minIv, int(checks.MinIntervalWhois.Seconds()))
			c.RetryIntervalSeconds = max(c.RetryIntervalSeconds, int(checks.MinRetryWhois.Seconds()))
		}
		if c.IntervalSeconds < minIv {
			c.IntervalSeconds = minIv
		}
		if c.RetryIntervalSeconds < 5 {
			c.RetryIntervalSeconds = 5
		}
		if c.RetryIntervalSeconds > c.IntervalSeconds {
			c.RetryIntervalSeconds = c.IntervalSeconds
		}
	} else if c.IntervalSeconds == 0 {
		c.IntervalSeconds = 60
	}
	if c.ConnectTimeoutSeconds <= 0 {
		c.ConnectTimeoutSeconds = 5
	}
	if c.TimeoutSeconds <= 0 {
		c.TimeoutSeconds = 10
	}
	if c.Execution == "online" || c.Execution == "both" { // gemessen von ipv64: Obergrenzen wie im Checker
		c.ConnectTimeoutSeconds = min(c.ConnectTimeoutSeconds, MaxConnectTimeout.Seconds())
		c.TimeoutSeconds = min(c.TimeoutSeconds, MaxTotalTimeout.Seconds())
	}
	if c.Stabilize <= 0 {
		c.Stabilize = 3
	}
	switch c.Policy {
	case "", "all", "any", "majority":
	default:
		return errors.New("policy must be all, any or majority")
	}
	switch c.Execution {
	case "", "local", "online", "both":
	default:
		return errors.New("execution must be local, online or both")
	}
	return nil
}

// isPrivateTarget: RFC 1918, ULA, Loopback, Link-Local, .local, localhost.
func isPrivateTarget(typ, target string) bool { return checks.IsPrivateTarget(typ, target) }

// ---------------------------------------------------------------- Bootstrap

// Bootstrap uebernimmt die lokale Konfiguration einer frisch verknuepften Node.
func (s *Store) Bootstrap(ctx context.Context, userID int64, nodeID string, in wire.Bootstrap) (*wire.BootstrapResult, error) {
	out := &wire.BootstrapResult{ChannelMap: map[int64]int64{}, MaintMap: map[int64]int64{}}
	for _, ch := range in.Channels {
		localID := ch.LocalID
		if localID == 0 {
			localID = ch.ID
		}
		data, _ := json.Marshal(ch)
		// Bei erneutem Verknuepfen denselben Kanal der Node weiterverwenden (sonst entstehen Dubletten)
		id := "0"
		var existing int64
		if err := s.db.QueryRowContext(ctx, `SELECT id FROM hc2_channels WHERE userid = ? AND node_id = ? AND type = ? AND name = ? AND deleted_at IS NULL ORDER BY id LIMIT 1`,
			userID, nodeID, ch.Type, ch.Name).Scan(&existing); err == nil && existing > 0 {
			id = strconv.FormatInt(existing, 10)
		}
		res, err := s.Propose(ctx, userID, nodeID, wire.Propose{Entity: "channel", Op: "upsert", ID: id, BaseRevision: -1, Data: data}, "node")
		if err != nil {
			return nil, err
		}
		if res.Error != "" {
			s.log.Warn("bootstrap channel skipped", "name", ch.Name, "err", res.Error)
			continue
		}
		var saved wire.Channel
		_ = json.Unmarshal(res.Data, &saved)
		out.ChannelMap[localID] = saved.ID
		out.Channels = append(out.Channels, saved)
	}
	for _, c := range in.Checks {
		token := c.Token
		// Token-Kollision mit einem Check eines anderen Accounts: neuen Token vergeben
		var other int64
		if err := s.db.QueryRowContext(ctx, `SELECT userid FROM hc2_checks WHERE token = ?`, token).Scan(&other); err == nil && other != userID {
			token = newToken()
			out.Renamed = append(out.Renamed, wire.Renamed{OldToken: c.Token, NewToken: token})
		}
		c.Token = token
		c.Execution = "local"
		c.NodeID = nodeID
		mapped := make([]int64, 0, len(c.Channels))
		for _, id := range c.Channels {
			if sid, ok := out.ChannelMap[id]; ok {
				mapped = append(mapped, sid)
			}
		}
		c.Channels = mapped
		data, _ := json.Marshal(c)
		res, err := s.Propose(ctx, userID, nodeID, wire.Propose{Entity: "check", Op: "upsert", ID: token, BaseRevision: -1, Data: data}, "node")
		if err != nil {
			return nil, err
		}
		if res.Error != "" {
			s.log.Warn("bootstrap check skipped", "name", c.Name, "err", res.Error)
			continue
		}
		var saved wire.Check
		_ = json.Unmarshal(res.Data, &saved)
		out.Checks = append(out.Checks, saved)
	}
	for _, m := range in.Maintenance {
		local := m.ID
		m.ID = 0
		data, _ := json.Marshal(m)
		res, err := s.Propose(ctx, userID, nodeID, wire.Propose{Entity: "maintenance", Op: "upsert", ID: "0", BaseRevision: -1, Data: data}, "node")
		if err != nil {
			return nil, err
		}
		if res.Error != "" {
			continue
		}
		var saved wire.Maintenance
		_ = json.Unmarshal(res.Data, &saved)
		out.MaintMap[local] = saved.ID
		out.Maintenance = append(out.Maintenance, saved)
	}
	out.Revision = s.CurrentRevision(ctx, userID)
	return out, nil
}

func newToken() string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	for i := range b {
		b[i] = chars[int(randomCode(1)[0])%len(chars)]
	}
	return string(b)
}

// ---------------------------------------------------------------- Messdaten der Node

// IngestMeasurements schreibt Messpunkte einer Node (idempotent ueber node_seq).
func (s *Store) IngestMeasurements(ctx context.Context, n *Node, batch []wire.Measurement) (*wire.Ack, error) {
	ack := &wire.Ack{AckSeq: n.LastAckSeq}
	if len(batch) == 0 {
		return ack, nil
	}
	source := "node:" + n.ID
	now := time.Now().UTC()
	job := ingestJob{nodeID: n.ID, done: make(chan error, 1)}
	var earliest time.Time
	for _, m := range batch {
		if m.Time.After(now.Add(5 * time.Minute)) {
			ack.Rejected = append(ack.Rejected, m.Seq)
		} else if m.Time.Before(now.AddDate(0, 0, -RawKeepDays)) {
			// aelter als die Rohdaten-Partitionen: nicht speichern, aber bestaetigen
		} else {
			var details any
			if len(m.Details) > 0 {
				if b, err := json.Marshal(m.Details); err == nil {
					details = string(b)
				}
			}
			if earliest.IsZero() || m.Time.Before(earliest) {
				earliest = m.Time.UTC()
			}
			job.rows = append(job.rows, []any{m.Token, source, m.Seq, m.Time.UTC().Format(TimeFormat), b2i(m.Status == "up"), m.LatencyMS, truncate(m.Reason, 64), truncate(m.Message, 500), truncate(m.Family, 4), details, m.Flags, nowStr()})
		}
		if m.Seq > ack.AckSeq {
			ack.AckSeq = m.Seq
		}
	}
	if ack.AckSeq > n.LastAckSeq {
		job.ackSeq = ack.AckSeq
	}
	if len(job.rows) == 0 && job.ackSeq == 0 {
		return ack, nil
	}
	// ueber den Sammel-Schreiber (ingest.go); Ack erst nach dem Schreiben
	select {
	case s.ingest <- job:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case err := <-job.done:
		if err != nil {
			return nil, err
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	n.LastAckSeq = ack.AckSeq
	if hour := now.Truncate(time.Hour); !earliest.IsZero() && earliest.Before(hour) {
		go s.aggregateLate(source, earliest, now)
	}
	return ack, nil
}

// IngestStates uebernimmt Zustaende der Messstelle node:<id> und bewertet den Gesamtzustand neu.
func (s *Store) IngestStates(ctx context.Context, n *Node, items []wire.State) error {
	if len(items) == 0 {
		return nil
	}
	source := "node:" + n.ID
	// eine Abfrage fuer alle: Besitzer, Gesamtzustand und bisheriger Zustand dieser Messstelle
	type prev struct {
		overall, nodes, owner, execution string
		state, last                      sql.NullString
		paused                           int
	}
	tokens := make([]any, 0, len(items)+1)
	tokens = append(tokens, source)
	ph := make([]string, 0, len(items))
	for _, it := range items {
		tokens = append(tokens, it.Token)
		ph = append(ph, "?")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT c.token, c.userid, c.state, c.nodes, COALESCE(c.node_id, ''), c.execution, c.paused, st.state, st.last_status
		FROM hc2_checks c LEFT JOIN hc2_check_states st ON st.token = c.token AND st.source = ?
		WHERE c.token IN (`+strings.Join(ph, ",")+`) AND c.deleted_at IS NULL`, tokens...)
	if err != nil {
		s.Metrics.add(&s.Metrics.DBErrors, 1)
		return err
	}
	known := map[string]prev{}
	for rows.Next() {
		var tok string
		var uid int64
		var p prev
		if err := rows.Scan(&tok, &uid, &p.overall, &p.nodes, &p.owner, &p.execution, &p.paused, &p.state, &p.last); err != nil {
			rows.Close()
			return err
		}
		if uid == n.UserID {
			known[tok] = p
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	// alle Zustaende mit einem Befehl schreiben (ein Abschluss statt einer je Check)
	var vals []string
	var args []any
	var changed []string
	for _, it := range items {
		p, ok := known[it.Token]
		if !ok {
			continue
		}
		vals = append(vals, "(?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
		state := orDefault(it.State, "pending")
		args = append(args, it.Token, source, state, ft(it.Since), ft(it.LastCheckAt), ft(it.NextCheckAt), nullStr(it.LastStatus), it.LatencyMS, nullStr(truncate(it.Reason, 64)), truncate(it.Message, 500),
			smallCount(it.ConsecutiveFail), smallCount(it.ConsecutiveOK), ft(it.DownSince), nowStr())
		// Neubewertung nur, wenn sich an dieser Messstelle etwas geaendert hat oder der Gesamtzustand
		// nicht dazu passt (neuer Check, einzige Messstelle mit anderem Zustand); sonst bleibt alles, wie es ist
		single := p.execution == "local" && len(measuringNodes(splitList(p.nodes), p.owner)) <= 1
		if !p.state.Valid || p.state.String != state || p.last.String != it.LastStatus || p.overall == "pending" ||
			(single && p.paused == 0 && p.overall != state) {
			changed = append(changed, it.Token)
		}
	}
	if len(vals) == 0 {
		return nil
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO hc2_check_states (token, source, state, since, last_check_at, next_check_at, last_status, last_latency_ms, last_reason, last_message, consecutive_fail, consecutive_ok, down_since, updated_at)
		VALUES `+strings.Join(vals, ",")+`
		ON DUPLICATE KEY UPDATE state=VALUES(state), since=VALUES(since), last_check_at=VALUES(last_check_at), next_check_at=VALUES(next_check_at), last_status=VALUES(last_status),
			last_latency_ms=VALUES(last_latency_ms), last_reason=VALUES(last_reason), last_message=VALUES(last_message), consecutive_fail=VALUES(consecutive_fail), consecutive_ok=VALUES(consecutive_ok),
			down_since=VALUES(down_since), updated_at=VALUES(updated_at)`, args...)
	if err != nil {
		s.Metrics.add(&s.Metrics.DBErrors, 1)
		return err
	}
	for _, tok := range changed {
		if err := s.Reverdict(ctx, tok); err != nil {
			s.log.Error("verdict after node state failed", "token", tok, "err", err)
		}
	}
	return nil
}

// IngestEvents speichert Statuswechsel der Node (still; Alarme kommen aus dem Gesamtzustand).
func (s *Store) IngestEvents(ctx context.Context, n *Node, events []wire.Event) (*wire.Ack, error) {
	ack := &wire.Ack{}
	for _, e := range events {
		res, err := s.db.ExecContext(ctx, `INSERT IGNORE INTO hc2_events (event_id, token, userid, source, kind, time, from_state, to_state, reason, message, duration_sec, flaps, flags, incident_id)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)`,
			e.EventID, e.Token, n.UserID, "node:"+n.ID, truncate(e.Kind, 20), ft(e.Time), nullStr(e.From), nullStr(e.To), nullStr(truncate(e.Reason, 64)), truncate(e.Message, 500), e.DurationSec, e.Flaps, e.Flags|FlagSilent)
		if err != nil {
			return nil, err
		}
		if k, _ := res.RowsAffected(); k == 0 {
			ack.Duplicates = append(ack.Duplicates, e.EventID)
		} else {
			ack.Accepted = append(ack.Accepted, e.EventID)
		}
	}
	return ack, nil
}

// IngestDeliveries protokolliert Zustellungen der Node-Kanaele.
func (s *Store) IngestDeliveries(ctx context.Context, n *Node, list []wire.Delivery) error {
	for _, d := range list {
		_, err := s.db.ExecContext(ctx, `INSERT IGNORE INTO hc2_deliveries (event_id, channel_id, userid, node_id, time, kind, ok, error) VALUES (?,?,?,?,?,?,?,?)`,
			d.EventID, d.ChannelID, n.UserID, n.ID, ft(d.Time), truncate(d.Kind, 20), b2i(d.OK), truncate(d.Error, 500))
		if err != nil {
			return err
		}
	}
	return nil
}

// Results liefert die Zustaende der Online-Messstellen fuer die lokale Ansicht der Node.
func (s *Store) Results(ctx context.Context, userID int64) ([]wire.State, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT st.token, st.source, st.state, st.last_status, st.last_latency_ms, st.last_reason, st.last_message, st.since, st.last_check_at, st.next_check_at, st.down_since
		FROM hc2_check_states st JOIN hc2_checks c ON c.token = st.token WHERE c.userid = ? AND c.deleted_at IS NULL AND st.source LIKE 'loc:%'`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []wire.State
	for rows.Next() {
		var st wire.State
		var source string
		var ls, reason, msg, since, last, next, ds sql.NullString
		var lat sql.NullFloat64
		if err := rows.Scan(&st.Token, &source, &st.State, &ls, &lat, &reason, &msg, &since, &last, &next, &ds); err != nil {
			return nil, err
		}
		st.LastStatus, st.LatencyMS, st.Reason, st.Message = ls.String, lat.Float64, reason.String+"", msg.String
		st.Reason = source + "|" + st.Reason // Quelle mitgeben (loc:nbg|ok)
		st.Since, st.LastCheckAt, st.NextCheckAt, st.DownSince = pt(since), pt(last), pt(next), pt(ds)
		out = append(out, st)
	}
	return out, rows.Err()
}

// OverallStates liefert Gesamtzustaende aller Checks eines Accounts (fuer die Node-Anzeige).
func (s *Store) OverallStates(ctx context.Context, userID int64) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT token, state FROM hc2_checks WHERE userid = ? AND deleted_at IS NULL`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var t, st string
		if rows.Scan(&t, &st) == nil {
			out[t] = st
		}
	}
	return out, rows.Err()
}

var _ = scheduler.StatePending

// measuringNodes liefert die messenden Nodes; leer = die Besitzer-Node (alte Checks).
func measuringNodes(list []string, owner string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, id := range list {
		id = strings.TrimSpace(id)
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	if len(out) == 0 && owner != "" {
		out = append(out, owner)
	}
	return out
}

// singleNodeType: der Docker-Socket bzw. die Proxmox-Abfrage gehoert zu einer Besitzer-Node (nicht umhaengbar, nie
// online); weitere messende Nodes nur, wenn die Node sie schickt (Cluster). Push-Checks sind frei zuordenbar.
func singleNodeType(typ string) bool { return typ == "docker" || typ == "proxmox" }

// sameAddress: dieselbe Adresse bzw. Nummer, nur anders geschrieben? Das Portal speichert Nummern als Ziffern
// ("+49 177 …" -> "49177…"), die Node schickt sie normalisiert ("0049177…"); das darf die Bestaetigung nicht
// zuruecksetzen.
func sameAddress(k, old, v string) bool {
	if k == "number" {
		a, err := notify.SMSNumber(old)
		return err == nil && a == v
	}
	return strings.EqualFold(strings.TrimSpace(old), v)
}
