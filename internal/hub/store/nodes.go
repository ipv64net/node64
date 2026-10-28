package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/wire"
)

// Node ist eine verknuepfte Node64-Instanz (hc2_nodes).
type Node struct {
	ID         string // node_id
	UserID     int64
	Name       string
	Location   string
	Version    string
	Timezone   string
	Modules    string
	RemoteMgmt string
	LastSeen   time.Time
	LastAckSeq int64
	Online     bool
	Hub        string
	RevokedAt  time.Time
	ProxyVia   string // Stellvertreter-Node: meldet ueber diese Node (proxy.go)
	Token      *NodeToken
}

// NodeToken ist der gehashte Zugangstoken.
type NodeToken struct {
	ID       int64
	Revoked  bool
	LastUsed time.Time
}

// ErrInvalidToken: Token unbekannt oder widerrufen.
var ErrInvalidToken = errors.New("invalid node token")

// ErrNodeOwned: die node_id ist (nicht getrennt) mit einem anderen Account verknuepft.
var ErrNodeOwned = errors.New("node is linked to another account")

const codeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // ohne 0/O/1/I

func randomCode(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = codeAlphabet[int(b[i])%len(codeAlphabet)]
	}
	return string(b)
}

func randomToken() string {
	b := make([]byte, 30)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return wire.TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
}

func tokenHash(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// LinkStart legt einen Device-Code an (10 Minuten gueltig).
func (s *Store) LinkStart(ctx context.Context, in wire.LinkStart) (*wire.LinkStarted, error) {
	for try := 0; try < 5; try++ {
		code := randomCode(8)
		secret := randomCode(32)
		exp := time.Now().UTC().Add(10 * time.Minute)
		_, err := s.db.ExecContext(ctx, `INSERT INTO hc2_link_codes (code, node_id, node_name, node_version, poll_secret, created_at, expires_at) VALUES (?,?,?,?,?,?,?)`,
			code, in.NodeID, truncate(in.Name, 100), truncate(in.Version, 32), secret, nowStr(), exp.Format(TimeFormat))
		if err != nil {
			if strings.Contains(err.Error(), "Duplicate") {
				continue
			}
			s.Metrics.add(&s.Metrics.DBErrors, 1)
			return nil, err
		}
		return &wire.LinkStarted{Code: code, PollSecret: secret, ExpiresAt: exp, Interval: 5}, nil
	}
	return nil, errors.New("could not allocate code")
}

// LinkPoll prueft, ob der Nutzer den Code im Portal eingeloest hat. Liefert
// (nil, nil) solange nicht; danach Node-Token (einmalig) und Account.
func (s *Store) LinkPoll(ctx context.Context, in wire.LinkPoll) (*wire.Linked, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	var nodeID, name, version, secret string
	var userid sql.NullInt64
	var location, remote, consumed, expires sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT node_id, node_name, node_version, poll_secret, userid, location, remote_mgmt, consumed_at, expires_at FROM hc2_link_codes WHERE code = ? FOR UPDATE`, strings.ToUpper(strings.ReplaceAll(in.Code, "-", ""))).
		Scan(&nodeID, &name, &version, &secret, &userid, &location, &remote, &consumed, &expires)
	if err == sql.ErrNoRows || (err == nil && secret != in.PollSecret) {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}
	if consumed.Valid || pt(expires).Before(time.Now().UTC()) {
		return nil, ErrInvalidToken
	}
	if !userid.Valid {
		return nil, nil // noch nicht eingeloest
	}
	rm := remote.String
	if rm == "" {
		rm = "full"
	}
	loc := location.String
	// node_id kommt von der Node: eine aktive Node eines anderen Accounts darf nicht uebernommen werden
	// (erst dort trennen). Wechselt der Account, gelten alte Tokens nicht mehr.
	var oldUser int64
	var oldRevoked sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT userid, revoked_at FROM hc2_nodes WHERE node_id = ? FOR UPDATE`, nodeID).Scan(&oldUser, &oldRevoked)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	if err == nil && oldUser != userid.Int64 {
		if !oldRevoked.Valid {
			// Code verbrauchen, damit die Node nicht bis zum Ablauf weiter fragt
			if _, err := tx.ExecContext(ctx, `UPDATE hc2_link_codes SET consumed_at = ? WHERE code = ?`, nowStr(), strings.ToUpper(strings.ReplaceAll(in.Code, "-", ""))); err != nil {
				return nil, err
			}
			if err := tx.Commit(); err != nil {
				return nil, err
			}
			return nil, ErrNodeOwned
		}
		if _, err := tx.ExecContext(ctx, `UPDATE hc2_node_tokens SET revoked_at = ? WHERE node_id = ? AND revoked_at IS NULL`, nowStr(), nodeID); err != nil {
			return nil, err
		}
	}
	// Node anlegen oder reaktivieren (gleiche node_id = gleiche Installation)
	if _, err := tx.ExecContext(ctx, `INSERT INTO hc2_nodes (userid, node_id, name, location, version, created_at, remote_mgmt) VALUES (?,?,?,?,?,?,?)
		ON DUPLICATE KEY UPDATE userid = VALUES(userid), name = VALUES(name), location = VALUES(location), version = VALUES(version), remote_mgmt = VALUES(remote_mgmt), revoked_at = NULL, proxy_via = NULL`,
		userid.Int64, nodeID, name, loc, version, nowStr(), rm); err != nil {
		return nil, err
	}
	token := randomToken()
	if _, err := tx.ExecContext(ctx, `INSERT INTO hc2_node_tokens (node_id, token_hash, created_at) VALUES (?,?,?)`, nodeID, tokenHash(token), nowStr()); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE hc2_link_codes SET consumed_at = ? WHERE code = ?`, nowStr(), strings.ToUpper(strings.ReplaceAll(in.Code, "-", ""))); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO hc2_config_log (userid, node_id, entity, entity_id, op, revision, origin, time) VALUES (?,?,'node',?,'upsert',0,'system',?)`, userid.Int64, nil, nodeID, nowStr()); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	acc, _ := s.Account(ctx, userid.Int64)
	eps, _ := s.Endpoints(ctx)
	return &wire.Linked{NodeToken: token, Account: acc, Name: name, Location: loc, RemoteMgmt: rm, Endpoints: eps}, nil
}

// LinkRedeem loest einen Code im Namen des Nutzers ein (fuer das Portal bzw. Tests).
func (s *Store) LinkRedeem(ctx context.Context, code string, userID int64, location, remoteMgmt string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE hc2_link_codes SET userid = ?, location = ?, remote_mgmt = ? WHERE code = ? AND userid IS NULL AND consumed_at IS NULL AND expires_at > ?`,
		userID, truncate(location, 100), remoteMgmt, strings.ToUpper(strings.ReplaceAll(code, "-", "")), nowStr())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("code unknown, expired or already used")
	}
	return nil
}

// NodeByToken authentifiziert einen Node-Token.
func (s *Store) NodeByToken(ctx context.Context, token string) (*Node, error) {
	if !strings.HasPrefix(token, wire.TokenPrefix) {
		return nil, ErrInvalidToken
	}
	var n Node
	var tok NodeToken
	var tokRevoked, nodeRevoked, lastSeen, lastUsed sql.NullString
	var online int
	err := s.db.QueryRowContext(ctx, `SELECT t.id, t.revoked_at, t.last_used, n.node_id, n.userid, n.name, n.location, n.version, n.timezone, n.modules, n.remote_mgmt, n.last_seen, n.last_ack_seq, n.online, n.node, n.revoked_at
		FROM hc2_node_tokens t JOIN hc2_nodes n ON n.node_id = t.node_id WHERE t.token_hash = ?`, tokenHash(token)).
		Scan(&tok.ID, &tokRevoked, &lastUsed, &n.ID, &n.UserID, &n.Name, &n.Location, &n.Version, &n.Timezone, &n.Modules, &n.RemoteMgmt, &lastSeen, &n.LastAckSeq, &online, &n.Hub, &nodeRevoked)
	if err == sql.ErrNoRows {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}
	if tokRevoked.Valid || nodeRevoked.Valid {
		return nil, ErrInvalidToken
	}
	n.LastSeen, n.Online, tok.LastUsed = pt(lastSeen), online == 1, pt(lastUsed)
	n.Token = &tok
	return &n, nil
}

// NodeByID laedt eine Node.
func (s *Store) NodeByID(ctx context.Context, nodeID string) (*Node, error) {
	var n Node
	var lastSeen, revoked sql.NullString
	var online int
	err := s.db.QueryRowContext(ctx, `SELECT node_id, userid, name, location, version, timezone, modules, remote_mgmt, last_seen, last_ack_seq, online, node, revoked_at, COALESCE(proxy_via, '') FROM hc2_nodes WHERE node_id = ?`, nodeID).
		Scan(&n.ID, &n.UserID, &n.Name, &n.Location, &n.Version, &n.Timezone, &n.Modules, &n.RemoteMgmt, &lastSeen, &n.LastAckSeq, &online, &n.Hub, &revoked, &n.ProxyVia)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	n.LastSeen, n.Online, n.RevokedAt = pt(lastSeen), online == 1, pt(revoked)
	return &n, nil
}

// NodeSeen setzt online/last_seen/hub (bei Verbindungsaufbau und Pong).
func (s *Store) NodeSeen(ctx context.Context, nodeID string, tokenID int64) error {
	now := nowStr()
	if _, err := s.db.ExecContext(ctx, `UPDATE hc2_nodes SET last_seen = ?, online = 1, node = ? WHERE node_id = ?`, now, s.node, nodeID); err != nil {
		return err
	}
	if tokenID > 0 {
		_, _ = s.db.ExecContext(ctx, `UPDATE hc2_node_tokens SET last_used = ? WHERE id = ?`, now, tokenID)
	}
	s.setNodeOnline(nodeID, true)
	return nil
}

// NodeGone markiert eine Node offline, aber nur, wenn sie zuletzt an diesem hub hing
// (sonst hat sie sich inzwischen woanders verbunden).
func (s *Store) NodeGone(ctx context.Context, nodeID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE hc2_nodes SET online = 0 WHERE node_id = ? AND node = ?`, nodeID, s.node)
	s.setNodeOnline(nodeID, false)
	return err
}

// NodeStatus uebernimmt die periodische Statusmeldung.
func (s *Store) NodeStatus(ctx context.Context, nodeID string, st wire.Status) error {
	_, err := s.db.ExecContext(ctx, `UPDATE hc2_nodes SET version = ?, modules = ?, timezone = ?, outbox_size = ?, conflicts = ?, last_sync = ? WHERE node_id = ?`,
		truncate(st.Version, 32), truncate(strings.Join(st.Modules, ","), 255), truncate(st.Timezone, 64), st.OutboxSize, st.Conflicts, nowStr(), nodeID)
	return err
}

// RenameNode uebernimmt Name und Standort, die an der Node geaendert wurden, und vermerkt die Aenderung
// fuer alle Nodes des Accounts (deren Liste der Messstellen zeigt den neuen Namen).
func (s *Store) RenameNode(ctx context.Context, userID int64, nodeID, name, location string) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE hc2_nodes SET name = ?, location = ? WHERE node_id = ? AND userid = ?`, truncate(name, 100), truncate(location, 100), nodeID, userID); err != nil {
		return 0, err
	}
	rev, err := nextRevision(ctx, tx, userID)
	if err != nil {
		return 0, err
	}
	if err := logChange(ctx, tx, userID, nil, "node", nodeID, "upsert", rev, "node"); err != nil {
		return 0, err
	}
	return rev, tx.Commit()
}

// AccountSettings liefert die Benachrichtigungs-Einstellungen eines Accounts (hc2_settings).
func (s *Store) AccountSettings(ctx context.Context, userID int64) (map[string]string, error) {
	out := map[string]string{}
	rows, err := s.db.QueryContext(ctx, "SELECT `key`, `value` FROM hc2_settings WHERE userid = ?", userID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if rows.Scan(&k, &v) == nil {
			out[k] = v
		}
	}
	return out, rows.Err()
}

// SetAccountSettings speichert Benachrichtigungs-Einstellungen eines Accounts (von einer Node) und meldet
// die Aenderung allen Nodes.
func (s *Store) SetAccountSettings(ctx context.Context, userID int64, kv map[string]string) (int64, error) {
	// nur tatsaechliche Aenderungen speichern und melden (keine Rundlaeufe zwischen den Nodes)
	cur, err := s.AccountSettings(ctx, userID)
	if err != nil {
		return 0, err
	}
	for k, v := range kv {
		if old, ok := cur[k]; ok && old == v {
			delete(kv, k)
		}
	}
	if len(kv) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	for k, v := range kv {
		if _, err := tx.ExecContext(ctx, "INSERT INTO hc2_settings (userid, `key`, `value`) VALUES (?,?,?) ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)", userID, k, truncate(v, 500)); err != nil {
			return 0, err
		}
	}
	rev, err := nextRevision(ctx, tx, userID)
	if err != nil {
		return 0, err
	}
	if err := logChange(ctx, tx, userID, nil, "settings", "notify", "upsert", rev, "node"); err != nil {
		return 0, err
	}
	return rev, tx.Commit()
}

// StaleNodes markiert Nodes offline, deren last_seen aelter als 3 Minuten ist
// (hub abgestuerzt o. ae.). Liefert die betroffenen IDs.
func (s *Store) StaleNodes(ctx context.Context) ([]string, error) {
	cut := time.Now().UTC().Add(-3 * time.Minute).Format(TimeFormat)
	rows, err := s.db.QueryContext(ctx, `SELECT node_id FROM hc2_nodes WHERE online = 1 AND (last_seen IS NULL OR last_seen < ?)`, cut)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		_, _ = s.db.ExecContext(ctx, `UPDATE hc2_nodes SET online = 0 WHERE node_id = ?`, id)
		s.setNodeOnline(id, false)
	}
	return ids, nil
}

// Unlink widerruft alle Tokens; Checks bleiben (online) oder werden geloescht.
func (s *Store) Unlink(ctx context.Context, n *Node, keepChecks bool) error {
	now := nowStr()
	if _, err := s.db.ExecContext(ctx, `UPDATE hc2_node_tokens SET revoked_at = ? WHERE node_id = ? AND revoked_at IS NULL`, now, n.ID); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE hc2_nodes SET revoked_at = ?, online = 0 WHERE node_id = ?`, now, n.ID); err != nil {
		return err
	}
	// Checks mit mehreren messenden Nodes: diese Node austragen; war sie Besitzer, uebernimmt die naechste
	if rows, err := s.db.QueryContext(ctx, `SELECT token FROM hc2_checks WHERE userid = ? AND deleted_at IS NULL AND execution IN ('local','both') AND FIND_IN_SET(?, nodes) > 0`, n.UserID, n.ID); err == nil {
		var tokens []string
		for rows.Next() {
			var t string
			if rows.Scan(&t) == nil {
				tokens = append(tokens, t)
			}
		}
		rows.Close()
		for _, t := range tokens {
			c, _, err := s.WireCheck(ctx, t)
			if err != nil || c == nil {
				continue
			}
			var rest []string
			for _, id := range c.Nodes {
				if id != n.ID {
					rest = append(rest, id)
				}
			}
			if len(rest) == 0 {
				continue // nur diese Node: wie bisher (online weiter oder loeschen)
			}
			c.Nodes = rest
			if c.NodeID == n.ID {
				c.NodeID = rest[0]
			}
			data, _ := json.Marshal(c)
			if res, err := s.Propose(ctx, n.UserID, "", wire.Propose{Entity: "check", Op: "upsert", ID: t, BaseRevision: -1, Data: data}, "system"); err != nil {
				return err
			} else if res.Error != "" {
				s.log.Info("unlink: node not removed from check", "token", t, "reason", res.Error)
			}
		}
	}
	if keepChecks {
		// Weiterlaufen lassen als Online-Checks, soweit Ziel oeffentlich und Limit frei; sonst loeschen.
		// Ueber Propose, damit Limit, Log und andere Nodes des Accounts stimmen.
		rows, err := s.db.QueryContext(ctx, `SELECT token FROM hc2_checks WHERE node_id = ? AND deleted_at IS NULL AND execution IN ('local','both')`, n.ID)
		if err != nil {
			return err
		}
		var tokens []string
		for rows.Next() {
			var t string
			if rows.Scan(&t) == nil {
				tokens = append(tokens, t)
			}
		}
		rows.Close()
		for _, t := range tokens {
			c, _, err := s.WireCheck(ctx, t)
			if err != nil || c == nil {
				continue
			}
			c.Execution, c.NodeID = "online", ""
			data, _ := json.Marshal(c)
			res, err := s.Propose(ctx, n.UserID, "", wire.Propose{Entity: "check", Op: "upsert", ID: t, BaseRevision: -1, Data: data}, "system")
			if err != nil {
				return err
			}
			if res.Error != "" {
				s.log.Info("unlink: check not kept online", "token", t, "reason", res.Error)
				if _, err := s.Propose(ctx, n.UserID, n.ID, wire.Propose{Entity: "check", Op: "delete", ID: t, BaseRevision: -1}, "system"); err != nil {
					return err
				}
			}
		}
		return nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT token FROM hc2_checks WHERE node_id = ? AND deleted_at IS NULL AND execution = 'local'`, n.ID)
	if err != nil {
		return err
	}
	var tokens []string
	for rows.Next() {
		var t string
		if rows.Scan(&t) == nil {
			tokens = append(tokens, t)
		}
	}
	rows.Close()
	for _, t := range tokens {
		if _, err := s.Propose(ctx, n.UserID, n.ID, wire.Propose{Entity: "check", Op: "delete", ID: t, BaseRevision: -1}, "system"); err != nil {
			return err
		}
	}
	return nil
}

// Account liefert Klasse und Limits fuer hello.
func (s *Store) Account(ctx context.Context, userID int64) (wire.Account, error) {
	var a wire.Account
	var class, limit, hcloc, sms, daily int
	err := s.db.QueryRowContext(ctx, `SELECT v.user_class, v.healthcheck_limit, v.hc_locations, v.sms_limit, c.healthcheck_update_limit FROM ipv64.hc2_users_v v
		JOIN ipv64.user_class c ON c.id = v.user_class WHERE v.id = ?`, userID).Scan(&class, &limit, &hcloc, &sms, &daily)
	if err != nil {
		return a, err
	}
	a.ID, a.HCLocation = userID, hcloc
	a.Plan = map[int]string{1: "Standard", 2: "VIP", 3: "Premium", 4: "Business", 5: "Company", 6: "Supporter"}[class]
	a.Limits = map[string]int{"healthchecks_online": limit, "locations": hcloc, "sms_per_day": sms, "checks_per_day": daily}
	var smsToday int
	_ = s.db.QueryRowContext(ctx, `SELECT count FROM hc2_sms_counter WHERE userid = ? AND day = ?`, userID, time.Now().UTC().Format("2006-01-02")).Scan(&smsToday)
	var checksToday int
	_ = s.db.QueryRowContext(ctx, `SELECT checks FROM hc2_usage_daily WHERE userid = ? AND day = ?`, userID, usageDay(time.Now())).Scan(&checksToday)
	if mem, _, _ := s.DailyUsage(userID); mem > checksToday {
		checksToday = mem
	}
	a.Usage = map[string]int{"sms_today": smsToday, "checks_today": checksToday}
	return a, nil
}

// Endpoints liefert die aktiven hub-Standorte.
func (s *Store) Endpoints(ctx context.Context) ([]wire.Endpoint, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT code, name, endpoint FROM hc2_locations WHERE enabled = 1 ORDER BY code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []wire.Endpoint
	for rows.Next() {
		var e wire.Endpoint
		if err := rows.Scan(&e.Location, &e.Name, &e.URL); err != nil {
			return nil, err
		}
		if !strings.HasPrefix(e.URL, "http") {
			e.URL = "https://" + e.URL
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---- Online-Cache fuer die Frische im Verdict

func (s *Store) setNodeOnline(id string, on bool) {
	s.mu.Lock()
	if s.nodeOnline == nil {
		s.nodeOnline = map[string]onlineState{}
	}
	s.nodeOnline[id] = onlineState{on: on, at: time.Now()}
	s.mu.Unlock()
}

type onlineState struct {
	on bool
	at time.Time
}

// NodeIsOnline fragt den Cache (30 s), sonst die Datenbank.
func (s *Store) NodeIsOnline(ctx context.Context, id string) bool {
	s.mu.RLock()
	st, ok := s.nodeOnline[id]
	s.mu.RUnlock()
	if ok && time.Since(st.at) < 30*time.Second {
		return st.on
	}
	var online int
	var lastSeen sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT online, last_seen FROM hc2_nodes WHERE node_id = ?`, id).Scan(&online, &lastSeen); err != nil {
		return false
	}
	on := online == 1 && time.Since(pt(lastSeen)) < 3*time.Minute
	s.setNodeOnline(id, on)
	return on
}

// AccountNode ist eine Node des Accounts (Auswahl der messenden Nodes).
type AccountNode struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Location string `json:"location"`
	Online   bool   `json:"online"`
	Via      string `json:"via,omitempty"` // Stellvertreter-Node: meldet ueber diese Node
}

// AccountNodes liefert die verknuepften Nodes eines Accounts (mit den Stellvertreter-Nodes).
func (s *Store) AccountNodes(ctx context.Context, userID int64) ([]AccountNode, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id, name, location, online, COALESCE(proxy_via, '') FROM hc2_nodes WHERE userid = ? AND revoked_at IS NULL ORDER BY name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AccountNode{}
	for rows.Next() {
		var a AccountNode
		var online int
		if rows.Scan(&a.ID, &a.Name, &a.Location, &online, &a.Via) == nil {
			a.Online = online == 1
			out = append(out, a)
		}
	}
	return out, rows.Err()
}
