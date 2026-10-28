// Package hubnotify verbindet den Benachrichtigungs-Dispatcher des Nodes
// (internal/notify) mit MySQL (hc2_channels, hc2_deliveries, hc2_settings)
// und liefert die Server-Sender ipv64_mail, ipv64_sms und app ueber die
// PHP-Bruecke des Portals.
package hubnotify

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/secrets"
)

const timeFormat = "2006-01-02 15:04:05.000"

// Store ist notify.ChannelStore ueber MySQL.
type Store struct {
	db  *sql.DB
	box *secrets.Box
	log *slog.Logger

	mu       sync.RWMutex
	owner    map[int64]int64  // channel id -> userid (fuer Deliveries)
	nodeOf   map[int64]string // channel id -> node_id bei Node-Kanaelen
	cache    map[int64]cached
	setmu    sync.Mutex
	setcache map[int64]cachedSettings
}

type cached struct {
	at   time.Time
	list []*notify.Channel
}

type cachedSettings struct {
	at time.Time
	kv map[string]string
}

// New erzeugt den Store. box entschluesselt Kanal-Geheimnisse (secret.key wie auf dem Web-Server).
func New(db *sql.DB, box *secrets.Box, log *slog.Logger) *Store {
	return &Store{db: db, box: box, log: log.With("module", "hubnotify"), owner: map[int64]int64{}, nodeOf: map[int64]string{}, cache: map[int64]cached{}, setcache: map[int64]cachedSettings{}}
}

// ChannelsFor liefert die aktiven Kanaele eines Accounts: Server-Kanaele sendet
// der hub selbst, Node-Kanaele (node_id gesetzt) werden als Sendeauftrag an die
// Node gegeben (Execution "node").
func (s *Store) ChannelsFor(ctx context.Context, userID int64) ([]*notify.Channel, error) {
	s.mu.RLock()
	c, ok := s.cache[userID]
	s.mu.RUnlock()
	if ok && time.Since(c.at) < 30*time.Second {
		return c.list, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, type, name, config_enc, enabled, is_default, lang, notify_down, notify_up, verified, revision, node_id
		FROM hc2_channels WHERE userid = ? AND deleted_at IS NULL ORDER BY name, id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*notify.Channel
	for rows.Next() {
		var ch notify.Channel
		var typ, cfg string
		var enabled, def, nd, nu, verified int
		var nodeID sql.NullString
		if err := rows.Scan(&ch.ID, &typ, &ch.Name, &cfg, &enabled, &def, &ch.Lang, &nd, &nu, &verified, &ch.Revision, &nodeID); err != nil {
			return nil, err
		}
		ch.UserID, ch.Type = userID, notify.Type(typ)
		ch.Enabled, ch.Default, ch.NotifyDown, ch.NotifyUp = enabled == 1 && verified == 1, def == 1, nd == 1, nu == 1
		ch.Execution = "server"
		if nodeID.Valid && nodeID.String != "" {
			ch.Execution, ch.NodeID = "node", nodeID.String
			s.mu.Lock()
			s.nodeOf[ch.ID] = nodeID.String
			s.mu.Unlock()
			cfg = "" // Geheimnisse der Node bleiben bei der Node
		}
		m := map[string]string{}
		if cfg != "" {
			if err := json.Unmarshal([]byte(cfg), &m); err != nil {
				s.log.Warn("channel config invalid", "channel", ch.ID, "err", err)
				continue
			}
		}
		for k, v := range m {
			if secrets.IsEncrypted(v) {
				if s.box == nil {
					s.log.Warn("channel secret but no key", "channel", ch.ID, "field", k)
					m[k] = ""
					continue
				}
				plain, err := s.box.Decrypt(v)
				if err != nil {
					s.log.Warn("channel secret undecryptable (key mismatch?)", "channel", ch.ID, "field", k)
					plain = ""
				}
				m[k] = plain
			}
		}
		ch.Config = m
		if ch.Lang == "" {
			ch.Lang = "de"
		}
		list = append(list, &ch)
		s.mu.Lock()
		s.owner[ch.ID] = userID
		s.mu.Unlock()
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.cache[userID] = cached{at: time.Now(), list: list}
	s.mu.Unlock()
	return list, nil
}

// NodeOfChannel liefert die Besitzer-Node eines Node-Kanals.
func (s *Store) NodeOfChannel(id int64) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nodeOf[id]
}

// AddSendOrder legt einen Sendeauftrag fuer einen Node-Kanal an.
func (s *Store) AddSendOrder(ctx context.Context, nodeID string, ch *notify.Channel, m notify.Message) error {
	payload, _ := json.Marshal(map[string]any{"title": m.Title, "text": m.Text, "url": m.URL, "priority": m.Priority, "kind": m.Kind, "language": m.Language,
		"check": m.Check, "payload": m.Payload, "time": m.Time.UTC().Format(time.RFC3339)})
	_, err := s.db.ExecContext(ctx, `INSERT INTO hc2_send_orders (node_id, channel_id, event_id, kind, payload, created_at) VALUES (?,?,?,?,?,?)`,
		nodeID, ch.ID, m.EventID, string(m.Kind), string(payload), time.Now().UTC().Format(timeFormat))
	return err
}

// Invalidate verwirft den Cache eines Accounts (nach Config-Log-Aenderung).
func (s *Store) Invalidate(userID int64) {
	s.mu.Lock()
	delete(s.cache, userID)
	s.mu.Unlock()
	s.setmu.Lock()
	delete(s.setcache, userID)
	s.setmu.Unlock()
}

// AddDelivery protokolliert eine Zustellung (Dedup ueber event_id + channel_id).
func (s *Store) AddDelivery(ctx context.Context, d notify.Delivery) error {
	s.mu.RLock()
	uid := s.owner[d.ChannelID]
	s.mu.RUnlock()
	ok := 0
	if d.OK {
		ok = 1
	}
	_, err := s.db.ExecContext(ctx, `INSERT IGNORE INTO hc2_deliveries (event_id, channel_id, userid, node_id, time, kind, ok, error) VALUES (?,?,?,'',?,?,?,?)`,
		d.EventID, d.ChannelID, uid, time.Now().UTC().Format(timeFormat), d.Kind, ok, truncate(d.Error, 500))
	return err
}

// Touch merkt letzte Nutzung und letzten Fehler am Kanal.
func (s *Store) Touch(ctx context.Context, id int64, errText string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE hc2_channels SET last_used = ?, last_error = ? WHERE id = ?`, time.Now().UTC().Format(timeFormat), truncate(errText, 500), id)
	return err
}

// SettingsFor liest hc2_settings eines Accounts (Cache 60 s) mit Server-Vorgaben.
func (s *Store) SettingsFor(userID int64) notify.Settings {
	return func(key, def string) string {
		kv := s.settings(userID)
		if v, ok := kv[key]; ok && (v != "" || key == notify.SetQuietDays) {
			return v // leere Tagesauswahl = keine Ruhezeit (wie auf der Node)
		}
		switch key {
		case notify.SetNodeName:
			return "ipv64.net Healthchecks"
		case notify.SetBaseURL:
			return "https://ipv64.net/healthchecks2"
		case notify.SetNodeTimezone:
			return "Europe/Berlin"
		}
		return def
	}
}

func (s *Store) settings(userID int64) map[string]string {
	s.setmu.Lock()
	c, ok := s.setcache[userID]
	s.setmu.Unlock()
	if ok && time.Since(c.at) < time.Minute {
		return c.kv
	}
	kv := map[string]string{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, "SELECT `key`, `value` FROM hc2_settings WHERE userid = ?", userID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var k, v string
			if rows.Scan(&k, &v) == nil {
				kv[k] = v
			}
		}
	}
	s.setmu.Lock()
	s.setcache[userID] = cachedSettings{at: time.Now(), kv: kv}
	s.setmu.Unlock()
	return kv
}

// SMSAllowed prueft das Tageslimit (user_class.sms_limit, 0 = unbegrenzt) und zaehlt hoch.
func (s *Store) SMSAllowed(ctx context.Context, userID int64) (bool, error) {
	var limit int
	if err := s.db.QueryRowContext(ctx, `SELECT sms_limit FROM ipv64.hc2_users_v WHERE id = ?`, userID).Scan(&limit); err != nil {
		return false, err
	}
	day := time.Now().UTC().Format("2006-01-02")
	var count int
	_ = s.db.QueryRowContext(ctx, `SELECT count FROM hc2_sms_counter WHERE userid = ? AND day = ?`, userID, day).Scan(&count)
	if limit > 0 && count >= limit {
		return false, nil
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO hc2_sms_counter (userid, day, count) VALUES (?,?,1) ON DUPLICATE KEY UPDATE count = count + 1`, userID, day)
	return err == nil, err
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// Describe liefert eine Kurzform fuer Logs.
func Describe(ch *notify.Channel) string {
	return fmt.Sprintf("%d/%s/%s", ch.ID, ch.Type, strings.TrimSpace(ch.Name))
}
