package notify

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"time"

	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Migrations liefert das Schema (Scope "notify", laeuft im Kern beim Start).
func Migrations() ([]store.Migration, error) { return store.ReadMigrations(migrationFS, "migrations") }

// Store ist die Datenhaltung der Kanaele und des Zustellprotokolls.
type Store struct {
	w, r *sql.DB
	box  *secrets.Box
	// cluster meldet Aenderungen an Kanaelen, die ueber den Cluster gehen (cluster.go); nil = kein Cluster
	cluster func(ctx context.Context, uid string, deleted bool)
}

func NewStore(core *store.Store, box *secrets.Box) *Store {
	return &Store{w: core.Writer(), r: core.Reader(), box: box}
}

const channelCols = `id, type, name, config, enabled, is_default, lang, notify_down, notify_up, secret_only_local, execution, revision, created_at, updated_at, last_used_at, last_error, remote_id, uid`

func (s *Store) scan(row interface{ Scan(...any) error }) (*Channel, error) {
	var c Channel
	var cfg, created, updated, used string
	var enabled, def, nd, nu, sol int
	if err := row.Scan(&c.ID, &c.Type, &c.Name, &cfg, &enabled, &def, &c.Lang, &nd, &nu, &sol, &c.Execution, &c.Revision, &created, &updated, &used, &c.LastError, &c.RemoteID, &c.UID); err != nil {
		return nil, err
	}
	c.Enabled, c.Default, c.NotifyDown, c.NotifyUp, c.SecretOnlyLocal = enabled == 1, def == 1, nd == 1, nu == 1, sol == 1
	c.CreatedAt, c.UpdatedAt, c.LastUsedAt = store.ParseTime(created), store.ParseTime(updated), store.ParseTime(used)
	m, err := decodeConfig(s.box, cfg)
	if err != nil {
		// Konfiguration bleibt sichtbar, Geheimnisse fehlen; der Fehler steht am Kanal
		c.LastError = "config: " + err.Error()
		m = map[string]string{}
		c.cfgErr = true
	}
	c.Config = m
	return &c, nil
}

// Channels liefert alle Kanaele sortiert nach Name.
// ChannelsFor (ChannelStore): im Node gibt es nur einen Account.
func (s *Store) ChannelsFor(ctx context.Context, _ int64) ([]*Channel, error) { return s.Channels(ctx) }

func (s *Store) Channels(ctx context.Context) ([]*Channel, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT `+channelCols+` FROM nf_channels ORDER BY name COLLATE NOCASE, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Channel
	for rows.Next() {
		c, err := s.scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Channel liefert einen Kanal oder nil.
func (s *Store) Channel(ctx context.Context, id int64) (*Channel, error) {
	c, err := s.scan(s.r.QueryRowContext(ctx, `SELECT `+channelCols+` FROM nf_channels WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return c, err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// OnChange (Sync): nach lokalen Aenderungen an Kanaelen; nil = standalone.
var OnChange func(ctx context.Context, id int64, op string)

type remoteKey struct{}

// WithRemote markiert Aenderungen, die vom Server kommen (kein Outbox-Eintrag).
func WithRemote(ctx context.Context) context.Context {
	return context.WithValue(ctx, remoteKey{}, true)
}

func changed(ctx context.Context, id int64, op string) {
	if OnChange != nil {
		if v, _ := ctx.Value(remoteKey{}).(bool); !v {
			OnChange(ctx, id, op)
		}
	}
}

// ByRemote findet einen Kanal ueber seine Server-ID.
func (s *Store) ByRemote(ctx context.Context, remoteID int64) (*Channel, error) {
	c, err := s.scan(s.r.QueryRowContext(ctx, `SELECT `+channelCols+` FROM nf_channels WHERE remote_id = ?`, remoteID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return c, err
}

// SetRemote setzt Server-ID und Revision (ohne Hook).
func (s *Store) SetRemote(ctx context.Context, id, remoteID, revision int64) error {
	_, err := s.w.ExecContext(ctx, `UPDATE nf_channels SET remote_id = ?, revision = ? WHERE id = ?`, remoteID, revision, id)
	return err
}

func (s *Store) Insert(ctx context.Context, c *Channel) error {
	cfg, err := encodeConfig(s.box, c.Type, c.Config)
	if err != nil {
		return err
	}
	now := store.Now()
	if c.UID == "" { // neu hier: eigene Kennung (aus dem Cluster: die der anderen Node)
		c.UID = newClusterUID()
	}
	res, err := s.w.ExecContext(ctx, `INSERT INTO nf_channels (type, name, config, enabled, is_default, lang, notify_down, notify_up, secret_only_local, execution, created_at, updated_at, remote_id, revision, uid)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, string(c.Type), c.Name, cfg, b2i(c.Enabled), b2i(c.Default), c.Lang, b2i(c.NotifyDown), b2i(c.NotifyUp), b2i(c.SecretOnlyLocal), c.Execution, now, now, c.RemoteID, max(c.Revision, 1), c.UID)
	if err != nil {
		return err
	}
	c.ID, _ = res.LastInsertId()
	changed(ctx, c.ID, "upsert")
	s.clusterChanged(ctx, nil, c)
	return nil
}

func (s *Store) Update(ctx context.Context, c *Channel) error {
	cfg, err := encodeConfig(s.box, c.Type, c.Config)
	if err != nil {
		return err
	}
	var old *Channel
	if s.cluster != nil {
		old, _ = s.Channel(ctx, c.ID)
	}
	_, err = s.w.ExecContext(ctx, `UPDATE nf_channels SET type=?, name=?, config=?, enabled=?, is_default=?, lang=?, notify_down=?, notify_up=?, secret_only_local=?, revision=CASE WHEN ?>0 THEN ? ELSE revision+1 END, updated_at=? WHERE id=?`,
		string(c.Type), c.Name, cfg, b2i(c.Enabled), b2i(c.Default), c.Lang, b2i(c.NotifyDown), b2i(c.NotifyUp), b2i(c.SecretOnlyLocal), c.Revision, c.Revision, store.Now(), c.ID)
	if err == nil {
		changed(ctx, c.ID, "upsert")
		if old != nil {
			c.UID = old.UID
			s.clusterChanged(ctx, old, c)
		}
	}
	return err
}

func (s *Store) Delete(ctx context.Context, id int64) error {
	var rid int64
	_ = s.w.QueryRowContext(ctx, `SELECT remote_id FROM nf_channels WHERE id = ?`, id).Scan(&rid)
	var old *Channel
	if s.cluster != nil {
		old, _ = s.Channel(ctx, id)
	}
	_, err := s.w.ExecContext(ctx, `DELETE FROM nf_channels WHERE id = ?`, id)
	if err == nil {
		changed(context.WithValue(ctx, deletedRemoteKey{}, rid), id, "delete")
		s.clusterChanged(ctx, old, nil)
	}
	return err
}

type deletedRemoteKey struct{}

// DeletedRemoteID liefert im "delete"-Hook die Server-ID des geloeschten Kanals (0 = nie synchronisiert).
func DeletedRemoteID(ctx context.Context) int64 {
	v, _ := ctx.Value(deletedRemoteKey{}).(int64)
	return v
}

// Touch merkt den letzten Versand und Fehler am Kanal.
func (s *Store) Touch(ctx context.Context, id int64, errText string) error {
	_, err := s.w.ExecContext(ctx, `UPDATE nf_channels SET last_used_at = ?, last_error = ? WHERE id = ?`, store.Now(), errText, id)
	return err
}

// Delivery ist ein Eintrag des Zustellprotokolls.
type Delivery struct {
	ID         int64
	Time       time.Time
	EventID    string
	ChannelID  int64
	Channel    string
	Kind       string
	CheckToken string
	Subject    string
	OK         bool
	Error      string
}

func (s *Store) AddDelivery(ctx context.Context, d Delivery) error {
	_, err := s.w.ExecContext(ctx, `INSERT INTO nf_deliveries (time, event_id, channel_id, channel, kind, check_token, subject, ok, error) VALUES (?,?,?,?,?,?,?,?,?)`,
		store.Now(), d.EventID, d.ChannelID, d.Channel, d.Kind, d.CheckToken, d.Subject, b2i(d.OK), d.Error)
	return err
}

// Deliveries liefert das Protokoll, neueste zuerst. channelID 0 = alle.
func (s *Store) Deliveries(ctx context.Context, limit int, before int64, channelID int64) ([]Delivery, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	q := `SELECT id, time, event_id, channel_id, channel, kind, check_token, subject, ok, error FROM nf_deliveries WHERE 1=1`
	args := []any{}
	if channelID > 0 {
		q += ` AND channel_id = ?`
		args = append(args, channelID)
	}
	if before > 0 {
		q += ` AND id < ?`
		args = append(args, before)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Delivery
	for rows.Next() {
		var d Delivery
		var t string
		var ok int
		if err := rows.Scan(&d.ID, &t, &d.EventID, &d.ChannelID, &d.Channel, &d.Kind, &d.CheckToken, &d.Subject, &ok, &d.Error); err != nil {
			return nil, err
		}
		d.Time, d.OK = store.ParseTime(t), ok == 1
		out = append(out, d)
	}
	return out, rows.Err()
}

// PruneDeliveries entfernt Eintraege aelter als keep.
func (s *Store) PruneDeliveries(ctx context.Context, keep time.Duration) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM nf_deliveries WHERE time < ?`, store.FormatTime(time.Now().Add(-keep)))
	return err
}

// SaveHeld speichert die in der Ruhezeit zurueckgehaltenen Alerts eines Accounts (leer = entfernen).
func (s *Store) SaveHeld(ctx context.Context, userID int64, list []Alert) error {
	if len(list) == 0 {
		_, err := s.w.ExecContext(ctx, `DELETE FROM nf_held WHERE user_id = ?`, userID)
		return err
	}
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	_, err = s.w.ExecContext(ctx, `INSERT INTO nf_held (user_id, alerts, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET alerts = excluded.alerts, updated_at = excluded.updated_at`, userID, string(b), store.Now())
	return err
}

// LoadHeld liefert die gespeicherten zurueckgehaltenen Alerts je Account (nach einem Neustart).
func (s *Store) LoadHeld(ctx context.Context) (map[int64][]Alert, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT user_id, alerts FROM nf_held`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]Alert{}
	for rows.Next() {
		var uid int64
		var raw string
		if err := rows.Scan(&uid, &raw); err != nil {
			return nil, err
		}
		var list []Alert
		if err := json.Unmarshal([]byte(raw), &list); err != nil {
			continue // kaputter Eintrag: nicht den Start blockieren
		}
		out[uid] = list
	}
	return out, rows.Err()
}
