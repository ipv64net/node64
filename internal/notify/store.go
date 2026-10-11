package notify

import (
	"context"
	"database/sql"
	"embed"
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
}

func NewStore(core *store.Store, box *secrets.Box) *Store {
	return &Store{w: core.Writer(), r: core.Reader(), box: box}
}

const channelCols = `id, type, name, config, enabled, is_default, lang, notify_down, notify_up, secret_only_local, execution, revision, created_at, updated_at, last_used_at, last_error, remote_id`

func (s *Store) scan(row interface{ Scan(...any) error }) (*Channel, error) {
	var c Channel
	var cfg, created, updated, used string
	var enabled, def, nd, nu, sol int
	if err := row.Scan(&c.ID, &c.Type, &c.Name, &cfg, &enabled, &def, &c.Lang, &nd, &nu, &sol, &c.Execution, &c.Revision, &created, &updated, &used, &c.LastError, &c.RemoteID); err != nil {
		return nil, err
	}
	c.Enabled, c.Default, c.NotifyDown, c.NotifyUp, c.SecretOnlyLocal = enabled == 1, def == 1, nd == 1, nu == 1, sol == 1
	c.CreatedAt, c.UpdatedAt, c.LastUsedAt = store.ParseTime(created), store.ParseTime(updated), store.ParseTime(used)
	m, err := decodeConfig(s.box, cfg)
	if err != nil {
		// Konfiguration bleibt sichtbar, Geheimnisse fehlen; der Fehler steht am Kanal
		c.LastError = "config: " + err.Error()
		m = map[string]string{}
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
	res, err := s.w.ExecContext(ctx, `INSERT INTO nf_channels (type, name, config, enabled, is_default, lang, notify_down, notify_up, secret_only_local, execution, created_at, updated_at, remote_id, revision)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, string(c.Type), c.Name, cfg, b2i(c.Enabled), b2i(c.Default), c.Lang, b2i(c.NotifyDown), b2i(c.NotifyUp), b2i(c.SecretOnlyLocal), c.Execution, now, now, c.RemoteID, max(c.Revision, 1))
	if err != nil {
		return err
	}
	c.ID, _ = res.LastInsertId()
	changed(ctx, c.ID, "upsert")
	return nil
}

func (s *Store) Update(ctx context.Context, c *Channel) error {
	cfg, err := encodeConfig(s.box, c.Type, c.Config)
	if err != nil {
		return err
	}
	_, err = s.w.ExecContext(ctx, `UPDATE nf_channels SET type=?, name=?, config=?, enabled=?, is_default=?, lang=?, notify_down=?, notify_up=?, secret_only_local=?, revision=CASE WHEN ?>0 THEN ? ELSE revision+1 END, updated_at=? WHERE id=?`,
		string(c.Type), c.Name, cfg, b2i(c.Enabled), b2i(c.Default), c.Lang, b2i(c.NotifyDown), b2i(c.NotifyUp), b2i(c.SecretOnlyLocal), c.Revision, c.Revision, store.Now(), c.ID)
	if err == nil {
		changed(ctx, c.ID, "upsert")
	}
	return err
}

func (s *Store) Delete(ctx context.Context, id int64) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM nf_channels WHERE id = ?`, id)
	if err == nil {
		changed(ctx, id, "delete")
	}
	return err
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
