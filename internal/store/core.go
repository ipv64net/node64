package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// ---------------------------------------------------------------- Settings

// Setting liest einen Wert; ok = false, wenn er nicht existiert.
func (s *Store) Setting(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := s.r.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return v, err == nil, err
}

// SettingOr liest einen Wert mit Standard.
func (s *Store) SettingOr(ctx context.Context, key, def string) string {
	v, ok, err := s.Setting(ctx, key)
	if err != nil || !ok {
		return def
	}
	return v
}

// SetSetting schreibt einen Wert.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.w.ExecContext(ctx, `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`, key, value, Now())
	if f := s.settingHook.Load(); err == nil && f != nil {
		(*f)(ctx, key)
	}
	return err
}

// SetSettingHook haengt einen Beobachter an jedes Schreiben einer Einstellung (z. B. Abgleich im Cluster, nodecfg);
// er bekommt nur den Schluessel und laeuft nach dem Schreiben. Es gibt genau einen (nil = keiner).
func (s *Store) SetSettingHook(f func(ctx context.Context, key string)) {
	if f == nil {
		s.settingHook.Store(nil)
		return
	}
	s.settingHook.Store(&f)
}

// ---------------------------------------------------------------- Users

type User struct {
	ID           int64
	UID          string // Kennung im Cluster (gleich auf allen Nodes)
	Username     string
	PasswordHash string
	TOTPSecret   string
	Lang         string
	Timezone     string
	CreatedAt    time.Time
	LastLoginAt  time.Time
}

const userCols = `id, uid, username, password_hash, totp_secret, lang, timezone, created_at, last_login_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var created, last string
	if err := row.Scan(&u.ID, &u.UID, &u.Username, &u.PasswordHash, &u.TOTPSecret, &u.Lang, &u.Timezone, &created, &last); err != nil {
		return nil, err
	}
	u.CreatedAt, u.LastLoginAt = ParseTime(created), ParseTime(last)
	return &u, nil
}

func (s *Store) UserCount(ctx context.Context) (int, error) {
	var n int
	err := s.r.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) CreateUser(ctx context.Context, username, passwordHash, lang, tz string) (*User, error) {
	uid := make([]byte, 16)
	_, _ = rand.Read(uid)
	res, err := s.w.ExecContext(ctx, `INSERT INTO users (uid, username, password_hash, lang, timezone, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		hex.EncodeToString(uid), username, passwordHash, lang, tz, Now())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	s.userChanged(ctx, id)
	return s.UserByID(ctx, id)
}

// SetLoginCluster haengt den Cluster an Benutzer und Anmeldung an (internal/usercluster, vor dem Start; nil = ohne).
func (s *Store) SetLoginCluster(f func(ctx context.Context, item, id string, deleted bool)) {
	s.loginCluster = f
}

// LoginChanged meldet eine Aenderung an Benutzern oder Anmeldung (Bereich, Kennung) an den Cluster.
func (s *Store) LoginChanged(ctx context.Context, item, id string, deleted bool) {
	if s.loginCluster != nil && id != "" {
		s.loginCluster(ctx, item, id, deleted)
	}
}

// userChanged meldet einen geaenderten Benutzer an den Cluster (Bereich accounts).
func (s *Store) userChanged(ctx context.Context, id int64) {
	if s.loginCluster == nil {
		return
	}
	var uid string
	if s.r.QueryRowContext(ctx, `SELECT uid FROM users WHERE id = ?`, id).Scan(&uid) == nil {
		s.LoginChanged(ctx, "accounts", uid, false)
	}
}

// DeleteUser loescht einen Benutzer samt Sitzungen, Keys, Verknuepfungen und Passkeys; false = gab es nicht.
func (s *Store) DeleteUser(ctx context.Context, id int64) (bool, error) {
	u, err := s.UserByID(ctx, id)
	if err != nil || u == nil {
		return false, err
	}
	if _, err := s.w.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id); err != nil {
		return false, err
	}
	s.LoginChanged(ctx, "accounts", u.UID, true)
	return true, nil
}

func (s *Store) UserByID(ctx context.Context, id int64) (*User, error) {
	u, err := scanUser(s.r.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return u, err
}

func (s *Store) UserByName(ctx context.Context, name string) (*User, error) {
	u, err := scanUser(s.r.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE username = ?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return u, err
}

func (s *Store) Users(ctx context.Context) ([]*User, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) TouchUserLogin(ctx context.Context, id int64) error {
	_, err := s.w.ExecContext(ctx, `UPDATE users SET last_login_at = ? WHERE id = ?`, Now(), id)
	return err
}

func (s *Store) UpdateUserPrefs(ctx context.Context, id int64, lang, tz string) error {
	_, err := s.w.ExecContext(ctx, `UPDATE users SET lang = ?, timezone = ? WHERE id = ?`, lang, tz, id)
	if err == nil {
		s.userChanged(ctx, id)
	}
	return err
}

func (s *Store) UpdateUserPassword(ctx context.Context, id int64, hash string) error {
	_, err := s.w.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, hash, id)
	if err == nil {
		s.userChanged(ctx, id)
	}
	return err
}

func (s *Store) UpdateUserTOTP(ctx context.Context, id int64, secret string) error {
	_, err := s.w.ExecContext(ctx, `UPDATE users SET totp_secret = ? WHERE id = ?`, secret, id)
	if err == nil {
		s.userChanged(ctx, id)
	}
	return err
}

// ---------------------------------------------------------------- Sessions

type Session struct {
	ID         string
	UserID     int64
	CSRF       string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	IP         string
	UserAgent  string
}

func (s *Store) CreateSession(ctx context.Context, sess *Session) error {
	_, err := s.w.ExecContext(ctx, `INSERT INTO sessions (id, user_id, csrf, created_at, last_seen_at, expires_at, ip, user_agent)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.ID, sess.UserID, sess.CSRF, FormatTime(sess.CreatedAt), FormatTime(sess.LastSeenAt), FormatTime(sess.ExpiresAt), sess.IP, sess.UserAgent)
	return err
}

// SessionByID liefert eine gueltige (nicht abgelaufene) Sitzung oder nil.
func (s *Store) SessionByID(ctx context.Context, id string) (*Session, error) {
	var sess Session
	var created, seen, expires string
	err := s.r.QueryRowContext(ctx, `SELECT id, user_id, csrf, created_at, last_seen_at, expires_at, ip, user_agent FROM sessions WHERE id = ?`, id).
		Scan(&sess.ID, &sess.UserID, &sess.CSRF, &created, &seen, &expires, &sess.IP, &sess.UserAgent)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sess.CreatedAt, sess.LastSeenAt, sess.ExpiresAt = ParseTime(created), ParseTime(seen), ParseTime(expires)
	if !sess.ExpiresAt.After(time.Now()) {
		return nil, nil
	}
	return &sess, nil
}

func (s *Store) TouchSession(ctx context.Context, id string, expires time.Time) error {
	_, err := s.w.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id = ?`, Now(), FormatTime(expires), id)
	return err
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	return err
}

func (s *Store) DeleteUserSessions(ctx context.Context, userID int64, keep string) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND id != ?`, userID, keep)
	return err
}

func (s *Store) PurgeSessions(ctx context.Context) (int64, error) {
	res, err := s.w.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, Now())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---------------------------------------------------------------- Modules

func (s *Store) ModuleEnabled(ctx context.Context, name string) (bool, error) {
	var n int
	err := s.r.QueryRowContext(ctx, `SELECT enabled FROM modules WHERE name = ?`, name).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return n == 1, err
}

func (s *Store) SetModuleEnabled(ctx context.Context, name string, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO modules (name, enabled, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET enabled = excluded.enabled, updated_at = excluded.updated_at`, name, v, Now())
	return err
}

// ---------------------------------------------------------------- Audit

type AuditEntry struct {
	ID      int64
	Time    time.Time
	Actor   string
	Action  string
	Target  string
	Details string
	IP      string
	Origin  string
}

func (s *Store) Audit(ctx context.Context, e AuditEntry) error {
	if e.Origin == "" {
		e.Origin = "local"
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO audit_log (time, actor, action, target, details, ip, origin) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		Now(), e.Actor, e.Action, e.Target, e.Details, e.IP, e.Origin)
	return err
}

// PruneAudit loescht Eintraege aelter als keep (keep <= 0: nichts). Liefert die Zahl der geloeschten Eintraege.
func (s *Store) PruneAudit(ctx context.Context, keep time.Duration) (int64, error) {
	if keep <= 0 {
		return 0, nil
	}
	res, err := s.w.ExecContext(ctx, `DELETE FROM audit_log WHERE time < ?`, FormatTime(time.Now().Add(-keep)))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// AuditList liefert die neuesten Eintraege, optional nur mit ID < before.
func (s *Store) AuditList(ctx context.Context, limit int, before int64) ([]AuditEntry, error) {
	return s.AuditListFiltered(ctx, limit, before, nil)
}

// AuditListFiltered wie AuditList, nur Aktionen, die mit einem der Praefixe beginnen (leer = alle).
func (s *Store) AuditListFiltered(ctx context.Context, limit int, before int64, prefixes []string) ([]AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	q := `SELECT id, time, actor, action, target, details, ip, origin FROM audit_log WHERE 1=1`
	args := []any{}
	if before > 0 {
		q += ` AND id < ?`
		args = append(args, before)
	}
	if len(prefixes) > 0 {
		q += ` AND (` + strings.TrimSuffix(strings.Repeat(`substr(action, 1, ?) = ? OR `, len(prefixes)), ` OR `) + `)`
		for _, p := range prefixes {
			args = append(args, len(p), p)
		}
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var t string
		if err := rows.Scan(&e.ID, &t, &e.Actor, &e.Action, &e.Target, &e.Details, &e.IP, &e.Origin); err != nil {
			return nil, err
		}
		e.Time = ParseTime(t)
		out = append(out, e)
	}
	return out, rows.Err()
}
