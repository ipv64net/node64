package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"
)

// ---------------------------------------------------------------- Zwei-Faktor

// SessionTOTPOK sagt, ob die zweite Stufe der Anmeldung erledigt ist.
func (s *Store) SessionTOTPOK(ctx context.Context, id string) (bool, error) {
	var ok int
	err := s.r.QueryRowContext(ctx, `SELECT totp_ok FROM sessions WHERE id = ?`, id).Scan(&ok)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return ok == 1, err
}

// SetSessionTOTP markiert die Sitzung als (nicht) vollstaendig angemeldet.
func (s *Store) SetSessionTOTP(ctx context.Context, id string, ok bool) error {
	v := 0
	if ok {
		v = 1
	}
	_, err := s.w.ExecContext(ctx, `UPDATE sessions SET totp_ok = ? WHERE id = ?`, v, id)
	return err
}

// SetUserTOTP speichert Geheimnis und Wiederherstellungscodes (gehasht, kommagetrennt).
func (s *Store) SetUserTOTP(ctx context.Context, id int64, secret, recoveryHashes string) error {
	_, err := s.w.ExecContext(ctx, `UPDATE users SET totp_secret = ?, totp_recovery = ? WHERE id = ?`, secret, recoveryHashes, id)
	if err == nil {
		s.userChanged(ctx, id) // auch ein verbrauchter Wiederherstellungscode: gilt dann auf keiner Node mehr
	}
	return err
}

// UserTOTPRecovery liefert die gehashten Wiederherstellungscodes.
func (s *Store) UserTOTPRecovery(ctx context.Context, id int64) (string, error) {
	var v string
	err := s.r.QueryRowContext(ctx, `SELECT totp_recovery FROM users WHERE id = ?`, id).Scan(&v)
	return v, err
}

// ---------------------------------------------------------------- API-Keys

type APIKey struct {
	ID         int64
	UserID     int64
	Name       string
	Hint       string
	CreatedAt  time.Time
	LastUsedAt time.Time
}

// NewAPIKey erzeugt einen Key (einmal sichtbar) und speichert nur den Hash.
func (s *Store) NewAPIKey(ctx context.Context, userID int64, name string) (string, *APIKey, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	key := "node64_" + base64.RawURLEncoding.EncodeToString(raw)
	hint := key[:7] + "…" + key[len(key)-4:]
	res, err := s.w.ExecContext(ctx, `INSERT INTO api_keys (user_id, name, key_hash, key_hint, created_at) VALUES (?,?,?,?,?)`, userID, name, HashAPIKey(key), hint, Now())
	if err != nil {
		return "", nil, err
	}
	id, _ := res.LastInsertId()
	return key, &APIKey{ID: id, UserID: userID, Name: name, Hint: hint, CreatedAt: time.Now()}, nil
}

// HashAPIKey ist der Speicher-Hash eines Keys (Keys haben hohe Entropie, SHA-256 genuegt).
func HashAPIKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// APIKeyByValue liefert den Key zu einem Klartextwert oder nil.
func (s *Store) APIKeyByValue(ctx context.Context, key string) (*APIKey, error) {
	k, err := scanAPIKey(s.r.QueryRowContext(ctx, `SELECT id, user_id, name, key_hint, created_at, last_used_at FROM api_keys WHERE key_hash = ?`, HashAPIKey(key)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return k, err
}

func scanAPIKey(row interface{ Scan(...any) error }) (*APIKey, error) {
	var k APIKey
	var created, used string
	if err := row.Scan(&k.ID, &k.UserID, &k.Name, &k.Hint, &created, &used); err != nil {
		return nil, err
	}
	k.CreatedAt, k.LastUsedAt = ParseTime(created), ParseTime(used)
	return &k, nil
}

func (s *Store) APIKeys(ctx context.Context, userID int64) ([]APIKey, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT id, user_id, name, key_hint, created_at, last_used_at FROM api_keys WHERE user_id = ? ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIKey
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *k)
	}
	return out, rows.Err()
}

func (s *Store) TouchAPIKey(ctx context.Context, id int64) error {
	_, err := s.w.ExecContext(ctx, `UPDATE api_keys SET last_used_at = ? WHERE id = ?`, Now(), id)
	return err
}

// DeleteAPIKey loescht einen Key des Benutzers; deleted = es gab ihn.
func (s *Store) DeleteAPIKey(ctx context.Context, userID, id int64) (deleted bool, err error) {
	res, err := s.w.ExecContext(ctx, `DELETE FROM api_keys WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
