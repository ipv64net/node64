package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Identity ist eine mit einem lokalen Benutzer verknuepfte SSO-Identitaet (OIDC).
type Identity struct {
	ID         int64
	UserID     int64
	Provider   string
	Subject    string
	Label      string
	CreatedAt  time.Time
	LastUsedAt time.Time
}

// LinkIdentity verknuepft eine SSO-Identitaet mit einem Benutzer. Gehoert sie schon einem anderen, ErrIdentityTaken.
func (s *Store) LinkIdentity(ctx context.Context, userID int64, provider, subject, label string) error {
	var owner int64
	err := s.r.QueryRowContext(ctx, `SELECT user_id FROM user_identities WHERE provider = ? AND subject = ?`, provider, subject).Scan(&owner)
	switch {
	case err == nil && owner != userID:
		return ErrIdentityTaken
	case err == nil:
		_, err = s.w.ExecContext(ctx, `UPDATE user_identities SET label = ? WHERE provider = ? AND subject = ?`, label, provider, subject)
	case !errors.Is(err, sql.ErrNoRows):
		return err
	default:
		_, err = s.w.ExecContext(ctx, `INSERT INTO user_identities (user_id, provider, subject, label, created_at) VALUES (?,?,?,?,?)`, userID, provider, subject, label, Now())
	}
	if err == nil {
		s.userChanged(ctx, userID) // Verknuepfungen gehoeren zum Benutzer (Cluster)
	}
	return err
}

// ErrIdentityTaken: die SSO-Identitaet ist schon mit einem anderen Benutzer verknuepft.
var ErrIdentityTaken = errors.New("identity already linked to another user")

// IdentityUser liefert den Benutzer zu einer SSO-Identitaet (0 = nicht verknuepft) und vermerkt die Nutzung.
func (s *Store) IdentityUser(ctx context.Context, provider, subject string) (int64, error) {
	var uid int64
	err := s.r.QueryRowContext(ctx, `SELECT user_id FROM user_identities WHERE provider = ? AND subject = ?`, provider, subject).Scan(&uid)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	_, _ = s.w.ExecContext(ctx, `UPDATE user_identities SET last_used_at = ? WHERE provider = ? AND subject = ?`, Now(), provider, subject)
	return uid, nil
}

// Identities liefert die SSO-Identitaeten eines Benutzers.
func (s *Store) Identities(ctx context.Context, userID int64) ([]Identity, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT id, user_id, provider, subject, label, created_at, last_used_at FROM user_identities WHERE user_id = ? ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Identity
	for rows.Next() {
		var i Identity
		var c, l string
		if err := rows.Scan(&i.ID, &i.UserID, &i.Provider, &i.Subject, &i.Label, &c, &l); err != nil {
			return nil, err
		}
		i.CreatedAt, i.LastUsedAt = ParseTime(c), ParseTime(l)
		out = append(out, i)
	}
	return out, rows.Err()
}

// UnlinkIdentity loest eine Verknuepfung des Benutzers; false = gab es nicht.
func (s *Store) UnlinkIdentity(ctx context.Context, userID, id int64) (bool, error) {
	res, err := s.w.ExecContext(ctx, `DELETE FROM user_identities WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		s.userChanged(ctx, userID)
	}
	return n > 0, nil
}

// Passkey ist ein registrierter Passkey (WebAuthn-Credential als JSON in Data).
type Passkey struct {
	ID           int64
	UserID       int64
	Name         string
	RPID         string
	CredentialID string
	Data         string
	CreatedAt    time.Time
	LastUsedAt   time.Time
}

const passkeyCols = `id, user_id, name, rp_id, credential_id, data, created_at, last_used_at`

func scanPasskey(row interface{ Scan(...any) error }) (*Passkey, error) {
	var p Passkey
	var c, l string
	if err := row.Scan(&p.ID, &p.UserID, &p.Name, &p.RPID, &p.CredentialID, &p.Data, &c, &l); err != nil {
		return nil, err
	}
	p.CreatedAt, p.LastUsedAt = ParseTime(c), ParseTime(l)
	return &p, nil
}

// AddPasskey speichert einen neuen Passkey.
func (s *Store) AddPasskey(ctx context.Context, p Passkey) error {
	_, err := s.w.ExecContext(ctx, `INSERT INTO passkeys (user_id, name, rp_id, credential_id, data, created_at) VALUES (?,?,?,?,?,?)`,
		p.UserID, p.Name, p.RPID, p.CredentialID, p.Data, Now())
	return err
}

// Passkeys liefert die Passkeys eines Benutzers (rpID leer = alle).
func (s *Store) Passkeys(ctx context.Context, userID int64, rpID string) ([]Passkey, error) {
	q, args := `SELECT `+passkeyCols+` FROM passkeys WHERE user_id = ?`, []any{userID}
	if rpID != "" {
		q += ` AND rp_id = ?`
		args = append(args, rpID)
	}
	rows, err := s.r.QueryContext(ctx, q+` ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Passkey
	for rows.Next() {
		p, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// PasskeyCount: Zahl aller Passkeys fuer einen Hostnamen (Login-Seite zeigt den Knopf nur, wenn es welche gibt).
func (s *Store) PasskeyCount(ctx context.Context, rpID string) int {
	var n int
	_ = s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM passkeys WHERE rp_id = ?`, rpID).Scan(&n)
	return n
}

// UpdatePasskey speichert die Daten nach einer Anmeldung (Zaehler, Flags) und vermerkt die Nutzung.
func (s *Store) UpdatePasskey(ctx context.Context, credentialID, data string) error {
	_, err := s.w.ExecContext(ctx, `UPDATE passkeys SET data = ?, last_used_at = ? WHERE credential_id = ?`, data, Now(), credentialID)
	return err
}

// DeletePasskey loescht einen Passkey des Benutzers; false = gab es nicht.
func (s *Store) DeletePasskey(ctx context.Context, userID, id int64) (bool, error) {
	res, err := s.w.ExecContext(ctx, `DELETE FROM passkeys WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
