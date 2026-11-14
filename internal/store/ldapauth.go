package store

import (
	"context"
	"strings"
)

// SetUserEmail merkt die E-Mail eines Benutzers aus LDAP/SSO (nur bei Aenderung, dann Cluster).
func (s *Store) SetUserEmail(ctx context.Context, id int64, email string) error {
	email = strings.TrimSpace(email)
	res, err := s.w.ExecContext(ctx, `UPDATE users SET email = ? WHERE id = ? AND email <> ?`, email, id, email)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		s.userChanged(ctx, id)
	}
	return nil
}
