package store

import "context"

// Ergaenzungen der Benutzerverwaltung (users.go) fuer Oberflaeche und Notfallzugang.

// RestoreAdmin macht einen Benutzer wieder zum aktiven lokalen Administrator (node64 reset-password): Rolle admin,
// nicht gesperrt, Herkunft lokal, kein „Passwort beim naechsten Anmelden setzen“.
func (s *Store) RestoreAdmin(ctx context.Context, id int64) error {
	_, err := s.w.ExecContext(ctx, `UPDATE users SET role = ?, disabled = 0, source = ?, must_change = 0 WHERE id = ?`,
		RoleAdmin, SourceLocal, id)
	if err == nil {
		s.userChanged(ctx, id)
	}
	return err
}

// GroupMembers liefert die Benutzer einer Gruppe: von Hand zugeordnet bzw. ueber LDAP/SSO ermittelt.
func (s *Store) GroupMembers(ctx context.Context, uid string) (manual, external []*User, err error) {
	users, err := s.Users(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, u := range users {
		for _, g := range u.GroupUIDs {
			if g == uid {
				manual = append(manual, u)
				break
			}
		}
		for _, g := range u.ExtGroupUIDs {
			if g == uid {
				external = append(external, u)
				break
			}
		}
	}
	return manual, external, nil
}
