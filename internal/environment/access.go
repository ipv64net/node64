package environment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

// Zugaenge (Phase E2): Auf der Ziel-Node B erstellt ein Administrator einen Zugang fuer eine andere Node (Name,
// Benutzer auf B). B zeigt den Zugangsschluessel einmal: n64env1.<Kennung von B>.<oeffentlicher Schluessel von B>.
// <Geheimnis>. Aus dem Geheimnis leiten beide Seiten ein Ed25519-Schluesselpaar ab; B speichert nur dessen
// oeffentlichen Teil (Pruefwert). Die oeffnende Node A signiert ihre Anfragen damit (gebunden an die TLS-Verbindung,
// remote.go). Wer die Datenbank von B liest, kann sich so nicht als A ausgeben (anders als mit einem HMAC).

const (
	keyPrefix   = "n64env1"
	accessLabel = "node64-env-access\n"
	maxNameLen  = 64
)

var (
	// ErrAccessDenied: Schluessel unbekannt (widerrufen) oder Signatur falsch.
	ErrAccessDenied = errors.New("access denied")
	// ErrInvalidKey: Zugangsschluessel hat nicht die erwartete Form.
	ErrInvalidKey = errors.New("invalid access key")
)

// Access ist ein Zugang auf dieser Node (ohne Geheimnis).
type Access struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	UserUID      string    `json:"user_uid"`
	Username     string    `json:"username"` // aktueller Name des Benutzers ("" = geloescht)
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
	LastUsedAt   time.Time `json:"last_used_at,omitzero"`
	LastFromNode string    `json:"last_from_node,omitempty"`
	LastFromName string    `json:"last_from_name,omitempty"`
}

// AccessKey ist ein zerlegter Zugangsschluessel.
type AccessKey struct {
	NodeID string // Kennung der Ziel-Node
	PubKey string // ihr oeffentlicher Schluessel, base64 (StdEncoding wie im Cluster)
	Secret []byte // 32 Byte
}

// String setzt den Schluessel zusammen.
func (k AccessKey) String() string {
	pub, _ := base64.StdEncoding.DecodeString(k.PubKey)
	return keyPrefix + "." + k.NodeID + "." + base64.RawURLEncoding.EncodeToString(pub) + "." + base64.RawURLEncoding.EncodeToString(k.Secret)
}

// ParseAccessKey zerlegt einen Zugangsschluessel (Leerraum am Rand wird ignoriert).
func ParseAccessKey(s string) (AccessKey, error) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) != 4 || parts[0] != keyPrefix || !nodeIDRe.MatchString(parts[1]) {
		return AccessKey{}, ErrInvalidKey
	}
	pub, err := base64.RawURLEncoding.DecodeString(parts[2])
	sec, err2 := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil || err2 != nil || len(pub) != ed25519.PublicKeySize || len(sec) != 32 {
		return AccessKey{}, ErrInvalidKey
	}
	return AccessKey{NodeID: parts[1], PubKey: base64.StdEncoding.EncodeToString(pub), Secret: sec}, nil
}

// accessPair leitet aus dem Geheimnis das Schluesselpaar des Zugangs ab.
func accessPair(secret []byte) ed25519.PrivateKey {
	seed := sha256.Sum256(append([]byte(accessLabel), secret...))
	return ed25519.NewKeyFromSeed(seed[:])
}

// accessPub ist der Pruefwert (oeffentlicher Schluessel des Zugangs, base64url), den B speichert.
func accessPub(secret []byte) string {
	return base64.RawURLEncoding.EncodeToString(accessPair(secret).Public().(ed25519.PublicKey))
}

// cleanName kuerzt einen Namen auf eine Zeile mit hoechstens maxNameLen Zeichen.
func cleanName(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	for utf8.RuneCountInString(s) > maxNameLen {
		_, n := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-n]
	}
	return s
}

// CreateAccess legt einen Zugang fuer den Benutzer mit userUID an und liefert ihn mit dem Schluessel (nur hier).
func (s *Service) CreateAccess(ctx context.Context, name, userUID, by string) (*Access, string, error) {
	name = cleanName(name)
	if name == "" {
		return nil, "", errors.New("environment: name missing")
	}
	if s.d.NodeID == nil || s.d.PublicKey == nil || s.d.NodeID() == "" || s.d.PublicKey() == "" {
		return nil, "", errors.New("environment: node identity missing")
	}
	u, err := s.d.Store.UserByUID(ctx, userUID)
	if err != nil {
		return nil, "", err
	}
	if u == nil {
		return nil, "", ErrUnknownUser
	}
	sec := make([]byte, 32)
	if _, err := rand.Read(sec); err != nil {
		return nil, "", err
	}
	now := s.d.Now().UTC()
	res, err := s.d.Store.Writer().ExecContext(ctx, `INSERT INTO env_access (name, user_uid, key_pub, created_by, created_at) VALUES (?, ?, ?, ?, ?)`,
		name, u.UID, accessPub(sec), by, now.Format(time.RFC3339))
	if err != nil {
		return nil, "", err
	}
	id, _ := res.LastInsertId()
	key := AccessKey{NodeID: s.d.NodeID(), PubKey: s.d.PublicKey(), Secret: sec}
	return &Access{ID: id, Name: name, UserUID: u.UID, Username: u.Username, CreatedBy: by, CreatedAt: now}, key.String(), nil
}

const accessCols = `id, name, user_uid, created_by, created_at, last_used_at, last_from_node, last_from_name`

func (s *Service) scanAccess(ctx context.Context, row interface{ Scan(...any) error }) (*Access, error) {
	var a Access
	var created, used string
	if err := row.Scan(&a.ID, &a.Name, &a.UserUID, &a.CreatedBy, &created, &used, &a.LastFromNode, &a.LastFromName); err != nil {
		return nil, err
	}
	a.CreatedAt, _ = time.Parse(time.RFC3339, created)
	a.LastUsedAt, _ = time.Parse(time.RFC3339, used)
	if u, _ := s.d.Store.UserByUID(ctx, a.UserUID); u != nil {
		a.Username = u.Username
	}
	return &a, nil
}

// Accesses liefert die Zugaenge dieser Node.
func (s *Service) Accesses(ctx context.Context) ([]Access, error) {
	rows, err := s.d.Store.Reader().QueryContext(ctx, `SELECT `+accessCols+` FROM env_access ORDER BY name COLLATE NOCASE, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var raw []*Access
	for rows.Next() {
		var a Access
		var created, used string
		if err := rows.Scan(&a.ID, &a.Name, &a.UserUID, &a.CreatedBy, &created, &used, &a.LastFromNode, &a.LastFromName); err != nil {
			return nil, err
		}
		a.CreatedAt, _ = time.Parse(time.RFC3339, created)
		a.LastUsedAt, _ = time.Parse(time.RFC3339, used)
		raw = append(raw, &a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	out := make([]Access, 0, len(raw))
	for _, a := range raw {
		if u, _ := s.d.Store.UserByUID(ctx, a.UserUID); u != nil {
			a.Username = u.Username
		}
		out = append(out, *a)
	}
	return out, nil
}

// AccessByID liefert einen Zugang (nil = gibt es nicht).
func (s *Service) AccessByID(ctx context.Context, id int64) (*Access, error) {
	a, err := s.scanAccess(ctx, s.d.Store.Reader().QueryRowContext(ctx, `SELECT `+accessCols+` FROM env_access WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return a, err
}

// RevokeAccess loescht einen Zugang (found=false: gab es nicht). Der Schluessel wirkt danach nicht mehr.
func (s *Service) RevokeAccess(ctx context.Context, id int64) (bool, error) {
	res, err := s.d.Store.Writer().ExecContext(ctx, `DELETE FROM env_access WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// accessByPub sucht den Zugang zum Pruefwert (nil = unbekannt, z. B. widerrufen).
func (s *Service) accessByPub(ctx context.Context, pub string) (*Access, error) {
	a, err := s.scanAccess(ctx, s.d.Store.Reader().QueryRowContext(ctx, `SELECT `+accessCols+` FROM env_access WHERE key_pub = ?`, pub))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return a, err
}

// touchAccess vermerkt die letzte Benutzung.
func (s *Service) touchAccess(ctx context.Context, id int64, fromNode, fromName string) {
	_, _ = s.d.Store.Writer().ExecContext(context.WithoutCancel(ctx), `UPDATE env_access SET last_used_at = ?, last_from_node = ?, last_from_name = ? WHERE id = ?`,
		s.d.Now().UTC().Format(time.RFC3339), fromNode, fromName, id)
}
