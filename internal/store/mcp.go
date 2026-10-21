package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

// ---------------------------------------------------------------- MCP-Schluessel

// MCPKey ist ein Schluessel der MCP-Schnittstelle (KI-Anwendungen). Getrennt von den API-Keys: eigenes Praefix,
// eigene Rechte je Bereich, nur fuer /mcp.
type MCPKey struct {
	ID         int64
	UserID     int64
	Name       string
	Hint       string
	Scopes     []string // z. B. "healthchecks:read"
	CreatedAt  time.Time
	LastUsedAt time.Time
	LastIP     string
}

// MCPKeyPrefix steht vor jedem MCP-Schluessel.
const MCPKeyPrefix = "mcp64_"

// CanRead sagt, ob der Schluessel den Bereich lesen darf.
func (k *MCPKey) CanRead(area string) bool {
	for _, s := range k.Scopes {
		if s == area+":read" {
			return true
		}
	}
	return false
}

// ReadAreas liefert die lesbaren Bereiche.
func (k *MCPKey) ReadAreas() []string {
	var out []string
	for _, s := range k.Scopes {
		if a, ok := strings.CutSuffix(s, ":read"); ok {
			out = append(out, a)
		}
	}
	return out
}

// NewMCPKey erzeugt einen Schluessel (einmal sichtbar) und speichert nur den Hash.
func (s *Store) NewMCPKey(ctx context.Context, userID int64, name string, scopes []string) (string, *MCPKey, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	key := MCPKeyPrefix + base64.RawURLEncoding.EncodeToString(raw)
	hint := key[:len(MCPKeyPrefix)+2] + "…" + key[len(key)-4:]
	res, err := s.w.ExecContext(ctx, `INSERT INTO mcp_keys (user_id, name, key_hash, key_hint, scopes, created_at) VALUES (?,?,?,?,?,?)`,
		userID, name, HashAPIKey(key), hint, strings.Join(scopes, ","), Now())
	if err != nil {
		return "", nil, err
	}
	id, _ := res.LastInsertId()
	return key, &MCPKey{ID: id, UserID: userID, Name: name, Hint: hint, Scopes: scopes, CreatedAt: time.Now()}, nil
}

const mcpKeyCols = `id, user_id, name, key_hint, scopes, created_at, last_used_at, last_ip`

func scanMCPKey(row interface{ Scan(...any) error }) (*MCPKey, error) {
	var k MCPKey
	var scopes, created, used string
	if err := row.Scan(&k.ID, &k.UserID, &k.Name, &k.Hint, &scopes, &created, &used, &k.LastIP); err != nil {
		return nil, err
	}
	if scopes != "" {
		k.Scopes = strings.Split(scopes, ",")
	}
	k.CreatedAt, k.LastUsedAt = ParseTime(created), ParseTime(used)
	return &k, nil
}

// MCPKeyByValue liefert den Schluessel zu einem Klartextwert oder nil.
func (s *Store) MCPKeyByValue(ctx context.Context, key string) (*MCPKey, error) {
	if !strings.HasPrefix(key, MCPKeyPrefix) {
		return nil, nil
	}
	k, err := scanMCPKey(s.r.QueryRowContext(ctx, `SELECT `+mcpKeyCols+` FROM mcp_keys WHERE key_hash = ?`, HashAPIKey(key)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return k, err
}

// MCPKeys liefert die Schluessel eines Benutzers.
func (s *Store) MCPKeys(ctx context.Context, userID int64) ([]MCPKey, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT `+mcpKeyCols+` FROM mcp_keys WHERE user_id = ? ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MCPKey
	for rows.Next() {
		k, err := scanMCPKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *k)
	}
	return out, rows.Err()
}

// TouchMCPKey merkt letzte Nutzung und Adresse.
func (s *Store) TouchMCPKey(ctx context.Context, id int64, ip string) error {
	_, err := s.w.ExecContext(ctx, `UPDATE mcp_keys SET last_used_at = ?, last_ip = ? WHERE id = ?`, Now(), ip, id)
	return err
}

// DeleteMCPKey widerruft einen Schluessel des Benutzers; deleted = es gab ihn.
func (s *Store) DeleteMCPKey(ctx context.Context, userID, id int64) (deleted bool, err error) {
	res, err := s.w.ExecContext(ctx, `DELETE FROM mcp_keys WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
