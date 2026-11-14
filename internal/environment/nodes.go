package environment

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/peer"
)

// Hinzugefuegte Nodes (Phase E2): Nodes ausserhalb des Clusters per Adresse, optional mit Zugangsschluessel der
// anderen Node. Ohne Schluessel: Link und Status (/api/health). Mit Schluessel: Status und Anmelde-Ticket ueber die
// gebundenen Endpunkte /peer/v2/env/* (remote.go); anmelden kann sich darueber nur der Benutzer, der den Schluessel
// eingetragen hat (gleiche uid, auch auf den anderen Mitgliedern mit Benutzer-Abgleich) - der Schluessel steht fuer
// eine Anmeldung als ein bestimmter Benutzer der anderen Node. Das Geheimnis liegt mit secret.key verschluesselt in
// env_nodes; im Cluster (Bereich environment/nodes) geht es im Klartext ueber die gebundene Verbindung und wird beim
// Empfaenger mit dessen Schluessel neu verschluesselt.

// ItemNodes ist der Bereich der hinzugefuegten Nodes im Cluster (Standard an).
const ItemNodes = "nodes"

var (
	// ErrInvalidURL: Adresse fehlt oder ist keine http(s)-Adresse ohne Pfad.
	ErrInvalidURL = errors.New("invalid address")
	// ErrHTTPSRequired: mit Zugangsschluessel nur https.
	ErrHTTPSRequired = errors.New("access key needs an https address")
	// ErrSelfKey: Schluessel dieser Node (oder eines Cluster-Mitglieds) - dafuer braucht es keinen Eintrag.
	ErrSelfKey = errors.New("access key of this node")
)

// AddedNode ist eine hinzugefuegte Node (ohne Geheimnis).
type AddedNode struct {
	UID         string    `json:"id"`
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	BrowserURL  string    `json:"browser_url,omitempty"`
	Description string    `json:"description,omitempty"`
	NodeID      string    `json:"node_id,omitempty"` // aus dem Zugangsschluessel
	HasKey      bool      `json:"has_key"`
	OwnerUID    string    `json:"owner_uid,omitempty"` // Benutzer, der den Schluessel eingetragen hat
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	nodePub     string
	sealed      string // Geheimnis (base64url), mit secret.key verschluesselt
}

// NodeInput ist das Formular bzw. die API zum Anlegen und Bearbeiten.
type NodeInput struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	BrowserURL  string `json:"browser_url"`
	Description string `json:"description"`
	Key         string `json:"key"`        // leer = beim Bearbeiten bisherigen behalten
	RemoveKey   bool   `json:"remove_key"` // Schluessel entfernen (nur Link und Status)
}

// NormURL macht aus einer Eingabe eine Adresse scheme://host[:port] (ohne Schema: https). Pfad, Abfrage und
// Zugangsdaten sind nicht erlaubt.
func NormURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	s = strings.TrimSuffix(s, "/")
	p, err := url.Parse(s)
	if err != nil || (p.Scheme != "https" && p.Scheme != "http") || p.Hostname() == "" || p.User != nil || p.Path != "" ||
		p.RawQuery != "" || p.Fragment != "" || len(s) > 255 || strings.HasSuffix(p.Host, ":") || strings.ContainsAny(p.Host, " ;,'\"\r\n\\") {
		return "", ErrInvalidURL
	}
	return p.Scheme + "://" + p.Host, nil
}

func newUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

const nodeCols = `uid, name, url, browser_url, description, node_id, node_pub, secret, owner_uid, created_at, updated_at`

func scanNode(row interface{ Scan(...any) error }) (*AddedNode, error) {
	var n AddedNode
	var created, updated string
	if err := row.Scan(&n.UID, &n.Name, &n.URL, &n.BrowserURL, &n.Description, &n.NodeID, &n.nodePub, &n.sealed, &n.OwnerUID, &created, &updated); err != nil {
		return nil, err
	}
	n.HasKey = n.sealed != "" && n.nodePub != "" && n.NodeID != ""
	n.CreatedAt, _ = time.Parse(time.RFC3339, created)
	n.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
	return &n, nil
}

// AddedNodes liefert die hinzugefuegten Nodes.
func (s *Service) AddedNodes(ctx context.Context) ([]AddedNode, error) {
	rows, err := s.d.Store.Reader().QueryContext(ctx, `SELECT `+nodeCols+` FROM env_nodes ORDER BY CASE name WHEN '' THEN url ELSE name END COLLATE NOCASE, uid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AddedNode
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *n)
	}
	return out, rows.Err()
}

// AddedNode liefert eine hinzugefuegte Node (nil = gibt es nicht).
func (s *Service) AddedNode(ctx context.Context, uid string) (*AddedNode, error) {
	if !uidRe.MatchString(uid) {
		return nil, nil
	}
	n, err := scanNode(s.d.Store.Reader().QueryRowContext(ctx, `SELECT `+nodeCols+` FROM env_nodes WHERE uid = ?`, uid))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return n, err
}

// checkInput prueft und normalisiert die Eingabe; key ist der zerlegte Schluessel (nil = keiner angegeben).
func (s *Service) checkInput(ctx context.Context, in *NodeInput) (*AccessKey, error) {
	var err error
	if in.URL, err = NormURL(in.URL); err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.BrowserURL) != "" {
		if in.BrowserURL, err = NormURL(in.BrowserURL); err != nil {
			return nil, err
		}
	} else {
		in.BrowserURL = ""
	}
	in.Name, in.Description = cleanName(in.Name), cleanText(in.Description, 200)
	if strings.TrimSpace(in.Key) == "" {
		return nil, nil
	}
	k, err := ParseAccessKey(in.Key)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(in.URL, "https://") {
		return nil, ErrHTTPSRequired
	}
	if s.d.NodeID != nil && k.NodeID == s.d.NodeID() {
		return nil, ErrSelfKey
	}
	if s.d.Members != nil {
		if list, _ := s.d.Members(ctx); hasMember(list, k.NodeID) {
			return nil, ErrSelfKey
		}
	}
	return &k, nil
}

// cleanText kuerzt einen einzeiligen Text auf n Zeichen.
func cleanText(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > n {
		s = string(r[:n])
	}
	return s
}

// AddNode legt eine Node an; ownerUID ist der Benutzer, der den Schluessel eintraegt.
func (s *Service) AddNode(ctx context.Context, in NodeInput, ownerUID string) (*AddedNode, error) {
	k, err := s.checkInput(ctx, &in)
	if err != nil {
		return nil, err
	}
	n := &AddedNode{UID: newUID(), Name: in.Name, URL: in.URL, BrowserURL: in.BrowserURL, Description: in.Description}
	if k != nil {
		n.NodeID, n.nodePub, n.sealed, n.OwnerUID = k.NodeID, k.PubKey, s.seal(k.Secret), ownerUID
	}
	now := s.d.Now().UTC()
	n.CreatedAt, n.UpdatedAt = now, now
	if err := s.writeNode(ctx, n); err != nil {
		return nil, err
	}
	n.HasKey = k != nil
	s.changed(ctx, n.UID, false)
	return n, nil
}

// UpdateNode aendert eine Node (nil = gibt es nicht). Ein neuer Schluessel gehoert dem Benutzer ownerUID.
func (s *Service) UpdateNode(ctx context.Context, uid string, in NodeInput, ownerUID string) (*AddedNode, error) {
	n, err := s.AddedNode(ctx, uid)
	if err != nil || n == nil {
		return nil, err
	}
	k, err := s.checkInput(ctx, &in)
	if err != nil {
		return nil, err
	}
	switch {
	case k != nil:
		n.NodeID, n.nodePub, n.sealed, n.OwnerUID = k.NodeID, k.PubKey, s.seal(k.Secret), ownerUID
	case in.RemoveKey:
		n.NodeID, n.nodePub, n.sealed, n.OwnerUID = "", "", "", ""
	case n.HasKey && in.URL != n.URL && !strings.HasPrefix(in.URL, "https://"):
		return nil, ErrHTTPSRequired
	}
	n.Name, n.URL, n.BrowserURL, n.Description = in.Name, in.URL, in.BrowserURL, in.Description
	n.UpdatedAt = s.d.Now().UTC()
	if err := s.writeNode(ctx, n); err != nil {
		return nil, err
	}
	n.HasKey = n.sealed != ""
	s.changed(ctx, n.UID, false)
	return n, nil
}

// RemoveNode loescht eine Node (found=false: gab es nicht).
func (s *Service) RemoveNode(ctx context.Context, uid string) (bool, error) {
	res, err := s.d.Store.Writer().ExecContext(ctx, `DELETE FROM env_nodes WHERE uid = ?`, uid)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil
	}
	s.changed(ctx, uid, true)
	return true, nil
}

func (s *Service) writeNode(ctx context.Context, n *AddedNode) error {
	_, err := s.d.Store.Writer().ExecContext(ctx, `INSERT INTO env_nodes (`+nodeCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(uid) DO UPDATE SET name = excluded.name, url = excluded.url, browser_url = excluded.browser_url, description = excluded.description,
		node_id = excluded.node_id, node_pub = excluded.node_pub, secret = excluded.secret, owner_uid = excluded.owner_uid, updated_at = excluded.updated_at`,
		n.UID, n.Name, n.URL, n.BrowserURL, n.Description, n.NodeID, n.nodePub, n.sealed, n.OwnerUID,
		n.CreatedAt.UTC().Format(time.RFC3339), n.UpdatedAt.UTC().Format(time.RFC3339))
	return err
}

func (s *Service) seal(secret []byte) string {
	v := base64.RawURLEncoding.EncodeToString(secret)
	if s.d.Box == nil {
		return v // nur Tests
	}
	return s.d.Box.Encrypt(v)
}

// key liefert den Zugangsschluessel einer Node (nil = keiner).
func (s *Service) key(n *AddedNode) (*AccessKey, error) {
	if !n.HasKey {
		return nil, nil
	}
	v := n.sealed
	if s.d.Box != nil {
		var err error
		if v, err = s.d.Box.Decrypt(v); err != nil {
			return nil, err
		}
	}
	sec, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil || len(sec) != 32 {
		return nil, ErrInvalidKey
	}
	return &AccessKey{NodeID: n.NodeID, PubKey: n.nodePub, Secret: sec}, nil
}

func (s *Service) changed(ctx context.Context, uid string, deleted bool) {
	if s.d.Change != nil {
		s.d.Change(ctx, ModuleID, ItemNodes, uid, deleted)
	}
}

// ---------------------------------------------------------------- Cluster (Bereich environment/nodes)

// clusterNode ist eine hinzugefuegte Node im Cluster (Geheimnis im Klartext, base64url).
type clusterNode struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	BrowserURL  string `json:"browser_url,omitempty"`
	Description string `json:"description,omitempty"`
	NodeID      string `json:"node_id,omitempty"`
	NodePub     string `json:"node_pub,omitempty"`
	Secret      string `json:"secret,omitempty"`
	OwnerUID    string `json:"owner_uid,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
}

// provider meldet die Bereiche environment/login (nur Schalter) und environment/nodes beim Cluster an.
type provider struct{ s *Service }

func (provider) ClusterModule() peer.ModuleInfo { return moduleInfo }

func (p provider) ClusterIDs(ctx context.Context, item string) ([]string, error) {
	if item != ItemNodes {
		return nil, nil
	}
	list, err := p.s.AddedNodes(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(list))
	for _, n := range list {
		out = append(out, n.UID)
	}
	return out, nil
}

func (p provider) ClusterGet(ctx context.Context, item, id string) (json.RawMessage, bool, error) {
	if item != ItemNodes {
		return nil, false, nil
	}
	n, err := p.s.AddedNode(ctx, id)
	if err != nil || n == nil {
		return nil, false, err
	}
	c := clusterNode{Name: n.Name, URL: n.URL, BrowserURL: n.BrowserURL, Description: n.Description, CreatedAt: n.CreatedAt.UTC().Format(time.RFC3339)}
	if n.HasKey {
		k, err := p.s.key(n)
		if err != nil {
			return nil, false, err // Geheimnis hier nicht lesbar: lieber nichts als ein Eintrag ohne Schluessel
		}
		c.NodeID, c.NodePub, c.Secret, c.OwnerUID = k.NodeID, k.PubKey, base64.RawURLEncoding.EncodeToString(k.Secret), n.OwnerUID
	}
	b, err := json.Marshal(c)
	return b, err == nil, err
}

func (p provider) ClusterApply(ctx context.Context, item, id string, data json.RawMessage, deleted bool) error {
	if item != ItemNodes {
		return nil
	}
	if !uidRe.MatchString(id) {
		return errors.New("environment: invalid id")
	}
	if deleted {
		_, err := p.s.d.Store.Writer().ExecContext(ctx, `DELETE FROM env_nodes WHERE uid = ?`, id)
		return err
	}
	var c clusterNode
	if err := json.Unmarshal(data, &c); err != nil {
		return err
	}
	n := &AddedNode{UID: id, Name: cleanName(c.Name), Description: cleanText(c.Description, 200)}
	var err error
	if n.URL, err = NormURL(c.URL); err != nil {
		return err
	}
	if c.BrowserURL != "" {
		if n.BrowserURL, err = NormURL(c.BrowserURL); err != nil {
			return err
		}
	}
	if c.Secret != "" {
		k, err := ParseAccessKey(AccessKey{NodeID: c.NodeID, PubKey: c.NodePub, Secret: mustB64(c.Secret)}.String())
		if err != nil || !strings.HasPrefix(n.URL, "https://") || (c.OwnerUID != "" && !uidRe.MatchString(c.OwnerUID)) {
			return ErrInvalidKey
		}
		n.NodeID, n.nodePub, n.sealed, n.OwnerUID = k.NodeID, k.PubKey, p.s.seal(k.Secret), c.OwnerUID
	}
	now := p.s.d.Now().UTC()
	n.CreatedAt, n.UpdatedAt = now, now
	if t, err := time.Parse(time.RFC3339, c.CreatedAt); err == nil {
		n.CreatedAt = t
	}
	return p.s.writeNode(ctx, n)
}

func mustB64(s string) []byte {
	b, _ := base64.RawURLEncoding.DecodeString(s)
	return b
}
