// Package environment: weitere Node64 an einer Stelle oeffnen (Menue „Environment“, docs/PLAN-NODE64-ENVIRONMENT.md).
// Phase E1: diese Node und die Mitglieder des Clusters. „Oeffnen“ holt serverseitig bei der anderen Node ein
// Anmelde-Ticket (Cluster-Anfrage environment/ticket ueber /peer/v2/call), der Browser loest es dort per POST auf
// /environment/enter ein. Ein Ticket ist 32 Byte Zufall, 60 s gueltig, einmal verwendbar und liegt nur im Speicher.
//
// Regeln: Anmeldung nur mit gleicher Kennung (uid) ueber den Benutzer-Abgleich (Bereich users/accounts auf beiden
// Seiten an) und mit dem Bereich environment/login auf beiden Seiten; sonst Anmeldeseite der anderen Node. Die Rolle
// wird nie groesser: hoechstens die Rolle auf der Ziel-Node und hoechstens die mitgeschickte der oeffnenden Node.
// Gesperrte und unbekannte Benutzer bekommen kein Ticket.
//
// Phase E2: hinzugefuegte Nodes ausserhalb des Clusters (nodes.go) mit Zugangsschluessel (access.go) und gebundenen
// Endpunkten /peer/v2/env/* (remote.go); Bereich environment/nodes gleicht sie im Cluster ab.
package environment

import (
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/peer"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

// Kennungen fuer den Cluster und den Scope der Migrationen.
const (
	Name       = "environment"
	ModuleID   = "environment"
	ItemLogin  = "login"  // Ticket-Anfragen anderer Mitglieder beantworten (Standard an)
	CallTicket = "ticket" // Cluster-Anfrage: Ticket fuer einen Benutzer ausstellen

	TicketTTL  = 60 * time.Second
	maxTickets = 1000 // Obergrenze offener Tickets im Speicher
)

var (
	// ErrNoUserSync: Benutzer-Abgleich mit der anfragenden Node aus (keine gemeinsame uid).
	ErrNoUserSync = errors.New("user sync with that node is off")
	// ErrUnknownUser: keinen Benutzer mit dieser uid.
	ErrUnknownUser = errors.New("unknown user")
	// ErrLocked: Benutzer gesperrt.
	ErrLocked = errors.New("user is locked")
	// ErrMember: anfragende Node unbekannt oder ausgesetzt.
	ErrMember = errors.New("node is not an active cluster member")

	uidRe = regexp.MustCompile(`^[0-9a-f]{16,64}$`) // wie usercluster
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Migrations liefert die Migrationen des Scopes environment.
func Migrations() ([]store.Migration, error) { return store.ReadMigrations(migrationFS, "migrations") }

// MinRole: die kleinere von zwei Rollen (unbekannte zaehlen als „nur lesen“).
func MinRole(a, b string) string {
	if store.IsAdmin(a) && store.IsAdmin(b) {
		return store.RoleAdmin
	}
	return store.RoleRead
}

// TicketRequest schickt die oeffnende Node mit (Rolle: wirksame Rolle des Benutzers dort, Back: Rueckweg fuer den
// Browser).
type TicketRequest struct {
	UID  string `json:"uid"`
	Role string `json:"role"`
	Back string `json:"back,omitempty"`
}

// TicketResponse ist die Antwort der Ziel-Node.
type TicketResponse struct {
	Ticket string `json:"ticket"`
}

// Ticket ist ein ausgestelltes, noch nicht eingeloestes Ticket.
type Ticket struct {
	UID      string
	Role     string // bereits begrenzt (Minimum aus mitgeschickter Rolle und Rolle hier)
	FromNode string
	FromName string
	Back     string
	expires  time.Time
}

// Origin merkt sich eine ueber Environment entstandene Sitzung.
type Origin struct {
	MaxRole  string
	FromNode string
	FromName string
	Back     string
}

// Node ist eine Zeile der Liste (ohne diese Node, die stellt die Oberflaeche selbst).
type Node struct {
	ID        string
	Name      string
	URL       string
	Version   string
	Online    bool
	Suspended bool
	Reason    string // Grund der Aussetzung
	Login     bool   // Oeffnen meldet mit dem eigenen Benutzer an (sonst Anmeldeseite)
}

// Deps sind die Anbindungen (Register fuellt die Cluster-Funktionen).
type Deps struct {
	Store *store.Store
	Log   *slog.Logger
	// Members: Mitglieder des Clusters.
	Members func(ctx context.Context) ([]peer.Member, error)
	// AreaOn: Mitglieder, bei denen ein Bereich hier und dort an ist (peer.AreaMembers).
	AreaOn func(ctx context.Context, module, item string) []peer.Member
	// Call: Ticket bei einer anderen Node anfragen.
	Call func(ctx context.Context, nodeID string, in TicketRequest, out *TicketResponse) error
	Now  func() time.Time
	// E2: Verschluesselung der Zugangsschluessel (nil nur in Tests), Kennung, Name, oeffentlicher Schluessel und
	// Version dieser Node, Aenderungen an den Cluster melden (Register fuellt NodeID, PublicKey und Change).
	Box       *secrets.Box
	NodeID    func() string
	NodeName  func() string
	PublicKey func() string
	Version   string
	Change    func(ctx context.Context, module, item, id string, deleted bool)
}

// Service stellt Tickets aus, loest sie ein und merkt sich die Sitzungen.
type Service struct {
	d       Deps
	mu      sync.Mutex
	tickets map[string]*Ticket
	nc      nonces // gebundene Anfragen (remote.go)
}

// New baut den Dienst.
func New(d Deps) *Service {
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Service{d: d, tickets: map[string]*Ticket{}}
}

// moduleInfo: Bereiche environment/login (nur Schalter) und environment/nodes (hinzugefuegte Nodes, nodes.go).
var moduleInfo = peer.ModuleInfo{ID: ModuleID, TitleKey: "cluster.mod.environment", Default: true, Items: []peer.ItemInfo{
	{ID: ItemLogin, TitleKey: "cluster.item.environment_login", HintKey: "cluster.environment_hint", Default: true},
	{ID: ItemNodes, TitleKey: "cluster.item.environment_nodes", HintKey: "cluster.environment_nodes_hint", Default: true},
}}

// Register meldet Environment beim Cluster an (vor peer.Run) und haengt die Cluster-Funktionen an.
func Register(pm *peer.Manager, s *Service) {
	pm.RegisterProvider(provider{s})
	pm.RegisterCall(ModuleID, CallTicket, s.HandleTicket)
	s.d.Members = pm.Members
	s.d.AreaOn = pm.AreaMembers
	s.d.NodeID = pm.NodeID
	s.d.PublicKey = pm.PublicKey
	s.d.Change = pm.ClusterChange
	s.d.Call = func(ctx context.Context, nodeID string, in TicketRequest, out *TicketResponse) error {
		return pm.Call(ctx, nodeID, ModuleID, CallTicket, in, out)
	}
}

func hasMember(list []peer.Member, id string) bool {
	for _, x := range list {
		if x.NodeID == id {
			return true
		}
	}
	return false
}

// loginWith: Oeffnen der Node meldet mit dem eigenen Benutzer an (Benutzer-Abgleich und environment/login auf
// beiden Seiten an, nicht ausgesetzt).
func (s *Service) loginWith(ctx context.Context, nodeID string) bool {
	if s.d.AreaOn == nil {
		return false
	}
	return hasMember(s.d.AreaOn(ctx, "users", "accounts"), nodeID) && hasMember(s.d.AreaOn(ctx, ModuleID, ItemLogin), nodeID)
}

// Nodes liefert die Mitglieder des Clusters fuer die Liste.
func (s *Service) Nodes(ctx context.Context) []Node {
	if s.d.Members == nil {
		return nil
	}
	list, _ := s.d.Members(ctx)
	out := make([]Node, 0, len(list))
	for _, x := range list {
		out = append(out, Node{ID: x.NodeID, Name: x.Name, URL: strings.TrimRight(x.URL, "/"), Version: x.Version, Online: x.Online(),
			Suspended: x.Suspended(), Reason: x.Reason, Login: !x.Suspended() && s.loginWith(ctx, x.NodeID)})
	}
	return out
}

// Member liefert ein Mitglied (nil = unbekannt).
func (s *Service) Member(ctx context.Context, id string) *Node {
	for _, n := range s.Nodes(ctx) {
		if n.ID == id {
			return &n
		}
	}
	return nil
}

// RequestTicket fragt auf der oeffnenden Node ein Ticket bei einer anderen Node an.
func (s *Service) RequestTicket(ctx context.Context, nodeID string, req TicketRequest) (string, error) {
	if s.d.Call == nil {
		return "", peer.ErrCallUnavailable
	}
	var out TicketResponse
	if err := s.d.Call(ctx, nodeID, req, &out); err != nil {
		return "", err
	}
	if len(out.Ticket) < 40 {
		return "", errors.New("environment: invalid ticket")
	}
	return out.Ticket, nil
}

// HandleTicket beantwortet die Ticket-Anfrage einer anderen Node (from: deren Kennung). Abgelehnte Anfragen stehen als
// Warnung im Log und im Audit-Log.
func (s *Service) HandleTicket(ctx context.Context, from string, body []byte) (any, error) {
	var req TicketRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, errors.New("environment: invalid request")
	}
	t, err := s.issue(ctx, from, req)
	if err != nil {
		s.d.Log.Warn("environment ticket denied", "from", from, "err", err)
		s.audit(ctx, from, "environment.ticket_denied", "", err.Error())
		return nil, err
	}
	return TicketResponse{Ticket: t}, nil
}

func (s *Service) issue(ctx context.Context, from string, req TicketRequest) (string, error) {
	if s.d.Members == nil {
		return "", ErrMember
	}
	list, _ := s.d.Members(ctx)
	var m *peer.Member
	for i := range list {
		if list[i].NodeID == from {
			m = &list[i]
		}
	}
	if m == nil || m.Suspended() {
		return "", ErrMember
	}
	if s.d.AreaOn == nil || !hasMember(s.d.AreaOn(ctx, "users", "accounts"), from) {
		return "", ErrNoUserSync
	}
	if !uidRe.MatchString(req.UID) {
		return "", ErrUnknownUser
	}
	u, err := s.d.Store.UserByUID(ctx, req.UID)
	if err != nil {
		return "", err
	}
	if u == nil {
		return "", ErrUnknownUser
	}
	if u.Disabled {
		return "", ErrLocked
	}
	back := ""
	if p, err := url.Parse(req.Back); err == nil && (p.Scheme == "https" || p.Scheme == "http") && p.Host != "" && len(req.Back) <= 512 {
		back = p.String()
	}
	return s.addTicket(&Ticket{UID: u.UID, Role: MinRole(req.Role, s.d.Store.EffectiveRole(ctx, u)), FromNode: from, FromName: m.Name, Back: back})
}

// addTicket legt ein Ticket (60 s gueltig) an und liefert es.
func (s *Service) addTicket(t *Ticket) (string, error) {
	t.expires = s.d.Now().Add(TicketTTL)
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := base64.RawURLEncoding.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked()
	if len(s.tickets) >= maxTickets {
		return "", errors.New("environment: too many open tickets")
	}
	s.tickets[tok] = t
	return tok, nil
}

func (s *Service) purgeLocked() {
	now := s.d.Now()
	for k, t := range s.tickets {
		if !now.Before(t.expires) {
			delete(s.tickets, k)
		}
	}
}

// Redeem loest ein Ticket ein (einmal; abgelaufen oder unbekannt: ok=false).
func (s *Service) Redeem(tok string) (*Ticket, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tickets[tok]
	if !ok {
		return nil, false
	}
	delete(s.tickets, tok)
	if !s.d.Now().Before(t.expires) {
		return nil, false
	}
	return t, true
}

// SaveSession merkt sich eine ueber Environment angelegte Sitzung (und raeumt Zeilen beendeter Sitzungen auf).
func (s *Service) SaveSession(ctx context.Context, sessionID string, o Origin) error {
	w := s.d.Store.Writer()
	_, _ = w.ExecContext(ctx, `DELETE FROM env_sessions WHERE session_id NOT IN (SELECT id FROM sessions)`)
	_, err := w.ExecContext(ctx, `INSERT OR REPLACE INTO env_sessions (session_id, max_role, from_node, from_name, back_url, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, sessionID, MinRole(o.MaxRole, o.MaxRole), // unbekannte Rolle: nur lesen
		o.FromNode, o.FromName, o.Back, store.Now())
	return err
}

// SessionOrigin liefert die Herkunft einer Sitzung (nil = normale Anmeldung). Bei einem Fehler weiss niemand, ob
// die Sitzung begrenzt ist: der Aufrufer behandelt sie dann als „nur lesen“.
func (s *Service) SessionOrigin(ctx context.Context, sessionID string) (*Origin, error) {
	if sessionID == "" {
		return nil, nil
	}
	var o Origin
	err := s.d.Store.Reader().QueryRowContext(ctx, `SELECT max_role, from_node, from_name, back_url FROM env_sessions WHERE session_id = ?`,
		sessionID).Scan(&o.MaxRole, &o.FromNode, &o.FromName, &o.Back)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &o, nil
}

func (s *Service) audit(ctx context.Context, from, action, target, details string) {
	by := from
	if s.d.Members != nil {
		if list, err := s.d.Members(ctx); err == nil {
			for _, x := range list {
				if x.NodeID == from {
					by = x.Name
				}
			}
		}
	}
	if err := s.d.Store.Audit(context.WithoutCancel(ctx), store.AuditEntry{Actor: "node:" + by, Action: action, Target: target, Details: details, Origin: "peer"}); err != nil {
		s.d.Log.Error("audit write failed", "err", err)
	}
}
