// Package peer ist der Cluster (frueher lokale Gruppe): Nodes desselben ipv64-Accounts (Nodes ohne Account duerfen
// dazu, nie zwei verschiedene Accounts) koppeln sich per Code und gleichen direkt untereinander ab (nur HTTPS, auch
// in verschiedenen Netzen), zusaetzlich zum hub.
//
// Vertrauen: jede Node hat ein Ed25519-Schluesselpaar. Gekoppelt wird mit einem Code, den Node A zeigt und
// der auf Node B eingegeben wird; beide beweisen per HMAC, dass sie den Code kennen (er geht nie im Klartext
// ueber das Netz) und tauschen ihre Schluessel. Danach ist jede Anfrage und jede Antwort signiert und an die
// TLS-Verbindung gebunden (transport.go), und der ipv64-Account der Absenderin muss bei jeder Anfrage zum Cluster
// passen (gleich oder 0, siehe compatible). Aendert sich etwas Grundlegendes, wird das Mitglied ausgesetzt
// (suspend.go).
package peer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Migrations liefert das Schema der lokalen Gruppe.
func Migrations() ([]store.Migration, error) { return store.ReadMigrations(migrationFS, "migrations") }

const (
	setKey    = "peer.key" // privater Schluessel (verschluesselt)
	codeTTL   = 10 * time.Minute
	pingEvery = 30 * time.Second
	offline   = 2 * time.Minute
	timeSkew  = 5 * time.Minute
)

// Errors der Kopplung (fuer verstaendliche Meldungen in der Oberflaeche).
var (
	// ErrNoAccount wird nicht mehr geliefert (Konto 0 = alle ohne ipv64 ist erlaubt), bleibt fuer die Oberflaeche.
	ErrNoAccount       = errors.New("no ipv64 account")
	ErrAccountMismatch = errors.New("account mismatch")
	ErrCode            = errors.New("code wrong or expired")
	ErrSelf            = errors.New("cannot pair with itself")
	// ErrNoHTTPS: diese oder die andere Node hat keinen HTTPS-Port (der Cluster spricht nur HTTPS).
	ErrNoHTTPS = errors.New("cluster needs https")
	// ErrTLSBinding: die Verbindung ist nicht direkt (z. B. TLS-terminierender Proxy dazwischen).
	ErrTLSBinding = errors.New("connection not bound to the pairing (proxy in between?)")
	// ErrSuspended: das Mitglied ist ausgesetzt (keine Kommunikation, Grund in Member.Reason).
	ErrSuspended = errors.New("cluster member suspended")
	// ErrUnknownMember: keine Node mit dieser Kennung in der Gruppe.
	ErrUnknownMember = errors.New("unknown group member")
	// errPeerHCOff: bei der anderen Node ist Healthchecks aus (dort nichts abzuholen).
	errPeerHCOff = errors.New("healthchecks not running on that node")
)

// Member ist eine andere Node der Gruppe.
type Member struct {
	NodeID    string    `json:"node_id"`
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	PubKey    string    `json:"pubkey"`
	AccountID int64     `json:"account_id"`
	AddedAt   time.Time `json:"-"`
	AddedBy   string    `json:"-"`
	LastSeen  time.Time `json:"-"`
	LastError string    `json:"-"`
	Version   string    `json:"-"`
	Linked    bool      `json:"-"` // mit dem hub verknuepft
	Sync      []string  `json:"-"` // eingeschaltete Cluster-Bereiche "modul/bereich" laut Ping (nil = aeltere Version)
	State     string    `json:"-"` // "" bzw. "active", "suspended" (suspend.go)
	Reason    string    `json:"-"` // Grund der Aussetzung (Kennung, z. B. account_changed)
	// SelfAccount: eigener Account bei der Kopplung (passend geaendert wird er nachgefuehrt, sonst ausgesetzt)
	SelfAccount int64 `json:"-"`
}

// Online: in den letzten zwei Minuten erreicht (ausgesetzte nie).
func (m Member) Online() bool {
	return !m.Suspended() && !m.LastSeen.IsZero() && time.Since(m.LastSeen) < offline
}

// Deps sind die Anbindungen an den Rest der Node.
type Deps struct {
	Core      *store.Store
	Box       *secrets.Box
	Log       *slog.Logger
	Version   string
	NodeID    func() string
	NodeName  func() string
	AccountID func() int64  // ipv64-Account (Healthchecks-Sync oder API-Key), 0 = keiner
	Checks    func() Checks // Healthchecks-Modul (nil bzw. Rueckgabe nil = nicht aktiv)
	Linked    func() bool   // mit dem hub verknuepft (Healthchecks-Sync)
	// HubNotifies: der hub ist verbunden und bestaetigt, er uebernimmt die Benachrichtigungen
	HubNotifies func() bool
	// SettingsToHub meldet geaenderte Benachrichtigungs-Einstellungen an den hub (settings.go)
	SettingsToHub func()
	// Forward reicht eine uebernommene Aenderung an den hub weiter (Outbox), wenn ihre Urheberin nicht verknuepft ist
	Forward func(ctx context.Context, entity, id, op string)
	// Hub meldet nicht verknuepfte Mitglieder als Stellvertreter-Nodes beim hub an (proxy.go), nil = nie
	Hub Hub
	// HTTPSPort, unter dem die anderen Nodes diese erreichen (der Cluster spricht nur HTTPS), 0 bzw. nil = keiner
	HTTPSPort func() int
	// Notify verschickt Meldungen (Mitglied nicht erreichbar/wieder da, watch.go), nil = keine
	Notify func(notify.Alert)
}

// Manager verwaltet Identitaet, Kopplung und Mitglieder.
type Manager struct {
	d      Deps
	db     *sql.DB
	priv   ed25519.PrivateKey
	pull   pullState   // Abgleich der Konfiguration (config.go)
	ready  atomic.Bool // erster Abgleich nach dem Start erledigt (notify.go)
	seeded atomic.Bool // vorhandene Checks und Fenster im Protokoll (config.go)

	mu      sync.Mutex
	prov    map[string]Provider // Module, die ueber den Cluster abgleichen (cluster.go)
	watch   map[string]bool     // Mitglieder, deren Ausfall diese Node gemeldet hat (watch.go)
	proxied map[string]bool     // Mitglieder, deren zurueckgehaltene Checks schon an den hub gingen (proxy.go)
	code    string              // offener Kopplungscode
	exp     time.Time
	tries   int

	nmu    sync.Mutex
	nonces map[string]time.Time // gesehene Nonces der Anfragen (Wiederholungsschutz, transport.go)
}

// New laedt bzw. erzeugt den Schluessel.
func New(ctx context.Context, d Deps) (*Manager, error) {
	m := &Manager{d: d, db: d.Core.Writer()}
	m.pull.kick, m.pull.busy = make(chan string, 16), map[string]*sync.Mutex{}
	raw := d.Core.SettingOr(ctx, setKey, "")
	if raw != "" && d.Box != nil {
		if plain, err := d.Box.Decrypt(raw); err == nil {
			raw = plain
		}
	}
	if b, err := base64.StdEncoding.DecodeString(raw); err == nil && len(b) == ed25519.PrivateKeySize {
		m.priv = ed25519.PrivateKey(b)
		return m, nil
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	m.priv = priv
	v := base64.StdEncoding.EncodeToString(priv)
	if d.Box != nil {
		v = d.Box.Encrypt(v)
	}
	return m, d.Core.SetSetting(ctx, setKey, v)
}

// Account ist der ipv64-Account dieser Node (0 = keiner; passt zu jedem Cluster, siehe compatible).
func (m *Manager) Account() int64 { return m.d.AccountID() }

// PublicKey der eigenen Node (base64).
func (m *Manager) PublicKey() string {
	return base64.StdEncoding.EncodeToString(m.priv.Public().(ed25519.PublicKey))
}

// Members liefert die Gruppe (ohne die eigene Node), nach Name sortiert.
func (m *Manager) Members(ctx context.Context) ([]Member, error) {
	rows, err := m.db.QueryContext(ctx, `SELECT node_id, name, url, pubkey, account_id, added_at, added_by, last_seen, last_error, version, linked, sync,
		state, reason, self_account FROM peer_members ORDER BY name, node_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		var x Member
		var added, seen string
		var caps sql.NullString
		if err := rows.Scan(&x.NodeID, &x.Name, &x.URL, &x.PubKey, &x.AccountID, &added, &x.AddedBy, &seen, &x.LastError, &x.Version, &x.Linked, &caps,
			&x.State, &x.Reason, &x.SelfAccount); err != nil {
			return nil, err
		}
		if caps.Valid {
			x.Sync = splitCaps(caps.String)
		}
		x.AddedAt, x.LastSeen = parseTime(added), parseTime(seen)
		out = append(out, x)
	}
	return out, rows.Err()
}

func (m *Manager) member(ctx context.Context, nodeID string) (*Member, error) {
	list, err := m.Members(ctx)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].NodeID == nodeID {
			return &list[i], nil
		}
	}
	return nil, nil
}

// upsert nimmt eine Node auf oder aktualisiert Name, Adresse (immer https) und Schluessel.
func (m *Manager) upsert(ctx context.Context, x Member, by string) error {
	if x.NodeID == "" || x.NodeID == m.d.NodeID() || x.PubKey == "" {
		return nil
	}
	_, err := m.db.ExecContext(ctx, `INSERT INTO peer_members (node_id, name, url, pubkey, account_id, added_at, added_by, self_account) VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(node_id) DO UPDATE SET name = excluded.name, url = CASE WHEN excluded.url != '' THEN excluded.url ELSE url END,
		pubkey = excluded.pubkey, account_id = excluded.account_id`,
		x.NodeID, trunc(x.Name, 100), trunc(httpsURL(x.URL), 300), x.PubKey, x.AccountID, fmtTime(time.Now()), by, m.d.AccountID())
	return err
}

func (m *Manager) remove(ctx context.Context, nodeID string) error {
	_, err := m.db.ExecContext(ctx, `DELETE FROM peer_members WHERE node_id = ?`, nodeID)
	return err
}

// SetURL aendert die Adresse einer Node (falls sie umgezogen ist; immer https, ohne Schema wird es ergaenzt).
func (m *Manager) SetURL(ctx context.Context, nodeID, url string) error {
	res, err := m.db.ExecContext(ctx, `UPDATE peer_members SET url = ? WHERE node_id = ?`, trunc(httpsURL(url), 300), nodeID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUnknownMember
	}
	return nil
}

func (m *Manager) seen(ctx context.Context, nodeID string, info pingInfo, err error) {
	if err != nil {
		_, _ = m.db.ExecContext(ctx, `UPDATE peer_members SET last_error = ? WHERE node_id = ?`, trunc(err.Error(), 300), nodeID)
		return
	}
	var caps any // aeltere Version ohne Angabe: NULL (gleicht nur Healthchecks ab)
	if info.Sync != nil {
		caps = joinCaps(info.Sync)
	}
	// account_id: der aktuelle Account des Mitglieds (passend geaendert, z. B. 0→X nach Uebernahme des API-Keys)
	_, _ = m.db.ExecContext(ctx, `UPDATE peer_members SET last_seen = ?, last_error = '', version = ?, linked = ?, sync = ?, account_id = ?, name = CASE WHEN ? != '' THEN ? ELSE name END WHERE node_id = ?`,
		fmtTime(time.Now()), trunc(info.Version, 32), info.Linked, caps, info.AccountID, info.Name, trunc(info.Name, 100), nodeID)
}

// linkedSelf: diese Node ist mit dem hub verknuepft.
func (m *Manager) linkedSelf() bool { return m.d.Linked != nil && m.d.Linked() }

// forwarder: diese Node reicht Aenderungen nicht verknuepfter Nodes an den hub weiter (genau eine: die mit der
// kleinsten Kennung unter den erreichbaren verknuepften Nodes, damit der hub nichts doppelt bekommt).
func (m *Manager) forwarder(ctx context.Context) bool {
	if !m.linkedSelf() {
		return false
	}
	self := m.d.NodeID()
	list, _ := m.Members(ctx)
	for _, x := range list {
		if x.Linked && x.Online() && x.NodeID < self {
			return false
		}
	}
	return true
}

// Run pingt die Gruppe regelmaessig (Erreichbarkeit, Version, Account).
func (m *Manager) Run(ctx context.Context) {
	m.seed(ctx)
	go m.pullLoop(ctx)
	t := time.NewTicker(pingEvery)
	defer t.Stop()
	m.pingAll(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.pingAll(ctx)
			m.watchMembers(ctx)
		}
	}
}

func (m *Manager) pingAll(ctx context.Context) {
	m.checkAccount(ctx) // eigener Account geaendert: passend vermerken, sonst Mitglieder der alten Kopplung aussetzen
	if list, err := m.Members(ctx); err == nil {
		for _, x := range list { // nur wegen alter Version ausgesetzt: nach deren Update von selbst wieder aktiv
			if x.Suspended() && x.Reason == ReasonVersionTooOld {
				_ = m.Resume(ctx, x.NodeID)
			}
		}
	}
	for _, x := range m.activeMembers(ctx) {
		var out pingInfo
		err := m.call(ctx, x, http.MethodGet, "/peer/v1/ping", nil, &out)
		switch {
		case errors.Is(err, ErrSuspended):
			continue // eben ausgesetzt (Grund steht fest)
		case err == nil && out.NodeID != x.NodeID:
			m.suspend(ctx, x, ReasonIdentityChanged, "other node at this address")
			continue
		case err == nil && !compatible(out.AccountID, m.ClusterAccount(ctx)): // anderer Account als der des Clusters
			m.suspend(ctx, x, ReasonAccountMismatch, "account of the other node does not match")
			continue
		}
		m.seen(ctx, x.NodeID, out, err)
	}
}

type pingInfo struct {
	NodeID    string   `json:"node_id"`
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	AccountID int64    `json:"account_id"`
	Linked    bool     `json:"linked"`
	Sync      []string `json:"sync"` // eingeschaltete Cluster-Bereiche (cluster.go; leer = nichts an, fehlt = aeltere Version)
}

func fmtTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }
func parseTime(s string) time.Time {
	t, _ := time.Parse("2006-01-02T15:04:05.000Z", s)
	return t
}
func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
