// Package certs ist die Zertifikatsverwaltung des Kerns: Zertifikate von Let's Encrypt (ipv64 DNS-01, ipv64-Alias
// per CNAME, HTTP-01) und hochgeladene. Abnehmer sind der gemeinsame Eingang (edge) und damit CDN64, spaeter DNS64
// und die Oberflaeche. Der private Schluessel liegt mit secret.key verschluesselt in der Datenbank; damit sind die
// Zertifikate im Backup.
//
// Erneuert wird 30 Tage vor Ablauf, solange es Zertifikate gibt (die Verwaltung haelt sich dann selbst) oder ein
// Abnehmer die Verwaltung haelt (Acquire). Ohne Zertifikate und Abnehmer laeuft keine Schleife, damit im
// Leerlauf nichts laeuft. Ein Abruf von Hand geht immer.
package certs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"embed"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Migrations: Tabellen der Zertifikatsverwaltung (Scope "certs").
func Migrations() ([]store.Migration, error) { return store.ReadMigrations(migrationFS, "migrations") }

// Wege zum Zertifikat.
const (
	SourceIPv64  = "ipv64"  // DNS-01, die Namen liegen im ipv64-Account
	SourceAlias  = "alias"  // DNS-01 ueber CNAME _acme-challenge.<name> -> ipv64-Domain (fremde Domains)
	SourceHTTP   = "http"   // HTTP-01 ueber Port 80 des Eingangs
	SourceDNS    = "dns"    // DNS-01 ueber einen anderen DNS-Anbieter (lego, Zugang in cert_dns_accounts)
	SourceUpload = "upload" // eigenes Zertifikat
	SourceCA     = "ca"     // von einer eigenen CA der Verwaltung ausgestellt (auch fuer IPs)
)

// Zustaende.
const (
	StatusPending = "pending" // angelegt, noch nicht geholt
	StatusValid   = "valid"
	StatusError   = "error" // letzter Abruf gescheitert (ein vorhandenes Zertifikat gilt weiter)
	StatusExpired = "expired"
)

const (
	setEmail = "certs.acme_email"
	setTOS   = "certs.acme_tos" // Nutzungsbedingungen von Let's Encrypt angenommen (Zeitpunkt)
	setKey   = "certs.acme_key" // Kontoschluessel (verschluesselt)

	renewBefore = 30 * 24 * time.Hour
	retryAfter  = 6 * time.Hour
	maxNames    = 100 // Grenze von Let's Encrypt
)

var (
	ErrNotFound = errors.New("certificate not found")
	ErrInUse    = errors.New("certificate is in use")
	ErrBusy     = errors.New("certificate is being issued")
	ErrTOS      = errors.New("terms of service of Let's Encrypt not accepted")
	ErrNoKey    = errors.New("no ipv64 API key")
	ErrUpload   = errors.New("uploaded certificates cannot be renewed")
)

// Cert ist ein Zertifikat ohne Schluessel.
type Cert struct {
	ID          int64     `json:"id"`
	Names       []string  `json:"names"`
	Source      string    `json:"source"`
	AliasZone   string    `json:"alias_zone,omitempty"`
	AliasPrefix string    `json:"alias_prefix,omitempty"`
	DNSAccount  int64     `json:"dns_account,omitempty"` // source dns
	CAID        int64     `json:"ca_id,omitempty"`       // source ca
	Days        int       `json:"days,omitempty"`        // source ca/self: Laufzeit
	KeyType     string    `json:"key_type,omitempty"`    // source self: ecdsa oder rsa
	ACMECA      int64     `json:"acme_ca,omitempty"`     // 0 = Let's Encrypt, sonst weitere ACME-Stelle
	Staging     bool      `json:"staging"`
	AutoRenew   bool      `json:"auto_renew"`
	Status      string    `json:"status"`
	Step        string    `json:"step,omitempty"` // laufender Schritt beim Abruf
	Issuer      string    `json:"issuer,omitempty"`
	NotBefore   time.Time `json:"not_before,omitzero"`
	NotAfter    time.Time `json:"not_after,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
	LastAttempt time.Time `json:"last_attempt,omitzero"`
	UsedBy      []string  `json:"used_by,omitempty"`
	UID         string    `json:"uid"`                   // stabile Kennung (Cluster)
	RenewedBy   string    `json:"renewed_by,omitempty"`  // Cluster: Node, die erneuert ("" = diese)
	RefMissing  bool      `json:"ref_missing,omitempty"` // Cluster: ACME-Stelle, DNS-Zugang oder CA fehlt hier (keine Erneuerung)
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	hasCert     bool
	warned      string
}

// DaysLeft: ganze Tage bis zum Ablauf (negativ = abgelaufen, 0 ohne Zertifikat).
func (c *Cert) DaysLeft() int {
	if c.NotAfter.IsZero() {
		return 0
	}
	return int(time.Until(c.NotAfter).Hours() / 24)
}

// Title: Hauptname, bei mehreren mit Anzahl (fuer Meldungen).
func (c *Cert) Title() string {
	if len(c.Names) > 1 {
		return fmt.Sprintf("%s (+%d)", c.Names[0], len(c.Names)-1)
	}
	if len(c.Names) == 1 {
		return c.Names[0]
	}
	return fmt.Sprintf("#%d", c.ID)
}

// Presenter beantwortet HTTP-01-Pruefungen (der gemeinsame Eingang).
type Presenter interface {
	Present(token, keyAuth string) (release func(), err error)
}

// Deps sind die Abhaengigkeiten.
type Deps struct {
	Store   *store.Store
	Box     *secrets.Box
	DNS     DNSAPI             // ipv64 (Domains, TXT-Records); nil = kein DNS-01
	HTTP    Presenter          // HTTP-01; nil = nicht moeglich
	Notify  func(notify.Alert) // nil = keine Meldungen
	Log     *slog.Logger
	Version string
	// Directory und StagingDirectory der ACME-Stelle ("" = Let's Encrypt; Tests setzen einen eigenen Server).
	Directory, StagingDirectory string
}

// Manager ist die Zertifikatsverwaltung.
type Manager struct {
	d    Deps
	log  *slog.Logger
	w, r *sql.DB

	mu     sync.Mutex
	loaded map[int64]*loadedCert
	steps  map[int64]string // laufende Abrufe
	users  map[string]func(ctx context.Context) map[int64][]string
	holds  map[string]bool
	holdMu sync.Mutex       // refreshHold: Zaehlen und Halten/Loslassen zusammen (sonst Release trotz Zertifikat)
	loadMu sync.Mutex       // reload und unload nacheinander (sonst setzt ein aelterer Stand loaded zurueck)
	onChg  []func(id int64) // nach jeder neuen Ausstellung
	stopLp context.CancelFunc
	lpDone chan struct{}
	reg    map[string]bool // ACME-Konto bei der Stelle angemeldet (je Verzeichnis)

	acme   sync.Mutex // ein Abruf gleichzeitig
	base   context.Context
	cancel context.CancelFunc
	bg     sync.WaitGroup

	// austauschbar fuer Tests
	txtVisible func(ctx context.Context, zone, fqdn, value string) error
	cnameOf    func(ctx context.Context, name string) (string, error)
	provider   func(id string, values map[string]string) (challenge.Provider, error) // nil = lego
	loopFirst  time.Duration
	loopEvery  time.Duration

	// issueTimeout: Zeitlimit eines Abrufs (ab der ACME-Sperre); manche Anbieter brauchen Minuten, bis TXT sichtbar ist
	issueTimeout time.Duration

	clSelf func() string // Cluster (cluster.go)
	clHook ClusterHook
}

type loadedCert struct {
	crt     *tls.Certificate
	leaf    *x509.Certificate
	staging bool
	public  bool // Kette endet bei einer System-Root (z. B. Let's Encrypt), nicht eigene CA/selbst signiert
}

// rank: oeffentlich vertrauenswuerdig vor eigener CA/selbst signiert/hochgeladen, Test-Zertifikate zuletzt.
func (l *loadedCert) rank() int {
	switch {
	case l.staging:
		return 0
	case l.public:
		return 2
	}
	return 1
}

// trustRoots: Roots fuer publicTrust (austauschbar fuer Tests).
var trustRoots = x509.SystemCertPool

// publicTrust: ob die Kette des Zertifikats bei einer System-Root endet.
func publicTrust(crt *tls.Certificate) bool {
	roots, err := trustRoots()
	if err != nil || roots == nil || crt.Leaf == nil {
		return false
	}
	inter := x509.NewCertPool()
	for _, der := range crt.Certificate[1:] {
		if c, err := x509.ParseCertificate(der); err == nil {
			inter.AddCert(c)
		}
	}
	_, err = crt.Leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return err == nil
}

// New legt die Verwaltung an und laedt die gueltigen Zertifikate.
func New(ctx context.Context, d Deps) (*Manager, error) {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	base, cancel := context.WithCancel(context.WithoutCancel(ctx))
	m := &Manager{d: d, log: d.Log.With("module", "certs"), w: d.Store.Writer(), r: d.Store.Reader(), loaded: map[int64]*loadedCert{},
		steps: map[int64]string{}, users: map[string]func(context.Context) map[int64][]string{}, holds: map[string]bool{}, reg: map[string]bool{},
		base: base, cancel: cancel, cnameOf: lookupCNAME, loopFirst: time.Minute, loopEvery: time.Hour, issueTimeout: 20 * time.Minute}
	m.txtVisible = m.waitTXTFor // mit den eingestellten Resolvern
	if err := m.reload(ctx); err != nil {
		cancel()
		return nil, err
	}
	m.refreshHold(ctx)
	return m, nil
}

// holdSelf: die Verwaltung haelt sich selbst, solange es Zertifikate gibt (Erneuerung und Ablauf-Warnungen auch
// fuer Zertifikate, die kein Modul benutzt, z. B. nur zum Herunterladen). Ohne Zertifikate laeuft nichts.
const holdSelf = "certs"

func (m *Manager) refreshHold(ctx context.Context) {
	m.holdMu.Lock()
	defer m.holdMu.Unlock()
	var n int
	if err := m.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM certs`).Scan(&n); err != nil {
		return
	}
	if n > 0 {
		m.Acquire(holdSelf)
	} else {
		m.Release(holdSelf)
	}
}

// SetHTTP haengt den Eingang fuer HTTP-01 an (beim Start, vor dem ersten Abruf).
func (m *Manager) SetHTTP(p Presenter) { m.d.HTTP = p }

// Close beendet laufende Abrufe und die Erneuerung.
func (m *Manager) Close() {
	m.mu.Lock()
	stop, done := m.stopLp, m.lpDone
	m.stopLp, m.lpDone = nil, nil
	m.mu.Unlock()
	if stop != nil {
		stop()
		<-done
	}
	m.cancel()
	m.bg.Wait()
}

// ---------------------------------------------------------------- Lesen

const cols = `id, names, source, alias_zone, alias_prefix, dns_account, staging, auto_renew, cert_pem != '', not_before, not_after, issuer, status, last_error,
	last_attempt, warned, created_at, updated_at, ca_id, days, acme_ca, key_type, uid, renewer, (source = 'dns' AND dns_account = 0 AND ref_dns_account != '') OR
	(source = 'ca' AND ca_id = 0 AND ref_ca != '') OR (acme_ca = 0 AND ref_acme_ca != '')`

func (m *Manager) scan(row interface{ Scan(...any) error }) (*Cert, error) {
	var c Cert
	var names, nb, na, la, ca, ua string
	if err := row.Scan(&c.ID, &names, &c.Source, &c.AliasZone, &c.AliasPrefix, &c.DNSAccount, &c.Staging, &c.AutoRenew, &c.hasCert, &nb, &na, &c.Issuer,
		&c.Status, &c.LastError, &la, &c.warned, &ca, &ua, &c.CAID, &c.Days, &c.ACMECA, &c.KeyType, &c.UID, &c.RenewedBy, &c.RefMissing); err != nil {
		return nil, err
	}
	c.Names = strings.Split(names, ",")
	c.LastError = notify.RedactSecrets(c.LastError) // auch aeltere Eintraege (vor der Schwaerzung gespeichert)
	c.NotBefore, c.NotAfter, c.LastAttempt = store.ParseTime(nb), store.ParseTime(na), store.ParseTime(la)
	c.CreatedAt, c.UpdatedAt = store.ParseTime(ca), store.ParseTime(ua)
	if c.hasCert && !c.NotAfter.IsZero() && time.Now().After(c.NotAfter) && c.Status != StatusError {
		c.Status = StatusExpired
	}
	return &c, nil
}

func (m *Manager) decorate(ctx context.Context, list []*Cert) {
	used := m.usedBy(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range list {
		c.Step = m.steps[c.ID]
		c.UsedBy = used[c.ID]
	}
}

// List liefert alle Zertifikate (ablaufende zuerst).
func (m *Manager) List(ctx context.Context) ([]*Cert, error) {
	rows, err := m.r.QueryContext(ctx, `SELECT `+cols+` FROM certs`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Cert
	for rows.Next() {
		c, err := m.scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].NotAfter, out[j].NotAfter
		if a.IsZero() != b.IsZero() {
			return a.IsZero() // ohne Zertifikat zuerst (Abruf laeuft oder gescheitert)
		}
		if !a.Equal(b) {
			return a.Before(b)
		}
		return out[i].ID < out[j].ID
	})
	m.decorate(ctx, out)
	return out, nil
}

// Get liefert ein Zertifikat.
func (m *Manager) Get(ctx context.Context, id int64) (*Cert, error) {
	c, err := m.scan(m.r.QueryRowContext(ctx, `SELECT `+cols+` FROM certs WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	m.decorate(ctx, []*Cert{c})
	return c, nil
}

// Chain liefert Zertifikat und Kette als PEM (ohne Schluessel).
func (m *Manager) Chain(ctx context.Context, id int64) (string, error) {
	var pemStr string
	err := m.r.QueryRowContext(ctx, `SELECT cert_pem FROM certs WHERE id = ?`, id).Scan(&pemStr)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && pemStr == "") {
		return "", ErrNotFound
	}
	return pemStr, err
}

// ---------------------------------------------------------------- Abnehmer

// SetUsers meldet, welche Zertifikate ein Abnehmer benutzt (Anzeige "benutzt von", Schutz beim Loeschen).
func (m *Manager) SetUsers(owner string, f func(ctx context.Context) map[int64][]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f == nil {
		delete(m.users, owner)
		return
	}
	m.users[owner] = f
}

func (m *Manager) usedBy(ctx context.Context) map[int64][]string {
	m.mu.Lock()
	fs := make([]func(context.Context) map[int64][]string, 0, len(m.users))
	for _, f := range m.users {
		fs = append(fs, f)
	}
	m.mu.Unlock()
	out := map[int64][]string{}
	for _, f := range fs {
		for id, list := range f(ctx) {
			out[id] = append(out[id], list...)
		}
	}
	return out
}

// ForName liefert ein gueltiges Zertifikat fuer den Namen (auch ueber Wildcard): oeffentlich vertrauenswuerdige vor
// eigener CA/selbst signierten, diese vor Test-Zertifikaten, sonst das am laengsten gueltige.
func (m *Manager) ForName(name string) *tls.Certificate {
	if id := m.MatchID(name); id > 0 {
		return m.ByID(id)
	}
	return nil
}

// MatchID: Kennung des Zertifikats, das ForName fuer den Namen liefern wuerde (0 = keins).
func (m *Manager) MatchID(name string) int64 {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	var best *loadedCert
	var id int64
	for i, l := range m.loaded {
		if now.Before(l.leaf.NotBefore) || now.After(l.leaf.NotAfter) || l.leaf.VerifyHostname(name) != nil {
			continue
		}
		if best == nil || l.rank() > best.rank() || (l.rank() == best.rank() && l.leaf.NotAfter.After(best.leaf.NotAfter)) {
			best, id = l, i
		}
	}
	return id
}

// ByID liefert ein bestimmtes gueltiges Zertifikat.
func (m *Manager) ByID(id int64) *tls.Certificate {
	m.mu.Lock()
	defer m.mu.Unlock()
	l := m.loaded[id]
	if l == nil || time.Now().After(l.leaf.NotAfter) {
		return nil
	}
	return l.crt
}

// reload liest alle Zertifikate mit Schluessel in den Speicher.
func (m *Manager) reload(ctx context.Context) error {
	m.loadMu.Lock() // Abfrage und Austausch zusammen: der zuletzt gelesene Stand gewinnt
	defer m.loadMu.Unlock()
	rows, err := m.r.QueryContext(ctx, `SELECT id, cert_pem, key_pem, staging FROM certs WHERE cert_pem != ''`)
	if err != nil {
		return err
	}
	defer rows.Close()
	loaded := map[int64]*loadedCert{}
	for rows.Next() {
		var id int64
		var certPEM, keySealed string
		var staging bool
		if err := rows.Scan(&id, &certPEM, &keySealed, &staging); err != nil {
			return err
		}
		keyPEM, err := m.d.Box.Decrypt(keySealed)
		if err != nil {
			m.log.Error("certificate key not readable", "id", id, "err", err)
			continue
		}
		crt, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
		if err != nil {
			m.log.Error("certificate not loadable", "id", id, "err", err)
			continue
		}
		loaded[id] = &loadedCert{crt: &crt, leaf: crt.Leaf, staging: staging, public: !staging && publicTrust(&crt)}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	m.loaded = loaded
	m.mu.Unlock()
	return nil
}

// unload nimmt ein geloeschtes Zertifikat aus dem Speicher (nach einem laufenden reload, der es noch gelesen hat).
func (m *Manager) unload(id int64) {
	m.loadMu.Lock()
	defer m.loadMu.Unlock()
	m.mu.Lock()
	delete(m.loaded, id)
	m.mu.Unlock()
}

// ---------------------------------------------------------------- Konto

// Account sind die Einstellungen des ACME-Kontos.
type Account struct {
	Email       string    `json:"email"`
	TOSAccepted bool      `json:"tos_accepted"`
	TOSAt       time.Time `json:"tos_at,omitzero"`
	TOSURL      string    `json:"tos_url"`
}

func (m *Manager) Account(ctx context.Context) Account {
	at := store.ParseTime(m.d.Store.SettingOr(ctx, setTOS, ""))
	return Account{Email: m.d.Store.SettingOr(ctx, setEmail, ""), TOSAccepted: !at.IsZero(), TOSAt: at, TOSURL: "https://letsencrypt.org/repository/"}
}

// SetAccount speichert Mail (optional) und die Annahme der Nutzungsbedingungen (zuruecknehmen geht nicht, dafuer
// genuegt es, nichts mehr anzufordern).
func (m *Manager) SetAccount(ctx context.Context, email string, acceptTOS bool) error {
	email = strings.TrimSpace(email)
	if email != "" {
		if a, err := mail.ParseAddress(email); err != nil || a.Address != email || len(email) > 254 {
			return fmt.Errorf("invalid email address")
		}
	}
	if err := m.d.Store.SetSetting(ctx, setEmail, email); err != nil {
		return err
	}
	if acceptTOS && m.d.Store.SettingOr(ctx, setTOS, "") == "" {
		if err := m.d.Store.SetSetting(ctx, setTOS, store.Now()); err != nil {
			return err
		}
	}
	m.mu.Lock()
	m.reg = map[string]bool{} // Kontaktadresse beim naechsten Abruf aktualisieren
	m.mu.Unlock()
	if m.d.Store.SettingOr(ctx, setKey, "") != "" { // ohne Kontoschluessel gibt es im Cluster noch kein Konto
		m.changedUID(ctx, ItemACME, clusterAccount, false)
	}
	return nil
}

// ---------------------------------------------------------------- Anlegen, Hochladen, Loeschen

// Request ist ein neues Zertifikat (Let's Encrypt, andere ACME-Stelle oder eigene CA).
type Request struct {
	Names       []string `json:"names"`
	Source      string   `json:"source"`       // ipv64, alias, http
	AliasZone   string   `json:"alias_zone"`   // alias
	AliasPrefix string   `json:"alias_prefix"` // alias, optional
	DNSAccount  int64    `json:"dns_account"`  // dns: Zugang
	CAID        int64    `json:"ca_id"`        // ca: eigene CA
	Days        int      `json:"days"`         // ca/self: Laufzeit (Standard 397, hoechstens 825)
	KeyType     string   `json:"key_type"`     // self: ecdsa (Standard) oder rsa
	ACMECA      int64    `json:"acme_ca"`      // weitere ACME-Stelle statt Let's Encrypt (0)
	Staging     bool     `json:"staging"`
	AutoRenew   *bool    `json:"auto_renew"` // Standard an
}

// ValidationError ist ein Fehler in der Anfrage (422).
type ValidationError struct{ Field, Msg string }

func (e *ValidationError) Error() string { return e.Field + ": " + e.Msg }

func invalid(field, format string, args ...any) error {
	return &ValidationError{Field: field, Msg: fmt.Sprintf(format, args...)}
}

// normNames prueft und vereinheitlicht die Namen.
func normNames(in []string) ([]string, error) { return normNamesIP(in, false) }

// normNamesIP: wie normNames, mit allowIP auch IP-Adressen (eigene CA).
func normNamesIP(in []string, allowIP bool) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, n := range in {
		if strings.TrimSpace(n) == "" {
			continue
		}
		if ip := net.ParseIP(strings.Trim(strings.TrimSpace(n), "[]")); ip != nil && allowIP {
			if s := ip.String(); !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
			continue
		}
		nn, err := edge.NormalizeName(n)
		if err != nil {
			return nil, invalid("names", "%v", err)
		}
		if !seen[nn] {
			seen[nn] = true
			out = append(out, nn)
		}
	}
	if len(out) == 0 {
		return nil, invalid("names", "at least one name")
	}
	if len(out) > maxNames {
		return nil, invalid("names", "at most %d names", maxNames)
	}
	return out, nil
}

// Create legt ein Zertifikat an und startet den Abruf im Hintergrund.
func (m *Manager) Create(ctx context.Context, req Request) (*Cert, error) {
	names, err := normNamesIP(req.Names, req.Source == SourceCA || req.Source == SourceSelf)
	if err != nil {
		return nil, err
	}
	req.AliasZone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(req.AliasZone)), ".")
	req.AliasPrefix = strings.Trim(strings.ToLower(strings.TrimSpace(req.AliasPrefix)), ".")
	switch req.Source {
	case SourceIPv64, SourceAlias:
		if m.d.DNS == nil || !m.d.DNS.Ready(ctx) {
			return nil, ErrNoKey
		}
		if req.Source == SourceIPv64 {
			for _, n := range names {
				if _, _, err := m.ipv64Target(ctx, n); err != nil {
					return nil, invalid("names", "%v", err)
				}
			}
		} else if err := m.checkAliasZone(ctx, req.AliasZone, req.AliasPrefix); err != nil {
			return nil, err
		}
	case SourceDNS:
		if _, _, err := m.dnsAccountRaw(ctx, req.DNSAccount); err != nil {
			return nil, invalid("dns_account", "unknown dns account")
		}
	case SourceHTTP:
		if m.d.HTTP == nil {
			return nil, invalid("source", "http-01 not available")
		}
		for _, n := range names {
			if strings.HasPrefix(n, "*.") {
				return nil, invalid("names", "wildcard %s needs a dns challenge (ipv64 or alias)", n)
			}
		}
	case SourceCA:
		ca, err := m.loadCA(ctx, req.CAID, false)
		if err != nil {
			return nil, invalid("ca_id", "unknown CA")
		}
		if req.Days == 0 {
			req.Days = defaultCADays
		}
		if req.Days < 1 || req.Days > maxCADays {
			return nil, invalid("days", "1 to %d days", maxCADays)
		}
		if err := ca.permits(names); err != nil {
			return nil, invalid("names", "%v", err)
		}
		req.ACMECA, req.Staging = 0, false
	case SourceSelf: // ohne Voraussetzung
		if req.Days == 0 {
			req.Days = defaultCADays
		}
		if req.Days < 1 || req.Days > maxCADays {
			return nil, invalid("days", "1 to %d days", maxCADays)
		}
		switch req.KeyType {
		case "":
			req.KeyType = KeyECDSA
		case KeyECDSA, KeyRSA:
		default:
			return nil, invalid("key_type", "ecdsa or rsa")
		}
		req.ACMECA, req.Staging = 0, false
	default:
		return nil, invalid("source", "unknown source %q", req.Source)
	}
	if req.Source != SourceSelf {
		req.KeyType = ""
	}
	if req.Source != SourceAlias {
		req.AliasZone, req.AliasPrefix = "", ""
	}
	if req.Source != SourceDNS {
		req.DNSAccount = 0
	}
	if req.Source != SourceCA {
		req.CAID = 0
	}
	if req.Source != SourceCA && req.Source != SourceSelf {
		req.Days = 0
		if req.ACMECA != 0 {
			if _, err := m.ACMECA(ctx, req.ACMECA); err != nil {
				return nil, invalid("acme_ca", "unknown ACME CA")
			}
			req.Staging = false // Staging gibt es nur bei Let's Encrypt
		} else if !m.Account(ctx).TOSAccepted {
			return nil, ErrTOS
		}
	}
	auto := req.AutoRenew == nil || *req.AutoRenew
	now := store.Now()
	res, err := m.w.ExecContext(ctx, `INSERT INTO certs (names, source, alias_zone, alias_prefix, dns_account, ca_id, days, acme_ca, key_type, staging, auto_renew,
		status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, strings.Join(names, ","), req.Source, req.AliasZone, req.AliasPrefix,
		req.DNSAccount, req.CAID, req.Days, req.ACMECA, req.KeyType, req.Staging, auto, StatusPending, now, now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	m.changed(ctx, ItemCertificates, id)
	_ = m.start(id, "new")
	m.refreshHold(ctx)
	return m.Get(ctx, id)
}

// checkAliasZone: die Ziel-Domain muss im ipv64-Account liegen.
func (m *Manager) checkAliasZone(ctx context.Context, zone, prefix string) error {
	if zone == "" {
		return invalid("alias_zone", "required")
	}
	if prefix != "" {
		if _, err := edge.NormalizeName(prefix + "." + zone); err != nil || strings.Contains(prefix, "*") {
			return invalid("alias_prefix", "invalid")
		}
	}
	domains, err := m.d.DNS.Domains(ctx)
	if err != nil {
		return fmt.Errorf("ipv64 domains: %w", err)
	}
	for _, d := range domains {
		if strings.EqualFold(d, zone) {
			return nil
		}
	}
	return invalid("alias_zone", "%s is not a domain of the ipv64 account", zone)
}

// Upload speichert ein eigenes Zertifikat (PEM: Zertifikat mit Kette, Schluessel).
func (m *Manager) Upload(ctx context.Context, certPEM, keyPEM string) (*Cert, error) {
	crt, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, invalid("cert", "certificate and key do not fit: %v", err)
	}
	leaf := crt.Leaf
	names := certNames(leaf)
	if len(names) == 0 {
		return nil, invalid("cert", "certificate contains no DNS name")
	}
	if time.Now().After(leaf.NotAfter) {
		return nil, invalid("cert", "certificate expired on %s", leaf.NotAfter.UTC().Format(time.DateOnly))
	}
	var chain []byte
	for _, der := range crt.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyOut, err := marshalKey(crt.PrivateKey)
	if err != nil {
		return nil, invalid("key", "%v", err)
	}
	now := store.Now()
	res, err := m.w.ExecContext(ctx, `INSERT INTO certs (names, source, auto_renew, cert_pem, key_pem, not_before, not_after, issuer, status, created_at, updated_at)
		VALUES (?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?)`, strings.Join(names, ","), SourceUpload, string(chain), m.d.Box.Encrypt(keyOut),
		store.FormatTime(leaf.NotBefore), store.FormatTime(leaf.NotAfter), issuerName(leaf), StatusValid, now, now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	if err := m.reload(ctx); err != nil {
		return nil, err
	}
	m.refreshHold(ctx)
	m.changed(ctx, ItemCertificates, id)
	return m.Get(ctx, id)
}

// SetAutoRenew schaltet die Erneuerung eines Let's-Encrypt-Zertifikats.
func (m *Manager) SetAutoRenew(ctx context.Context, id int64, on bool) error {
	c, err := m.Get(ctx, id)
	if err != nil {
		return err
	}
	if c.Source == SourceUpload {
		return ErrUpload
	}
	_, err = m.w.ExecContext(ctx, `UPDATE certs SET auto_renew = ?, updated_at = ? WHERE id = ?`, on, store.Now(), id)
	if err == nil {
		m.changed(ctx, ItemCertificates, id)
	}
	return err
}

// Delete entfernt ein Zertifikat; benutzt nur mit force.
func (m *Manager) Delete(ctx context.Context, id int64, force bool) error {
	c, err := m.Get(ctx, id)
	if err != nil {
		return err
	}
	if len(c.UsedBy) > 0 && !force {
		return ErrInUse
	}
	m.mu.Lock()
	busy := m.steps[id] != ""
	m.mu.Unlock()
	if busy {
		return ErrBusy
	}
	uid := m.deleting(ctx, ItemCertificates, id)
	if _, err := m.w.ExecContext(ctx, `DELETE FROM certs WHERE id = ?`, id); err != nil {
		return err
	}
	m.unload(id)
	m.refreshHold(ctx)
	m.changedUID(ctx, ItemCertificates, uid, true)
	return nil
}

// Renew startet einen Abruf von Hand.
func (m *Manager) Renew(ctx context.Context, id int64) error {
	c, err := m.Get(ctx, id)
	if err != nil {
		return err
	}
	if c.Source == SourceUpload {
		return ErrUpload
	}
	if c.RefMissing {
		return invalid("cluster", "ACME CA, DNS account or CA of this certificate is not on this node")
	}
	if c.Source != SourceCA && c.Source != SourceSelf && c.ACMECA == 0 && !m.Account(ctx).TOSAccepted {
		return ErrTOS
	}
	return m.start(id, "manual")
}

// AutoSource waehlt den Weg fuer neue Namen: ipv64 DNS-01, wenn alle Namen in Domains des ipv64-Accounts liegen,
// sonst HTTP-01.
func (m *Manager) AutoSource(ctx context.Context, names []string) string {
	if !m.DNSReady(ctx) {
		return SourceHTTP
	}
	domains, err := m.Domains(ctx)
	if err != nil {
		return SourceHTTP
	}
	for _, n := range names {
		base := strings.TrimPrefix(strings.ToLower(strings.TrimSuffix(n, ".")), "*.")
		found := false
		for _, d := range domains {
			if base == d || strings.HasSuffix(base, "."+d) {
				found = true
				break
			}
		}
		if !found {
			return SourceHTTP
		}
	}
	return SourceIPv64
}

// DNSReady: DNS-01 ueber ipv64 ist moeglich (API-Key eingetragen), ohne Abruf bei ipv64.
func (m *Manager) DNSReady(ctx context.Context) bool { return m.d.DNS != nil && m.d.DNS.Ready(ctx) }

// HTTPReady: HTTP-01 ueber den gemeinsamen Eingang ist moeglich.
func (m *Manager) HTTPReady() bool { return m.d.HTTP != nil }

// Domains: ipv64-Domains des Accounts (Auswahl in der Oberflaeche).
func (m *Manager) Domains(ctx context.Context) ([]string, error) {
	if m.d.DNS == nil || !m.d.DNS.Ready(ctx) {
		return nil, ErrNoKey
	}
	return m.d.DNS.Domains(ctx)
}

func certNames(leaf *x509.Certificate) []string {
	var out []string
	seen := map[string]bool{}
	for _, n := range leaf.DNSNames {
		if nn, err := edge.NormalizeName(n); err == nil && !seen[nn] {
			seen[nn] = true
			out = append(out, nn)
		}
	}
	if len(out) == 0 && leaf.Subject.CommonName != "" {
		if nn, err := edge.NormalizeName(leaf.Subject.CommonName); err == nil {
			out = append(out, nn)
		}
	}
	for _, ip := range leaf.IPAddresses { // eigene CA: auch fuer IPs
		out = append(out, ip.String())
	}
	return out
}

func issuerName(leaf *x509.Certificate) string {
	if leaf.Issuer.CommonName != "" {
		return leaf.Issuer.CommonName
	}
	if len(leaf.Issuer.Organization) > 0 {
		return leaf.Issuer.Organization[0]
	}
	return ""
}

func marshalKey(k any) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}
