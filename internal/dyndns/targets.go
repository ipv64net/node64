package dyndns

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/store"
)

// Modi je Adressfamilie
const (
	Mode4Auto  = "auto"  // oeffentliche IPv4 des Anschlusses
	Mode4Fixed = "fixed" // feste Adresse
	Mode4Off   = "off"

	Mode6Host   = "host"   // von aussen gesehene IPv6 dieses Hosts
	Mode6Prefix = "prefix" // nur das /64-Praefix melden (Records mit Interface-ID bei ipv64, wirkt zonenweit)
	Mode6Suffix = "suffix" // Praefix + eigene Interface-ID, lokal zusammengesetzt (nur dieser Record)
	Mode6Iface  = "iface"  // stabile Adresse eines Interfaces (Host-Netzwerk)
	Mode6Fixed  = "fixed"
	Mode6Off    = "off"
)

var (
	Modes4   = []string{Mode4Auto, Mode4Fixed, Mode4Off}
	Modes6   = []string{Mode6Host, Mode6Prefix, Mode6Suffix, Mode6Iface, Mode6Fixed, Mode6Off}
	ifaceRe  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
	hostRe   = regexp.MustCompile(`^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$`)
	domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	tokenRe  = regexp.MustCompile(`^[A-Za-z0-9]{24}$|^[A-Za-z0-9]{32}$`) // update.php nimmt 24 oder 32 Zeichen
)

// Target ist ein Name (Domain + Host), den diese Node aktuell haelt.
type Target struct {
	ID         int64
	Domain     string
	Host       string
	RecordID   int64
	TokenKind  string // record, domain
	Token      string // im Speicher entschluesselt
	Mode4      string
	Fixed4     string
	Mode6      string
	Fixed6     string
	Suffix6    string
	Iface      string
	Enabled    bool
	Paused     string
	LastIP4    string
	LastIP6    string
	LastPrefix string
	LastOKAt   time.Time
	LastError  string
	LastErrAt  time.Time
	DNSState   int
	DNSAt      time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
	UID        string // Kennung im Cluster (gleich auf allen Nodes, cluster.go)
}

// FQDN ist der volle Name.
func (t *Target) FQDN() string {
	if t.Host == "" {
		return t.Domain
	}
	return t.Host + "." + t.Domain
}

// Status fasst den Zustand fuer die Anzeige zusammen: paused, off, error, pending, dns, cdn, ok, new.
func (t *Target) Status() string {
	switch {
	case t.Paused != "":
		return "paused"
	case !t.Enabled:
		return "off"
	case t.LastError != "" && t.LastErrAt.After(t.LastOKAt):
		return "error"
	case t.DNSState == 2 && !t.LastOKAt.IsZero() && time.Since(t.LastOKAt) < dnsGrace:
		return "pending"
	case t.DNSState == 2 && !t.LastOKAt.IsZero():
		return "dns"
	case t.DNSState == dnsRedirected:
		return "cdn"
	case !t.LastOKAt.IsZero() || t.DNSState == 1:
		return "ok"
	}
	return "new"
}

// StatusClass ist die Badge-Farbe zum Status.
func (t *Target) StatusClass() string {
	return map[string]string{"paused": "text-bg-warning", "off": "text-bg-secondary", "error": "text-bg-danger", "dns": "text-bg-warning", "pending": "text-bg-info", "cdn": "text-bg-success", "ok": "text-bg-success", "new": "text-bg-light"}[t.Status()]
}

// TokenMasked zeigt nur Anfang und Ende des Tokens.
func (t *Target) TokenMasked() string {
	if len(t.Token) < 8 {
		return "••••"
	}
	return "…" + t.Token[len(t.Token)-4:]
}

// Normalize bereinigt Eingaben und prueft sie.
func (t *Target) Normalize() error {
	t.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(t.Domain), "."))
	t.Host = strings.ToLower(strings.Trim(strings.TrimSpace(t.Host), "."))
	if t.Host == "@" {
		t.Host = ""
	}
	t.Token = strings.TrimSpace(t.Token)
	t.Fixed4, t.Fixed6, t.Suffix6, t.Iface = strings.TrimSpace(t.Fixed4), strings.TrimSpace(t.Fixed6), strings.TrimSpace(t.Suffix6), strings.TrimSpace(t.Iface)
	if !domainRe.MatchString(t.Domain) || len(t.Domain) > 253 {
		return errors.New("domain")
	}
	if t.Host != "" && (!hostRe.MatchString(t.Host) || len(t.Host) > 200) {
		return errors.New("host")
	}
	if t.TokenKind != "record" && t.TokenKind != "domain" {
		return errors.New("token_kind")
	}
	if !tokenRe.MatchString(t.Token) {
		return errors.New("token")
	}
	if !in(t.Mode4, Modes4) || !in(t.Mode6, Modes6) {
		return errors.New("mode")
	}
	if t.Mode4 == Mode4Off && t.Mode6 == Mode6Off {
		return errors.New("mode_none")
	}
	if t.Mode4 == Mode4Fixed {
		if a, err := netip.ParseAddr(t.Fixed4); err != nil || !a.Is4() || !publicAddr(a) {
			return errors.New("fixed4")
		}
	}
	if t.Mode6 == Mode6Fixed {
		if a, err := netip.ParseAddr(t.Fixed6); err != nil || !a.Is6() || !publicAddr(a) {
			return errors.New("fixed6")
		}
	}
	if t.Mode6 == Mode6Suffix {
		s, err := normSuffix(t.Suffix6)
		if err != nil {
			return errors.New("suffix6")
		}
		t.Suffix6 = s
	}
	if t.Mode6 == Mode6Iface && !ifaceRe.MatchString(t.Iface) {
		return errors.New("iface")
	}
	return nil
}

// normSuffix prueft eine Interface-ID ("::1:2:3:4" oder "1:2:3:4") und liefert sie als "::x:x:x:x".
func normSuffix(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "::") && strings.Count(s, ":") == 3 {
		s = "::" + s
	}
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is6() || a.Zone() != "" {
		return "", errors.New("suffix")
	}
	b := a.As16()
	for i := 0; i < 8; i++ {
		if b[i] != 0 {
			return "", errors.New("suffix must fit into the lower 64 bits")
		}
	}
	if a.IsUnspecified() {
		return "", errors.New("suffix")
	}
	return a.String(), nil
}

// withSuffix setzt Praefix (obere 64 Bit) und Interface-ID (untere 64 Bit) zusammen.
func withSuffix(prefix netip.Prefix, suffix string) (netip.Addr, error) {
	s, err := netip.ParseAddr(suffix)
	if err != nil || !prefix.Addr().Is6() {
		return netip.Addr{}, errors.New("suffix")
	}
	p, b := prefix.Masked().Addr().As16(), s.As16()
	copy(p[8:], b[8:])
	return netip.AddrFrom16(p), nil
}

func in(s string, list []string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- Speicher

const targetCols = `id, domain, host, record_id, token_kind, token, mode4, fixed4, mode6, fixed6, suffix6, iface, enabled, paused,
	last_ip4, last_ip6, last_prefix, last_ok_at, last_error, last_err_at, dns_state, dns_at, created_at, updated_at, uid`

func (m *Module) scanTarget(row interface{ Scan(...any) error }) (*Target, error) {
	var t Target
	var enabled int
	var okAt, errAt, dnsAt, created, updated string
	if err := row.Scan(&t.ID, &t.Domain, &t.Host, &t.RecordID, &t.TokenKind, &t.Token, &t.Mode4, &t.Fixed4, &t.Mode6, &t.Fixed6, &t.Suffix6, &t.Iface, &enabled, &t.Paused,
		&t.LastIP4, &t.LastIP6, &t.LastPrefix, &okAt, &t.LastError, &errAt, &t.DNSState, &dnsAt, &created, &updated, &t.UID); err != nil {
		return nil, err
	}
	t.Enabled = enabled == 1
	t.LastOKAt, t.LastErrAt, t.DNSAt = store.ParseTime(okAt), store.ParseTime(errAt), store.ParseTime(dnsAt)
	t.CreatedAt, t.UpdatedAt = store.ParseTime(created), store.ParseTime(updated)
	if m.box != nil {
		plain, err := m.box.Decrypt(t.Token)
		if err != nil {
			return nil, fmt.Errorf("%w %s: %w", errToken, t.FQDN(), err)
		}
		t.Token = plain
	}
	return &t, nil
}

func (m *Module) seal(token string) string {
	if m.box == nil {
		return token
	}
	return m.box.Encrypt(token)
}

// Targets liefert alle Ziele, sortiert nach Name.
func (m *Module) Targets(ctx context.Context) ([]*Target, error) {
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT `+targetCols+` FROM dyn_targets ORDER BY domain, host`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Target
	for rows.Next() {
		t, err := m.scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Target liefert ein Ziel (nil, nil = gibt es nicht).
func (m *Module) Target(ctx context.Context, id int64) (*Target, error) {
	t, err := m.scanTarget(m.core.Reader().QueryRowContext(ctx, `SELECT `+targetCols+` FROM dyn_targets WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

// errToken: Token nicht entschluesselbar (z. B. anderer Schluessel nach Wiederherstellung).
var errToken = errors.New("token of")

// ErrExists: Domain + Host gibt es schon.
var ErrExists = errors.New("target exists")

// InsertTarget legt ein Ziel an.
func (m *Module) InsertTarget(ctx context.Context, t *Target) error {
	if err := t.Normalize(); err != nil {
		return err
	}
	now := store.Now()
	if t.UID == "" { // neu hier: eigene Kennung (aus dem Cluster: die der anderen Node)
		t.UID = newClusterUID()
	}
	res, err := m.core.Writer().ExecContext(ctx, `INSERT INTO dyn_targets (domain, host, record_id, token_kind, token, mode4, fixed4, mode6, fixed6, suffix6, iface, enabled, created_at, updated_at, uid)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, t.Domain, t.Host, t.RecordID, t.TokenKind, m.seal(t.Token), t.Mode4, t.Fixed4, t.Mode6, t.Fixed6, t.Suffix6, t.Iface, b2i(t.Enabled), now, now, t.UID)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return ErrExists
		}
		return err
	}
	t.ID, _ = res.LastInsertId()
	m.clusterChanged(ctx, t.UID, false)
	return nil
}

// UpdateTarget speichert die Einstellungen eines Ziels (nicht den Laufzeitstand).
func (m *Module) UpdateTarget(ctx context.Context, t *Target) error {
	if err := t.Normalize(); err != nil {
		return err
	}
	_, err := m.core.Writer().ExecContext(ctx, `UPDATE dyn_targets SET record_id = ?, token_kind = ?, token = ?, mode4 = ?, fixed4 = ?, mode6 = ?, fixed6 = ?, suffix6 = ?, iface = ?,
		enabled = ?, paused = ?, updated_at = ? WHERE id = ?`, t.RecordID, t.TokenKind, m.seal(t.Token), t.Mode4, t.Fixed4, t.Mode6, t.Fixed6, t.Suffix6, t.Iface, b2i(t.Enabled), t.Paused, store.Now(), t.ID)
	if err == nil {
		m.clusterChanged(ctx, m.uidOf(ctx, t.ID), false)
	}
	return err
}

// DeleteTarget loescht ein Ziel; der Verlauf bleibt (mit Namen) erhalten.
func (m *Module) DeleteTarget(ctx context.Context, id int64) error {
	uid := m.uidOf(ctx, id)
	_, err := m.core.Writer().ExecContext(ctx, `DELETE FROM dyn_targets WHERE id = ?`, id)
	if err == nil {
		m.clusterChanged(ctx, uid, true)
	}
	return err
}
