package cdn64

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/store"
)

// Zertifikat eines Hosts.
const (
	CertAuto = 0  // passendes Zertifikat nach Namen
	CertNone = -1 // nur HTTP
)

const maxNames = 50

// Host ist ein Proxy-Host.
type Host struct {
	ID             int64     `json:"id"`
	Kind           string    `json:"kind"`
	Names          []string  `json:"names"`
	Enabled        bool      `json:"enabled"`
	Scheme         string    `json:"scheme"`      // Ziel http | https
	TargetHost     string    `json:"target_host"` // Name oder IP
	TargetPort     int       `json:"target_port"`
	WebSockets     bool      `json:"websockets"`
	BlockExploits  bool      `json:"block_exploits"`
	CacheAssets    bool      `json:"cache_assets"`
	CertID         int64     `json:"cert_id"` // 0 = passendes, -1 = nur HTTP
	ForceSSL       bool      `json:"force_ssl"`
	HTTP2          bool      `json:"http2"`
	HTTP3          bool      `json:"http3"`
	HSTS           bool      `json:"hsts"`
	HSTSSubdomains bool      `json:"hsts_subdomains"`
	MinTLS         string    `json:"min_tls"`       // 1.2 | 1.3
	VerifyTarget   bool      `json:"verify_target"` // Zertifikat eines https-Ziels pruefen
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Target ist die Adresse des Ziels (scheme://host:port).
func (h *Host) Target() string {
	return h.Scheme + "://" + net.JoinHostPort(h.TargetHost, strconv.Itoa(h.TargetPort))
}

// HTTPS: der Host nimmt HTTPS an.
func (h *Host) HTTPS() bool { return h.CertID != CertNone }

// newHost: Standardwerte eines neuen Hosts.
func newHost() *Host {
	return &Host{Kind: "proxy", Enabled: true, Scheme: "http", TargetPort: 80, WebSockets: true, HTTP2: true, HTTP3: true, MinTLS: "1.2"}
}

// FieldError ist ein Fehler in einem Feld (Formular, API 422); Key ist der Text, Name ein Wert dazu.
type FieldError struct{ Field, Key, Name string }

func (e *FieldError) Error() string { return e.Field + ": " + e.Key }

func ferr(field, key string) error { return &FieldError{Field: field, Key: key} }

var errNotFound = errors.New("host not found")

// ParseNames teilt eine Eingabe (Komma, Leerzeichen, Zeilen) in Namen.
func ParseNames(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' || r == ';' })
}

// normalize prueft einen Host und bringt ihn in die Grundform.
func (h *Host) normalize() error {
	seen := map[string]bool{}
	var names []string
	for _, n := range h.Names {
		if strings.TrimSpace(n) == "" {
			continue
		}
		nn, err := edge.NormalizeName(n)
		if err != nil {
			return ferr("names", "cdn64.err.name")
		}
		if !seen[nn] {
			seen[nn] = true
			names = append(names, nn)
		}
	}
	if len(names) == 0 {
		return ferr("names", "cdn64.err.names_required")
	}
	if len(names) > maxNames {
		return ferr("names", "cdn64.err.names_many")
	}
	h.Names = names
	if h.Kind == "" {
		h.Kind = "proxy"
	}
	if h.Scheme != "http" && h.Scheme != "https" {
		return ferr("scheme", "cdn64.err.scheme")
	}
	t := strings.TrimSpace(h.TargetHost)
	t = strings.TrimSuffix(strings.TrimPrefix(t, "["), "]")
	if a, err := netip.ParseAddr(t); err == nil {
		t = a.String()
	} else if nn, err := edge.NormalizeName(t); err == nil && !strings.HasPrefix(nn, "*") {
		t = nn
	} else if !isSingleLabel(t) {
		return ferr("target_host", "cdn64.err.target_host")
	}
	h.TargetHost = strings.ToLower(t)
	if h.TargetPort < 1 || h.TargetPort > 65535 {
		return ferr("target_port", "cdn64.err.port")
	}
	if h.MinTLS != "1.3" {
		h.MinTLS = "1.2"
	}
	if h.CertID < CertNone {
		return ferr("cert_id", "cdn64.err.cert")
	}
	if !h.HTTPS() { // ohne HTTPS gibt es keine HTTPS-Optionen
		h.ForceSSL, h.HSTS, h.HSTSSubdomains = false, false, false
	}
	if !h.HSTS {
		h.HSTSSubdomains = false
	}
	return nil
}

// isSingleLabel: einfacher Rechnername im LAN ("nas", "homeassistant").
func isSingleLabel(s string) bool {
	if s == "" || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, c := range strings.ToLower(s) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- Datenbank

const hostCols = `id, kind, names, enabled, scheme, target_host, target_port, websockets, block_exploits, cache_assets, cert_id, force_ssl, http2,
	http3, hsts, hsts_subdomains, min_tls, verify_target, created_at, updated_at`

func scanHost(row interface{ Scan(...any) error }) (*Host, error) {
	var h Host
	var names, ca, ua string
	if err := row.Scan(&h.ID, &h.Kind, &names, &h.Enabled, &h.Scheme, &h.TargetHost, &h.TargetPort, &h.WebSockets, &h.BlockExploits, &h.CacheAssets,
		&h.CertID, &h.ForceSSL, &h.HTTP2, &h.HTTP3, &h.HSTS, &h.HSTSSubdomains, &h.MinTLS, &h.VerifyTarget, &ca, &ua); err != nil {
		return nil, err
	}
	h.Names = strings.Split(names, ",")
	h.CreatedAt, h.UpdatedAt = store.ParseTime(ca), store.ParseTime(ua)
	return &h, nil
}

func (m *Module) hosts(ctx context.Context) ([]*Host, error) {
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT `+hostCols+` FROM cdn_hosts ORDER BY names`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (m *Module) host(ctx context.Context, id int64) (*Host, error) {
	h, err := scanHost(m.core.Reader().QueryRowContext(ctx, `SELECT `+hostCols+` FROM cdn_hosts WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return h, err
}

// checkUnique: kein Name ist schon bei einem anderen Host.
func (m *Module) checkUnique(ctx context.Context, h *Host) error {
	list, err := m.hosts(ctx)
	if err != nil {
		return err
	}
	for _, o := range list {
		if o.ID == h.ID {
			continue
		}
		for _, n := range o.Names {
			for _, w := range h.Names {
				if n == w {
					return &FieldError{Field: "names", Key: "cdn64.err.name_taken", Name: n}
				}
			}
		}
	}
	return nil
}

// saveHost legt an (ID 0) oder aendert und baut die Routen neu.
func (m *Module) saveHost(ctx context.Context, h *Host) error {
	if err := h.normalize(); err != nil {
		return err
	}
	if h.CertID > 0 && m.certs != nil {
		if _, err := m.certs.Get(ctx, h.CertID); err != nil {
			return ferr("cert_id", "cdn64.err.cert")
		}
	}
	if err := m.checkUnique(ctx, h); err != nil {
		return err
	}
	now := store.Now()
	w := m.core.Writer()
	args := []any{h.Kind, strings.Join(h.Names, ","), h.Enabled, h.Scheme, h.TargetHost, h.TargetPort, h.WebSockets, h.BlockExploits, h.CacheAssets,
		h.CertID, h.ForceSSL, h.HTTP2, h.HTTP3, h.HSTS, h.HSTSSubdomains, h.MinTLS, h.VerifyTarget}
	if h.ID == 0 {
		res, err := w.ExecContext(ctx, `INSERT INTO cdn_hosts (kind, names, enabled, scheme, target_host, target_port, websockets, block_exploits, cache_assets,
			cert_id, force_ssl, http2, http3, hsts, hsts_subdomains, min_tls, verify_target, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, append(args, now, now)...)
		if err != nil {
			return err
		}
		h.ID, _ = res.LastInsertId()
	} else {
		res, err := w.ExecContext(ctx, `UPDATE cdn_hosts SET kind = ?, names = ?, enabled = ?, scheme = ?, target_host = ?, target_port = ?, websockets = ?,
			block_exploits = ?, cache_assets = ?, cert_id = ?, force_ssl = ?, http2 = ?, http3 = ?, hsts = ?, hsts_subdomains = ?, min_tls = ?,
			verify_target = ?, updated_at = ? WHERE id = ?`, append(args, now, h.ID)...)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return errNotFound
		}
	}
	m.cache.dropHost(h.ID)
	m.apply(ctx)
	m.checkSoon(h.ID)
	return nil
}

func (m *Module) setEnabled(ctx context.Context, id int64, on bool) error {
	res, err := m.core.Writer().ExecContext(ctx, `UPDATE cdn_hosts SET enabled = ?, updated_at = ? WHERE id = ?`, on, store.Now(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	m.apply(ctx)
	if on {
		m.checkSoon(id)
	}
	return nil
}

func (m *Module) deleteHost(ctx context.Context, id int64) error {
	res, err := m.core.Writer().ExecContext(ctx, `DELETE FROM cdn_hosts WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	m.cache.dropHost(id)
	m.reach.forget(id)
	m.apply(ctx)
	return nil
}

// summary: kurze Beschreibung fuer das Audit.
func (h *Host) summary() string {
	return fmt.Sprintf("target=%s enabled=%v ws=%v exploits=%v cache=%v cert=%d force_ssl=%v http2=%v http3=%v hsts=%v tls=%s", h.Target(), h.Enabled,
		h.WebSockets, h.BlockExploits, h.CacheAssets, h.CertID, h.ForceSSL, h.HTTP2, h.HTTP3, h.HSTS, h.MinTLS)
}
