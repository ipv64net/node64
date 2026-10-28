package cdn64

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/ports"
	"github.com/ipv64net/node64/internal/store"
)

// Zertifikat eines Hosts.
const (
	CertAuto = 0  // passendes Zertifikat nach Namen
	CertNone = -1 // nur HTTP
)

const maxNames = 50

// Arten von Hosts.
const (
	KindProxy    = "proxy"       // Reverse-Proxy auf ein Ziel
	KindRedirect = "redirect"    // Weiterleitung auf eine andere Domain
	KindDead     = "dead"        // antwortet immer mit 404
	KindPass     = "passthrough" // TLS durchreichen (das Ziel beendet TLS selbst)
	KindStatus   = "status"      // Statusseite der Healthchecks (StatusPageID)
)

var redirectCodes = map[int]bool{300: true, 301: true, 302: true, 303: true, 307: true, 308: true}

// Host ist ein Proxy-Host.
// TLSBSI: Host.MinTLS fuer TLS nach BSI TR-02102-2 (TLS 1.2 und 1.3, Verfahren nach der Richtlinie, edge.Route.BSI).
const TLSBSI = "bsi"

type Host struct {
	ID             int64      `json:"id"`
	Kind           string     `json:"kind"`
	Names          []string   `json:"names"`
	Enabled        bool       `json:"enabled"`
	Scheme         string     `json:"scheme"`      // Ziel http | https
	TargetHost     string     `json:"target_host"` // Name oder IP
	TargetPort     int        `json:"target_port"`
	WebSockets     bool       `json:"websockets"`
	BlockExploits  bool       `json:"block_exploits"`
	CacheAssets    bool       `json:"cache_assets"`
	CertID         int64      `json:"cert_id"` // 0 = passendes, -1 = nur HTTP
	ForceSSL       bool       `json:"force_ssl"`
	HTTP2          bool       `json:"http2"`
	HTTP3          bool       `json:"http3"`
	HSTS           bool       `json:"hsts"`
	HSTSSubdomains bool       `json:"hsts_subdomains"`
	MinTLS         string     `json:"min_tls"`                   // 1.2 | 1.3 | bsi (TLS nach BSI TR-02102-2)
	VerifyTarget   bool       `json:"verify_target"`             // Zertifikat eines https-Ziels pruefen
	RedirectTarget string     `json:"redirect_target,omitempty"` // Weiterleitung: Domain[:Port][/Pfad]
	RedirectScheme string     `json:"redirect_scheme,omitempty"` // auto | http | https
	RedirectCode   int        `json:"redirect_code,omitempty"`   // 301, 302, 307, 308 …
	PreservePath   bool       `json:"preserve_path"`             // Pfad und Abfrage mitnehmen
	AccessListID   int64      `json:"access_list_id"`            // Zugriffsliste (0 = keine)
	Locations      []Location `json:"locations"`                 // Custom Locations (nur Proxy-Hosts)
	Advanced       Advanced   `json:"advanced"`                  // weitere Optionen
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`

	StatusPageID int64 `json:"status_page_id"` // Statusseite der Healthchecks (nur Hostart status)

	// Von Docker verwaltet (docker.go): Namen, Schema und Ziel kommen aus den Labels des Containers, nur lesen.
	DockerContainer string `json:"docker_container,omitempty"` // Container-Name ("" = von Hand angelegt)
	DockerRouter    string `json:"docker_router,omitempty"`    // Traefik-Router ("" = node64.proxy.*)
}

// Target ist die Adresse des Ziels (scheme://host:port).
func (h *Host) Target() string {
	return h.Scheme + "://" + net.JoinHostPort(h.TargetHost, strconv.Itoa(h.TargetPort))
}

// HTTPS: der Host beendet HTTPS hier (beim Durchreichen macht das das Ziel).
func (h *Host) HTTPS() bool { return h.CertID != CertNone && h.Kind != KindPass }

// probed: das Ziel wird auf Erreichbarkeit geprueft.
func (h *Host) probed() bool { return h.Kind == KindProxy || h.Kind == KindPass }

// newHost: Standardwerte eines neuen Hosts.
func newHost() *Host { return newHostKind(KindProxy) }

func newHostKind(kind string) *Host {
	h := &Host{Kind: kind, Enabled: true, Scheme: "http", TargetPort: 80, WebSockets: true, HTTP2: true, HTTP3: true, MinTLS: "1.2",
		RedirectScheme: "auto", RedirectCode: 301, PreservePath: true}
	if kind == KindPass {
		h.Scheme, h.TargetPort, h.CertID = "https", 443, CertNone
	}
	h.Advanced.Gzip = kind == KindProxy // Komprimierung fuer neue Proxy-Hosts an
	return h
}

func validKind(k string) bool {
	return k == KindProxy || k == KindRedirect || k == KindDead || k == KindPass || k == KindStatus
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
		h.Kind = KindProxy
	}
	if !validKind(h.Kind) {
		return ferr("kind", "cdn64.err.kind")
	}
	if err := h.Advanced.normalize(); err != nil {
		return err
	}
	if h.Kind == KindDead { // 404-Host: nichts zu schuetzen
		h.Advanced.GeoMode = ""
	}
	h.Advanced.normalizeAI(h.Kind)
	if err := h.Advanced.normalizeGeo(); err != nil {
		return err
	}
	if err := h.Advanced.normalizeMaint(h.Kind); err != nil {
		return err
	}
	if h.Locations == nil {
		h.Locations = []Location{}
	}
	if h.Kind != KindProxy {
		h.Locations = []Location{}
	}
	if err := normalizeLocations(h.Locations); err != nil {
		return err
	}
	if h.AccessListID < 0 {
		h.AccessListID = 0
	}
	if h.Kind == KindPass || h.Kind == KindDead {
		h.AccessListID = 0
	}
	if h.MinTLS != "1.3" && h.MinTLS != TLSBSI {
		h.MinTLS = "1.2"
	}
	if h.Kind != KindStatus {
		h.StatusPageID = 0
	}
	switch h.Kind {
	case KindRedirect:
		if err := h.normalizeRedirect(); err != nil {
			return err
		}
		h.TargetHost, h.TargetPort, h.WebSockets, h.CacheAssets = "", 0, false, false
		return h.normalizeTLS()
	case KindDead:
		h.TargetHost, h.TargetPort, h.WebSockets, h.CacheAssets, h.BlockExploits = "", 0, false, false, false
		return h.normalizeTLS()
	case KindStatus: // Seite kommt aus den Healthchecks: kein Ziel, keine Weiterleitung
		if h.StatusPageID <= 0 {
			return ferr("status_page_id", "cdn64.err.status_page")
		}
		h.TargetHost, h.TargetPort, h.WebSockets, h.CacheAssets, h.RedirectTarget = "", 0, false, false, ""
		return h.normalizeTLS()
	case KindPass:
		h.Scheme, h.CertID, h.WebSockets, h.CacheAssets, h.BlockExploits = "https", CertNone, false, false, false
		h.ForceSSL, h.HSTS, h.HSTSSubdomains, h.HTTP3 = false, false, false, false
		for _, n := range h.Names {
			if strings.HasPrefix(n, "*.") {
				return ferr("names", "cdn64.err.pass_wildcard")
			}
		}
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
	return h.normalizeTLS()
}

// normalizeTLS: Zertifikat und HTTPS-Optionen.
func (h *Host) normalizeTLS() error {
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

// normalizeRedirect prueft Ziel, Schema und Code einer Weiterleitung.
func (h *Host) normalizeRedirect() error {
	t := strings.TrimSpace(h.RedirectTarget)
	for _, p := range []string{"https://", "http://"} {
		t = strings.TrimPrefix(t, p)
	}
	u, err := url.Parse("http://" + t)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return ferr("redirect_target", "cdn64.err.redirect_target")
	}
	host := u.Hostname()
	if a, err := netip.ParseAddr(host); err == nil {
		host = a.String()
	} else if nn, err := edge.NormalizeName(host); err != nil || strings.HasPrefix(nn, "*") {
		return ferr("redirect_target", "cdn64.err.redirect_target")
	} else {
		host = nn
	}
	hp := host
	if strings.Contains(host, ":") {
		hp = "[" + host + "]"
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return ferr("redirect_target", "cdn64.err.redirect_target")
		}
		hp += ":" + p
	}
	h.RedirectTarget = hp + strings.TrimSuffix(u.EscapedPath(), "/")
	if h.RedirectScheme != "http" && h.RedirectScheme != "https" {
		h.RedirectScheme = "auto"
	}
	if h.RedirectCode == 0 {
		h.RedirectCode = 301
	}
	if !redirectCodes[h.RedirectCode] {
		return ferr("redirect_code", "cdn64.err.redirect_code")
	}
	for _, n := range h.Names { // Weiterleitung auf sich selbst
		if hp == n {
			return ferr("redirect_target", "cdn64.err.redirect_self")
		}
	}
	return nil
}

// normalizeTarget prueft ein Ziel (Name, IP oder einfacher Rechnername) und bringt es in die Grundform.
func normalizeTarget(t string) (string, bool) {
	t = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(t), "["), "]")
	if a, err := netip.ParseAddr(t); err == nil {
		return a.String(), true
	}
	if nn, err := edge.NormalizeName(t); err == nil && !strings.HasPrefix(nn, "*") {
		return nn, true
	}
	if isSingleLabel(t) {
		return strings.ToLower(t), true
	}
	return "", false
}

// normalizeLocations prueft die Custom Locations (Pfad eindeutig, Ziel gueltig).
func normalizeLocations(list []Location) error {
	seen := map[string]bool{}
	for i := range list {
		l := &list[i]
		l.Path = "/" + strings.Trim(strings.TrimSpace(l.Path), "/")
		if l.Path == "/" || strings.ContainsAny(l.Path, " ?#\\") || len(l.Path) > 200 {
			return &FieldError{Field: "locations", Key: "cdn64.err.location_path", Name: l.Path}
		}
		if seen[l.Path] {
			return &FieldError{Field: "locations", Key: "cdn64.err.location_dup", Name: l.Path}
		}
		seen[l.Path] = true
		if l.Scheme != "https" {
			l.Scheme = "http"
		}
		t, ok := normalizeTarget(l.TargetHost)
		if !ok || l.TargetPort < 1 || l.TargetPort > 65535 {
			return &FieldError{Field: "locations", Key: "cdn64.err.location_target", Name: l.Path}
		}
		l.TargetHost = t
		if fp := strings.TrimSpace(l.ForwardPath); fp != "" {
			fp = "/" + strings.Trim(fp, "/")
			if strings.ContainsAny(fp, " ?#") || len(fp) > 200 {
				return &FieldError{Field: "locations", Key: "cdn64.err.location_path", Name: fp}
			}
			l.ForwardPath = fp
		}
		if l.AccessListID < 0 {
			l.AccessListID = 0
		}
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
	http3, hsts, hsts_subdomains, min_tls, verify_target, redirect_target, redirect_scheme, redirect_code, preserve_path, access_list_id, locations,
	advanced, created_at, updated_at, status_page_id, docker_container, docker_router`

func scanHost(row interface{ Scan(...any) error }) (*Host, error) {
	var h Host
	var names, locs, adv, ca, ua string
	if err := row.Scan(&h.ID, &h.Kind, &names, &h.Enabled, &h.Scheme, &h.TargetHost, &h.TargetPort, &h.WebSockets, &h.BlockExploits, &h.CacheAssets,
		&h.CertID, &h.ForceSSL, &h.HTTP2, &h.HTTP3, &h.HSTS, &h.HSTSSubdomains, &h.MinTLS, &h.VerifyTarget, &h.RedirectTarget, &h.RedirectScheme,
		&h.RedirectCode, &h.PreservePath, &h.AccessListID, &locs, &adv, &ca, &ua, &h.StatusPageID, &h.DockerContainer, &h.DockerRouter); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(locs), &h.Locations)
	if h.Locations == nil {
		h.Locations = []Location{}
	}
	_ = json.Unmarshal([]byte(adv), &h.Advanced)
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
	if h.Kind == KindPass && m.passToSelf(ctx, h) {
		return ferr("target_port", "cdn64.err.pass_self")
	}
	for _, id := range append([]int64{h.AccessListID}, locationACLs(h)...) {
		if id > 0 {
			if _, err := m.accessList(ctx, id); err != nil {
				return ferr("access_list_id", "cdn64.err.acl_unknown")
			}
		}
	}
	locs, _ := json.Marshal(h.Locations)
	adv, _ := json.Marshal(h.Advanced)
	now := store.Now()
	w := m.core.Writer()
	args := []any{h.Kind, strings.Join(h.Names, ","), h.Enabled, h.Scheme, h.TargetHost, h.TargetPort, h.WebSockets, h.BlockExploits, h.CacheAssets,
		h.CertID, h.ForceSSL, h.HTTP2, h.HTTP3, h.HSTS, h.HSTSSubdomains, h.MinTLS, h.VerifyTarget, h.RedirectTarget, h.RedirectScheme, h.RedirectCode,
		h.PreservePath, h.AccessListID, string(locs), string(adv), h.StatusPageID}
	if h.ID == 0 {
		res, err := w.ExecContext(ctx, `INSERT INTO cdn_hosts (kind, names, enabled, scheme, target_host, target_port, websockets, block_exploits, cache_assets,
			cert_id, force_ssl, http2, http3, hsts, hsts_subdomains, min_tls, verify_target, redirect_target, redirect_scheme, redirect_code, preserve_path,
			access_list_id, locations, advanced, status_page_id, created_at, updated_at, docker_container, docker_router)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, append(args, now, now, h.DockerContainer, h.DockerRouter)...)
		if err != nil {
			return err
		}
		h.ID, _ = res.LastInsertId()
	} else {
		res, err := w.ExecContext(ctx, `UPDATE cdn_hosts SET kind = ?, names = ?, enabled = ?, scheme = ?, target_host = ?, target_port = ?, websockets = ?,
			block_exploits = ?, cache_assets = ?, cert_id = ?, force_ssl = ?, http2 = ?, http3 = ?, hsts = ?, hsts_subdomains = ?, min_tls = ?,
			verify_target = ?, redirect_target = ?, redirect_scheme = ?, redirect_code = ?, preserve_path = ?, access_list_id = ?, locations = ?,
			advanced = ?, status_page_id = ?, updated_at = ? WHERE id = ?`,
			append(args, now, h.ID)...)
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
	m.onlineKick() // entfernte Namen auch bei CDN64 online ausschalten
	return nil
}

// setHostDocker setzt die Docker-Kennung eines Hosts (Container "" = wieder von Hand); saveHost aendert sie nicht.
func (m *Module) setHostDocker(ctx context.Context, id int64, container, router string) error {
	res, err := m.core.Writer().ExecContext(ctx, `UPDATE cdn_hosts SET docker_container = ?, docker_router = ?, updated_at = ? WHERE id = ?`,
		container, router, store.Now(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

// dockerHostOf: der Docker-Host zu Container und Router (nil = keiner).
func dockerHostOf(list []*Host, container, router string) *Host {
	for _, h := range list {
		if h.DockerContainer != "" && h.DockerContainer == container && h.DockerRouter == router {
			return h
		}
	}
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
	m.onlineKick() // Namen bei CDN64 online ausschalten
	return nil
}

func locationACLs(h *Host) []int64 {
	var out []int64
	for _, l := range h.Locations {
		out = append(out, l.AccessListID)
	}
	return out
}

// summary: kurze Beschreibung fuer das Audit.
func (h *Host) summary() string {
	switch h.Kind {
	case KindRedirect:
		return fmt.Sprintf("kind=redirect to=%s://%s code=%d preserve_path=%v enabled=%v cert=%d force_ssl=%v", h.RedirectScheme, h.RedirectTarget,
			h.RedirectCode, h.PreservePath, h.Enabled, h.CertID, h.ForceSSL)
	case KindDead:
		return fmt.Sprintf("kind=dead enabled=%v cert=%d force_ssl=%v", h.Enabled, h.CertID, h.ForceSSL)
	case KindStatus:
		return fmt.Sprintf("kind=status page=%d enabled=%v cert=%d force_ssl=%v acl=%d", h.StatusPageID, h.Enabled, h.CertID, h.ForceSSL, h.AccessListID)
	case KindPass:
		return fmt.Sprintf("kind=passthrough target=%s enabled=%v", net.JoinHostPort(h.TargetHost, strconv.Itoa(h.TargetPort)), h.Enabled)
	}
	return fmt.Sprintf("target=%s enabled=%v ws=%v exploits=%v cache=%v cert=%d force_ssl=%v http2=%v http3=%v hsts=%v tls=%s acl=%d locations=%d", h.Target(),
		h.Enabled, h.WebSockets, h.BlockExploits, h.CacheAssets, h.CertID, h.ForceSSL, h.HTTP2, h.HTTP3, h.HSTS, h.MinTLS, h.AccessListID, len(h.Locations))
}

// passToSelf: Durchreichen auf die eigene Oberflaeche (Port des Kerns "web" auf localhost bzw. einer Adresse dieser
// Node) gaebe Fremden aus dem Internet eine Verbindung, die wie aus dem Heimnetz aussieht (ohne weitergereichte
// Client-Adresse; /mcp und Heimnetz-Pruefungen sind dann blind). Die Oberflaeche geht ueber einen Proxy-Host.
func (m *Module) passToSelf(ctx context.Context, h *Host) bool {
	if m.ports == nil {
		return false
	}
	web := false
	for _, c := range m.ports.All(ctx) {
		if c.Owner == "web" && c.Proto == ports.TCP && c.Port == h.TargetPort {
			web = true
		}
	}
	if !web {
		return false
	}
	if h.TargetHost == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(h.TargetHost)
	if err != nil {
		return false
	}
	a = a.Unmap()
	if a.IsLoopback() || a.IsUnspecified() {
		return true
	}
	addrs, _ := net.InterfaceAddrs()
	for _, x := range addrs {
		if p, err := netip.ParsePrefix(x.String()); err == nil && p.Addr().Unmap() == a {
			return true
		}
	}
	return false
}
