package ipam64

import (
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/store"
)

// Datenmodell v2 (Plan docs/PLAN-NODE64-IPAM64.md): Praefixe, Adressbereiche und feste Adressen, IPv4 und IPv6, je
// mit uid als Kennung im Cluster. Grundlage war der Entwurf von UlrichSchwarz (Pruefung und Normalisierung der
// Eingaben); Netze heissen jetzt Praefixe und duerfen ineinander liegen (Hierarchie).

//go:embed migrations
var migrationFS embed.FS

// Migrations liefert die eingebetteten Migrationen des Moduls (Scope Name).
func Migrations() []store.Migration {
	ms, err := store.ReadMigrations(migrationFS, "migrations")
	if err != nil {
		panic(err)
	}
	return ms
}

// Grenzen der Eingaben.
const (
	minBits4   = 8   // groesstes IPv4-Praefix
	minBits6   = 16  // groesstes IPv6-Praefix
	maxName    = 64  // Name eines Praefixes bzw. Bereichs
	maxHost    = 63  // Rechnername (ein DNS-Label)
	maxComment = 200 // Beschreibung
	maxTags    = 10
	maxTag     = 32
)

// Status eines Praefixes bzw. einer Adresse.
const (
	StatusContainer  = "container" // nur Gliederung, keine Adressen (nur Praefixe)
	StatusActive     = "active"
	StatusReserved   = "reserved"
	StatusDeprecated = "deprecated"
)

// Arten eines Adressbereichs.
const (
	RangeFixed    = "fixed"    // feste Adressen (hier sucht "naechste freie Adresse")
	RangeReserved = "reserved" // frei halten
)

// Scan-Einstellung eines Praefixes.
const (
	ScanOff     = "off"
	ScanPassive = "passive" // nur Nachbartabelle
	ScanActive  = "active"  // zusaetzlich Netz-Scan (nur private IPv4-Netze bis /22)
)

// Rollen einer Adresse.
var addrRoles = []string{"", "gateway", "dns", "vip", "anycast"}

// Fehler der Eingaben (Texte ueber errKey).
var (
	ErrPrefix   = errors.New("ipam64: invalid prefix")
	ErrSize     = errors.New("ipam64: prefix too large")
	ErrDup      = errors.New("ipam64: prefix already exists")
	ErrName     = errors.New("ipam64: invalid name")
	ErrHost     = errors.New("ipam64: invalid host name")
	ErrStatus   = errors.New("ipam64: invalid status")
	ErrVLAN     = errors.New("ipam64: invalid vlan")
	ErrTags     = errors.New("ipam64: invalid tags")
	ErrRange    = errors.New("ipam64: invalid range")
	ErrRangeNet = errors.New("ipam64: range outside a prefix")
	ErrOverlap  = errors.New("ipam64: range overlaps another range")
	ErrIP       = errors.New("ipam64: invalid address")
	ErrNoNet    = errors.New("ipam64: address in no prefix")
	ErrNetAddr  = errors.New("ipam64: network or broadcast address")
	ErrMAC      = errors.New("ipam64: invalid mac")
	ErrTaken    = errors.New("ipam64: address already entered")
	ErrRole     = errors.New("ipam64: invalid role")
	ErrNotFound = errors.New("ipam64: not found")
	ErrBusy     = errors.New("ipam64: scan already running")
)

var (
	hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	tagRe  = regexp.MustCompile(`^[\p{L}\p{N}_.-]{1,32}$`)
	zoneRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	uidRe  = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// Prefix ist ein Praefix in IPAM64.
type Prefix struct {
	UID         string    `json:"uid"`
	Prefix      string    `json:"prefix"`
	Family      int       `json:"family"`
	Name        string    `json:"name"`
	Status      string    `json:"status"`
	Role        string    `json:"role"`
	VLAN        int       `json:"vlan"`
	Tags        []string  `json:"tags"`
	Description string    `json:"description"`
	MarkFull    bool      `json:"mark_full"`
	DNSZone     string    `json:"dns_zone"`
	Scan        string    `json:"scan"`
	ScanNode    string    `json:"scan_node"`
	DynParent   string    `json:"dyn_parent,omitempty"`
	DynIndex    string    `json:"dyn_index,omitempty"`
	DynSource   string    `json:"dyn_source,omitempty"`
	Updated     time.Time `json:"updated"`
	UpdatedBy   string    `json:"updated_by"`
}

// Range ist ein Adressbereich (gehoert zu dem Praefix, in dem er liegt).
type Range struct {
	UID         string    `json:"uid"`
	Start       string    `json:"start"`
	End         string    `json:"end"`
	Kind        string    `json:"kind"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Updated     time.Time `json:"updated"`
	UpdatedBy   string    `json:"updated_by"`
}

// Address ist eine feste Adresse in IPAM64.
type Address struct {
	UID         string    `json:"uid"`
	Address     string    `json:"address"`
	Status      string    `json:"status"`
	Role        string    `json:"role"`
	Name        string    `json:"name"`
	DNS         bool      `json:"dns"`
	DNSZone     string    `json:"dns_zone"`
	PTR         bool      `json:"ptr"`
	MAC         string    `json:"mac"`
	DHCP        bool      `json:"dhcp"`
	Description string    `json:"description"`
	Tags        []string  `json:"tags"`
	Updated     time.Time `json:"updated"`
	UpdatedBy   string    `json:"updated_by"`
}

// seenRow ist eine Sichtung aus der Nachbartabelle.
type seenRow struct {
	IP          netip.Addr
	MAC         string
	First, Last time.Time
}

func newUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func clean(s string, max int) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) > max || strings.ContainsAny(s, "\r\n\t<>\x00") {
		return "", false
	}
	return s, true
}

// normTags prueft Tags (getrennt durch Leerzeichen oder Komma), ohne Doppel, sortiert.
func normTags(in []string) ([]string, error) {
	var out []string
	for _, t := range in {
		for _, f := range strings.FieldsFunc(t, func(r rune) bool { return r == ',' || r == ' ' }) {
			f = strings.ToLower(f)
			if !tagRe.MatchString(f) {
				return nil, ErrTags
			}
			if !slices.Contains(out, f) {
				out = append(out, f)
			}
		}
	}
	if len(out) > maxTags {
		return nil, ErrTags
	}
	slices.Sort(out)
	return out, nil
}

func tagsText(t []string) string { return strings.Join(t, " ") }

func tagsOf(s string) []string {
	if f := strings.Fields(s); len(f) > 0 {
		return f
	}
	return []string{}
}

// normMAC liefert aa:bb:cc:dd:ee:ff ("" bleibt leer).
func normMAC(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return "", ErrMAC
	}
	return hw.String(), nil
}

// ParsePrefix prueft ein Praefix (IPv4 /8../32, IPv6 /16../128) und liefert es mit Netzadresse.
func ParsePrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return netip.Prefix{}, ErrPrefix
	}
	p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-unmapBits(p))
	if p.Addr().Zone() != "" {
		return netip.Prefix{}, ErrPrefix
	}
	if (p.Addr().Is4() && p.Bits() < minBits4) || (p.Addr().Is6() && p.Bits() < minBits6) {
		return netip.Prefix{}, ErrSize
	}
	return p.Masked(), nil
}

// unmapBits: ::ffff:a.b.c.d/n ist das IPv4-Praefix /n-96.
func unmapBits(p netip.Prefix) int {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		return 96
	}
	return 0
}

// ParseAddr prueft eine Adresse (ohne Zone) und liefert sie kanonisch.
func ParseAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, ErrIP
	}
	return a.Unmap(), nil
}

func validStatus(s string, prefix bool) bool {
	switch s {
	case StatusActive, StatusReserved, StatusDeprecated:
		return true
	case StatusContainer:
		return prefix
	}
	return false
}

// normalizePrefix prueft die Eingaben eines Praefixes.
func normalizePrefix(p *Prefix) error {
	pp, err := ParsePrefix(p.Prefix)
	if err != nil {
		return err
	}
	p.Prefix, p.Family = pp.String(), 4
	if pp.Addr().Is6() {
		p.Family = 6
	}
	var ok bool
	if p.Name, ok = clean(p.Name, maxName); !ok {
		return ErrName
	}
	if p.Role, ok = clean(p.Role, maxTag); !ok {
		return ErrName
	}
	if p.Description, ok = clean(p.Description, maxComment); !ok {
		return ErrName
	}
	if p.Status == "" {
		p.Status = StatusActive
	}
	if !validStatus(p.Status, true) {
		return ErrStatus
	}
	if p.VLAN < 0 || p.VLAN > 4094 {
		return ErrVLAN
	}
	if p.Tags, err = normTags(p.Tags); err != nil {
		return err
	}
	if p.DNSZone = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p.DNSZone), ".")); p.DNSZone != "" && (len(p.DNSZone) > 253 || !zoneRe.MatchString(p.DNSZone)) {
		return ErrName
	}
	switch p.Scan {
	case "":
		p.Scan = ScanPassive
	case ScanOff, ScanPassive, ScanActive:
	default:
		return ErrStatus
	}
	if p.ScanNode, ok = clean(p.ScanNode, 64); !ok {
		return ErrName
	}
	return nil
}

// normalizeAddress prueft die Eingaben einer Adresse (ohne den Bezug zu einem Praefix).
func normalizeAddress(a *Address) error {
	ip, err := ParseAddr(a.Address)
	if err != nil {
		return err
	}
	a.Address = ip.String()
	if a.Status == "" {
		a.Status = StatusActive
	}
	if !validStatus(a.Status, false) {
		return ErrStatus
	}
	if !slices.Contains(addrRoles, a.Role) {
		return ErrRole
	}
	if a.Name = strings.ToLower(strings.TrimSpace(a.Name)); a.Name != "" && (len(a.Name) > maxHost || !hostRe.MatchString(a.Name)) {
		return ErrHost
	}
	if a.DNSZone = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(a.DNSZone), ".")); a.DNSZone != "" && (len(a.DNSZone) > 253 || !zoneRe.MatchString(a.DNSZone)) {
		return ErrHost
	}
	if a.MAC, err = normMAC(a.MAC); err != nil {
		return err
	}
	if a.DHCP && (a.MAC == "" || !ip.Is4()) { // Reservierung nur mit MAC und nur IPv4 (kein DHCPv6)
		return ErrMAC
	}
	var ok bool
	if a.Description, ok = clean(a.Description, maxComment); !ok {
		return ErrName
	}
	if a.Tags, err = normTags(a.Tags); err != nil {
		return err
	}
	return nil
}

// normalizeRange prueft einen Adressbereich (Anfang und Ende gleiche Familie, Anfang <= Ende).
func normalizeRange(r *Range) error {
	a, err1 := ParseAddr(r.Start)
	b, err2 := ParseAddr(r.End)
	if err1 != nil || err2 != nil || a.Is4() != b.Is4() || b.Less(a) {
		return ErrRange
	}
	r.Start, r.End = a.String(), b.String()
	if r.Kind == "" {
		r.Kind = RangeFixed
	}
	if r.Kind != RangeFixed && r.Kind != RangeReserved {
		return ErrRange
	}
	var ok bool
	if r.Name, ok = clean(r.Name, maxName); !ok {
		return ErrName
	}
	if r.Description, ok = clean(r.Description, maxComment); !ok {
		return ErrName
	}
	return nil
}

// ---- Lesen ----

const prefixCols = `uid, prefix, family, name, status, role, vlan, tags, description, mark_full, dns_zone, scan, scan_node, dyn_parent, dyn_index, dyn_source, updated, updated_by`

type scanner interface{ Scan(dest ...any) error }

func scanPrefix(s scanner) (Prefix, error) {
	var p Prefix
	var tags string
	var full, ts int64
	err := s.Scan(&p.UID, &p.Prefix, &p.Family, &p.Name, &p.Status, &p.Role, &p.VLAN, &tags, &p.Description, &full, &p.DNSZone, &p.Scan, &p.ScanNode,
		&p.DynParent, &p.DynIndex, &p.DynSource, &ts, &p.UpdatedBy)
	p.Tags, p.MarkFull, p.Updated = tagsOf(tags), full != 0, time.Unix(ts, 0).UTC()
	return p, err
}

// Prefixes liefert alle Praefixe.
func (m *Module) Prefixes(ctx context.Context) ([]Prefix, error) {
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT `+prefixCols+` FROM ipam_prefixes`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Prefix
	for rows.Next() {
		p, err := scanPrefix(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (m *Module) prefixByUID(ctx context.Context, uid string) (*Prefix, error) {
	p, err := scanPrefix(m.core.Reader().QueryRowContext(ctx, `SELECT `+prefixCols+` FROM ipam_prefixes WHERE uid = ?`, uid))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &p, err
}

const rangeCols = `uid, start_addr, end_addr, kind, name, description, updated, updated_by`

func scanRange(s scanner) (Range, error) {
	var r Range
	var ts int64
	err := s.Scan(&r.UID, &r.Start, &r.End, &r.Kind, &r.Name, &r.Description, &ts, &r.UpdatedBy)
	r.Updated = time.Unix(ts, 0).UTC()
	return r, err
}

// Ranges liefert alle Adressbereiche.
func (m *Module) Ranges(ctx context.Context) ([]Range, error) {
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT `+rangeCols+` FROM ipam_ranges`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Range
	for rows.Next() {
		r, err := scanRange(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (m *Module) rangeByUID(ctx context.Context, uid string) (*Range, error) {
	r, err := scanRange(m.core.Reader().QueryRowContext(ctx, `SELECT `+rangeCols+` FROM ipam_ranges WHERE uid = ?`, uid))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &r, err
}

const addrCols = `uid, address, status, role, name, dns, dns_zone, ptr, mac, dhcp, description, tags, updated, updated_by`

func scanAddress(s scanner) (Address, error) {
	var a Address
	var dns, ptr, dhcp, ts int64
	var tags string
	err := s.Scan(&a.UID, &a.Address, &a.Status, &a.Role, &a.Name, &dns, &a.DNSZone, &ptr, &a.MAC, &dhcp, &a.Description, &tags, &ts, &a.UpdatedBy)
	a.DNS, a.PTR, a.DHCP, a.Tags, a.Updated = dns != 0, ptr != 0, dhcp != 0, tagsOf(tags), time.Unix(ts, 0).UTC()
	return a, err
}

// Addresses liefert alle festen Adressen.
func (m *Module) Addresses(ctx context.Context) ([]Address, error) {
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT `+addrCols+` FROM ipam_addresses`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Address
	for rows.Next() {
		a, err := scanAddress(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (m *Module) addressWhere(ctx context.Context, where string, args ...any) (*Address, error) {
	a, err := scanAddress(m.core.Reader().QueryRowContext(ctx, `SELECT `+addrCols+` FROM ipam_addresses WHERE `+where, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &a, err
}

// AddressByIP liefert die feste Adresse zu einer IP (nil = keine).
func (m *Module) AddressByIP(ctx context.Context, ip string) (*Address, error) {
	a, err := ParseAddr(ip)
	if err != nil {
		return nil, err
	}
	return m.addressWhere(ctx, `address = ?`, a.String())
}

// ---- Schreiben ----

// SavePrefix legt ein Praefix an (UID leer) bzw. aendert es. Praefixe duerfen ineinander liegen, aber nicht doppelt
// vorkommen. actor steht in updated_by.
func (m *Module) SavePrefix(ctx context.Context, p Prefix, actor string) (Prefix, error) {
	if err := normalizePrefix(&p); err != nil {
		return p, err
	}
	if p.UID != "" && !uidRe.MatchString(p.UID) {
		return p, ErrNotFound
	}
	var other string
	err := m.core.Reader().QueryRowContext(ctx, `SELECT uid FROM ipam_prefixes WHERE prefix = ?`, p.Prefix).Scan(&other)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return p, err
	}
	if err == nil && other != p.UID {
		return p, ErrDup
	}
	if p.UID != "" {
		if old, err := m.prefixByUID(ctx, p.UID); err != nil {
			return p, err
		} else if old == nil {
			return p, ErrNotFound
		}
	} else {
		p.UID = newUID()
	}
	p.Updated, p.UpdatedBy = m.now().UTC().Truncate(time.Second), actor
	if err := m.writePrefix(ctx, p); err != nil {
		return p, err
	}
	m.changed(ctx, ClusterItemPrefixes, p.UID, false)
	return p, nil
}

func (m *Module) writePrefix(ctx context.Context, p Prefix) error {
	_, err := m.core.Writer().ExecContext(ctx, `INSERT INTO ipam_prefixes (`+prefixCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT (uid) DO UPDATE SET prefix = excluded.prefix, family = excluded.family, name = excluded.name, status = excluded.status,
			role = excluded.role, vlan = excluded.vlan, tags = excluded.tags, description = excluded.description, mark_full = excluded.mark_full,
			dns_zone = excluded.dns_zone, scan = excluded.scan, scan_node = excluded.scan_node, dyn_parent = excluded.dyn_parent,
			dyn_index = excluded.dyn_index, dyn_source = excluded.dyn_source, updated = excluded.updated, updated_by = excluded.updated_by`,
		p.UID, p.Prefix, p.Family, p.Name, p.Status, p.Role, p.VLAN, tagsText(p.Tags), p.Description, boolInt(p.MarkFull), p.DNSZone, p.Scan, p.ScanNode,
		p.DynParent, p.DynIndex, p.DynSource, p.Updated.Unix(), p.UpdatedBy)
	return err
}

// DeletePrefix loescht ein Praefix. Adressen und Bereiche darin bleiben (sie gehoeren dann zum naechstgroesseren
// Praefix bzw. erscheinen ohne Praefix nicht mehr in den Listen, bis wieder eins angelegt ist).
func (m *Module) DeletePrefix(ctx context.Context, uid string) (*Prefix, error) {
	p, err := m.prefixByUID(ctx, uid)
	if err != nil || p == nil {
		return nil, notFound(err)
	}
	if _, err := m.core.Writer().ExecContext(ctx, `DELETE FROM ipam_prefixes WHERE uid = ?`, uid); err != nil {
		return nil, err
	}
	m.changed(ctx, ClusterItemPrefixes, uid, true)
	return p, nil
}

// SaveRange legt einen Adressbereich an bzw. aendert ihn. Er muss ganz in einem Praefix liegen und darf andere
// Bereiche nicht ueberschneiden.
func (m *Module) SaveRange(ctx context.Context, r Range, actor string) (Range, error) {
	if err := normalizeRange(&r); err != nil {
		return r, err
	}
	if r.UID != "" && !uidRe.MatchString(r.UID) {
		return r, ErrNotFound
	}
	a, b := netip.MustParseAddr(r.Start), netip.MustParseAddr(r.End)
	prefixes, err := m.Prefixes(ctx)
	if err != nil {
		return r, err
	}
	inside := false
	for _, p := range prefixes {
		pp, err := netip.ParsePrefix(p.Prefix)
		inside = inside || (err == nil && pp.Contains(a) && pp.Contains(b))
	}
	for _, h := range m.hintList(ctx) { // auch in einem DHCP-Netz aus DNS64
		inside = inside || (h.Subnet.Contains(a) && h.Subnet.Contains(b))
	}
	if !inside {
		return r, ErrRangeNet
	}
	list, err := m.Ranges(ctx)
	if err != nil {
		return r, err
	}
	for _, o := range list {
		oa, err1 := netip.ParseAddr(o.Start)
		ob, err2 := netip.ParseAddr(o.End)
		if o.UID != r.UID && err1 == nil && err2 == nil && oa.Is4() == a.Is4() && !b.Less(oa) && !ob.Less(a) {
			return r, ErrOverlap
		}
	}
	if r.UID != "" {
		if old, err := m.rangeByUID(ctx, r.UID); err != nil {
			return r, err
		} else if old == nil {
			return r, ErrNotFound
		}
	} else {
		r.UID = newUID()
	}
	r.Updated, r.UpdatedBy = m.now().UTC().Truncate(time.Second), actor
	if err := m.writeRange(ctx, r); err != nil {
		return r, err
	}
	m.changed(ctx, ClusterItemRanges, r.UID, false)
	return r, nil
}

func (m *Module) writeRange(ctx context.Context, r Range) error {
	_, err := m.core.Writer().ExecContext(ctx, `INSERT INTO ipam_ranges (`+rangeCols+`) VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT (uid) DO UPDATE SET start_addr = excluded.start_addr, end_addr = excluded.end_addr, kind = excluded.kind, name = excluded.name,
			description = excluded.description, updated = excluded.updated, updated_by = excluded.updated_by`,
		r.UID, r.Start, r.End, r.Kind, r.Name, r.Description, r.Updated.Unix(), r.UpdatedBy)
	return err
}

// DeleteRange loescht einen Adressbereich.
func (m *Module) DeleteRange(ctx context.Context, uid string) (*Range, error) {
	r, err := m.rangeByUID(ctx, uid)
	if err != nil || r == nil {
		return nil, notFound(err)
	}
	if _, err := m.core.Writer().ExecContext(ctx, `DELETE FROM ipam_ranges WHERE uid = ?`, uid); err != nil {
		return nil, err
	}
	m.changed(ctx, ClusterItemRanges, uid, true)
	return r, nil
}

// SaveAddress traegt eine feste Adresse ein (UID leer) bzw. aendert sie. Die Adresse muss in einem Praefix (oder
// DHCP-Netz) liegen und darf bei IPv4 nicht Netz- oder Broadcast-Adresse sein.
func (m *Module) SaveAddress(ctx context.Context, a Address, actor string) (Address, error) {
	if err := normalizeAddress(&a); err != nil {
		return a, err
	}
	if a.UID != "" && !uidRe.MatchString(a.UID) {
		return a, ErrNotFound
	}
	ip := netip.MustParseAddr(a.Address)
	p, ok := m.containing(ctx, ip)
	if !ok {
		return a, ErrNoNet
	}
	if ip.Is4() && p.Bits() <= 30 && (ip == p.Masked().Addr() || ip == lastAddr(p)) {
		return a, ErrNetAddr
	}
	other, err := m.addressWhere(ctx, `address = ?`, a.Address)
	if err != nil {
		return a, err
	}
	if other != nil && other.UID != a.UID {
		return a, ErrTaken
	}
	if a.UID != "" {
		if old, err := m.addressWhere(ctx, `uid = ?`, a.UID); err != nil {
			return a, err
		} else if old == nil {
			return a, ErrNotFound
		}
	} else {
		a.UID = newUID()
	}
	a.Updated, a.UpdatedBy = m.now().UTC().Truncate(time.Second), actor
	if err := m.writeAddress(ctx, a); err != nil {
		return a, err
	}
	m.changed(ctx, ClusterItemAddresses, a.UID, false)
	return a, nil
}

func (m *Module) writeAddress(ctx context.Context, a Address) error {
	_, err := m.core.Writer().ExecContext(ctx, `INSERT INTO ipam_addresses (`+addrCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT (uid) DO UPDATE SET address = excluded.address, status = excluded.status, role = excluded.role, name = excluded.name,
			dns = excluded.dns, dns_zone = excluded.dns_zone, ptr = excluded.ptr, mac = excluded.mac, dhcp = excluded.dhcp,
			description = excluded.description, tags = excluded.tags, updated = excluded.updated, updated_by = excluded.updated_by`,
		a.UID, a.Address, a.Status, a.Role, a.Name, boolInt(a.DNS), a.DNSZone, boolInt(a.PTR), a.MAC, boolInt(a.DHCP), a.Description, tagsText(a.Tags),
		a.Updated.Unix(), a.UpdatedBy)
	return err
}

// DeleteAddress loescht eine feste Adresse.
func (m *Module) DeleteAddress(ctx context.Context, uid string) (*Address, error) {
	a, err := m.addressWhere(ctx, `uid = ?`, uid)
	if err != nil || a == nil {
		return nil, notFound(err)
	}
	if _, err := m.core.Writer().ExecContext(ctx, `DELETE FROM ipam_addresses WHERE uid = ?`, uid); err != nil {
		return nil, err
	}
	m.changed(ctx, ClusterItemAddresses, uid, true)
	return a, nil
}

func notFound(err error) error {
	if err != nil {
		return err
	}
	return ErrNotFound
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// containing liefert das kleinste Praefix bzw. DHCP-Netz, in dem ip liegt.
func (m *Module) containing(ctx context.Context, ip netip.Addr) (netip.Prefix, bool) {
	var best netip.Prefix
	list, _ := m.Prefixes(ctx)
	for _, p := range list {
		if pp, err := netip.ParsePrefix(p.Prefix); err == nil && pp.Contains(ip) && (!best.IsValid() || pp.Bits() > best.Bits()) {
			best = pp
		}
	}
	for _, h := range m.hintList(ctx) {
		if h.Subnet.Contains(ip) && (!best.IsValid() || h.Subnet.Bits() > best.Bits()) {
			best = h.Subnet
		}
	}
	return best, best.IsValid()
}

// ---- Sichtungen ----

// saveSeen merkt Sichtungen (IP -> MAC) zum Zeitpunkt now.
func (m *Module) saveSeen(ctx context.Context, seen map[netip.Addr]string, now time.Time) error {
	if len(seen) == 0 {
		return nil
	}
	tx, err := m.core.Writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for ip, mac := range seen {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ipam_seen (ip, mac, first_seen, last_seen) VALUES (?, ?, ?, ?)
			ON CONFLICT (ip, mac) DO UPDATE SET last_seen = MAX(last_seen, excluded.last_seen)`, ip.String(), mac, now.Unix(), now.Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (m *Module) seenRows(ctx context.Context) ([]seenRow, error) {
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT ip, mac, first_seen, last_seen FROM ipam_seen ORDER BY last_seen`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []seenRow
	for rows.Next() {
		var ip string
		var s seenRow
		var a, b int64
		if err := rows.Scan(&ip, &s.MAC, &a, &b); err != nil {
			return nil, err
		}
		if s.IP, err = netip.ParseAddr(ip); err != nil {
			continue
		}
		s.First, s.Last = time.Unix(a, 0), time.Unix(b, 0)
		out = append(out, s)
	}
	return out, rows.Err()
}

// pruneSeen loescht Sichtungen, die aelter als seenKeep sind.
func (m *Module) pruneSeen(ctx context.Context, now time.Time) {
	if _, err := m.core.Writer().ExecContext(ctx, `DELETE FROM ipam_seen WHERE last_seen < ?`, now.Add(-seenKeep).Unix()); err != nil {
		m.log.Warn("ipam64: prune sightings", "err", err)
	}
}

// lastAddr ist die letzte Adresse eines Praefixes (IPv4: Broadcast).
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	host := len(b)*8 - p.Bits()
	for i := len(b) - 1; i >= 0 && host > 0; i-- {
		n := min(host, 8)
		b[i] |= byte(1<<n - 1)
		host -= n
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
