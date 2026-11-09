package dns64

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/dns64/dhcp"
	"github.com/ipv64net/node64/internal/dns64/groups"
	"github.com/ipv64net/node64/internal/dns64/localnet"
	"github.com/ipv64net/node64/internal/notify"
)

// DHCP-Server (Paket dhcp, Plan docs/PLAN-NODE64-DNS64-DHCP.md): Teil von DNS64, aber opt-in. Schalter dns64.dhcp je
// Node (nie im Cluster): aus = kein Socket, Probelauf = nur zuhoeren, an = Adressen vergeben. Netze, feste Adressen
// und Leases in node64.db. Laeuft neben dem DNS-Dienst (ein Neustart von DNS64 nach Einstellungen beruehrt ihn nicht),
// endet aber mit dem Modul. Nach jeder Aenderung an Netzen oder festen Adressen startet nur der DHCP-Server neu.

const (
	setDHCP     = "dns64.dhcp"      // off | observe | on
	setDHCPRole = "dns64.dhcp_role" // primary | reserve (je Node, nie im Cluster)
	dhcpPrimary = "primary"
	dhcpReserve = "reserve"
	dhcpOff     = "off"
	dhcpObserve = "observe"
	dhcpOn      = "on"

	dhcpPoolWarn = 90 // Prozent belegt: Benachrichtigung
	dhcpPoolOK   = 80 // darunter wieder melden
)

// dhcpBridge: Docker-Bridge-Netz (DHCP gesperrt); Tests ersetzen es.
var dhcpBridge = localnet.Bridge

// DHCPScope ist ein DHCP-Netz (Seite und API).
type DHCPScope struct {
	ID            int64     `json:"id"`
	Name          string    `json:"name"`
	Iface         string    `json:"interface"`
	Subnet        string    `json:"subnet"`
	Start         string    `json:"range_start"`
	End           string    `json:"range_end"`
	Router        string    `json:"router"`
	DNS           []string  `json:"dns"` // leer = diese Node
	Domain        string    `json:"domain"`
	LeaseHours    int       `json:"lease_hours"`
	NTP           []string  `json:"ntp"`
	Authoritative bool      `json:"authoritative"`
	BootServer    string    `json:"boot_server"`
	BootBIOS      string    `json:"boot_bios"`
	BootUEFI      string    `json:"boot_uefi"`
	BootIPXE      string    `json:"boot_ipxe"`
	Relay         bool      `json:"relay"` // Netz hinter einem DHCP-Relay (Router leitet weiter)
	Enabled       bool      `json:"enabled"`
	CreatedAt     time.Time `json:"created_at"`
}

// DHCPReservation ist eine feste Adresse.
type DHCPReservation struct {
	ID      int64  `json:"id"`
	ScopeID int64  `json:"scope_id"`
	MAC     string `json:"mac"`
	IP      string `json:"ip"`
	Name    string `json:"name"`
	Comment string `json:"comment,omitempty"`
	GroupID int64  `json:"group_id,omitempty"` // nur beim Anlegen: MAC zusaetzlich in diese Geraetegruppe aufnehmen
}

// dhcpState: laufender DHCP-Server (dhcpMu).
type dhcpState struct {
	mu       sync.Mutex
	cancel   context.CancelFunc
	done     chan struct{}
	poolMu   sync.Mutex
	poolSent map[int64]bool // Netz fast voll: gemeldet

	soonMu    sync.Mutex
	namesT    *time.Timer // Namen neu bauen (gebuendelt)
	leasesT   *time.Timer // Vergaben an den Cluster melden (gebuendelt)
	standbyAt time.Time   // Reserve: zuletzt geprueft
	standby   bool
}

func (m *Module) dhcpMode(ctx context.Context) string {
	return oneOf(m.core.SettingOr(ctx, setDHCP, ""), dhcpOff, dhcpOff, dhcpObserve, dhcpOn)
}

// SetDHCPMode schaltet den DHCP-Server (off, observe, on) und startet ihn passend.
func (m *Module) SetDHCPMode(ctx context.Context, mode string) error {
	if mode != dhcpOff && mode != dhcpObserve && mode != dhcpOn {
		return errCfg("err_dhcp_mode")
	}
	if mode != dhcpOff && dhcpBridge() {
		return errCfg("err_dhcp_bridge")
	}
	if err := m.core.SetSetting(ctx, setDHCP, mode); err != nil {
		return err
	}
	m.dhcpApply(ctx)
	return nil
}

// dhcpApply stoppt den DHCP-Server und startet ihn mit dem aktuellen Stand neu, wenn das Modul laeuft, der Schalter
// nicht aus ist und es ein eingeschaltetes Netz gibt.
func (m *Module) dhcpApply(ctx context.Context) {
	m.dh.mu.Lock()
	defer m.dh.mu.Unlock()
	old := m.dhcpSrv.Load()
	m.dhcpHaltLocked()
	m.mu.Lock()
	on := m.life != nil
	m.mu.Unlock()
	mode := m.dhcpMode(ctx)
	if !on || mode == dhcpOff || dhcpBridge() {
		return
	}
	cfg, err := m.dhcpConfig(ctx)
	if err != nil {
		if !m.noTable(err) {
			m.log.Warn("dhcp config", "err", err)
		}
		return
	}
	if len(cfg.Scopes) == 0 {
		return
	}
	cfg.Observe = mode == dhcpObserve
	s := dhcp.New(cfg, dhcpStore{m}, m.log.With("part", "dhcp"))
	s.Probe = dhcp.ARPProbe
	s.OnForeign = m.dhcpForeign
	s.OnChange = m.dhcpChanged
	if m.dhcpRole(ctx) == dhcpReserve { // Reserve: still, solange die Haupt-Node lebt; oefter nach ihr sehen
		s.Standby, s.CheckEvery = m.dhcpStandby, time.Minute
	}
	s.Carry(old)
	rctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.Run(rctx) }()
	m.dh.cancel, m.dh.done = cancel, done
	m.dhcpSrv.Store(s)
}

// dhcpHalt stoppt den DHCP-Server (Modul aus).
func (m *Module) dhcpHalt() {
	m.dh.mu.Lock()
	defer m.dh.mu.Unlock()
	m.dhcpHaltLocked()
	m.dhcpSrv.Store(nil)
}

func (m *Module) dhcpHaltLocked() {
	if m.dh.cancel != nil {
		m.dh.cancel()
		<-m.dh.done
		m.dh.cancel, m.dh.done = nil, nil
	}
}

// dhcpConfig liest eingeschaltete Netze, feste Adressen und Leases.
func (m *Module) dhcpConfig(ctx context.Context) (dhcp.Config, error) {
	var cfg dhcp.Config
	scopes, err := m.DHCPScopes(ctx)
	if err != nil {
		return cfg, err
	}
	for _, s := range scopes {
		if s.Enabled && s.Iface != "" { // aus dem Cluster ohne passende Schnittstelle: aus
			sc := s.toDHCP()
			sc.ExtraDNS = m.dhcpPeerDNS(ctx, sc.Subnet)
			cfg.Scopes = append(cfg.Scopes, sc)
		}
	}
	res, err := m.DHCPReservations(ctx)
	if err != nil {
		return cfg, err
	}
	for _, r := range res {
		ip, _ := netip.ParseAddr(r.IP)
		cfg.Reservations = append(cfg.Reservations, dhcp.Reservation{Scope: r.ScopeID, MAC: r.MAC, IP: ip, Name: r.Name})
	}
	cfg.Leases, err = m.dhcpLeaseRows(ctx)
	return cfg, err
}

func (s DHCPScope) toDHCP() dhcp.Scope {
	p, _ := netip.ParsePrefix(s.Subnet)
	a, _ := netip.ParseAddr(s.Start)
	b, _ := netip.ParseAddr(s.End)
	r, _ := netip.ParseAddr(s.Router)
	return dhcp.Scope{ID: s.ID, Name: s.Name, Iface: s.Iface, Subnet: p, Start: a, End: b, Router: r, DNS: dhcpAddrs(s.DNS), Domain: s.Domain,
		Lease: time.Duration(s.LeaseHours) * time.Hour, NTP: dhcpAddrs(s.NTP), Authoritative: s.Authoritative,
		BootServer: s.BootServer, BootBIOS: s.BootBIOS, BootUEFI: s.BootUEFI, BootIPXE: s.BootIPXE, Relay: s.Relay}
}

func dhcpAddrs(list []string) []netip.Addr {
	var out []netip.Addr
	for _, v := range list {
		if a, err := netip.ParseAddr(v); err == nil {
			out = append(out, a)
		}
	}
	return out
}

// dhcpStore speichert Leases in node64.db.
type dhcpStore struct{ m *Module }

func (d dhcpStore) SaveLease(l dhcp.Lease) error {
	ctx := context.Background()
	w := d.m.core.Writer()
	if _, err := w.ExecContext(ctx, `DELETE FROM dns64_dhcp_leases WHERE scope_id = ? AND ip = ? AND mac <> ?`, l.Scope, l.IP.String(), l.MAC); err != nil {
		return err
	}
	_, err := w.ExecContext(ctx, `INSERT INTO dns64_dhcp_leases (scope_id, mac, ip, hostname, expires, state) VALUES (?,?,?,?,?,?)
		ON CONFLICT(scope_id, mac) DO UPDATE SET ip = excluded.ip, hostname = excluded.hostname, expires = excluded.expires, state = excluded.state`,
		l.Scope, l.MAC, l.IP.String(), l.Hostname, l.Expires.UTC().Format(time.RFC3339), l.State)
	return err
}

func (d dhcpStore) DeleteLease(scope int64, mac string) error {
	_, err := d.m.core.Writer().ExecContext(context.Background(), `DELETE FROM dns64_dhcp_leases WHERE scope_id = ? AND mac = ?`, scope, mac)
	return err
}

// ---- Benachrichtigungen: fremder DHCP-Server, Netz fast voll ----

func (m *Module) dhcpNotify(scope int64, reason string) {
	if m.notifier == nil {
		return
	}
	name := strconv.FormatInt(scope, 10)
	if sc, err := m.dhcpScope(context.Background(), scope); err == nil {
		name = sc.label()
	}
	now := time.Now().UTC()
	m.log.Info("notification", "kind", notify.KindDNS64DHCP, "name", name, "reason", reason)
	m.notifier(notify.Alert{EventID: "dns64-dhcp-" + strconv.FormatInt(now.UnixNano(), 36), Kind: notify.KindDNS64DHCP, Time: now,
		Check: notify.CheckInfo{Name: name, NotifyDown: true, NotifyUp: true, Local: true}, Reason: reason})
}

func (m *Module) dhcpForeign(scope int64, server netip.Addr) {
	if m.dhcpIsPeer(server) { // Node des Clusters (Haupt-/Reserve-Node), kein fremder Server
		return
	}
	m.dhcpNotify(scope, "other DHCP server "+server.String())
}

// dhcpChanged: Vergaben geaendert (vom Server, ohne gehaltene Sperre) - Belegung pruefen, Namen und Cluster nachziehen.
func (m *Module) dhcpChanged() {
	m.dhcpPoolCheck()
	m.dhcpNamesSoon()
	m.dhcpLeasesSoon()
}

// dhcpPoolCheck meldet ein Netz, das zu 90 % belegt ist (einmal, wieder erst unter 80 %).
func (m *Module) dhcpPoolCheck() {
	s := m.dhcpSrv.Load()
	if s == nil {
		return
	}
	m.dh.poolMu.Lock()
	defer m.dh.poolMu.Unlock()
	if m.dh.poolSent == nil {
		m.dh.poolSent = map[int64]bool{}
	}
	for _, v := range s.Snapshot().Scopes {
		if v.Size == 0 {
			continue
		}
		pct := (v.Used + v.Reserved) * 100 / v.Size
		switch {
		case pct >= dhcpPoolWarn && !m.dh.poolSent[v.ID]:
			m.dh.poolSent[v.ID] = true
			go m.dhcpNotify(v.ID, "address pool "+strconv.Itoa(pct)+"% used")
		case pct < dhcpPoolOK:
			delete(m.dh.poolSent, v.ID)
		}
	}
}

// ---- Netze ----

func (s DHCPScope) label() string {
	if s.Name != "" {
		return s.Name + " (" + s.Iface + ")"
	}
	return s.Iface + " " + s.Subnet
}

const dhcpScopeCols = `id, name, iface, subnet, range_start, range_end, router, dns, domain, lease_hours, ntp, authoritative, boot_server, boot_bios, boot_uefi, boot_ipxe, relay, enabled, created_at`

type rowScanner interface{ Scan(...any) error }

func scanDHCPScope(r rowScanner) (DHCPScope, error) {
	var s DHCPScope
	var dns, ntp, created string
	err := r.Scan(&s.ID, &s.Name, &s.Iface, &s.Subnet, &s.Start, &s.End, &s.Router, &dns, &s.Domain, &s.LeaseHours, &ntp, &s.Authoritative,
		&s.BootServer, &s.BootBIOS, &s.BootUEFI, &s.BootIPXE, &s.Relay, &s.Enabled, &created)
	s.DNS, s.NTP = dhcpList(dns), dhcpList(ntp)
	s.CreatedAt, _ = time.Parse(time.RFC3339, created)
	return s, err
}

func dhcpList(v string) []string {
	out := []string{}
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == ';' }) {
		out = append(out, f)
	}
	return out
}

// DHCPScopes liefert alle Netze (nach Schnittstelle).
func (m *Module) DHCPScopes(ctx context.Context) ([]DHCPScope, error) {
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT `+dhcpScopeCols+` FROM dns64_dhcp_scopes ORDER BY iface, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DHCPScope{}
	for rows.Next() {
		s, err := scanDHCPScope(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (m *Module) dhcpScope(ctx context.Context, id int64) (DHCPScope, error) {
	s, err := scanDHCPScope(m.core.Reader().QueryRowContext(ctx, `SELECT `+dhcpScopeCols+` FROM dns64_dhcp_scopes WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return s, errNotFound
	}
	return s, err
}

func validIface(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' || c == '@' || c == ':') {
			return false
		}
	}
	return true
}

func addr4List(list []string, max int, key string) ([]string, error) {
	out := []string{}
	for _, v := range list {
		a, err := netip.ParseAddr(strings.TrimSpace(v))
		if err != nil || !a.Is4() {
			return nil, errCfg(key)
		}
		out = append(out, a.String())
	}
	if len(out) > max {
		return nil, errCfg(key)
	}
	return out, nil
}

func bootValue(v string, max int) (string, bool) {
	v = strings.TrimSpace(v)
	if len(v) > max {
		return v, false
	}
	for _, c := range v {
		if c <= ' ' || c > '~' {
			return v, false
		}
	}
	return v, true
}

func normalizeDHCPScope(s *DHCPScope) error {
	s.Name = strings.TrimSpace(s.Name)
	if len(s.Name) > 60 {
		return errCfg("err_dhcp_name")
	}
	if s.Iface = strings.TrimSpace(s.Iface); !validIface(s.Iface) {
		return errCfg("err_dhcp_iface")
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(s.Subnet))
	if err != nil || !p.Addr().Is4() || p.Bits() < 8 || p.Bits() > 30 {
		return errCfg("err_dhcp_subnet")
	}
	p = p.Masked()
	s.Subnet = p.String()
	a, err1 := netip.ParseAddr(strings.TrimSpace(s.Start))
	b, err2 := netip.ParseAddr(strings.TrimSpace(s.End))
	if err1 != nil || err2 != nil || !p.Contains(a) || !p.Contains(b) || b.Less(a) || a == p.Addr() || b == dhcp.Broadcast(p) {
		return errCfg("err_dhcp_range")
	}
	s.Start, s.End = a.String(), b.String()
	if s.Router = strings.TrimSpace(s.Router); s.Router != "" {
		r, err := netip.ParseAddr(s.Router)
		if err != nil || !p.Contains(r) {
			return errCfg("err_dhcp_router")
		}
		s.Router = r.String()
	}
	if s.DNS, err = addr4List(s.DNS, 4, "err_dhcp_dns"); err != nil {
		return err
	}
	if s.NTP, err = addr4List(s.NTP, 4, "err_dhcp_ntp"); err != nil {
		return err
	}
	if s.Domain = hostName(s.Domain); s.Domain != "" && !validName(s.Domain) {
		return errCfg("err_dhcp_domain")
	}
	if s.LeaseHours == 0 {
		s.LeaseHours = 24
	}
	if s.LeaseHours < 1 || s.LeaseHours > 8760 {
		return errCfg("err_dhcp_lease")
	}
	ok := true
	for _, f := range []struct {
		p   *string
		max int
	}{{&s.BootServer, 63}, {&s.BootBIOS, 127}, {&s.BootUEFI, 127}, {&s.BootIPXE, 127}} {
		var good bool
		*f.p, good = bootValue(*f.p, f.max)
		ok = ok && good
	}
	if !ok {
		return errCfg("err_dhcp_boot")
	}
	return nil
}

// dhcpIfaceTaken: je Schnittstelle ein Netz (Relay-Netze teilen sich die Schnittstelle mit anderen).
func (m *Module) dhcpIfaceTaken(ctx context.Context, s DHCPScope, id int64) bool {
	if s.Relay {
		return false
	}
	var n int
	_ = m.core.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM dns64_dhcp_scopes WHERE iface = ? AND relay = 0 AND id <> ?`, s.Iface, id).Scan(&n)
	return n > 0
}

// dhcpSubnetTaken: jedes Netz nur einmal (Kennung im Cluster).
func (m *Module) dhcpSubnetTaken(ctx context.Context, subnet string, id int64) bool {
	var n int
	_ = m.core.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM dns64_dhcp_scopes WHERE subnet = ? AND id <> ?`, subnet, id).Scan(&n)
	return n > 0
}

// AddDHCPScope legt ein Netz an (je Schnittstelle eins).
func (m *Module) AddDHCPScope(ctx context.Context, s DHCPScope) (DHCPScope, error) {
	if err := normalizeDHCPScope(&s); err != nil {
		return s, err
	}
	if m.dhcpIfaceTaken(ctx, s, 0) {
		return s, errCfg("err_dhcp_iface_dup")
	}
	if m.dhcpSubnetTaken(ctx, s.Subnet, 0) {
		return s, errCfg("err_dhcp_subnet_dup")
	}
	s.Enabled, s.CreatedAt = true, time.Now().UTC()
	res, err := m.core.Writer().ExecContext(ctx, `INSERT INTO dns64_dhcp_scopes (name, iface, subnet, range_start, range_end, router, dns, domain, lease_hours, ntp, authoritative, boot_server, boot_bios, boot_uefi, boot_ipxe, relay, enabled, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?)`, s.Name, s.Iface, s.Subnet, s.Start, s.End, s.Router, strings.Join(s.DNS, ","), s.Domain, s.LeaseHours,
		strings.Join(s.NTP, ","), s.Authoritative, s.BootServer, s.BootBIOS, s.BootUEFI, s.BootIPXE, s.Relay, s.CreatedAt.Format(time.RFC3339))
	if err != nil {
		return s, err
	}
	s.ID, _ = res.LastInsertId()
	m.dhcpApply(ctx)
	m.dhcpSynced(ctx)
	return s, nil
}

// UpdateDHCPScope aendert ein Netz; an/aus bleibt.
func (m *Module) UpdateDHCPScope(ctx context.Context, id int64, s DHCPScope) (DHCPScope, error) {
	if err := normalizeDHCPScope(&s); err != nil {
		return s, err
	}
	if m.dhcpIfaceTaken(ctx, s, id) {
		return s, errCfg("err_dhcp_iface_dup")
	}
	if m.dhcpSubnetTaken(ctx, s.Subnet, id) {
		return s, errCfg("err_dhcp_subnet_dup")
	}
	err := m.dhcpExec(ctx, `UPDATE dns64_dhcp_scopes SET name = ?, iface = ?, subnet = ?, range_start = ?, range_end = ?, router = ?, dns = ?, domain = ?, lease_hours = ?, ntp = ?, authoritative = ?,
		boot_server = ?, boot_bios = ?, boot_uefi = ?, boot_ipxe = ?, relay = ? WHERE id = ?`, s.Name, s.Iface, s.Subnet, s.Start, s.End, s.Router, strings.Join(s.DNS, ","), s.Domain,
		s.LeaseHours, strings.Join(s.NTP, ","), s.Authoritative, s.BootServer, s.BootBIOS, s.BootUEFI, s.BootIPXE, s.Relay, id)
	s.ID = id
	return s, err
}

// DeleteDHCPScope loescht ein Netz mit seinen festen Adressen und Leases.
func (m *Module) DeleteDHCPScope(ctx context.Context, id int64) error {
	return m.dhcpExec(ctx, `DELETE FROM dns64_dhcp_scopes WHERE id = ?`, id)
}

// SetDHCPScopeEnabled schaltet ein Netz an oder aus.
func (m *Module) SetDHCPScopeEnabled(ctx context.Context, id int64, on bool) error {
	return m.dhcpExec(ctx, `UPDATE dns64_dhcp_scopes SET enabled = ? WHERE id = ?`, on, id)
}

func (m *Module) dhcpExec(ctx context.Context, q string, args ...any) error {
	res, err := m.core.Writer().ExecContext(ctx, q, args...)
	if isUnique(err) {
		return errCfg("err_dhcp_res_dup")
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	m.dhcpApply(ctx)
	m.dhcpSynced(ctx)
	return nil
}

// ---- Feste Adressen ----

// DHCPReservations liefert alle festen Adressen (nach Netz und IP).
func (m *Module) DHCPReservations(ctx context.Context) ([]DHCPReservation, error) {
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT id, scope_id, mac, ip, name, comment FROM dns64_dhcp_reservations ORDER BY scope_id, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DHCPReservation{}
	for rows.Next() {
		var r DHCPReservation
		if err := rows.Scan(&r.ID, &r.ScopeID, &r.MAC, &r.IP, &r.Name, &r.Comment); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (m *Module) normalizeDHCPReservation(ctx context.Context, r *DHCPReservation) error {
	hw, err := net.ParseMAC(strings.TrimSpace(r.MAC))
	if err != nil || len(hw) != 6 {
		return errCfg("err_dhcp_mac")
	}
	r.MAC = hw.String()
	sc, err := m.dhcpScope(ctx, r.ScopeID)
	if err != nil {
		return errCfg("err_dhcp_scope")
	}
	p, _ := netip.ParsePrefix(sc.Subnet)
	ip, err := netip.ParseAddr(strings.TrimSpace(r.IP))
	if err != nil || !p.Contains(ip) || ip == p.Addr() || ip == dhcp.Broadcast(p) {
		return errCfg("err_dhcp_res_ip")
	}
	r.IP = ip.String()
	r.Name, r.Comment = strings.TrimSpace(r.Name), strings.TrimSpace(r.Comment)
	if len(r.Name) > 63 || len(r.Comment) > 200 {
		return errCfg("err_comment")
	}
	return nil
}

// AddDHCPReservation legt eine feste Adresse an (MAC und IP je Netz eindeutig).
func (m *Module) AddDHCPReservation(ctx context.Context, r DHCPReservation) (DHCPReservation, error) {
	if err := m.normalizeDHCPReservation(ctx, &r); err != nil {
		return r, err
	}
	res, err := m.core.Writer().ExecContext(ctx, `INSERT INTO dns64_dhcp_reservations (scope_id, mac, ip, name, comment) VALUES (?,?,?,?,?)`, r.ScopeID, r.MAC, r.IP, r.Name, r.Comment)
	if isUnique(err) {
		return r, errCfg("err_dhcp_res_dup")
	}
	if err != nil {
		return r, err
	}
	r.ID, _ = res.LastInsertId()
	m.dhcpApply(ctx)
	m.dhcpSynced(ctx)
	if r.GroupID > 0 { // MAC in die Geraetegruppe aufnehmen (Regeln gelten auch bei neuer IP)
		if _, err := m.AddMember(ctx, groups.Member{GroupID: r.GroupID, Kind: groups.KindMAC, Value: r.MAC, Label: r.Name}); err != nil {
			return r, err
		}
	}
	return r, nil
}

// UpdateDHCPReservation aendert eine feste Adresse.
func (m *Module) UpdateDHCPReservation(ctx context.Context, id int64, r DHCPReservation) (DHCPReservation, error) {
	if err := m.normalizeDHCPReservation(ctx, &r); err != nil {
		return r, err
	}
	r.ID = id
	return r, m.dhcpExec(ctx, `UPDATE dns64_dhcp_reservations SET scope_id = ?, mac = ?, ip = ?, name = ?, comment = ? WHERE id = ?`, r.ScopeID, r.MAC, r.IP, r.Name, r.Comment, id)
}

// DeleteDHCPReservation loescht eine feste Adresse.
func (m *Module) DeleteDHCPReservation(ctx context.Context, id int64) error {
	return m.dhcpExec(ctx, `DELETE FROM dns64_dhcp_reservations WHERE id = ?`, id)
}

// ReleaseDHCPLease gibt ein Lease von Hand frei.
func (m *Module) ReleaseDHCPLease(ctx context.Context, scope int64, mac string) error {
	if s := m.dhcpSrv.Load(); s != nil && s.Release(scope, mac) {
		return nil // der Server loescht in der Datenbank, OnChange zieht Namen und Cluster nach
	}
	defer m.dhcpChanged()
	res, err := m.core.Writer().ExecContext(ctx, `DELETE FROM dns64_dhcp_leases WHERE scope_id = ? AND mac = ?`, scope, mac)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

// ---- Schnittstellen und Vorschlag fuer das erste Netz ----

// dhcpIface ist eine Schnittstelle des Hosts mit IPv4 (Auswahl im Formular).
type dhcpIface struct {
	Name    string         `json:"name"`
	Addrs   []netip.Prefix `json:"addrs"`
	Suggest DHCPScope      `json:"suggest"`
}

// dhcpInterfaces: Schnittstellen mit IPv4 (ohne Loopback), je mit Vorschlag fuer Netz, Bereich und Router.
func dhcpInterfaces() []dhcpIface {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	gw := localnet.Gateway()
	var out []dhcpIface
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagUp == 0 {
			continue
		}
		addrs := dhcp.IfaceAddrs(ifi.Name)
		if len(addrs) == 0 {
			continue
		}
		out = append(out, dhcpIface{Name: ifi.Name, Addrs: addrs, Suggest: suggestScope(ifi.Name, addrs[0], gw)})
	}
	return out
}

// suggestScope: Netz der Adresse, Bereich .100–.199 (im eigenen /24) bzw. obere Haelfte kleiner Netze, Router =
// Default-Gateway, wenn es im Netz liegt.
func suggestScope(iface string, a netip.Prefix, gw netip.Addr) DHCPScope {
	p := a.Masked()
	s := DHCPScope{Iface: iface, Subnet: p.String(), LeaseHours: 24, Authoritative: true}
	b := a.Addr().As4()
	if p.Bits() <= 24 {
		s.Start = netip.AddrFrom4([4]byte{b[0], b[1], b[2], 100}).String()
		s.End = netip.AddrFrom4([4]byte{b[0], b[1], b[2], 199}).String()
	} else {
		n := p.Addr().As4()
		size := uint32(1) << (32 - p.Bits())
		v := uint32(n[0])<<24 | uint32(n[1])<<16 | uint32(n[2])<<8 | uint32(n[3])
		lo, hi := v+size/2, v+size-2
		s.Start = netip.AddrFrom4([4]byte{byte(lo >> 24), byte(lo >> 16), byte(lo >> 8), byte(lo)}).String()
		s.End = netip.AddrFrom4([4]byte{byte(hi >> 24), byte(hi >> 16), byte(hi >> 8), byte(hi)}).String()
	}
	if gw.IsValid() && p.Contains(gw) {
		s.Router = gw.String()
	}
	return s
}
