package dns64

import (
	"context"
	"database/sql"
	"errors"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ipv64net/node64/internal/dns64/dhcp"
	"github.com/ipv64net/node64/internal/dns64/groups"
	"github.com/ipv64net/node64/internal/dns64/localnet"
	"github.com/ipv64net/node64/internal/metrics"
	"github.com/ipv64net/node64/internal/notify"
)

// DHCP-Server (Paket dhcp, Plan docs/PLAN-NODE64-DNS64-DHCP.md): Teil von DNS64, aber opt-in. Schalter dns64.dhcp je
// Node (nie im Cluster): aus = kein Socket, Probelauf = nur zuhoeren, an = Adressen vergeben. Netze, feste Adressen
// und Leases in node64.db. Laeuft neben dem DNS-Dienst (ein Neustart von DNS64 nach Einstellungen beruehrt ihn nicht),
// endet aber mit dem Modul. Nach jeder Aenderung an Netzen oder festen Adressen startet nur der DHCP-Server neu;
// das ist mit Start, Stopp und Neustart des Moduls ueber m.ctl abgestimmt.

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

	soonMu       sync.Mutex
	namesT       *time.Timer             // Namen neu bauen (gebuendelt)
	leasesT      *time.Timer             // Vergaben an den Cluster melden (gebuendelt)
	applyT       *time.Timer             // DHCP-Server nach Uebernahmen neu starten (gebuendelt)
	standby      map[string]standbyState // Reserve: Zustand je Netz (kurz zwischengespeichert)
	conflictSent map[string]bool         // zwei Haupt-Nodes: gemeldet (Netz|Node)

	ra raState // IPv6-DNS per Router Advertisement (dhcp_ra.go)
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

// dhcpApply startet den DHCP-Server mit dem aktuellen Stand neu, wenn das Modul laeuft, der Schalter nicht aus ist
// und es ein eingeschaltetes Netz gibt; sonst stoppt es ihn. Unter m.ctl: waehrend eines Neustarts von DNS64 wartet
// es, statt den Server wegen des kurz fehlenden m.life abzuschalten, und nach dem Stopp des Moduls startet es nichts.
func (m *Module) dhcpApply(ctx context.Context) {
	m.ctl.Lock()
	defer m.ctl.Unlock()
	m.dhcpApplyLocked(ctx)
}

// dhcpApplyLocked: dhcpApply mit gehaltenem m.ctl (Start).
func (m *Module) dhcpApplyLocked(ctx context.Context) {
	ctx = context.WithoutCancel(ctx) // eine abgebrochene Anfrage darf den DHCP-Server nicht aus (oder ohne Rolle) lassen
	m.mu.Lock()
	on := m.life != nil
	m.mu.Unlock()
	mode, role := m.dhcpMode(ctx), m.dhcpRole(ctx)
	var cfg dhcp.Config
	start := on && mode != dhcpOff && !dhcpBridge()
	if start {
		var err error
		if cfg, err = m.dhcpConfig(ctx); err != nil { // vor dem Stopp lesen: bei Fehlern laeuft der alte Stand weiter
			if !m.noTable(err) {
				m.log.Warn("dhcp config", "err", err)
			}
			return
		}
		start = len(cfg.Scopes) > 0
	}
	m.dh.mu.Lock()
	old := m.dhcpSrv.Load()
	m.dhcpHaltLocked()
	if start {
		// Vergaben erst jetzt lesen: der alte Server hat bis zum Stopp noch bestaetigt und gespeichert
		if leases, err := m.dhcpLeaseRows(ctx); err == nil {
			cfg.Leases = leases
		}
		cfg.Observe = mode == dhcpObserve
		s := dhcp.New(cfg, dhcpStore{m}, m.log.With("part", "dhcp"))
		s.Probe = dhcp.ARPProbe
		s.OnForeign = m.dhcpForeign
		s.OnChange = m.dhcpChanged
		if role == dhcpReserve { // Reserve: still, solange eine Haupt-Node fuer das Netz lebt; oefter nach ihr sehen
			s.Standby, s.CheckEvery = m.dhcpStandby, time.Minute
		}
		s.Carry(old)
		rctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); s.Run(rctx) }()
		m.dh.cancel, m.dh.done = cancel, done
		m.dhcpSrv.Store(s)
	}
	m.dh.mu.Unlock()
	m.dhcpLeasesSoon() // eigener Zustand fuer den Cluster (Rolle, Schalter, Netze)
	go m.dhcpCheckConflicts(ctx)
}

// dhcpHalt stoppt den DHCP-Server (Modul aus).
func (m *Module) dhcpHalt() {
	m.dh.mu.Lock()
	defer m.dh.mu.Unlock()
	m.dhcpHaltLocked()
}

// dhcpHaltLocked stoppt den laufenden Server (m.dh.mu gehalten); danach gilt DHCP als aus.
func (m *Module) dhcpHaltLocked() {
	if m.dh.cancel != nil {
		m.dh.cancel()
		<-m.dh.done
		m.dh.cancel, m.dh.done = nil, nil
	}
	m.dhcpSrv.Store(nil)
}

// dhcpConfig liest eingeschaltete Netze, feste Adressen und Leases.
func (m *Module) dhcpConfig(ctx context.Context) (dhcp.Config, error) {
	var cfg dhcp.Config
	scopes, err := m.DHCPScopes(ctx)
	if err != nil {
		return cfg, err
	}
	// DNS-Server der Geraete (DNS leer): DNS64 muss dort auf Port 53 antworten (Bind-Adresse, Port)
	var dnsBind netip.Addr
	noSelf := m.port(ctx) != 53
	if b, err := netip.ParseAddr(strings.TrimSpace(m.core.SettingOr(ctx, setBind, ""))); err == nil && !b.IsUnspecified() {
		if b.Is4() {
			dnsBind = b
		} else {
			noSelf = true
		}
	}
	cl := m.dhcpClusterState(ctx)
	for _, s := range scopes {
		if s.Enabled && s.Iface != "" { // aus dem Cluster ohne passende Schnittstelle: aus
			sc := s.toDHCP()
			sc.ExtraDNS = cl.peerDNS(sc.Subnet)
			sc.DNSBind, sc.NoSelfDNS = dnsBind, noSelf
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

// SaveLease schreibt eine Vergabe (eine Transaktion: die Adresse gehoert danach nur noch dieser MAC).
func (d dhcpStore) SaveLease(l dhcp.Lease) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tx, err := d.m.core.Writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM dns64_dhcp_leases WHERE scope_id = ? AND ip = ? AND mac <> ?`, l.Scope, l.IP.String(), l.MAC); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO dns64_dhcp_leases (scope_id, mac, ip, hostname, expires, state) VALUES (?,?,?,?,?,?)
		ON CONFLICT(scope_id, mac) DO UPDATE SET ip = excluded.ip, hostname = excluded.hostname, expires = excluded.expires, state = excluded.state`,
		l.Scope, l.MAC, l.IP.String(), l.Hostname, l.Expires.UTC().Format(time.RFC3339), l.State); err != nil {
		return err
	}
	return tx.Commit()
}

func (d dhcpStore) DeleteLease(scope int64, mac string) error {
	_, err := d.m.core.Writer().ExecContext(context.Background(), `DELETE FROM dns64_dhcp_leases WHERE scope_id = ? AND mac = ?`, scope, mac)
	return err
}

// ---- Benachrichtigungen: fremder DHCP-Server, Netz fast voll ----

// dhcpNotify verschickt eine DHCP-Meldung; text ist der Schluessel notify.text.<text> (Sprache des Kanals), data
// seine Werte.
func (m *Module) dhcpNotify(scope int64, text string, data map[string]string) {
	if m.notifier == nil {
		return
	}
	name := strconv.FormatInt(scope, 10)
	if sc, err := m.dhcpScope(context.Background(), scope); err == nil {
		name = sc.label()
	}
	d := map[string]string{"text": "notify.text." + text}
	maps.Copy(d, data)
	now := time.Now().UTC()
	m.log.Info("notification", "kind", notify.KindDNS64DHCP, "name", name, "text", text)
	m.notifier(notify.Alert{EventID: "dns64-dhcp-" + strconv.FormatInt(now.UnixNano(), 36), Kind: notify.KindDNS64DHCP, Time: now,
		Check: notify.CheckInfo{Name: name, NotifyDown: true, NotifyUp: true, Local: true}, Data: d})
}

func (m *Module) dhcpForeign(scope int64, server netip.Addr) {
	if m.dhcpExpected(server) { // Haupt-Node des Clusters (Reserve: erwartet; zwei Haupt-Nodes: eigener Hinweis)
		return
	}
	m.dhcpNotify(scope, "dns64_dhcp_foreign", map[string]string{"server": server.String()})
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
	for _, v := range s.Usage() {
		if v.Size == 0 {
			continue
		}
		pct := (v.Used + v.Reserved) * 100 / v.Size
		switch {
		case pct >= dhcpPoolWarn && !m.dh.poolSent[v.ID]:
			m.dh.poolSent[v.ID] = true
			go m.dhcpNotify(v.ID, "dns64_dhcp_pool", map[string]string{"pct": strconv.Itoa(pct)})
		case pct < dhcpPoolOK:
			delete(m.dh.poolSent, v.ID)
		}
	}
}

// ---- Prometheus ----

// dhcpMetrics: Kennzahlen des DHCP-Servers fuer GET /api/metrics (nur wenn eingeschaltet; Zaehler seit dem Start
// des Moduls, Neustarts nach Aenderungen uebernehmen sie).
func (m *Module) dhcpMetrics(ctx context.Context, w *metrics.Writer) {
	mode := m.dhcpMode(ctx)
	if mode == dhcpOff {
		return
	}
	s := m.dhcpSrv.Load()
	w.Gauge("node64_dns64_dhcp_up", "DHCP-Server laeuft (Schalter an oder Probelauf, mindestens ein Netz).", metrics.Bool(s != nil))
	w.Gauge("node64_dns64_dhcp_observe", "DHCP im Probelauf (hoert nur zu).", metrics.Bool(mode == dhcpObserve))
	if s == nil {
		return
	}
	byID := map[int64]DHCPScope{}
	if scopes, err := m.DHCPScopes(ctx); err == nil {
		for _, sc := range scopes {
			byID[sc.ID] = sc
		}
	}
	reserve := m.dhcpRole(ctx) == dhcpReserve
	for _, v := range s.Usage() {
		sc := byID[v.ID]
		l := []string{"network", sc.Subnet, "interface", sc.Iface}
		w.Gauge("node64_dns64_dhcp_addresses", "Vergebbare Adressen im Bereich (ohne Router und Node).", float64(v.Size), l...)
		w.Gauge("node64_dns64_dhcp_leased", "Vergebene oder angebotene Adressen im Bereich (ohne feste).", float64(v.Used), l...)
		w.Gauge("node64_dns64_dhcp_reserved", "Feste Adressen im Bereich.", float64(v.Reserved), l...)
		w.Gauge("node64_dns64_dhcp_network_error", "Netz mit Fehler (Schnittstelle, Adresse oder Port 67).", metrics.Bool(v.Error != ""), l...)
		if reserve {
			p, _ := netip.ParsePrefix(sc.Subnet)
			w.Gauge("node64_dns64_dhcp_standby", "Reserve-Node bleibt still (Haupt-Node lebt oder keine bekannt).", metrics.Bool(m.dhcpStandby(p)), l...)
		}
	}
	stats, foreign := s.Counters()
	keys := slices.Sorted(maps.Keys(stats))
	for _, k := range keys {
		if r, ok := strings.CutPrefix(k, "result_"); ok {
			w.Counter("node64_dns64_dhcp_results_total", "Ergebnisse (offer, ack, nak, ignored, observe, standby, full, conflict, decline, release).", float64(stats[k]), "result", r)
		}
	}
	for _, k := range keys {
		if !strings.HasPrefix(k, "result_") {
			w.Counter("node64_dns64_dhcp_requests_total", "DHCP-Anfragen je Art (discover, request, decline, release, inform).", float64(stats[k]), "type", k)
		}
	}
	w.Gauge("node64_dns64_dhcp_foreign_servers", "Fremde DHCP-Server, die in den letzten 30 Minuten geantwortet haben.", float64(foreign))
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
		if err != nil || !a.Is4() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
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
	if s.Relay || s.Iface == "" {
		return false
	}
	var n int
	_ = m.core.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM dns64_dhcp_scopes WHERE iface = ? AND relay = 0 AND id <> ?`, s.Iface, id).Scan(&n)
	return n > 0
}

// dhcpOverlap: anderes Netz, das sich mit subnet ueberschneidet (auch gleich) - jedes Netz nur einmal, sonst waere
// die Zuordnung einer Anfrage nicht eindeutig (und das Netz ist die Kennung im Cluster).
func (m *Module) dhcpOverlap(ctx context.Context, subnet string, id int64) (string, bool) {
	p, err := netip.ParsePrefix(subnet)
	if err != nil {
		return "", false
	}
	scopes, _ := m.DHCPScopes(ctx)
	for _, s := range scopes {
		if q, err := netip.ParsePrefix(s.Subnet); err == nil && s.ID != id && q.Overlaps(p) {
			return s.Subnet, true
		}
	}
	return "", false
}

// AddDHCPScope legt ein Netz an (je Schnittstelle eins).
func (m *Module) AddDHCPScope(ctx context.Context, s DHCPScope) (DHCPScope, error) {
	if err := normalizeDHCPScope(&s); err != nil {
		return s, err
	}
	if m.dhcpIfaceTaken(ctx, s, 0) {
		return s, errCfg("err_dhcp_iface_dup")
	}
	if other, taken := m.dhcpOverlap(ctx, s.Subnet, 0); taken {
		return s, errCfg("err_dhcp_subnet_dup", "net", other)
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
	cur, err := m.dhcpScope(ctx, id)
	if err != nil {
		return s, err
	}
	if cur.Subnet != s.Subnet { // das Netz ist die Kennung (Cluster, feste Adressen, Vergaben): neu anlegen statt aendern
		return s, errCfg("err_dhcp_subnet_fixed")
	}
	err = m.dhcpExec(ctx, `UPDATE dns64_dhcp_scopes SET name = ?, iface = ?, subnet = ?, range_start = ?, range_end = ?, router = ?, dns = ?, domain = ?, lease_hours = ?, ntp = ?, authoritative = ?,
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

// normalizeDHCPReservation prueft eine feste Adresse; local = hier angelegt (dann auch nicht auf eine Adresse dieser
// Node - aus dem Cluster gilt die Pruefung der anlegenden Node, sonst scheiterte der Abgleich hier dauerhaft).
func (m *Module) normalizeDHCPReservation(ctx context.Context, r *DHCPReservation, local bool) error {
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
	if err != nil || !p.Contains(ip) || ip == p.Addr() || ip == dhcp.Broadcast(p) || ip.String() == sc.Router || (local && dhcpLocalAddr(ip)) {
		return errCfg("err_dhcp_res_ip")
	}
	r.IP = ip.String()
	r.Name, r.Comment = strings.TrimSpace(r.Name), strings.TrimSpace(r.Comment)
	if len(r.Name) > 63 || len(r.Comment) > 200 {
		return errCfg("err_comment")
	}
	return nil
}

// dhcpLocalAddr: Adresse dieser Node (darf keine feste Adresse fuer ein Geraet sein).
func dhcpLocalAddr(ip netip.Addr) bool {
	for _, i := range dhcpInterfaces() {
		for _, a := range i.Addrs {
			if a.Addr() == ip {
				return true
			}
		}
	}
	return false
}

// AddDHCPReservation legt eine feste Adresse an (MAC und IP je Netz eindeutig); mit GroupID kommt die MAC ausserdem
// in diese Geraetegruppe (vorher geprueft, Tags bleiben).
func (m *Module) AddDHCPReservation(ctx context.Context, r DHCPReservation) (DHCPReservation, error) {
	if err := m.normalizeDHCPReservation(ctx, &r, true); err != nil {
		return r, err
	}
	var member groups.Member
	if r.GroupID > 0 {
		var n int
		if err := m.core.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM dns64_groups WHERE id = ?`, r.GroupID).Scan(&n); err != nil {
			return r, err
		}
		if n == 0 {
			return r, errNotFound
		}
		label := r.Name
		for utf8.RuneCountInString(label) > 60 { // Grenze der Gruppen-Mitglieder
			_, size := utf8.DecodeLastRuneInString(label)
			label = label[:len(label)-size]
		}
		member = groups.Member{GroupID: r.GroupID, Kind: groups.KindMAC, Value: r.MAC, Label: label}
		member.Tags = m.memberTags(ctx, member)
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
		if _, err := m.AddMember(ctx, member); err != nil {
			return r, err
		}
	}
	return r, nil
}

// UpdateDHCPReservation aendert eine feste Adresse.
func (m *Module) UpdateDHCPReservation(ctx context.Context, id int64, r DHCPReservation) (DHCPReservation, error) {
	if err := m.normalizeDHCPReservation(ctx, &r, true); err != nil {
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
