package cdn64

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/hpbridge"
)

// PROXY64 und Honeypot64 (Opt-in, je Punkt ein Schalter, Standard aus; Verbindung ueber internal/hpbridge):
//  1. Koeder: Anfragen ohne passenden Host (nur IP, fremde Domain, leere SNI) bekommt der Web-Koeder des Honeypots
//     statt der Standardseite.
//  2. Zugriffe: je Anfrage gehen Metadaten (IP, Host, Methode, Pfad ohne Abfrage, Status, TLS, fehlgeschlagene
//     Anmeldung) an den Log-Sensor des Honeypots - nie Inhalte.
//     Mit Weg je Art (HoneypotRoute) bekommen auch als schaedlich erkannte Anfragen den Koeder statt 403: IPs der
//     Blocklisten, vom Honeypot gemeldete, Exploit-Muster, KI-Bots, Laendersperre. Nur HTTP(S) ueber den Web-Eingang;
//     Streams und TLS-Durchreichen weisen weiter ab. Laeuft der Honeypot mit der Vorlage "Nur ueber PROXY64"
//     (hpbridge.Wanted), gilt der Koeder als eingeschaltet.
//  3. Sofort-Sperre: IPs, die im Honeypot auffallen, sperrt PROXY64 lokal fuer eine einstellbare Dauer (Standard
//     24 h) fuer alle Hosts und Streams - private Adressen, Ausnahmen der Blocklisten und vertrauenswuerdige Proxys
//     der Hosts nie. Eingeschaltet hier oder im Honeypot (hpbridge.BlockWanted, dort Standard an). Die Liste liegt
//     im Speicher und in cdn_hp_blocks (uebersteht einen Neustart; hoechstens hpMaxBlocks Eintraege, laufen von
//     selbst ab).

const (
	setHoneypot     = "cdn64.honeypot" // HoneypotSettings als JSON
	hpMaxBlocks     = 50000
	hpDefaultHours  = 24
	hpMaxHours      = 24 * 30
	rejHoneypot     = "honeypot" // Abweisung: vom Honeypot gemeldet
	hpReasonMaxLen  = 80
	hpSweepInterval = time.Minute
	hpPurgeInterval = time.Hour // abgelaufene Eintraege aus cdn_hp_blocks loeschen
)

// HoneypotSettings: die drei Schalter und die Wege schaedlicher Anfragen.
type HoneypotSettings struct {
	Decoy      bool           `json:"decoy"`           // unbekannte Anfragen an den Koeder
	Access     bool           `json:"access"`          // Zugriffe an den Log-Sensor
	Block      bool           `json:"block"`           // Angreifer aus dem Honeypot sofort sperren
	BlockHours int            `json:"block_hours"`     // Dauer der Sperre (Stunden)
	Route      *HoneypotRoute `json:"route,omitempty"` // nil = Standard (hpDefaultRoute)
}

// HoneypotRoute: welche abgewiesenen Anfragen statt 403 den Koeder bekommen (nur mit Koeder).
type HoneypotRoute struct {
	Blocklist bool `json:"blocklist"` // IPs der ipv64-Blocklisten
	Honeypot  bool `json:"honeypot"`  // vom Honeypot gemeldete Angreifer (Sofort-Sperre)
	Exploit   bool `json:"exploit"`   // Exploit-Muster (Block Common Exploits)
	AIBot     bool `json:"ai_bot"`    // KI-Bots und Scanner nach User-Agent
	Geo       bool `json:"geo"`       // Laendersperre (trifft auch echte Besucher, Standard aus)
}

// hpDefaultRoute: Angriffe ja, Laendersperre nein; Ueberlast (Rate-Limits) nie - das ist Schutz, kein Angriff.
func hpDefaultRoute() HoneypotRoute {
	return HoneypotRoute{Blocklist: true, Honeypot: true, Exploit: true, AIBot: true}
}

// HoneypotBlock: eine lokal gesperrte IP (IPv6 als /64, wie die Sperren des DoS-Schutzes).
type HoneypotBlock struct {
	IP     string    `json:"ip"`
	Reason string    `json:"reason"`
	Since  time.Time `json:"since"`
	Until  time.Time `json:"until"`
}

type hpEntry struct {
	reason       string
	since, until time.Time
}

type hpState struct {
	cfg      atomic.Pointer[HoneypotSettings]
	mu       sync.Mutex
	m        map[netip.Addr]hpEntry
	swept    time.Time
	cancel   func() // Abo der Sperren
	purged   time.Time
	added    atomic.Int64
	rejected atomic.Int64 // abgewiesene Verbindungen und Anfragen
	decoyed  atomic.Int64 // an den Koeder gegebene Anfragen
	reported atomic.Int64 // an den Log-Sensor gegebene Zugriffe
}

func (s HoneypotSettings) normalized() HoneypotSettings {
	if s.BlockHours <= 0 {
		s.BlockHours = hpDefaultHours
	}
	s.BlockHours = min(s.BlockHours, hpMaxHours)
	if s.Route == nil {
		r := hpDefaultRoute()
		s.Route = &r
	}
	return s
}

// hpLoad liest die Einstellungen (und haelt sie fuer die schnellen Pruefungen bereit).
func (m *Module) hpLoad(ctx context.Context) HoneypotSettings {
	var s HoneypotSettings
	_ = json.Unmarshal([]byte(m.core.SettingOr(ctx, setHoneypot, "{}")), &s)
	s = s.normalized()
	m.hp.cfg.Store(&s)
	return s
}

var errHoneypotHours = errors.New("block_hours must be between 1 and 720")

// hpSave speichert die Einstellungen; Sperre aus (auch im Honeypot) = Liste leeren.
func (m *Module) hpSave(ctx context.Context, s HoneypotSettings) error {
	if s.BlockHours < 0 || s.BlockHours > hpMaxHours {
		return errHoneypotHours
	}
	s = s.normalized()
	b, _ := json.Marshal(s)
	if err := m.core.SetSetting(ctx, setHoneypot, string(b)); err != nil {
		return err
	}
	m.hp.cfg.Store(&s)
	if !s.Block && !hpbridge.BlockWanted() {
		m.hp.mu.Lock()
		m.hp.m = nil
		m.hp.mu.Unlock()
		if _, err := m.core.Writer().ExecContext(ctx, `DELETE FROM cdn_hp_blocks`); err != nil {
			return err
		}
	}
	return nil
}

// hpBlockOn: Sofort-Sperre eingeschaltet (hier oder im laufenden Honeypot).
func (m *Module) hpBlockOn() bool { return m.hpSettings().Block || hpbridge.BlockWanted() }

func hpTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// hpRestore laedt die noch gueltigen Sperren aus der Datenbank (Start des Moduls).
func (m *Module) hpRestore(ctx context.Context) {
	now := time.Now()
	_, _ = m.core.Writer().ExecContext(ctx, `DELETE FROM cdn_hp_blocks WHERE until <= ?`, hpTime(now))
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT ip, reason, since, until FROM cdn_hp_blocks ORDER BY until DESC LIMIT ?`, hpMaxBlocks)
	if err != nil {
		m.log.Warn("cdn64 honeypot blocks not loaded", "err", err)
		return
	}
	defer rows.Close()
	list := map[netip.Addr]hpEntry{}
	var moved []netip.Addr // alte Eintraege je IPv6-Adresse (vor 1.45.1): unter dem /64 neu speichern
	for rows.Next() {
		var ip, reason, since, until string
		if rows.Scan(&ip, &reason, &since, &until) != nil {
			continue
		}
		a, err1 := netip.ParseAddr(ip)
		s, err2 := time.Parse(time.RFC3339, since)
		u, err3 := time.Parse(time.RFC3339, until)
		if err1 == nil && err2 == nil && err3 == nil && now.Before(u) {
			k := limKey(a)
			if k != a {
				moved = append(moved, a)
			}
			if old, ok := list[k]; !ok || old.until.Before(u) {
				list[k] = hpEntry{reason: reason, since: s, until: u}
			}
		}
	}
	m.hp.mu.Lock()
	m.hp.m, m.hp.purged = list, now
	m.hp.mu.Unlock()
	for _, a := range moved {
		m.hpPersist(limKey(a), list[limKey(a)], a, false)
	}
}

// hpPersist schreibt eine Sperre (gone: verdraengter Eintrag) und loescht ab und zu abgelaufene.
func (m *Module) hpPersist(ip netip.Addr, e hpEntry, gone netip.Addr, purge bool) {
	ctx, w := context.Background(), m.core.Writer()
	if _, err := w.ExecContext(ctx, `INSERT INTO cdn_hp_blocks (ip, reason, since, until) VALUES (?,?,?,?)
		ON CONFLICT(ip) DO UPDATE SET reason = excluded.reason, until = excluded.until`, ip.String(), e.reason, hpTime(e.since), hpTime(e.until)); err != nil {
		m.log.Warn("cdn64 honeypot block not saved", "err", err)
	}
	if gone.IsValid() {
		_, _ = w.ExecContext(ctx, `DELETE FROM cdn_hp_blocks WHERE ip = ?`, gone.String())
	}
	if purge {
		_, _ = w.ExecContext(ctx, `DELETE FROM cdn_hp_blocks WHERE until <= ?`, hpTime(time.Now()))
	}
}

func (m *Module) hpSettings() HoneypotSettings {
	if p := m.hp.cfg.Load(); p != nil {
		return *p
	}
	return HoneypotSettings{BlockHours: hpDefaultHours}.normalized()
}

// hpStart: Sperren abonnieren und unbekannte Anfragen uebernehmen (bei Start des Moduls).
func (m *Module) hpStart(ctx context.Context) {
	m.hpLoad(ctx)
	m.hpRestore(ctx)
	m.hp.cancel = hpbridge.SubscribeBlocks(m.hpOnBlock)
	if m.edge != nil {
		m.edge.SetUnknown(m.hpUnknown, m.hpDecoyActive)
	}
}

func (m *Module) hpStop() {
	if m.hp.cancel != nil {
		m.hp.cancel()
		m.hp.cancel = nil
	}
	if m.edge != nil {
		m.edge.SetUnknown(nil, nil)
	}
}

// hpDecoyActive: unbekannte Anfragen gehen gerade an den Koeder (Schalter an oder Honeypot "nur ueber PROXY64",
// und Honeypot64 laeuft).
func (m *Module) hpDecoyActive() bool {
	return (m.hpSettings().Decoy || hpbridge.Wanted()) && hpbridge.Decoy() != nil
}

// hpRoute: diese abgewiesene Anfrage geht an den Koeder statt 403 (Koeder aktiv und Weg der Art an).
func (m *Module) hpRoute(reason string) bool {
	if !m.hpDecoyActive() {
		return false
	}
	r := m.hpSettings().Route
	if r == nil {
		return false
	}
	switch reason {
	case rejBlocklist:
		return r.Blocklist
	case rejHoneypot:
		return r.Honeypot
	case rejExploit:
		return r.Exploit
	case rejAIBot:
		return r.AIBot
	case rejGeo:
		return r.Geo
	}
	return false
}

// hpDivert: abgewiesene Anfrage an den Koeder statt der Fehlerseite; false = nicht umgeleitet (Aufrufer weist ab).
// Die Statistik zaehlt sie dann als "an den Honeypot" statt als abgewiesen.
func (m *Module) hpDivert(w http.ResponseWriter, r *http.Request, client netip.Addr, reason string) bool {
	if !m.hpRoute(reason) || !m.hpServeDecoy(w, r, client) {
		return false
	}
	if p, ok := r.Context().Value(ctxDecoyKey{}).(*bool); ok {
		*p = true
	}
	return true
}

type ctxDecoyKey struct{}

// hpServeDecoy gibt die Anfrage dem Koeder (der liest die Quelle aus RemoteAddr "ip:port", Host bleibt).
func (m *Module) hpServeDecoy(w http.ResponseWriter, r *http.Request, client netip.Addr) bool {
	d := hpbridge.Decoy()
	if d == nil {
		return false
	}
	m.hp.decoyed.Add(1)
	r2 := r.Clone(r.Context())
	port := uint16(0)
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		port = ap.Port()
	}
	r2.RemoteAddr = netip.AddrPortFrom(client, port).String()
	d.ServeHTTP(w, r2)
	return true
}

// hpExempt: Adressen, die nie gesperrt werden (privat, CGNAT, Ausnahmen der Blocklisten, Proxys der Hosts).
func (m *Module) hpExempt(ctx context.Context, ip netip.Addr) bool {
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || cgnat.Contains(ip) || m.lim.lan.has(ip) {
		return true
	}
	for _, p := range m.blAllow(ctx) {
		if p.Contains(ip) {
			return true
		}
	}
	list, _ := m.hosts(ctx)
	for _, h := range list {
		h.Advanced.prepare()
		if h.Advanced.isTrusted(ip) {
			return true
		}
	}
	return false
}

// hpOnBlock: Sperre aus dem Honeypot (nur mit eingeschalteter Sofort-Sperre). IPv6 je /64 (limKey): sonst genuegte
// ein Adresswechsel im eigenen Netz, und eine Adressflut fuellte die Tabelle.
func (m *Module) hpOnBlock(b hpbridge.Block) {
	s := m.hpSettings()
	ip := b.IP.Unmap().WithZone("")
	if !m.hpBlockOn() || m.hpExempt(context.Background(), ip) {
		return
	}
	ip = limKey(ip)
	now := time.Now()
	e := hpEntry{reason: trunc(b.Reason, hpReasonMaxLen), since: now, until: now.Add(time.Duration(s.BlockHours) * time.Hour)}
	var gone netip.Addr
	m.hp.mu.Lock()
	if m.hp.m == nil {
		m.hp.m = map[netip.Addr]hpEntry{}
	}
	if old, ok := m.hp.m[ip]; ok {
		e.since = old.since // Verlaengerung
	} else if len(m.hp.m) >= hpMaxBlocks {
		m.hpSweepLocked(now)
		if len(m.hp.m) >= hpMaxBlocks { // voll: die am fruehesten ablaufende weicht
			var first netip.Addr
			var at time.Time
			for k, x := range m.hp.m {
				if at.IsZero() || x.until.Before(at) {
					first, at = k, x.until
				}
			}
			delete(m.hp.m, first)
			gone = first
		}
	}
	m.hp.m[ip] = e
	m.hp.added.Add(1)
	purge := now.Sub(m.hp.purged) > hpPurgeInterval
	if purge {
		m.hp.purged = now
	}
	m.hp.mu.Unlock()
	m.hpPersist(ip, e, gone, purge)
}

func (m *Module) hpSweepLocked(now time.Time) {
	for k, x := range m.hp.m {
		if !now.Before(x.until) {
			delete(m.hp.m, k)
		}
	}
	m.hp.swept = now
}

// hpBlocked: IP gerade vom Honeypot gesperrt (zaehlt die Abweisung).
func (m *Module) hpBlocked(ip netip.Addr) bool {
	if !m.hpBlockOn() {
		return false
	}
	ip, now := limKey(ip), time.Now()
	m.hp.mu.Lock()
	e, ok := m.hp.m[ip]
	if now.Sub(m.hp.swept) > hpSweepInterval {
		m.hpSweepLocked(now)
	}
	m.hp.mu.Unlock()
	if !ok || !now.Before(e.until) {
		return false
	}
	m.hp.rejected.Add(1)
	return true
}

// hpList: aktuelle Sperren, neueste zuerst.
func (m *Module) hpList() []HoneypotBlock {
	now := time.Now()
	m.hp.mu.Lock()
	out := make([]HoneypotBlock, 0, len(m.hp.m))
	for ip, e := range m.hp.m {
		if now.Before(e.until) {
			out = append(out, HoneypotBlock{IP: limShow(ip), Reason: e.reason, Since: e.since, Until: e.until})
		}
	}
	m.hp.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Since.After(out[j].Since) })
	return out
}

// hpUnblock hebt eine Sperre auf (IP oder /64).
func (m *Module) hpUnblock(s string) bool {
	s = strings.TrimSpace(s)
	var ip netip.Addr
	if p, err := netip.ParsePrefix(s); err == nil {
		ip = p.Addr()
	} else if ip, err = netip.ParseAddr(s); err != nil {
		return false
	}
	ip = limKey(ip)
	m.hp.mu.Lock()
	_, ok := m.hp.m[ip]
	delete(m.hp.m, ip)
	m.hp.mu.Unlock()
	if !ok {
		return false
	}
	_, _ = m.core.Writer().ExecContext(context.Background(), `DELETE FROM cdn_hp_blocks WHERE ip = ?`, ip.String())
	return true
}

// hpReport gibt einen Zugriff an den Log-Sensor (nur mit Schalter und laufender Auswertung).
func (m *Module) hpReport(r *http.Request, client netip.Addr, known bool, status int, authFail bool) {
	if !m.hpSettings().Access || !hpbridge.AccessActive() {
		return
	}
	m.hp.reported.Add(1)
	hpbridge.Report(hpbridge.Access{Time: time.Now(), Src: client.Unmap(), Host: strings.ToLower(hostOnly(r.Host)), Known: known,
		Method: r.Method, Path: trunc(r.URL.Path, 500), Status: status, TLS: r.TLS != nil, AuthFail: authFail, UA: trunc(r.UserAgent(), 200)})
}

// hpUnknown: Anfrage ohne passenden Host (ohne Host gibt es keine vertrauenswuerdigen Proxys: Quelle ist die
// Gegenstelle bzw. beim CDN64-Tunnel der Besucher; gesperrte IPs trennt schon der Eingang vor der Host-Auswahl) - an den Koeder (falls eingeschaltet und Honeypot64 laeuft), sonst die
// Standardseite; gemeldet wird sie in beiden Faellen (Schalter Zugriffe).
func (m *Module) hpUnknown(w http.ResponseWriter, r *http.Request, def http.Handler) {
	client := peerIP(r)
	sw := &statusWriter{ResponseWriter: w}
	defer func() { m.hpReport(r, client, false, sw.code(), false) }()
	if m.hpBlocked(client) && !m.hpRoute(rejHoneypot) {
		page(sw, http.StatusForbidden)
		return
	}
	if m.hpDecoyActive() && m.hpServeDecoy(sw, r, client) {
		if sdb := m.stats2.Load(); sdb != nil { // Statistik: Host 0 = Anfragen ohne passenden Namen
			sdb.add(hit{time: time.Now(), client: client, method: r.Method, host: hostOnly(r.Host), path: trunc(r.URL.RequestURI(), 500),
				status: sw.code(), reason: "unknown", decoy: true, all: m.debug()})
			edge.MarkWatched(r) // steht schon im Log (Debug-Beobachter des Eingangs)
		}
		return
	}
	def.ServeHTTP(sw, r)
}

type ctxAuthFailKey struct{}

// setAuthFail: Anmeldung an der Zugriffsliste fehlgeschlagen (fuer die Meldung an den Honeypot).
func setAuthFail(r *http.Request) {
	if p, ok := r.Context().Value(ctxAuthFailKey{}).(*bool); ok {
		*p = true
	}
}
