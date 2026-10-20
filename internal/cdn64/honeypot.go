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

	"github.com/ipv64net/node64/internal/hpbridge"
)

// PROXY64 und Honeypot64 (Opt-in, je Punkt ein Schalter, Standard aus; Verbindung ueber internal/hpbridge):
//  1. Koeder: Anfragen ohne passenden Host (nur IP, fremde Domain, leere SNI) bekommt der Web-Koeder des Honeypots
//     statt der Standardseite.
//  2. Zugriffe: je Anfrage gehen Metadaten (IP, Host, Methode, Pfad ohne Abfrage, Status, TLS, fehlgeschlagene
//     Anmeldung) an den Log-Sensor des Honeypots - nie Inhalte.
//  3. Sofort-Sperre: IPs, die im Honeypot auffallen, sperrt PROXY64 lokal fuer eine einstellbare Dauer (Standard
//     24 h) fuer alle Hosts und Streams - private Adressen, Ausnahmen der Blocklisten und vertrauenswuerdige Proxys
//     der Hosts nie. Die Liste liegt im Speicher (hoechstens hpMaxBlocks Eintraege, laufen von selbst ab).

const (
	setHoneypot     = "cdn64.honeypot" // HoneypotSettings als JSON
	hpMaxBlocks     = 50000
	hpDefaultHours  = 24
	hpMaxHours      = 24 * 30
	rejHoneypot     = "honeypot" // Abweisung: vom Honeypot gemeldet
	hpReasonMaxLen  = 80
	hpSweepInterval = time.Minute
)

// HoneypotSettings: die drei Schalter.
type HoneypotSettings struct {
	Decoy      bool `json:"decoy"`       // unbekannte Anfragen an den Koeder
	Access     bool `json:"access"`      // Zugriffe an den Log-Sensor
	Block      bool `json:"block"`       // Angreifer aus dem Honeypot sofort sperren
	BlockHours int  `json:"block_hours"` // Dauer der Sperre (Stunden)
}

// HoneypotBlock: eine lokal gesperrte IP.
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

// hpSave speichert die Einstellungen; Sperre aus = Liste leeren.
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
	if !s.Block {
		m.hp.mu.Lock()
		m.hp.m = nil
		m.hp.mu.Unlock()
	}
	return nil
}

func (m *Module) hpSettings() HoneypotSettings {
	if p := m.hp.cfg.Load(); p != nil {
		return *p
	}
	return HoneypotSettings{BlockHours: hpDefaultHours}
}

// hpStart: Sperren abonnieren und unbekannte Anfragen uebernehmen (bei Start des Moduls).
func (m *Module) hpStart(ctx context.Context) {
	m.hpLoad(ctx)
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

// hpDecoyActive: unbekannte Anfragen gehen gerade an den Koeder (Schalter an und Honeypot64 laeuft).
func (m *Module) hpDecoyActive() bool { return m.hpSettings().Decoy && hpbridge.Decoy() != nil }

// hpExempt: Adressen, die nie gesperrt werden (privat, CGNAT, Ausnahmen der Blocklisten, Proxys der Hosts).
func (m *Module) hpExempt(ctx context.Context, ip netip.Addr) bool {
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || cgnat.Contains(ip) {
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

// hpOnBlock: Sperre aus dem Honeypot (nur mit eingeschalteter Sofort-Sperre).
func (m *Module) hpOnBlock(b hpbridge.Block) {
	s := m.hpSettings()
	ip := b.IP.Unmap()
	if !s.Block || m.hpExempt(context.Background(), ip) {
		return
	}
	now := time.Now()
	e := hpEntry{reason: trunc(b.Reason, hpReasonMaxLen), since: now, until: now.Add(time.Duration(s.BlockHours) * time.Hour)}
	m.hp.mu.Lock()
	defer m.hp.mu.Unlock()
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
		}
	}
	m.hp.m[ip] = e
	m.hp.added.Add(1)
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
	if !m.hpSettings().Block {
		return false
	}
	ip, now := ip.Unmap(), time.Now()
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
			out = append(out, HoneypotBlock{IP: ip.String(), Reason: e.reason, Since: e.since, Until: e.until})
		}
	}
	m.hp.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Since.After(out[j].Since) })
	return out
}

// hpUnblock hebt eine Sperre auf.
func (m *Module) hpUnblock(s string) bool {
	ip, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return false
	}
	m.hp.mu.Lock()
	defer m.hp.mu.Unlock()
	if _, ok := m.hp.m[ip.Unmap()]; !ok {
		return false
	}
	delete(m.hp.m, ip.Unmap())
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
	if m.hpBlocked(client) {
		page(w, http.StatusForbidden)
		m.hpReport(r, client, false, http.StatusForbidden, false)
		return
	}
	sw := &statusWriter{ResponseWriter: w}
	defer func() { m.hpReport(r, client, false, sw.code(), false) }()
	if d := hpbridge.Decoy(); d != nil && m.hpSettings().Decoy {
		m.hp.decoyed.Add(1)
		r2 := r.Clone(r.Context()) // der Koeder liest die Quelle aus RemoteAddr ("ip:port"), Host bleibt
		if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
			r2.RemoteAddr = netip.AddrPortFrom(client, ap.Port()).String()
		}
		d.ServeHTTP(sw, r2)
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
