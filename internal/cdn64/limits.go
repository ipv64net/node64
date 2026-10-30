package cdn64

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Schutz vor Ueberlastung (wie stick-tables/maxconn beim HAProxy): Verbindungen und Anfragen je IP, Verbindungen
// insgesamt, gleichzeitige Anfragen je Ziel und eine Sperre fuer IPs, die dauernd an den Limits abprallen.
// Gezaehlt wird je IPv4-Adresse bzw. je IPv6-/64 (ein Anschluss hat meist ein ganzes /64).

const (
	setLimits     = "cdn64.limits"
	limStrikeSpan = time.Minute // Fenster fuer "abgewiesen" bis zur Sperre
	limMaxIPs     = 100000      // darueber werden neue IPs nicht mehr einzeln gezaehlt (nur noch insgesamt)
)

var limQueueWait = 10 * time.Second // so lange wartet eine Anfrage auf einen freien Platz beim Ziel (Tests kuerzer)

// Gruende fuer Abweisungen (Statistik, Zugriffs-Log; Texte unter cdn64.reject.*).
const (
	rejBlocklist = "blocklist" // ipv64-Blocklisten
	rejDeny      = "deny"      // eigene Sperrliste
	rejBan       = "ban"       // gesperrt wegen Ueberlastung
	rejConns     = "conns"     // zu viele Verbindungen je IP
	rejConnRate  = "conn_rate" // zu viele neue Verbindungen je IP
	rejMaxConns  = "max_conns" // Verbindungen insgesamt erreicht
	rejReqRate   = "req_rate"  // zu viele Anfragen je IP (429)
	rejTarget    = "target"    // Ziel ausgelastet (503)
	rejExploit   = "exploit"   // Block Common Exploits
	rejACL       = "acl"       // Zugriffsliste
)

// Limits sind die Einstellungen (0 = ohne dieses Limit).
type Limits struct {
	Enabled     bool `json:"enabled"`
	ConnsPerIP  int  `json:"conns_per_ip"` // gleichzeitige Verbindungen je IP
	ConnRate    int  `json:"conn_rate"`    // neue Verbindungen je IP und Sekunde (kurzzeitig das Zehnfache)
	ReqRate     int  `json:"req_rate"`     // Anfragen je IP und Sekunde
	ReqBurst    int  `json:"req_burst"`    // kurzzeitig bis zu so vielen Anfragen am Stueck
	MaxConns    int  `json:"max_conns"`    // offene Verbindungen insgesamt
	TargetConns int  `json:"target_conns"` // gleichzeitige Anfragen je Proxy-Host an sein Ziel (danach Warteschlange)
	BanAfter    int  `json:"ban_after"`    // so oft in einer Minute abgewiesen: gesperrt
	BanMinutes  int  `json:"ban_minutes"`  // Dauer der Sperre
	ExemptLAN   bool `json:"exempt_lan"`   // private Adressen (Heimnetz) nie begrenzen
}

// DefaultLimits: grosszuegig fuer Browser, Apps und Sync-Clients (auch mehrere Geraete hinter einer Adresse, Galerien
// mit vielen Anfragen auf einmal), eng genug gegen Flooding von einer Adresse. Verbindungen insgesamt so, dass auch
// kleine Geraete sie tragen; erst 60 Adressen mit je vollem Limit fuellen sie.
func DefaultLimits() Limits {
	return Limits{Enabled: true, ConnsPerIP: 100, ConnRate: 20, ReqRate: 50, ReqBurst: 500, MaxConns: 6000, TargetConns: 100,
		BanAfter: 300, BanMinutes: 10, ExemptLAN: true}
}

func (l *Limits) normalize() error {
	for _, v := range []struct{ n, max int }{{l.ConnsPerIP, 100000}, {l.ConnRate, 100000}, {l.ReqRate, 100000}, {l.ReqBurst, 1000000},
		{l.MaxConns, 1000000}, {l.TargetConns, 100000}, {l.BanAfter, 1000000}, {l.BanMinutes, 10080}} {
		if v.n < 0 || v.n > v.max {
			return ferr("limits", "cdn64.lim.err_range")
		}
	}
	if l.ReqRate > 0 && l.ReqBurst < l.ReqRate {
		l.ReqBurst = l.ReqRate
	}
	if l.BanAfter > 0 && l.BanMinutes == 0 {
		l.BanMinutes = 10
	}
	return nil
}

// Ban ist eine gesperrte Adresse (IPv6 als /64).
type Ban struct {
	IP    string    `json:"ip"`
	Until time.Time `json:"until"`
}

type ipState struct {
	conns    int
	connTok  float64
	reqTok   float64
	at       time.Time // letzte Auffuellung der Eimer
	strikes  int
	strikeAt time.Time
}

type limiter struct {
	cfg      atomic.Pointer[Limits]
	exempt   atomic.Pointer[[]netip.Prefix] // Ausnahmen der Blocklisten und vertrauenswuerdige Proxys
	mu       sync.Mutex
	ips      map[netip.Addr]*ipState
	bans     map[netip.Addr]time.Time
	nbans    atomic.Int32
	conns    atomic.Int64 // offen insgesamt (am Eingang und bei Streams)
	rejected atomic.Int64 // abgewiesen seit dem Start
	now      func() time.Time
	onBan    func(ip netip.Addr, until time.Time)
	wmu      sync.Mutex
	warned   map[string]time.Time // Warnungen im Log: hoechstens einmal je Minute
}

func newLimiter() *limiter {
	l := &limiter{ips: map[netip.Addr]*ipState{}, bans: map[netip.Addr]time.Time{}, now: time.Now, warned: map[string]time.Time{}}
	d := DefaultLimits()
	l.cfg.Store(&d)
	return l
}

func (l *limiter) config() Limits { return *l.cfg.Load() }

// limKey: IPv4-Adresse bzw. IPv6-/64.
func limKey(a netip.Addr) netip.Addr {
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.Addr()
	}
	return a
}

func limShow(k netip.Addr) string {
	if k.Is6() {
		return netip.PrefixFrom(k, 64).String()
	}
	return k.String()
}

func (l *limiter) exempted(c *Limits, a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || c.ExemptLAN && (a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()) {
		return true
	}
	if ex := l.exempt.Load(); ex != nil {
		for _, p := range *ex {
			if p.Contains(a) {
				return true
			}
		}
	}
	return false
}

// stateLocked liefert den Zaehler einer Adresse und fuellt die Eimer auf (nil = Tabelle voll).
func (l *limiter) stateLocked(c *Limits, k netip.Addr, now time.Time) *ipState {
	st := l.ips[k]
	if st == nil {
		if len(l.ips) >= limMaxIPs {
			return nil
		}
		st = &ipState{connTok: float64(c.ConnRate * 10), reqTok: float64(c.ReqBurst), at: now}
		l.ips[k] = st
		return st
	}
	if dt := now.Sub(st.at).Seconds(); dt > 0 {
		st.connTok = min(st.connTok+dt*float64(c.ConnRate), float64(c.ConnRate*10))
		st.reqTok = min(st.reqTok+dt*float64(c.ReqRate), float64(c.ReqBurst))
		st.at = now
	}
	return st
}

// strikeLocked zaehlt eine Abweisung; nach BanAfter in einer Minute wird die Adresse gesperrt.
func (l *limiter) strikeLocked(c *Limits, k netip.Addr, st *ipState, now time.Time) {
	l.rejected.Add(1)
	if st == nil || c.BanAfter <= 0 {
		return
	}
	if now.Sub(st.strikeAt) > limStrikeSpan {
		st.strikes, st.strikeAt = 0, now
	}
	st.strikes++
	if st.strikes >= c.BanAfter {
		st.strikes = 0
		until := now.Add(time.Duration(c.BanMinutes) * time.Minute)
		if _, had := l.bans[k]; !had {
			l.nbans.Add(1)
		}
		l.bans[k] = until
		if l.onBan != nil {
			go l.onBan(k, until)
		}
	}
}

// open: neue Verbindung (Eingang, Streams). release gibt den Platz wieder frei; reason != "" = abgewiesen.
func (l *limiter) open(a netip.Addr) (release func(), reason string) {
	c := l.cfg.Load()
	if !c.Enabled || l.exempted(c, a) {
		return nil, ""
	}
	if c.MaxConns > 0 && l.conns.Load() >= int64(c.MaxConns) {
		l.rejected.Add(1)
		return nil, rejMaxConns
	}
	k, now := limKey(a), l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.stateLocked(c, k, now)
	if st == nil {
		l.conns.Add(1)
		return func() { l.conns.Add(-1) }, ""
	}
	if c.ConnsPerIP > 0 && st.conns >= c.ConnsPerIP {
		l.strikeLocked(c, k, st, now)
		return nil, rejConns
	}
	if c.ConnRate > 0 && st.connTok < 1 {
		l.strikeLocked(c, k, st, now)
		return nil, rejConnRate
	}
	if c.ConnRate > 0 {
		st.connTok--
	}
	st.conns++
	l.conns.Add(1)
	return func() {
		l.mu.Lock()
		st.conns--
		l.mu.Unlock()
		l.conns.Add(-1)
	}, ""
}

// warn: true, wenn zu diesem Schluessel seit einer Minute nichts im Log stand.
func (l *limiter) warn(key string) bool {
	now := l.now()
	l.wmu.Lock()
	defer l.wmu.Unlock()
	if now.Sub(l.warned[key]) < time.Minute {
		return false
	}
	if len(l.warned) > 1000 {
		l.warned = map[string]time.Time{}
	}
	l.warned[key] = now
	return true
}

// request: eine Anfrage der (echten) Client-IP; false = zu viele (429).
func (l *limiter) request(a netip.Addr) bool {
	c := l.cfg.Load()
	if !c.Enabled || c.ReqRate <= 0 || l.exempted(c, a) {
		return true
	}
	k, now := limKey(a), l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.stateLocked(c, k, now)
	if st == nil {
		return true
	}
	if st.reqTok < 1 {
		l.strikeLocked(c, k, st, now)
		return false
	}
	st.reqTok--
	return true
}

// banned: Adresse ist gesperrt (zaehlt mit).
func (l *limiter) banned(a netip.Addr) bool {
	if l.nbans.Load() == 0 {
		return false
	}
	c := l.cfg.Load()
	if !c.Enabled || l.exempted(c, a) {
		return false
	}
	k := limKey(a)
	l.mu.Lock()
	until, ok := l.bans[k]
	if ok && !l.now().Before(until) {
		delete(l.bans, k)
		l.nbans.Add(-1)
		ok = false
	}
	l.mu.Unlock()
	if ok {
		l.rejected.Add(1)
	}
	return ok
}

// unban hebt eine Sperre auf (IP oder /64).
func (l *limiter) unban(s string) bool {
	var a netip.Addr
	if p, err := netip.ParsePrefix(s); err == nil {
		a = p.Addr()
	} else if a, err = netip.ParseAddr(s); err != nil {
		return false
	}
	k := limKey(a)
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.bans[k]; !ok {
		return false
	}
	delete(l.bans, k)
	l.nbans.Add(-1)
	if st := l.ips[k]; st != nil {
		st.strikes = 0
	}
	return true
}

func (l *limiter) banList() []Ban {
	now := l.now()
	l.mu.Lock()
	out := make([]Ban, 0, len(l.bans))
	for k, t := range l.bans {
		if now.Before(t) {
			out = append(out, Ban{IP: limShow(k), Until: t})
		}
	}
	l.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Until.After(out[j].Until) })
	return out
}

// sweep raeumt ruhige Adressen und abgelaufene Sperren weg.
func (l *limiter) sweep() {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, st := range l.ips {
		if st.conns == 0 && now.Sub(st.at) > 2*limStrikeSpan {
			delete(l.ips, k)
		}
	}
	for k, t := range l.bans {
		if !now.Before(t) {
			delete(l.bans, k)
			l.nbans.Add(-1)
		}
	}
}

// slots begrenzt die gleichzeitigen Anfragen eines Hosts an sein Ziel (nil = ohne).
type slots chan struct{}

// acquire wartet hoechstens limQueueWait auf einen Platz; false = Ziel ausgelastet oder Anfrage abgebrochen.
func (s slots) acquire(ctx context.Context, wait time.Duration) bool {
	select {
	case s <- struct{}{}:
		return true
	default:
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case s <- struct{}{}:
		return true
	case <-t.C:
	case <-ctx.Done():
	}
	return false
}

func (s slots) release() { <-s }

// ---------------------------------------------------------------- Modul

// limLoad liest die Einstellungen (ohne gespeicherte Werte: Standard, eingeschaltet).
func (m *Module) limLoad(ctx context.Context) Limits {
	c := DefaultLimits()
	if v := m.core.SettingOr(ctx, setLimits, ""); v != "" {
		_ = json.Unmarshal([]byte(v), &c)
		if c.normalize() != nil {
			c = DefaultLimits()
		}
	}
	m.lim.cfg.Store(&c)
	return c
}

// limExempt: Ausnahmen der Blocklisten und die vertrauenswuerdigen Proxys aller Hosts.
func (m *Module) limExempt(ctx context.Context, list []*Host) {
	ex := m.blAllow(ctx)
	for _, h := range list {
		for _, n := range h.Advanced.TrustedProxies {
			if p, err := parsePrefix(n); err == nil {
				ex = append(ex, p)
			}
		}
	}
	m.lim.exempt.Store(&ex)
}

func (m *Module) limSave(ctx context.Context, c Limits) error {
	if err := c.normalize(); err != nil {
		return err
	}
	b, _ := json.Marshal(c)
	if err := m.core.SetSetting(ctx, setLimits, string(b)); err != nil {
		return err
	}
	m.lim.cfg.Store(&c)
	m.apply(ctx) // Plaetze je Ziel neu
	return nil
}

func (m *Module) limLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.lim.sweep()
			m.authFail.sweep()
		}
	}
}

// rejectConn: Verbindung vor der ersten Anfrage abgewiesen (Statistik unter Host 0, Zugriffs-Log gebremst).
// where ist "" fuer den gemeinsamen Eingang, sonst z. B. "stream :25565".
func (m *Module) rejectConn(a netip.Addr, reason, where string) {
	if reason == rejMaxConns {
		m.overload(rejMaxConns, "")
	}
	if sdb := m.stats2.Load(); sdb != nil {
		sdb.add(hit{time: time.Now(), client: a.Unmap(), method: "-", host: where, reason: reason, conn: true})
	}
}

// overload schreibt eine Warnung ins Log (je Art und Host hoechstens einmal je Minute).
func (m *Module) overload(kind, host string) {
	if !m.lim.warn(kind + "|" + host) {
		return
	}
	c := m.lim.config()
	switch kind {
	case rejMaxConns:
		m.log.Warn("cdn64 overload: connection limit in total reached, new connections are rejected", "max_conns", c.MaxConns)
	case rejTarget:
		m.log.Warn("cdn64 overload: target busy, requests answered with 503", "host", host, "target_conns", c.TargetConns)
	}
}

// blockedAny: eigene Sperrliste, ipv64-Blocklisten oder gesperrt wegen Ueberlastung (am Eingang vor TLS).
func (m *Module) blockedAny(a netip.Addr) bool {
	return m.connBlocked(a, "")
}

func (m *Module) connBlocked(a netip.Addr, where string) bool {
	web := where == "" // Web-Eingang: mit Weg an den Koeder bleibt die Verbindung offen, die Anfrage bekommt ihn
	switch {
	case m.bl.Denied(a):
		m.rejectConn(a, rejDeny, where)
	case m.lim.banned(a):
		m.rejectConn(a, rejBan, where)
	case m.bl.Blocked(a):
		if web && m.hpRoute(rejBlocklist) {
			return false
		}
		m.rejectConn(a, rejBlocklist, where)
	case m.hpBlocked(a):
		if web && m.hpRoute(rejHoneypot) {
			return false
		}
		m.rejectConn(a, rejHoneypot, where)
	default:
		return false
	}
	return true
}

// gateOpen: Limits beim Annehmen einer Verbindung (Edge.SetGate).
func (m *Module) gateOpen(a netip.Addr) (func(), bool) {
	return m.connOpen(a, "")
}

func (m *Module) connOpen(a netip.Addr, where string) (func(), bool) {
	release, reason := m.lim.open(a)
	if reason != "" {
		m.rejectConn(a, reason, where)
		return nil, false
	}
	return release, true
}

func netAddr(a net.Addr) netip.Addr {
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}
