package honeypot

import (
	"context"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/geoip"
	"github.com/ipv64net/node64/internal/notify"
)

// Ueberwachung der eigenen Anmeldung (Regel node64/login@1): Die Oberflaeche meldet jeden Fehlversuch (Passwort,
// TOTP, Passkey, SSO ohne Konto, ungueltiger API-/MCP-Key) nur mit Quell-IP, lokalem Port und TLS an das Modul
// (internal/web, LoginWatcher; verbunden in cmd/node64/main.go). Erreicht eine oeffentliche IP die Schwelle im
// Fenster, entsteht genau ein Ereignis (Quelle log, Art http:bruteforce, ohne Benutzernamen oder Passwort) – mit
// Benachrichtigung, Sofort-Sperre ueber PROXY64 (bridge.go, nur mit Opt-in dort) und Meldung an ipv64 (wenn an).
// Private, Loopback- und andere nicht meldbare Adressen werden nur gezaehlt (z. B. Tippfehler im LAN oder ein
// Reverse-Proxy ohne NODE64_TRUST_PROXY).

const (
	LoginRuleID      = "node64/login"
	loginRuleVersion = 1

	LoginDefThreshold = 5  // Fehlversuche je IP im Fenster
	LoginDefWindow    = 10 // Minuten
	loginMaxThreshold = 100
	loginMaxWindow    = 24 * 60
	loginMaxIPs       = 10000            // gemerkte IPs; voll = abgelaufene fallen weg, notfalls alle
	loginNotifyEvery  = 10 * time.Minute // hoechstens eine Benachrichtigung in diesem Abstand (Rest in der naechsten)

	setNodeName = "node.name" // Name der Node (Einstellung des Kerns, web.SettingNodeName)
)

// KindNotifyLogin ist die Art der Benachrichtigung „Angriff auf die Node64-Anmeldung“.
const KindNotifyLogin = notify.KindHoneypotLogin

// LoginConfig ist die Einstellung der Ueberwachung (Teil von ModuleConfig; leer = an mit Standardwerten).
type LoginConfig struct {
	Off       bool `json:"off,omitempty"`        // Ueberwachung aus
	Threshold int  `json:"threshold,omitempty"`  // Fehlversuche je IP im Fenster, 0 = LoginDefThreshold
	Window    int  `json:"window_min,omitempty"` // Fenster in Minuten, 0 = LoginDefWindow
	NoNotify  bool `json:"no_notify,omitempty"`  // keine Benachrichtigung
}

// LoginRuleTag ist die Regel-Kennung der Ereignisse.
func LoginRuleTag() string { return LoginRuleID + "@" + strconv.Itoa(loginRuleVersion) }

// limits liefert Schwelle und Fenster (Standard fuer 0).
func (c LoginConfig) limits() (int, time.Duration) {
	thr, win := c.Threshold, c.Window
	if thr <= 0 {
		thr = LoginDefThreshold
	}
	if win <= 0 {
		win = LoginDefWindow
	}
	return thr, time.Duration(win) * time.Minute
}

// loginProblems prueft die Einstellung (i18n-Schluessel mit Werten nach "|").
func loginProblems(c LoginConfig) map[string]string {
	out := map[string]string{}
	if c.Threshold != 0 && (c.Threshold < 2 || c.Threshold > loginMaxThreshold) {
		out["login_threshold"] = "honeypot.err.login_threshold|2|" + strconv.Itoa(loginMaxThreshold)
	}
	if c.Window != 0 && (c.Window < 1 || c.Window > loginMaxWindow) {
		out["login_window"] = "honeypot.err.login_window|1|" + strconv.Itoa(loginMaxWindow)
	}
	return out
}

// loginWatch zaehlt Fehlversuche je IP. Je IP und Fenster hoechstens ein Ereignis.
type loginWatch struct {
	now func() time.Time

	cfg atomic.Pointer[LoginConfig] // Stand nach dem letzten Apply (nil = Modul aus)

	mu         sync.Mutex
	ips        map[netip.Addr]*loginCount
	lastNotify time.Time
	pending    int // Ereignisse seit der letzten Benachrichtigung, die nicht gemeldet wurden

	fails, local, events atomic.Int64 // seit dem Start: gewertete und lokale Fehlversuche, Ereignisse
}

type loginCount struct {
	start time.Time // erster Fehlversuch im Fenster
	n     int
	fired bool // Ereignis in diesem Fenster schon gemeldet
}

func newLoginWatch() *loginWatch {
	return &loginWatch{now: time.Now, ips: map[netip.Addr]*loginCount{}}
}

// fail zaehlt einen Fehlversuch; true = Schwelle in diesem Fenster gerade erreicht (ein Ereignis).
func (w *loginWatch) fail(src netip.Addr, thr int, win time.Duration) bool {
	now := w.now()
	w.mu.Lock()
	defer w.mu.Unlock()
	c := w.ips[src]
	if c != nil && now.Sub(c.start) > win {
		c = nil
	}
	if c == nil {
		if len(w.ips) >= loginMaxIPs {
			for k, x := range w.ips {
				if now.Sub(x.start) > win {
					delete(w.ips, k)
				}
			}
			if len(w.ips) >= loginMaxIPs {
				clear(w.ips)
			}
		}
		c = &loginCount{start: now}
		w.ips[src] = c
	}
	c.n++
	if c.fired || c.n < thr {
		return false
	}
	c.fired = true
	return true
}

// notifyDue: eine Benachrichtigung darf raus (true, mit der Zahl der zurueckgehaltenen), sonst wird gezaehlt.
func (w *loginWatch) notifyDue() (bool, int) {
	now := w.now()
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.lastNotify.IsZero() && now.Sub(w.lastNotify) < loginNotifyEvery {
		w.pending++
		return false, 0
	}
	n := w.pending
	w.lastNotify, w.pending = now, 0
	return true, n
}

// LoginFailed nimmt einen Fehlversuch der Oberflaeche an (web.LoginWatcher). Nur Adresse, lokaler Port und TLS –
// nie Benutzername oder Passwort. Kehrt sofort zurueck; tut nichts, solange das Modul aus oder die Ueberwachung
// abgeschaltet ist.
func (m *Module) LoginFailed(src netip.Addr, port int, tls bool) {
	cfg := m.login.cfg.Load()
	if cfg == nil || cfg.Off || !src.IsValid() {
		return
	}
	src = src.Unmap().WithZone("")
	if !reportable(src) { // LAN, Loopback, reserviert: nur zaehlen
		m.login.local.Add(1)
		return
	}
	m.login.fails.Add(1)
	thr, win := cfg.limits()
	if !m.login.fail(src, thr, win) {
		return
	}
	m.login.events.Add(1)
	svc := SvcHTTP
	if tls {
		svc = SvcHTTPS
	}
	// bewusst ohne Username/Password/Path/UA (wie die Log-Regeln): nur IP, Art, Dienst, Port und Regel
	ev := Event{Time: time.Now(), Service: svc, Port: port, Kind: KindHTTPBrute, Src: src, Source: SrcLog, Rule: LoginRuleTag(),
		Detail: LoginRuleID + ",threshold=" + strconv.Itoa(thr) + ",window=" + strconv.Itoa(int(win/time.Minute)) + "m"}
	m.sink(ev) // Speicher, Zaehler, Sofort-Sperre ueber PROXY64; die Meldung an ipv64 liest den Speicher
	m.log.Warn("honeypot: failed logins at the node64 interface", "rule", ev.Rule, "src", src, "threshold", thr, "window", win.String())
	if cfg.NoNotify || m.notifier == nil {
		return
	}
	ok, held := m.login.notifyDue()
	if !ok {
		return
	}
	ip := src.String()
	if cc := countryOf(ip); cc != "" {
		ip += " (" + strings.TrimSpace(geoip.Flag(cc)+" "+cc) + ")"
	}
	msg := ip + ": " + strconv.Itoa(thr) + " / " + strconv.Itoa(int(win/time.Minute)) + " min, " + strings.ToUpper(svc) + " " + strconv.Itoa(port)
	if held > 0 {
		msg += " (+" + strconv.Itoa(held) + ")"
	}
	now := time.Now()
	name := m.core.SettingOr(context.Background(), setNodeName, "Node64") // Name der Node im Betreff
	m.notifier(notify.Alert{EventID: "honeypot-login-" + strconv.FormatInt(now.UnixNano(), 36) + "-" + strconv.FormatInt(m.login.events.Load(), 36), Kind: KindNotifyLogin, Time: now.UTC(),
		Check: notify.CheckInfo{Name: name, NotifyDown: true, NotifyUp: true, Local: true}, Message: msg})
}

// loginView ist die Zeile „Angriffe auf die Node64-Anmeldung“ der Uebersicht.
type loginView struct {
	On                   bool
	Threshold, Window    int
	Day, Week            int64 // Ereignisse der Regel
	Fails, Local, Events int64 // seit dem Start
}

// loginOverview liefert den Stand fuer die Uebersicht.
func (m *Module) loginOverview(ctx context.Context, c LoginConfig) loginView {
	thr, win := c.limits()
	v := loginView{On: !c.Off && m.running() != nil, Threshold: thr, Window: int(win / time.Minute),
		Fails: m.login.fails.Load(), Local: m.login.local.Load(), Events: m.login.events.Load()}
	now := time.Now()
	v.Day, _ = storeCountRule(ctx, m.st, LoginRuleTag(), now.Add(-24*time.Hour))
	v.Week, _ = storeCountRule(ctx, m.st, LoginRuleTag(), now.Add(-7*24*time.Hour))
	return v
}

// storeCountRule zaehlt die Ereignisse einer Regel ab since.
func storeCountRule(ctx context.Context, st *Store, rule string, since time.Time) (int64, error) {
	var n int64
	err := st.st.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM hp_events WHERE ts >= ? AND rule = ?`, storeTime(since), rule).Scan(&n)
	return n, err
}
