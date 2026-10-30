package dyndns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/store"
)

// Updater: vergleicht je Ziel die Soll-Adresse mit der zuletzt gemeldeten und mit dem, was die
// ipv64-Nameserver ausliefern, und ruft update.php nur bei einer Abweichung auf (nochg kostet Limit).
// Alle Aufrufe laufen nacheinander mit mindestens callGap Abstand (ipv64: 3 Log-Eintraege je 10 s).

const (
	defaultUpdateURL = "https://ipv64.net/update.php"
	flapWindow       = 2 * time.Hour
	flapMax          = 3               // so oft in flapWindow von aussen geaendert -> Ziel pausieren
	dnsGrace         = 3 * time.Minute // nach einem Update: alte DNS-Antwort heisst "wird uebernommen" (Bot bei ipv64)
	redirectRecheck  = 24 * time.Hour  // umgeleiteter Name: so lange keine Nachmeldung allein wegen abweichendem DNS
)

// DNS-Zustand eines Ziels (Spalte dns_state)
const (
	dnsUnknown    = 0
	dnsOK         = 1
	dnsDiffers    = 2
	dnsRedirected = 3 // ipv64 liefert fuer den Namen andere Adressen aus (Reverse-Proxy/CDN, Failover): gewollt
)

// callGap ist der Mindestabstand zwischen zwei Aufrufen (Variable nur fuer Tests).
var callGap = 5 * time.Second

// Gruende einer automatischen Pause
const (
	PauseBadAuth  = "badauth"  // Token ungueltig (z. B. bei ipv64 neu erzeugt)
	PauseNoHost   = "nohost"   // Name gibt es bei ipv64 nicht
	PauseConflict = "conflict" // CNAME/CDN/Failover verhindert das Update
	PauseFlapping = "flapping" // jemand anderes setzt den Record staendig anders
	PauseIgnored  = "ignored"  // ipv64 ignoriert die Familie fuer diese Domain (Einstellung bei ipv64)
)

// updState ist der gemeinsame Zustand aller Aufrufe (Abstand, Backoff, Tageslimit).
type updState struct {
	run       sync.Mutex // genau ein Abgleich zur Zeit (Runde oder "Jetzt aktualisieren")
	mu        sync.Mutex // schuetzt die Felder darunter
	lastCall  time.Time
	backoff   time.Time // nach Cooldown (429) bis hierhin keine Aufrufe
	step      int
	limitTill time.Time // Tageslimit erreicht
	flaps     map[int64][]time.Time
	nsCache   map[string]nsEntry
	external  map[int64]bool     // letzte Runde sah eine Aenderung von aussen (erst die zweite in Folge zaehlt)
	tback     map[int64]tBackoff // Rueckhalt je Ziel nach Server- oder Netzfehlern
	alerted   map[int64]bool     // Fehler dieses Ziels wurde gemeldet (Entwarnung beim naechsten Erfolg)
}

// tBackoff haelt ein Ziel nach wiederholten Server- oder Netzfehlern zurueck.
type tBackoff struct {
	n     int
	until time.Time
}

// ErrBusy: gerade laeuft schon ein Abgleich.
var ErrBusy = errors.New("update already running")

// Ergebnis von UpdateNow
const (
	NowSent    = "sent"    // an ipv64 gemeldet
	NowNothing = "nothing" // nichts zu melden (keine aktuelle Adresse fuer die Modi)
	NowOther   = "other"   // im Cluster aktualisiert eine andere Node die Namen
)

// Automatische Pausen werden nach dieser Zeit erneut versucht (badauth nur mit neuem Token).
var resumeAfter = map[string]time.Duration{PauseNoHost: 6 * time.Hour, PauseConflict: 6 * time.Hour, PauseIgnored: 6 * time.Hour, PauseFlapping: 6 * time.Hour}

type nsEntry struct {
	addrs []string
	at    time.Time
}

// plan ist das Soll eines Ziels.
type plan struct {
	IP4, IP6, Prefix string // leer = Familie nicht melden (aus oder gerade unbekannt)
	Note             string // warum eine Familie fehlt (zur Anzeige)
}

// planFor bestimmt aus Modus und Anschluss, was gemeldet werden soll.
func (m *Module) planFor(t *Target) plan {
	var p plan
	v4, v6 := m.state(4), m.state(6)
	// nur aktuelle Adressen melden: schlug die letzte Pruefung fehl, bleibt die Familie unangetastet
	// (sonst wuerde z. B. bei ausgefallenem IPv6 die alte, nicht mehr gueltige Adresse gemeldet)
	if v4.Err != "" {
		v4.IP = netip.Addr{}
	}
	if v6.Err != "" {
		v6.IP = netip.Addr{}
	}
	switch t.Mode4 {
	case Mode4Auto:
		if v4.IP.IsValid() {
			p.IP4 = v4.IP.String()
		} else {
			p.Note = "ipv4 unknown"
		}
	case Mode4Fixed:
		p.IP4 = t.Fixed4
	}
	switch t.Mode6 {
	case Mode6Host:
		if v6.IP.IsValid() {
			p.IP6 = m.stableFor(v6.IP).String()
		} else {
			p.Note = "ipv6 unknown"
		}
	case Mode6Prefix:
		if v6.IP.IsValid() {
			p.Prefix = prefix64(v6.IP).String()
		} else {
			p.Note = "ipv6 unknown"
		}
	case Mode6Suffix:
		if v6.IP.IsValid() {
			if a, err := withSuffix(prefix64(v6.IP), t.Suffix6); err == nil {
				p.IP6 = a.String()
			}
		} else {
			p.Note = "ipv6 unknown"
		}
	case Mode6Iface:
		for _, l := range m.local() {
			if l.Iface == t.Iface && !l.Temporary && !l.Deprecated {
				p.IP6 = l.Addr.String()
				break
			}
		}
		if p.IP6 == "" {
			p.Note = "no stable address on " + t.Iface
		}
	case Mode6Fixed:
		p.IP6 = t.Fixed6
		if a, err := netip.ParseAddr(t.Fixed6); err == nil {
			p.IP6 = a.String() // aeltere Eintraege sind evtl. nicht kanonisch gespeichert
		}
	}
	return p
}

// stableFor ersetzt eine temporaere Privacy-Adresse dieses Hosts durch eine stabile aus demselben /64
// (sonst wechselt der AAAA-Record taeglich). Ohne passende Adresse bleibt es bei der gesehenen.
func (m *Module) stableFor(a netip.Addr) netip.Addr {
	local := m.local()
	temp := false
	for _, l := range local {
		if l.Addr == a && l.Temporary {
			temp = true
		}
	}
	if !temp {
		return a
	}
	pfx := prefix64(a)
	for _, l := range local {
		if !l.Temporary && !l.Deprecated && pfx.Contains(l.Addr) {
			return l.Addr
		}
	}
	return a
}

// dnsView ist, was die Nameserver von ipv64 fuer den Namen liefern (Known=false: nicht abfragbar).
type dnsView struct {
	Known  bool
	A      []string
	AAAA   []string
	Failed string
}

// has: die Soll-Adresse ist unter den ausgelieferten (mehrere A/AAAA sind erlaubt, z. B. Round-Robin).
func (d dnsView) has(list []string, want string) bool {
	for _, x := range list {
		if x == want {
			return true
		}
	}
	return false
}

// matches: liefert DNS die Soll-Adressen (Praefix-Modus laesst sich so nicht pruefen)?
func (d dnsView) matches(p plan) bool {
	return (p.IP4 == "" || d.has(d.A, p.IP4)) && (p.IP6 == "" || d.has(d.AAAA, p.IP6))
}

// runUpdates prueft alle aktiven Ziele (nach jeder Pruefrunde).
func (m *Module) runUpdates(ctx context.Context) {
	m.upd.run.Lock()
	defer m.upd.run.Unlock()
	list, err := m.Targets(ctx)
	if err != nil {
		m.log.Error("targets", "err", err)
		return
	}
	now := time.Now()
	for _, t := range list {
		if ctx.Err() != nil {
			return
		}
		if !t.Enabled {
			continue
		}
		if t.Paused != "" && !m.resume(ctx, t, now) {
			continue
		}
		if m.heldBack(t.ID, now) {
			continue
		}
		if stop := m.updateTarget(ctx, t, false, "auto"); stop {
			return // Cooldown oder Tageslimit: Rest in der naechsten Runde
		}
	}
}

// UpdateNow gleicht ein Ziel sofort ab und meldet es auch ohne Abweichung (Knopf "Jetzt aktualisieren").
// Laeuft gerade eine Runde, kommt ErrBusy (statt zu warten und die Zeit des Aufrufers zu verbrauchen).
func (m *Module) UpdateNow(ctx context.Context, t *Target) (string, error) {
	if v := m.clusterView(ctx); v.On && v.Leader != "" && !v.Here {
		return NowOther, nil // sonst setzte diese Node die Adresse ihres Anschlusses gegen die zustaendige
	}
	if !m.upd.run.TryLock() {
		return "", ErrBusy
	}
	defer m.upd.run.Unlock()
	t.Paused = ""
	m.setPaused(ctx, t, "")
	if p := m.planFor(t); p.IP4 == "" && p.IP6 == "" && p.Prefix == "" {
		return NowNothing, nil
	}
	m.updateTarget(ctx, t, true, "manual")
	return NowSent, nil
}

// resume nimmt eine automatische Pause wieder auf: nach Ablauf der Wartezeit, bei badauth nur mit neuem
// Token (mit API-Key wird er geholt). true = Ziel jetzt abgleichen.
func (m *Module) resume(ctx context.Context, t *Target, now time.Time) bool {
	if t.Paused == PauseBadAuth {
		if m.keyOf(ctx) == "" || now.Sub(t.LastErrAt) < time.Hour {
			return false
		}
		old := t.Token
		if err := m.refreshToken(ctx, t); err != nil || t.Token == old {
			t.LastErrAt = now // naechster Versuch in einer Stunde
			m.saveRuntime(ctx, t)
			return false
		}
		m.log.Info("new record token fetched, target resumed", "target", t.FQDN())
	} else if wait, ok := resumeAfter[t.Paused]; !ok || now.Sub(t.LastErrAt) < wait {
		return false
	}
	m.log.Info("paused target retried", "target", t.FQDN(), "reason", t.Paused)
	t.Paused = ""
	m.setPaused(ctx, t, "")
	return true
}

// heldBack: Ziel nach Server- oder Netzfehlern noch zurueckhalten?
func (m *Module) heldBack(id int64, now time.Time) bool {
	m.upd.mu.Lock()
	defer m.upd.mu.Unlock()
	return now.Before(m.upd.tback[id].until)
}

// updateTarget gleicht ein Ziel ab und ruft bei Bedarf (oder erzwungen) update.php auf.
// stop = keine weiteren Aufrufe in dieser Runde.
func (m *Module) updateTarget(ctx context.Context, t *Target, force bool, trigger string) (stop bool) {
	p := m.planFor(t)
	dns := m.lookupDNS(ctx, t)
	now := time.Now()
	redirected := t.DNSState == dnsRedirected
	if dns.Known {
		t.DNSAt = now
		t.DNSState = dnsOK
		if !dns.matches(p) && redirected {
			t.DNSState = dnsRedirected
		} else if !dns.matches(p) {
			t.DNSState = dnsDiffers
		}
	}
	// kurz nach einem Update liefern die Nameserver evtl. noch den alten Stand: dann nicht erneut melden;
	// bei einem umgeleiteten Namen (CDN) ist die Abweichung gewollt, nur einmal am Tag nachsehen
	grace := !t.LastOKAt.IsZero() && now.Sub(t.LastOKAt) < max(dnsGrace, 2*m.interval())
	keep := t.DNSState == dnsRedirected && now.Sub(t.LastOKAt) < redirectRecheck
	diff4 := dns.Known && p.IP4 != "" && !dns.has(dns.A, p.IP4) && !(grace && p.IP4 == t.LastIP4) && !keep
	diff6 := dns.Known && p.IP6 != "" && !dns.has(dns.AAAA, p.IP6) && !(grace && p.IP6 == t.LastIP6) && !keep
	need4 := p.IP4 != "" && (p.IP4 != t.LastIP4 || diff4)
	need6 := p.IP6 != "" && (p.IP6 != t.LastIP6 || diff6)
	needP := p.Prefix != "" && p.Prefix != t.LastPrefix
	// von aussen geaendert: Soll unveraendert, aber DNS weicht ab
	external := (diff4 && p.IP4 == t.LastIP4) || (diff6 && p.IP6 == t.LastIP6)
	if !force && m.externalInRow(t.ID, external) && m.flapped(t.ID, now) {
		t.Paused, t.LastError, t.LastErrAt = PauseFlapping, "changed from elsewhere repeatedly", now
		m.log.Warn("target changed from elsewhere repeatedly, paused", "target", t.FQDN())
		m.saveRuntime(ctx, t)
		m.setPaused(ctx, t, PauseFlapping)
		m.alertFail(ctx, t, "flapping")
		return false
	}
	if force {
		need4, need6, needP = p.IP4 != "", p.IP6 != "", p.Prefix != ""
	}
	if !need4 && !need6 && !needP {
		m.saveRuntime(ctx, t)
		return false
	}
	if wait, why := m.blocked(now); wait > 0 && !force {
		m.log.Debug("update postponed", "target", t.FQDN(), "reason", why, "for", wait.Round(time.Second).String())
		return true
	}
	if need4 || need6 {
		ip4, ip6 := "", ""
		if need4 {
			ip4 = p.IP4
		}
		if need6 {
			ip6 = p.IP6
		}
		r := m.call(ctx, t, ip4, ip6, "", trigger)
		// ipv64 hat die Adresse schon (oder das CDN verwaltet die Familie), liefert aber andere aus: umgeleitet
		if r.OK && (r.Redirected || strings.EqualFold(r.Info, "nochg") && dns.Known && !dns.matches(plan{IP4: ip4, IP6: ip6})) {
			if t.DNSState != dnsRedirected {
				m.log.Info("dns redirected by ipv64 (cdn/proxy or failover), difference accepted", "target", t.FQDN())
			}
			t.DNSState = dnsRedirected
		}
		if m.apply(ctx, t, r, ip4, ip6, "", trigger) {
			return true
		}
	}
	if needP && t.Paused == "" {
		r := m.call(ctx, t, "", "", p.Prefix, trigger)
		if m.apply(ctx, t, r, "", "", p.Prefix, trigger) {
			return true
		}
	}
	m.saveRuntime(ctx, t)
	return false
}

// blocked: Wartezeit wegen Cooldown-Backoff oder Tageslimit.
func (m *Module) blocked(now time.Time) (time.Duration, string) {
	u := m.upd
	u.mu.Lock()
	defer u.mu.Unlock()
	if now.Before(u.limitTill) {
		return u.limitTill.Sub(now), "daily limit"
	}
	if now.Before(u.backoff) {
		return u.backoff.Sub(now), "cooldown"
	}
	return 0, ""
}

// externalInRow merkt, ob die letzte Runde auch schon eine Aenderung von aussen sah; erst dann zaehlt sie
// (eine einzelne verspaetete Antwort eines Nameservers loest nichts aus).
func (m *Module) externalInRow(id int64, external bool) bool {
	m.upd.mu.Lock()
	defer m.upd.mu.Unlock()
	prev := m.upd.external[id]
	m.upd.external[id] = external
	return external && prev
}

// flapped merkt eine Aenderung von aussen; true, wenn es zu oft war.
func (m *Module) flapped(id int64, now time.Time) bool {
	u := m.upd
	u.mu.Lock()
	defer u.mu.Unlock()
	var keep []time.Time
	for _, t := range u.flaps[id] {
		if now.Sub(t) < flapWindow {
			keep = append(keep, t)
		}
	}
	keep = append(keep, now)
	u.flaps[id] = keep
	return len(keep) >= flapMax
}

// updResult ist die ausgewertete Antwort von update.php.
type updResult struct {
	HTTP       int
	Status     string
	Info       string
	Prefix     string
	OK         bool
	Pause      string // Grund fuer eine Pause des Ziels
	Cooldown   bool
	Limit      bool
	Redirected bool // eine Familie verwaltet das ipv64-CDN (Record nicht angefasst)
	Err        string
	Dur        time.Duration
}

// call ruft update.php mit dem Token im Header auf (nicht in der URL) und protokolliert den Aufruf.
func (m *Module) call(ctx context.Context, t *Target, ip4, ip6, prefix, trigger string) updResult {
	u := m.upd
	u.mu.Lock()
	wait := callGap - time.Since(u.lastCall)
	u.mu.Unlock()
	if wait > 0 {
		select {
		case <-ctx.Done():
		case <-time.After(wait):
		}
	}
	u.mu.Lock()
	u.lastCall = time.Now()
	u.mu.Unlock()

	q := url.Values{"output": {"full"}, "domain": {t.Domain}}
	if t.Host != "" {
		q.Set("praefix", t.Host)
	}
	if ip4 != "" {
		q.Set("ipv4", ip4)
	}
	if ip6 != "" {
		q.Set("ipv6", ip6)
	}
	if prefix != "" {
		q.Set("ipv6prefix", prefix)
		q.Set("onlyprefix", "1")
	}
	start := time.Now()
	r := m.doCall(ctx, q, t.Token)
	r.Dur = time.Since(start)
	if ctx.Err() != nil { // Modul stoppt oder Aufrufer weg: kein Ergebnis, nichts protokollieren
		r.Err = "canceled"
		return r
	}
	ok := 0
	if r.OK {
		ok = 1
	}
	if _, err := m.core.Writer().ExecContext(context.WithoutCancel(ctx), `INSERT INTO dyn_updates (time, target_id, target, trigger, sent4, sent6, sent_prefix, http_status, status, info, ok, error, duration_ms)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`, store.FormatTime(start), t.ID, t.FQDN(), trigger, ip4, ip6, prefix, r.HTTP, r.Status, r.Info, ok, r.Err, r.Dur.Milliseconds()); err != nil {
		m.log.Error("dyn_updates insert", "err", err)
	}
	if r.OK {
		m.log.Info("dyndns updated", "target", t.FQDN(), "ipv4", ip4, "ipv6", ip6, "prefix", prefix, "info", r.Info, "trigger", trigger)
	} else {
		m.log.Warn("dyndns update failed", "target", t.FQDN(), "http", r.HTTP, "info", r.Info, "err", r.Err)
	}
	return r
}

func (m *Module) doCall(ctx context.Context, q url.Values, token string) updResult {
	var r updResult
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.updateURL+"?"+q.Encode(), nil)
	if err != nil {
		r.Err = err.Error()
		return r
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "node64/"+m.version)
	resp, err := m.httpc.Do(req)
	if err != nil {
		r.Err = shortErr(err).Error()
		return r
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	r.HTTP = resp.StatusCode
	var a struct {
		Status     string          `json:"status"`
		Info       string          `json:"info"`
		IPv6Prefix json.RawMessage `json:"ipv6prefix"`
		IP         json.RawMessage `json:"ip"`
	}
	parsed := json.Unmarshal(body, &a) == nil
	var ips struct {
		IPv4 string `json:"ipv4"`
		IPv6 string `json:"ipv6"`
	}
	_ = json.Unmarshal(a.IP, &ips)
	r.Status, r.Info = a.Status, a.Info
	if len(a.IPv6Prefix) > 0 {
		_ = json.Unmarshal(a.IPv6Prefix, &r.Prefix)
	}
	text := strings.ToLower(string(body))
	info := strings.ToLower(strings.TrimSpace(r.Info))
	switch {
	case r.HTTP == http.StatusTooManyRequests && strings.Contains(text, "overcommited"):
		r.Limit, r.Err = true, "daily update limit reached"
	case r.HTTP == http.StatusTooManyRequests:
		r.Cooldown, r.Err = true, "cooldown"
	case r.HTTP == http.StatusUnauthorized || (parsed && info == "badauth"):
		r.Pause, r.Err = PauseBadAuth, "token rejected (badauth)"
	case r.HTTP == http.StatusNotFound || (parsed && info == "nohost"):
		r.Pause, r.Err = PauseNoHost, "name not found (nohost)"
	case r.HTTP == http.StatusConflict:
		r.Pause, r.Err = PauseConflict, "conflict: "+firstNonEmpty(r.Info, "CNAME/CDN")
	case r.HTTP == http.StatusOK && !parsed:
		r.Err = "unexpected answer (no JSON)"
	case r.HTTP == http.StatusOK && r.Prefix == "format error":
		r.Err = "prefix format error"
	case r.HTTP == http.StatusOK && (r.Status == "success" || r.Status == "" && q.Get("onlyprefix") != "" && (r.Prefix != "" || r.Info != "")):
		r.OK = true // bei geaendertem Praefix fehlt status
	case r.HTTP == http.StatusOK:
		r.Err = firstNonEmpty(r.Info, r.Status, "unexpected answer")
	default:
		r.Err = fmt.Sprintf("HTTP %d %s", r.HTTP, firstNonEmpty(r.Info, r.Status))
	}
	// "success", aber ipv64 hat die Adresse nicht uebernommen: Familie ignoriert oder CDN verwaltet den Record
	for _, x := range []struct{ sent, got, fam string }{{q.Get("ipv4"), ips.IPv4, "ipv4"}, {q.Get("ipv6"), ips.IPv6, "ipv6"}} {
		if !r.OK || x.sent == "" {
			continue
		}
		switch strings.ToLower(x.got) {
		case "ignore":
			r.OK, r.Pause, r.Err = false, PauseIgnored, x.fam+" ignored by ipv64 (domain setting)"
		case "cdn": // kein Fehler: das CDN verwaltet diese Familie, ipv64 laesst den Record in Ruhe
			r.Redirected = true
		}
	}
	return r
}

// apply uebernimmt das Ergebnis in das Ziel und den gemeinsamen Zustand; true = Runde abbrechen.
// Fehlermeldungen nur bei automatischen Laeufen (von Hand sieht man das Ergebnis sofort).
func (m *Module) apply(ctx context.Context, t *Target, r updResult, ip4, ip6, prefix, trigger string) bool {
	if ctx.Err() != nil {
		return true // Modul stoppt: kein Fehler, keine Meldung
	}
	ctx = context.WithoutCancel(ctx)
	now := time.Now()
	u := m.upd
	switch {
	case r.OK:
		if ip4 != "" {
			t.LastIP4 = ip4
		}
		if ip6 != "" {
			t.LastIP6 = ip6
		}
		if prefix != "" {
			t.LastPrefix = prefix
		}
		t.LastOKAt, t.LastError = now, ""
		u.mu.Lock()
		u.step = 0
		delete(u.tback, t.ID)
		u.mu.Unlock()
	case r.Limit:
		u.mu.Lock()
		u.limitTill = now.Add(time.Hour) // ipv64 setzt den Zaehler taeglich zurueck; stuendlich neu versuchen
		u.mu.Unlock()
	case r.Cooldown:
		u.mu.Lock()
		steps := []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute}
		u.backoff = now.Add(steps[min(u.step, len(steps)-1)])
		u.step++
		u.mu.Unlock()
	case r.Pause != "":
		t.Paused = r.Pause
	default: // Server- oder Netzfehler: dieses Ziel 2, 4, 8 ... hoechstens 60 min zurueckhalten
		u.mu.Lock()
		b := u.tback[t.ID]
		b.n++
		b.until = now.Add(min(time.Duration(1<<min(b.n, 6))*time.Minute, time.Hour))
		u.tback[t.ID] = b
		u.mu.Unlock()
	}
	if !r.OK {
		t.LastError, t.LastErrAt = r.Err, now
	}
	m.saveRuntime(ctx, t)
	if r.Pause != "" {
		m.setPaused(ctx, t, r.Pause)
	}
	switch {
	case r.Limit:
		if m.notifyOnce(ctx, setLimitReachedSent) {
			m.alert(ctx, SetNotifyLimit, notify.KindDynLimit, "", "", "ipv64: daily update limit reached", "text", "notify.text.dyndns_limit_reached")
		}
	case r.OK:
		m.alertOK(ctx, t)
	case r.Cooldown || trigger == "manual":
	default:
		m.alertFail(ctx, t, r.Err)
	}
	return r.Limit || r.Cooldown
}

// alertFail meldet den Fehler eines Ziels einmal (bis zum naechsten Erfolg).
func (m *Module) alertFail(ctx context.Context, t *Target, reason string) {
	m.upd.mu.Lock()
	done := m.upd.alerted[t.ID]
	m.upd.alerted[t.ID] = true
	m.upd.mu.Unlock()
	if !done {
		m.alert(ctx, SetNotifyFail, notify.KindDynFail, t.FQDN(), reason, "")
	}
}

// alertOK meldet nach einem gemeldeten Fehler, dass das Ziel wieder aktualisiert wird.
func (m *Module) alertOK(ctx context.Context, t *Target) {
	m.upd.mu.Lock()
	was := m.upd.alerted[t.ID]
	delete(m.upd.alerted, t.ID)
	m.upd.mu.Unlock()
	if was {
		m.alert(ctx, SetNotifyFail, notify.KindDynOK, t.FQDN(), "", "")
	}
}

// setPaused speichert nur den Pausegrund (getrennt vom Laufzeitstand, damit eine gleichzeitige Bearbeitung
// durch den Nutzer, z. B. neuer Token, nicht ueberschrieben wird).
func (m *Module) setPaused(ctx context.Context, t *Target, reason string) {
	if _, err := m.core.Writer().ExecContext(context.WithoutCancel(ctx), `UPDATE dyn_targets SET paused = ? WHERE id = ?`, reason, t.ID); err != nil {
		m.log.Error("save pause", "err", err)
	}
}

// saveRuntime speichert den Laufzeitstand eines Ziels.
func (m *Module) saveRuntime(ctx context.Context, t *Target) {
	ft := func(x time.Time) string {
		if x.IsZero() {
			return ""
		}
		return store.FormatTime(x)
	}
	if _, err := m.core.Writer().ExecContext(context.WithoutCancel(ctx), `UPDATE dyn_targets SET last_ip4 = ?, last_ip6 = ?, last_prefix = ?, last_ok_at = ?, last_error = ?, last_err_at = ?, dns_state = ?, dns_at = ? WHERE id = ?`,
		t.LastIP4, t.LastIP6, t.LastPrefix, ft(t.LastOKAt), t.LastError, ft(t.LastErrAt), t.DNSState, ft(t.DNSAt), t.ID); err != nil {
		m.log.Error("save target state", "err", err)
	}
}

// ---------------------------------------------------------------- DNS

// lookupDNS fragt die zustaendigen Nameserver direkt (ohne Cache dazwischen).
func (m *Module) lookupDNS(ctx context.Context, t *Target) dnsView {
	if m.dnsLookup != nil {
		return m.dnsLookup(ctx, t)
	}
	var v dnsView
	servers, err := m.nameservers(ctx, t.Domain)
	if err != nil || len(servers) == 0 {
		v.Failed = "no nameserver"
		return v
	}
	// bis zu zwei Nameserver fragen und zusammenfassen: liefert einer schon die neue Adresse, gilt sie als da
	name := t.FQDN() + "." // absolut, keine Suchdomains
	asked := 0
	for _, ns := range servers {
		if asked == 2 {
			break
		}
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", ns)
		}}
		lctx, cancel := context.WithTimeout(ctx, 6*time.Second)
		a, err4 := lookupFam(lctx, r, "ip4", name)
		aaaa, err6 := lookupFam(lctx, r, "ip6", name)
		cancel()
		if err4 != nil || err6 != nil {
			v.Failed = firstNonEmpty(errText(err4), errText(err6))
			continue
		}
		asked++
		v.Known = true
		v.A, v.AAAA = union(v.A, a), union(v.AAAA, aaaa)
	}
	if v.Known {
		v.Failed = ""
	}
	return v
}

// lookupFam: keine Adresse der Familie ist ein gueltiges Ergebnis (leere Liste), kein Fehler.
func lookupFam(ctx context.Context, r *net.Resolver, network, name string) ([]string, error) {
	addrs, err := r.LookupNetIP(ctx, network, name)
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range addrs {
		out = append(out, a.Unmap().String())
	}
	return out, nil
}

// nameservers sucht die NS der Zone (Domain oder eine Ebene darueber) und haelt sie eine Stunde vor.
func (m *Module) nameservers(ctx context.Context, domain string) ([]string, error) {
	u := m.upd
	u.mu.Lock()
	if e, ok := u.nsCache[domain]; ok && time.Since(e.at) < time.Hour {
		u.mu.Unlock()
		return e.addrs, nil
	}
	u.mu.Unlock()
	name := domain
	var hosts []string
	for strings.Count(name, ".") >= 1 {
		ns, err := net.DefaultResolver.LookupNS(ctx, name)
		if err == nil && len(ns) > 0 {
			for _, n := range ns {
				hosts = append(hosts, strings.TrimSuffix(n.Host, "."))
			}
			break
		}
		name = name[strings.Index(name, ".")+1:]
	}
	var addrs []string
	for _, h := range hosts {
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", h)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if ip.Unmap().Is4() || m.probe(6) {
				addrs = append(addrs, netip.AddrPortFrom(ip.Unmap(), 53).String())
				break
			}
		}
	}
	if len(addrs) == 0 {
		return nil, errors.New("no nameserver for " + domain)
	}
	u.mu.Lock()
	u.nsCache[domain] = nsEntry{addrs: addrs, at: time.Now()}
	u.mu.Unlock()
	return addrs, nil
}

func union(a, b []string) []string {
	for _, x := range b {
		found := false
		for _, y := range a {
			found = found || x == y
		}
		if !found {
			a = append(a, x)
		}
	}
	return a
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}
