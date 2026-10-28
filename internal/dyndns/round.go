package dyndns

import (
	"context"
	"math/rand/v2"
	"net/netip"
	"strconv"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/store"
)

// Einstellungen des Moduls (Tabelle settings)
const (
	SetInterval    = "dyndns.interval"    // Minuten zwischen zwei Pruefrunden
	SetSource4     = "dyndns.source4"     // eigene Pruef-URL IPv4 (leer = ipv64)
	SetSource6     = "dyndns.source6"     // eigene Pruef-URL IPv6
	SetKeepChecks  = "dyndns.keep_checks" // Tage, die IP-Pruefungen aufbewahrt werden
	SetKeepUpdates = "dyndns.keep_updates"
)

// IntervalOptions sind die waehlbaren Pruefabstaende in Minuten.
var IntervalOptions = []int{1, 2, 5, 10, 15, 30, 60}

const defaultInterval = 5

// famState ist der Stand einer Adressfamilie (4 oder 6).
type famState struct {
	IP        netip.Addr
	Source    string
	CheckedAt time.Time
	ChangedAt time.Time
	Err       string
	NoRoute   bool
}

func famIdx(fam int) int { return fam / 6 } // 4 -> 0, 6 -> 1

// state liefert eine Kopie des aktuellen Stands.
func (m *Module) state(fam int) famState {
	m.stMu.Lock()
	defer m.stMu.Unlock()
	return m.fam[famIdx(fam)]
}

func (m *Module) interval() time.Duration {
	n, err := strconv.Atoi(m.core.SettingOr(context.Background(), SetInterval, ""))
	if err != nil || n < 1 || n > 60 {
		n = defaultInterval
	}
	return time.Duration(n) * time.Minute
}

// loadState holt den letzten Stand aus dem Protokoll (nach Neustart).
func (m *Module) loadState(ctx context.Context) {
	for _, fam := range []int{4, 6} {
		var s famState
		var ip, src, at, errText string
		var noRoute int
		err := m.core.Reader().QueryRowContext(ctx, `SELECT ip, source, time, error, CASE WHEN error = 'no route' THEN 1 ELSE 0 END FROM dyn_checks WHERE family = ? ORDER BY id DESC LIMIT 1`, strconv.Itoa(fam)).
			Scan(&ip, &src, &at, &errText, &noRoute)
		if err != nil {
			continue
		}
		s.CheckedAt, s.Source, s.Err, s.NoRoute = store.ParseTime(at), src, errText, noRoute == 1
		if s.Err != "" { // letzte gueltige Adresse trotzdem merken (Vergleich beim naechsten Erfolg)
			_ = m.core.Reader().QueryRowContext(ctx, `SELECT ip FROM dyn_checks WHERE family = ? AND ip <> '' ORDER BY id DESC LIMIT 1`, strconv.Itoa(fam)).Scan(&ip)
		}
		s.IP, _ = netip.ParseAddr(ip)
		var ch string
		if m.core.Reader().QueryRowContext(ctx, `SELECT time FROM dyn_checks WHERE family = ? AND changed = 1 ORDER BY id DESC LIMIT 1`, strconv.Itoa(fam)).Scan(&ch) == nil {
			s.ChangedAt = store.ParseTime(ch)
		}
		m.stMu.Lock()
		m.fam[famIdx(fam)] = s
		m.stMu.Unlock()
	}
}

// loop: erste Runde kurz nach dem Start, dann im eingestellten Takt (mit Versatz, damit nicht alle
// Nodes zur selben Sekunde fragen). "Jetzt pruefen" kommt ueber m.trigger.
func (m *Module) loop(ctx context.Context) {
	defer m.wg.Done()
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	prune := time.NewTicker(time.Hour)
	defer prune.Stop()
	watch := time.NewTicker(clusterTick) // Cluster: zustaendige Node ausgefallen -> gleich uebernehmen
	defer watch.Stop()
	next := func() time.Duration {
		iv := m.interval()
		return iv + time.Duration(rand.Int64N(int64(iv/10)+1)) - iv/20
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if m.hasActive(ctx) { // ohne aktive Ziele ruht das Modul (keine Abfragen, keine Protokollzeilen)
				m.round(ctx)
				m.maybeAnalyze(ctx)
				if lead, _ := m.clusterLead(ctx); lead { // im Cluster aktualisiert nur die zustaendige Node
					m.runUpdates(ctx)
				}
				m.refreshLimit(ctx, limitEvery)
			}
			t.Reset(next())
		case done := <-m.trigger: // "Jetzt pruefen": immer eine Runde
			m.round(ctx)
			if m.hasActive(ctx) {
				m.maybeAnalyze(ctx)
				if lead, _ := m.clusterLead(ctx); lead {
					m.runUpdates(ctx)
				}
				m.refreshLimit(ctx, limitEvery)
			}
			close(done)
			if !t.Stop() {
				select {
				case <-t.C:
				default:
				}
			}
			t.Reset(next())
		case <-watch.C:
			if _, became := m.clusterLead(ctx); became && m.hasActive(ctx) {
				m.runUpdates(ctx) // gerade zustaendig geworden: nicht bis zur naechsten Runde warten
			}
		case <-prune.C:
			m.prune(ctx)
		}
	}
}

// maybeAnalyze prueft den Weg ins Internet (CGNAT/DS-Lite) nach jedem Start des Moduls (auch nach
// einem Wechsel des Netzwerkmodus), alle 6 Stunden und nach einem Wechsel der IPv4.
func (m *Module) maybeAnalyze(ctx context.Context) {
	last := m.lastNetInfo(ctx)
	v4 := m.state(4)
	if !v4.IP.IsValid() && !v4.NoRoute && v4.Err != "" {
		return // gerade keine Verbindung, spaeter erneut
	}
	if last.At.IsZero() || last.At.Before(m.startedAt) || time.Since(last.At) > 6*time.Hour || v4.ChangedAt.After(last.At) {
		m.analyzePath(ctx)
	}
}

// familyUsed: ein aktives Ziel braucht die Adresse dieser Familie.
func (m *Module) familyUsed(ctx context.Context, fam int) bool {
	q := `SELECT count(*) FROM dyn_targets WHERE enabled = 1 AND mode4 = 'auto'`
	if fam == 6 {
		q = `SELECT count(*) FROM dyn_targets WHERE enabled = 1 AND mode6 IN ('host', 'prefix', 'suffix')`
	}
	var n int
	_ = m.core.Reader().QueryRowContext(ctx, q).Scan(&n)
	return n > 0
}

// hasActive: mindestens ein eingeschaltetes Ziel.
func (m *Module) hasActive(ctx context.Context) bool {
	var n int
	_ = m.core.Reader().QueryRowContext(ctx, `SELECT count(*) FROM dyn_targets WHERE enabled = 1`).Scan(&n)
	return n > 0
}

// ipFailAlert: so viele fehlgeschlagene Ermittlungen in Folge werden gemeldet (bei 5 min Takt: 15 min).
const ipFailAlert = 3

// trackIPFailure meldet eine dauerhaft gestoerte IP-Ermittlung einmal und gibt Entwarnung, wenn sie wieder klappt.
func (m *Module) trackIPFailure(ctx context.Context, fam int, failed bool, errText string) {
	i := famIdx(fam)
	m.stMu.Lock()
	if failed {
		m.ipFail[i]++
	} else {
		m.ipFail[i] = 0
	}
	n, alerted := m.ipFail[i], m.ipAlerted[i]
	send, recover := failed && n >= ipFailAlert && !alerted, !failed && alerted
	if send {
		m.ipAlerted[i] = true
	}
	if recover {
		m.ipAlerted[i] = false
	}
	m.stMu.Unlock()
	name := "IPv" + strconv.Itoa(fam)
	switch {
	case send:
		m.alert(ctx, SetNotifyFail, notify.KindDynFail, name, errText, "public "+name+" address not determined "+strconv.Itoa(n)+" times in a row",
			"text", "notify.text.dyndns_addr_failed", "family", name, "count", strconv.Itoa(n))
	case recover:
		m.alert(ctx, SetNotifyFail, notify.KindDynOK, name, "", "")
	}
}

// round ermittelt IPv4 und IPv6 und protokolliert jede Pruefung.
func (m *Module) round(ctx context.Context) {
	for _, fam := range []int{4, 6} {
		m.checkFamily(ctx, fam)
	}
}

func (m *Module) checkFamily(ctx context.Context, fam int) {
	prev := m.state(fam)
	cur := prev
	start := time.Now()
	cur.CheckedAt, cur.Err, cur.NoRoute = start, "", false
	var src string
	var addr netip.Addr
	if !m.probe(fam) {
		cur.NoRoute, cur.Err = true, "no route"
	} else {
		key := SetSource4
		if fam == 6 {
			key = SetSource6
		}
		for _, s := range sourceList(m.core.SettingOr(ctx, key, ""), fam) {
			rctx, cancel := context.WithTimeout(ctx, 12*time.Second)
			a, err := m.fetch(rctx, fam, s)
			cancel()
			src = sourceHost(s)
			if err == nil {
				addr, cur.Err = a, ""
				break
			}
			cur.Err = err.Error()
			m.log.Debug("ip source failed", "family", fam, "source", src, "err", err)
		}
	}
	if ctx.Err() != nil {
		return
	}
	changed := addr.IsValid() && addr != prev.IP
	if addr.IsValid() {
		cur.IP, cur.Source = addr, src
		if changed && !prev.IP.IsValid() {
			cur.ChangedAt = start
			m.log.Info("public address detected", "family", fam, "ip", addr.String(), "source", src)
		} else if changed {
			cur.ChangedAt = start
			m.log.Info("public address changed", "family", fam, "old", prev.IP.String(), "new", addr.String(), "source", src)
			m.alert(ctx, SetNotifyIP, notify.KindDynIP, "IPv"+strconv.Itoa(fam), "", "IPv"+strconv.Itoa(fam)+": "+prev.IP.String()+" → "+addr.String())
		}
	} else if prev.Err != cur.Err && cur.NoRoute { // ohne Route ist normal (z. B. Docker-Bridge ohne IPv6)
		m.log.Info("no route for address family", "family", fam)
	} else if prev.Err != cur.Err { // Fehler nur beim Wechsel laut melden
		m.log.Warn("public address not determined", "family", fam, "err", cur.Err)
	}
	if !cur.NoRoute && m.familyUsed(ctx, fam) {
		m.trackIPFailure(ctx, fam, !addr.IsValid(), cur.Err)
	}
	ip := ""
	if addr.IsValid() {
		ip = addr.String()
	}
	_, err := m.core.Writer().ExecContext(ctx, `INSERT INTO dyn_checks (time, family, source, ip, error, duration_ms, changed) VALUES (?,?,?,?,?,?,?)`,
		store.FormatTime(start), strconv.Itoa(fam), src, ip, cur.Err, time.Since(start).Milliseconds(), b2i(changed))
	if err != nil {
		m.log.Error("dyn_checks insert", "err", err)
	}
	m.stMu.Lock()
	m.fam[famIdx(fam)] = cur
	m.stMu.Unlock()
}

// checkNow startet eine Runde ausserhalb des Takts und wartet hoechstens wait darauf.
func (m *Module) checkNow(wait time.Duration) bool {
	done := make(chan struct{})
	select {
	case m.trigger <- done:
	case <-time.After(wait): // Modul aus oder Runde haengt
		return false
	}
	select {
	case <-done:
		return true
	case <-time.After(wait):
		return false
	}
}

// prune loescht alte Pruefungen und Aufrufe (0 = unbegrenzt).
func (m *Module) prune(ctx context.Context) {
	for _, p := range []struct {
		table, key string
		def        int
	}{{"dyn_checks", SetKeepChecks, 30}, {"dyn_updates", SetKeepUpdates, 365}} {
		days, err := strconv.Atoi(m.core.SettingOr(ctx, p.key, ""))
		if err != nil || days < 0 {
			days = p.def
		}
		if days == 0 {
			continue
		}
		cut := store.FormatTime(time.Now().AddDate(0, 0, -days))
		if _, err := m.core.Writer().ExecContext(ctx, `DELETE FROM `+p.table+` WHERE time < ?`, cut); err != nil {
			m.log.Error("prune", "table", p.table, "err", err)
		}
	}
}

func defaultProbe(fam int) bool {
	if fam == 6 {
		return checks.ProbeFamily("ipv6")
	}
	return checks.ProbeFamily("ipv4")
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
