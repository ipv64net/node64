package dyndns

import (
	"context"
	"strconv"
	"time"

	"github.com/ipv64net/node64/internal/notify"
)

// Update-Limit des Accounts (API v2 GET /me: usage.dyndns_updates_24h), nur mit API-Key.
// Abgefragt hoechstens alle limitEvery in der Pruefrunde, beim Oeffnen der Seite wenn aelter als limitPage.

const (
	limitEvery = 15 * time.Minute
	limitPage  = 5 * time.Minute
	limitWarn  = 80 // Prozent
)

// limitInfo ist der letzte bekannte Stand.
type limitInfo struct {
	Known  bool
	Used   int
	Limit  int // 0 = unbegrenzt
	At     time.Time
	Err    string
	Own24h int // Aufrufe dieser Node in 24 h
}

// Pct ist der Verbrauch in Prozent (0 bei unbegrenzt).
func (l limitInfo) Pct() int {
	if l.Limit <= 0 {
		return 0
	}
	p := l.Used * 100 / l.Limit
	if p > 100 {
		p = 100
	}
	return p
}

// Warn: Verbrauch ab limitWarn Prozent.
func (l limitInfo) Warn() bool { return l.Known && l.Limit > 0 && l.Pct() >= limitWarn }

// refreshLimit fragt ipv64, wenn der Stand aelter als maxAge ist.
func (m *Module) refreshLimit(ctx context.Context, maxAge time.Duration) {
	key := m.keyOf(ctx)
	if key == "" {
		return
	}
	m.stMu.Lock()
	fresh := !m.lim.At.IsZero() && time.Since(m.lim.At) < maxAge
	m.stMu.Unlock()
	if fresh {
		return
	}
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	me, err := m.key.Client().Me(lctx, key)
	cancel()
	m.stMu.Lock()
	defer m.stMu.Unlock()
	m.lim.At = time.Now()
	if err != nil {
		m.lim.Err = err.Error()
		return
	}
	m.lim.Known, m.lim.Err, m.lim.Used, m.lim.Limit = true, "", me.Usage.DynDNSUpdates.Used, 0
	if l := me.Usage.DynDNSUpdates.Limit; l != nil {
		m.lim.Limit = *l
	}
	if l := m.lim; l.Warn() {
		go func() { // ausserhalb der Sperre
			if !m.limitNotifiedToday(ctx) {
				m.alert(ctx, SetNotifyLimit, notify.KindDynLimit, "", "", strconv.Itoa(l.Used)+" / "+strconv.Itoa(l.Limit))
			}
		}()
	}
}

// limit liefert den Stand fuer die Anzeige (mit eigenem Zaehler).
func (m *Module) limit(ctx context.Context) limitInfo {
	m.stMu.Lock()
	l := m.lim
	m.stMu.Unlock()
	l.Own24h = m.callsSince(ctx, time.Now().Add(-24*time.Hour))
	return l
}
