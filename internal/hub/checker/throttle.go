package checker

import (
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/scheduler"
)

// Bremse gegen Missbrauch der Messstellen als Lastquelle: je Zielhost (ueber alle Accounts) und fuer den ganzen
// Server hoechstens so viele Laeufe pro Zeit. Ein ausgelassener Lauf aendert keinen Zustand, der Check kommt nach
// seinem Intervall wieder dran. Normaler Betrieb erreicht die Grenzen nicht (Online-Intervall ab 20 s).

const (
	DefaultPerTargetPerMinute = 600 // je Zielhost und Server: 10 Laeufe/s
	DefaultRunsPerSecond      = 300 // je Server
)

type bucket struct {
	tokens float64
	last   time.Time
}

// take: Token-Bucket mit rate pro Sekunde und Fassungsvermoegen burst.
func (b *bucket) take(now time.Time, rate, burst float64) bool {
	if b.last.IsZero() {
		b.tokens = burst
	} else {
		b.tokens = min(burst, b.tokens+now.Sub(b.last).Seconds()*rate)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type throttle struct {
	mu        sync.Mutex
	perTarget float64 // je Sekunde
	perSecond float64
	global    bucket
	targets   map[string]*bucket
	warned    map[string]time.Time
	skipped   uint64
	now       func() time.Time
	log       *slog.Logger
	pruned    time.Time
}

func newThrottle(perTargetPerMinute, runsPerSecond int, log *slog.Logger) *throttle {
	if perTargetPerMinute <= 0 {
		perTargetPerMinute = DefaultPerTargetPerMinute
	}
	if runsPerSecond <= 0 {
		runsPerSecond = DefaultRunsPerSecond
	}
	return &throttle{perTarget: float64(perTargetPerMinute) / 60, perSecond: float64(runsPerSecond), targets: map[string]*bucket{},
		warned: map[string]time.Time{}, now: time.Now, log: log}
}

// allow: darf der Check jetzt laufen?
func (t *throttle) allow(c scheduler.Check) bool {
	host := strings.ToLower(strings.TrimSuffix(checks.TargetHost(c.Def), "."))
	if host == "" {
		host = strings.ToLower(c.Def.Target)
	}
	if a, err := netip.ParseAddr(host); err == nil { // eine Adresse, ein Eimer (2001:0db8::1 = 2001:db8::1, ::ffff:1.2.3.4 = 1.2.3.4)
		host = a.Unmap().String()
	}
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if now.Sub(t.pruned) > 10*time.Minute { // Eimer ohne Laeufe seit 10 Minuten wieder voll – weg damit
		for k, b := range t.targets {
			if now.Sub(b.last) > 10*time.Minute {
				delete(t.targets, k)
			}
		}
		for k, at := range t.warned {
			if now.Sub(at) > time.Hour {
				delete(t.warned, k)
			}
		}
		t.pruned = now
	}
	b := t.targets[host]
	if b == nil {
		b = &bucket{}
		t.targets[host] = b
	}
	// Zielhost: Fassungsvermoegen 1 Minute; Server: 1 Sekunde
	if !b.take(now, t.perTarget, t.perTarget*60) {
		t.skip(now, "target", host)
		return false
	}
	if !t.global.take(now, t.perSecond, t.perSecond) {
		b.tokens++ // nicht verbraucht
		t.skip(now, "server", "")
		return false
	}
	return true
}

func (t *throttle) skip(now time.Time, kind, host string) {
	t.skipped++
	key := kind + ":" + host
	if at, ok := t.warned[key]; !ok || now.Sub(at) > 10*time.Minute {
		t.warned[key] = now
		t.log.Warn("check run throttled", "limit", kind, "target", host, "skipped_total", t.skipped)
	}
}

// Skipped: ausgelassene Laeufe seit dem Start (Metriken).
func (c *Checker) Skipped() uint64 {
	if c.throttle == nil {
		return 0
	}
	c.throttle.mu.Lock()
	defer c.throttle.mu.Unlock()
	return c.throttle.skipped
}

// SetLimits setzt die Bremse (vor Start; 0 = Standard).
func (c *Checker) SetLimits(perTargetPerMinute, runsPerSecond int) {
	c.throttle = newThrottle(perTargetPerMinute, runsPerSecond, c.log)
}
