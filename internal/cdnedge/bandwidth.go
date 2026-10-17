package cdnedge

import (
	"sync"
	"time"
)

// bandwidth: Limit je Account (user_class.cdn_bandwidth, Mbit/s, beide Richtungen zusammen). Jeder Server misst,
// was er selbst weiterreicht, und erfaehrt jede Sekunde vom Nachbarn dessen Rate; erlaubt ist hier, was vom Limit
// uebrig bleibt (mindestens ein Zehntel, damit kein Server ganz verhungert). Ohne Limit kostet es nichts.
type bandwidth struct {
	mu     sync.Mutex
	limit  map[int]float64 // Bytes/s je Account
	b      map[int]*bucket
	peer   map[int]float64 // Rate beim Nachbarn
	peerAt time.Time
	now    func() time.Time
	sleep  func(time.Duration)
}

type bucket struct {
	tokens   float64
	last     time.Time
	win      int64     // Bytes im laufenden Messfenster
	winStart time.Time //
	rate     float64   // gemessen im letzten Fenster (Bytes/s)
}

func newBandwidth() *bandwidth {
	return &bandwidth{limit: map[int]float64{}, b: map[int]*bucket{}, peer: map[int]float64{}, now: time.Now, sleep: time.Sleep}
}

// setLimits aus der Konfiguration von ipv64 (Mbit/s; 0 = frei).
func (w *bandwidth) setLimits(mbit map[int]int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.limit = map[int]float64{}
	for uid, m := range mbit {
		if m > 0 {
			w.limit[uid] = float64(m) * 1e6 / 8
		}
	}
}

// setPeer: Raten des Nachbarn (gilt 3 s).
func (w *bandwidth) setPeer(r map[int]float64) {
	w.mu.Lock()
	w.peer, w.peerAt = r, w.now()
	w.mu.Unlock()
}

// take verbucht n Bytes und wartet, wenn der Account sein Limit ueberschreitet.
func (w *bandwidth) take(uid, n int) {
	if w == nil || uid == 0 {
		return
	}
	w.mu.Lock()
	lim, ok := w.limit[uid]
	now := w.now()
	b := w.b[uid]
	if b == nil {
		b = &bucket{last: now, winStart: now}
		if ok {
			b.tokens = lim / 2
		}
		w.b[uid] = b
	}
	b.win += int64(n)
	if d := now.Sub(b.winStart); d >= time.Second {
		b.rate, b.win, b.winStart = float64(b.win)/d.Seconds(), 0, now
	}
	if !ok {
		w.mu.Unlock()
		return
	}
	allowed := lim
	if now.Sub(w.peerAt) < 3*time.Second {
		allowed = max(lim-w.peer[uid], lim/10)
	}
	b.tokens = min(b.tokens+now.Sub(b.last).Seconds()*allowed, allowed/2) // halbe Sekunde Puffer
	b.last = now
	b.tokens -= float64(n)
	wait := time.Duration(0)
	if b.tokens < 0 {
		wait = time.Duration(-b.tokens / allowed * float64(time.Second))
	}
	w.mu.Unlock()
	if wait > 0 {
		w.sleep(min(wait, 2*time.Second))
	}
}

// rates: eigene Raten der Accounts mit Limit (fuer den Nachbarn).
func (w *bandwidth) rates() map[int]float64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := map[int]float64{}
	now := w.now()
	for uid := range w.limit {
		if b := w.b[uid]; b != nil {
			r := b.rate
			if now.Sub(b.winStart) > 2*time.Second { // ruhig
				r = 0
			}
			out[uid] = r
		}
	}
	return out
}
