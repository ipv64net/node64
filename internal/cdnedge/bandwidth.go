package cdnedge

import (
	"math"
	"sort"
	"sync"
	"time"
)

// bandwidth: Limit je Account (user_class.cdn_bandwidth, Mbit/s, beide Richtungen zusammen). Jeder Server misst,
// was er selbst weiterreicht, und erfaehrt jede Sekunde vom Nachbarn dessen Rate; erlaubt ist hier, was vom Limit
// uebrig bleibt (mindestens ein Zehntel, damit kein Server ganz verhungert). Ohne Limit kostet es nichts.
//
// Dazu die faire Drossel je Server: Der Server kennt seine Kapazitaet (capacity_mbit). Ab 80 % Auslastung teilt er
// sie gerecht auf (Max-Min): Accounts, die weniger als ihren Anteil brauchen, bekommen alles; die grossen teilen sich
// den Rest (90 % der Kapazitaet, 10 % bleiben fuer neue Besucher frei). Niemand wird getrennt, nur gebremst. Unter
// 60 % Auslastung faellt die Drossel wieder weg. Gilt fuer alle Modi und den Portmapper; die Klassen-Grenze bleibt.
type bandwidth struct {
	mu       sync.Mutex
	limit    map[int]float64 // Bytes/s je Account
	b        map[int]*bucket
	peer     map[int]float64 // Rate beim Nachbarn
	peerAt   time.Time
	capacity float64         // Bytes/s dieses Servers (0 = keine faire Drossel)
	fair     map[int]float64 // gerade gedrosselte Accounts: Bytes/s
	total    float64         // zuletzt gemessen, alle Accounts
	now      func() time.Time
	sleep    func(time.Duration)
}

const minFair = 125000 // 1 Mbit/s bekommt jeder mindestens

type bucket struct {
	tokens   float64
	last     time.Time
	win      int64     // Bytes im laufenden Messfenster
	winStart time.Time //
	rate     float64   // gemessen im letzten Fenster (Bytes/s)
}

func newBandwidth() *bandwidth {
	return &bandwidth{limit: map[int]float64{}, b: map[int]*bucket{}, peer: map[int]float64{}, fair: map[int]float64{}, now: time.Now, sleep: time.Sleep}
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
	fl, fok := w.fair[uid]
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
	if !ok && !fok {
		w.mu.Unlock()
		return
	}
	allowed := math.Inf(1)
	if ok {
		allowed = lim
		if now.Sub(w.peerAt) < 3*time.Second {
			allowed = max(lim-w.peer[uid], lim/10)
		}
	}
	if fok {
		allowed = min(allowed, fl)
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

// setCapacity: Kapazitaet des Servers in Mbit/s (0 oder weniger = keine faire Drossel).
func (w *bandwidth) setCapacity(mbit int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.capacity = 0
	if mbit > 0 {
		w.capacity = float64(mbit) * 1e6 / 8
	}
}

// fairRound (jede Sekunde): Auslastung messen und die Drossel neu verteilen.
func (w *bandwidth) fairRound() {
	w.mu.Lock()
	defer w.mu.Unlock()
	type acc struct {
		uid    int
		demand float64 // gemessen; +Inf, wenn der Account an seiner Drossel haengt (er wuerde mehr nehmen)
	}
	now := w.now()
	var list []acc
	total := 0.0
	for uid, b := range w.b {
		r := b.rate
		if now.Sub(b.winStart) > 2*time.Second { // ruhig
			r = 0
		}
		if r <= 0 {
			continue
		}
		total += r
		d := r
		if f, ok := w.fair[uid]; ok && r >= 0.9*f {
			d = math.Inf(1)
		}
		list = append(list, acc{uid, d})
	}
	w.total = total
	if w.capacity <= 0 || total < 0.6*w.capacity || (len(w.fair) == 0 && total < 0.8*w.capacity) {
		if len(w.fair) > 0 {
			w.fair = map[int]float64{}
		}
		return
	}
	sort.Slice(list, func(i, j int) bool { return list[i].demand < list[j].demand })
	fair := map[int]float64{}
	remaining := 0.9 * w.capacity
	for i, a := range list {
		share := remaining / float64(len(list)-i)
		if a.demand <= share {
			remaining -= a.demand
			continue
		}
		for _, x := range list[i:] {
			fair[x.uid] = max(share, minFair)
		}
		break
	}
	w.fair = fair
}

// fairStatus fuer /health: Auslastung (Mbit/s) und gedrosselte Accounts (Mbit/s).
func (w *bandwidth) fairStatus() (load float64, capacity float64, throttled map[int]float64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	throttled = map[int]float64{}
	for uid, f := range w.fair {
		throttled[uid] = math.Round(f*8/1e5) / 10
	}
	return math.Round(w.total*8/1e5) / 10, w.capacity * 8 / 1e6, throttled
}
