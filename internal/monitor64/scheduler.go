package monitor64

import (
	"container/heap"
	"context"
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"
)

// Planer der Abfragen (Plan "Speicher und Leistung", Abschnitt "Abfragen"):
//   - Hosts gleichmaessig ueber ihr Intervall verteilt (fester Versatz je Schluessel, keine Lastspitze zur vollen Minute),
//   - Arbeiter-Pool mit Obergrenze,
//   - Zeitlimit je Lauf hoechstens 80 % des Intervalls (max. 30 s),
//   - laeuft die vorige Runde noch, faellt die naechste aus und zaehlt als "verspaetet".

// minInterval: kleinstes Intervall (Tests verkuerzen).
var minInterval = 30 * time.Second

const (
	maxInterval    = 15 * time.Minute
	maxJobTimeout  = 30 * time.Second
	defaultWorkers = 16
)

// JobFunc fuehrt eine Abfrage aus; ctx endet nach dem Zeitlimit.
type JobFunc func(ctx context.Context)

// JobStats ist der Laufzeitstand eines Auftrags.
type JobStats struct {
	Runs     int64         `json:"runs"`
	Late     int64         `json:"late"` // ausgefallen, weil die vorige Runde noch lief
	LastRun  time.Time     `json:"last_run"`
	LastTook time.Duration `json:"last_took"`
	Running  bool          `json:"running"`
}

// SchedStats ist der Gesamtstand des Planers.
type SchedStats struct {
	Jobs    int   `json:"jobs"`
	Running int64 `json:"running"`
	Workers int   `json:"workers"`
	Runs    int64 `json:"runs"`
	Late    int64 `json:"late"`
}

type job struct {
	key      string
	interval time.Duration
	fn       JobFunc
	next     time.Time
	idx      int // Position im Heap, -1 = nicht eingeplant
	running  atomic.Bool
	st       JobStats
	gen      uint64 // Erzeugung: ein ersetzter Auftrag plant sich nicht neu ein
}

type jobHeap []*job

func (h jobHeap) Len() int           { return len(h) }
func (h jobHeap) Less(i, j int) bool { return h[i].next.Before(h[j].next) }
func (h jobHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i]; h[i].idx = i; h[j].idx = j }
func (h *jobHeap) Push(x any)        { j := x.(*job); j.idx = len(*h); *h = append(*h, j) }
func (h *jobHeap) Pop() any {
	old := *h
	n := len(old)
	j := old[n-1]
	old[n-1] = nil
	j.idx = -1
	*h = old[:n-1]
	return j
}

// Scheduler plant Auftraege (je Host einer) und fuehrt sie im Pool aus.
type Scheduler struct {
	mu      sync.Mutex
	jobs    map[string]*job
	h       jobHeap
	wake    chan struct{}
	sem     chan struct{}
	workers int
	gen     uint64
	now     func() time.Time
	// OnPanic meldet einen abgefangenen Fehler in einem Auftrag (Log); nil = still.
	OnPanic func(key string, v any)

	running atomic.Int64
	runs    atomic.Int64
	late    atomic.Int64
	wg      sync.WaitGroup
}

// NewScheduler legt einen Planer mit workers gleichzeitigen Laeufen an (<= 0: Standard 16).
func NewScheduler(workers int) *Scheduler {
	if workers <= 0 {
		workers = defaultWorkers
	}
	return &Scheduler{jobs: map[string]*job{}, wake: make(chan struct{}, 1), sem: make(chan struct{}, workers), workers: workers, now: time.Now}
}

// clampInterval begrenzt das Intervall auf 30 s .. 15 min.
func clampInterval(d time.Duration) time.Duration {
	if d < minInterval {
		return minInterval
	}
	if d > maxInterval {
		return maxInterval
	}
	return d
}

// jobTimeout: hoechstens 80 % des Intervalls, hoechstens 30 s.
func jobTimeout(interval time.Duration) time.Duration {
	t := interval * 8 / 10
	if t > maxJobTimeout {
		t = maxJobTimeout
	}
	return t
}

// offset ist der feste Versatz eines Schluessels im Intervall (gleichmaessige Verteilung).
func offset(key string, interval time.Duration) time.Duration {
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	return time.Duration(h.Sum64() % uint64(interval))
}

// firstRun: naechster Zeitpunkt nach now, der auf dem Raster (Vielfache des Intervalls + Versatz) liegt.
func firstRun(now time.Time, key string, interval time.Duration) time.Time {
	off := offset(key, interval)
	base := now.Truncate(interval).Add(off)
	for !base.After(now) {
		base = base.Add(interval)
	}
	return base
}

// Set legt einen Auftrag an oder ersetzt ihn (neues Intervall bzw. neue Funktion).
func (s *Scheduler) Set(key string, interval time.Duration, fn JobFunc) {
	interval = clampInterval(interval)
	s.mu.Lock()
	s.gen++
	if old, ok := s.jobs[key]; ok {
		if old.idx >= 0 {
			heap.Remove(&s.h, old.idx)
		}
		old.gen = 0 // laeuft er gerade, plant er sich danach nicht neu ein
	}
	j := &job{key: key, interval: interval, fn: fn, idx: -1, gen: s.gen}
	j.next = firstRun(s.now(), key, interval)
	s.jobs[key] = j
	heap.Push(&s.h, j)
	s.mu.Unlock()
	s.poke()
}

// Remove entfernt einen Auftrag (ein laufender Lauf endet normal).
func (s *Scheduler) Remove(key string) {
	s.mu.Lock()
	if j, ok := s.jobs[key]; ok {
		if j.idx >= 0 {
			heap.Remove(&s.h, j.idx)
		}
		j.gen = 0
		delete(s.jobs, key)
	}
	s.mu.Unlock()
	s.poke()
}

// RunNow stoesst einen Auftrag sofort an (z. B. Trap, "jetzt pruefen"); laeuft er schon, passiert nichts.
func (s *Scheduler) RunNow(key string) {
	s.mu.Lock()
	j, ok := s.jobs[key]
	if ok && j.idx >= 0 {
		j.next = s.now()
		heap.Fix(&s.h, j.idx)
	}
	s.mu.Unlock()
	if ok {
		s.poke()
	}
}

// Keys liefert die eingeplanten Schluessel.
func (s *Scheduler) Keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.jobs))
	for k := range s.jobs {
		out = append(out, k)
	}
	return out
}

// Job liefert den Stand eines Auftrags.
func (s *Scheduler) Job(key string) (JobStats, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[key]
	if !ok {
		return JobStats{}, false
	}
	st := j.st
	st.Running = j.running.Load()
	return st, true
}

// Stats liefert den Gesamtstand.
func (s *Scheduler) Stats() SchedStats {
	s.mu.Lock()
	n := len(s.jobs)
	s.mu.Unlock()
	return SchedStats{Jobs: n, Running: s.running.Load(), Workers: s.workers, Runs: s.runs.Load(), Late: s.late.Load()}
}

func (s *Scheduler) poke() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Run plant und startet Auftraege, bis ctx endet; wartet danach auf laufende Auftraege.
func (s *Scheduler) Run(ctx context.Context) {
	defer s.wg.Wait()
	t := time.NewTimer(time.Hour)
	defer t.Stop()
	for {
		s.mu.Lock()
		wait := time.Hour
		now := s.now()
		for s.h.Len() > 0 {
			j := s.h[0]
			if j.next.After(now) {
				wait = j.next.Sub(now)
				break
			}
			heap.Pop(&s.h)
			s.dispatchLocked(ctx, j, now)
		}
		s.mu.Unlock()
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		t.Reset(wait)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.wake:
		}
	}
}

// dispatchLocked startet einen faelligen Auftrag (oder zaehlt ihn als verspaetet) und plant den naechsten Lauf.
func (s *Scheduler) dispatchLocked(ctx context.Context, j *job, now time.Time) {
	// naechster Lauf auf dem Raster (verpasste Laeufe nicht nachholen)
	next := j.next.Add(j.interval)
	for !next.After(now) {
		next = next.Add(j.interval)
	}
	j.next = next
	if j.gen != 0 {
		heap.Push(&s.h, j)
	}
	if j.running.Load() {
		j.st.Late++
		s.late.Add(1)
		return
	}
	j.running.Store(true)
	s.wg.Add(1)
	go s.exec(ctx, j)
}

func (s *Scheduler) exec(ctx context.Context, j *job) {
	defer s.wg.Done()
	defer j.running.Store(false)
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return
	}
	defer func() { <-s.sem }()
	s.running.Add(1)
	defer s.running.Add(-1)
	start := s.now()
	rctx, cancel := context.WithTimeout(ctx, jobTimeout(j.interval))
	func() {
		defer func() { // ein Fehler in einer Abfrage darf die Node nicht beenden
			if v := recover(); v != nil && s.OnPanic != nil {
				s.OnPanic(j.key, v)
			}
		}()
		j.fn(rctx)
	}()
	cancel()
	took := s.now().Sub(start)
	s.runs.Add(1)
	s.mu.Lock()
	j.st.Runs++
	j.st.LastRun = start
	j.st.LastTook = took
	s.mu.Unlock()
}
