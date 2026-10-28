// Package scheduler fuehrt Checks nach Intervall aus und fuehrt je Check den
// Zustandsautomaten:
//
//	pending/up --(retries+1 Fehlschlaege in Folge)--> down
//	down --(1 Erfolg)--> stabilizing --(stabilize Erfolge in Folge)--> up
//	stabilizing --(Fehlschlag)--> down (ohne neuen Alarm)
//	zu viele Wechsel im Zeitfenster --> flapping --(ruhig fuer FlapCalm)--> up/down
//	Fehlschlag, waehrend ein uebergeordneter Check down ist --> dependent (kein eigener Alarm)
//
// Pro Check laeuft eine Goroutine mit Timer und Jitter; die Gesamtparallelitaet
// begrenzt ein Worker-Pool. Push-Checks haben statt des Timers einen Watchdog.
// Wartungsfenster unterdruecken Benachrichtigungen, Messpunkte werden markiert.
package scheduler

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/checks"
)

type State string

const (
	StatePending     State = "pending"
	StateUp          State = "up"
	StateDown        State = "down"
	StateStabilizing State = "stabilizing"
	StateFlapping    State = "flapping"
	StateDependent   State = "dependent"
	StatePaused      State = "paused"
	// StateDegraded ist nur ein Gesamtzustand: ein Teil der Messstellen ist down.
	StateDegraded State = "degraded"
)

// Check ist die Konfiguration, die der Scheduler braucht.
type Check struct {
	Token         string
	Name          string
	Def           checks.Definition
	Interval      time.Duration
	RetryInterval time.Duration
	Retries       int
	Invert        bool
	Stabilize     int
	Paused        bool
	Parent        string
}

// Runtime ist der persistierte Laufzeitzustand eines Checks.
type Runtime struct {
	State           State
	Since           time.Time
	LastCheck       time.Time
	NextCheck       time.Time
	ConsecutiveFail int
	ConsecutiveOK   int
	LastStatus      checks.Status // letztes Messergebnis (nach Invertierung)
	LastLatency     time.Duration
	LastReason      checks.Reason
	LastMessage     string
	LastPush        time.Time
	Transitions     []time.Time // up/down-Wechsel fuer die Flatter-Erkennung
	FlapSince       time.Time
	DownSince       time.Time // Beginn der aktuellen Stoerung
	Incident        int64     // offene Stoerung (ID aus dem Store), 0 = keine
	// Unalerted: die laufende Stoerung wurde nicht gemeldet (begann in der Wartung oder nur abhaengig gestoert).
	// Nicht gespeichert: nach einem Neustart gilt sie als gemeldet (wie bisher).
	Unalerted bool
}

// Measurement ist ein Messpunkt (append-only).
type Measurement struct {
	Token       string
	Time        time.Time
	Status      checks.Status
	Latency     time.Duration
	Reason      checks.Reason
	Message     string
	Family      string
	Details     map[string]any
	Results     []checks.Result // Teilergebnisse bei v4+v6
	Maintenance bool
	Dependent   bool
}

type EventKind string

const (
	EventDown          EventKind = "down"
	EventUp            EventKind = "up"
	EventFlappingStart EventKind = "flapping_start"
	EventFlappingEnd   EventKind = "flapping_end"
	EventDependent     EventKind = "dependent"
	EventPaused        EventKind = "paused"
	EventResumed       EventKind = "resumed"
)

// Event ist ein Statuswechsel mit eindeutiger ID (gegen Doppelalarme).
type Event struct {
	ID          string
	Token       string
	Kind        EventKind
	Time        time.Time
	From, To    State
	Reason      checks.Reason
	Message     string
	Duration    time.Duration // bei up: Dauer der Stoerung
	Flaps       int           // bei flapping: Anzahl Wechsel
	Maintenance bool
	// Silent: keine Benachrichtigung (Wartung, abhaengig gestoert).
	Silent   bool
	Incident int64
}

// Store persistiert Messpunkte, Zustand und Ereignisse.
type Store interface {
	SaveMeasurement(ctx context.Context, m Measurement) error
	SaveRuntime(ctx context.Context, token string, rt Runtime) error
	// OpenIncident legt eine Stoerung an und liefert ihre ID; CloseIncident schliesst sie.
	OpenIncident(ctx context.Context, token string, at time.Time, reason checks.Reason, message string) (int64, error)
	CloseIncident(ctx context.Context, id int64, at time.Time) error
	SaveEvent(ctx context.Context, e Event) error
	InMaintenance(ctx context.Context, token string, at time.Time) bool
}

// Notifier bekommt jedes Ereignis; Silent-Ereignisse nur zur Kenntnis.
type Notifier interface {
	Notify(ctx context.Context, e Event, c Check)
}

// Options steuern Parallelitaet und Flatter-Erkennung.
type Options struct {
	Workers       int           // Standard 20
	FlapThreshold int           // Wechsel, ab denen ein Check flattert; Standard 3
	FlapWindow    time.Duration // Zeitfenster; Standard 15 min
	FlapCalm      time.Duration // Ruhe bis Ende des Flatterns; Standard 15 min
	Jitter        float64       // Anteil des Intervalls, Standard 0.1
	// Allow (optional, hub): false = Ausfuehrung auslassen, z. B. Tageskontingent erschoepft; push = Push-Auswertung
	Allow func(token string, push bool) bool
	// Throttle (optional, hub): false = diesen Lauf auslassen, weil das Ziel bzw. der Server gerade genug Anfragen
	// bekommt (Bremse gegen Missbrauch als Lastquelle); Zustand bleibt, naechster Versuch nach dem Intervall.
	Throttle func(c Check) bool
}

type entry struct {
	mu        sync.Mutex
	rec       sync.Mutex // eine Auswertung (record) zur Zeit; Upsert wartet darauf
	replaced  bool       // durch Upsert ersetzt: record wertet nicht mehr aus (e.mu)
	check     Check
	rt        Runtime
	wake      chan struct{}
	stop      chan struct{}
	done      chan struct{}
	immediate bool // neu angelegt oder fortgesetzt: sofort pruefen statt Jitter
}

type Scheduler struct {
	st       Store
	notifier Notifier
	runner   *checks.Runner
	log      *slog.Logger
	opts     Options
	workers  chan struct{}
	now      func() time.Time

	mu      sync.RWMutex
	entries map[string]*entry
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	running bool
}

func New(st Store, n Notifier, runner *checks.Runner, log *slog.Logger, opts Options) *Scheduler {
	if opts.Workers <= 0 {
		opts.Workers = 20
	}
	if opts.FlapThreshold <= 0 {
		opts.FlapThreshold = 3
	}
	if opts.FlapWindow <= 0 {
		opts.FlapWindow = 15 * time.Minute
	}
	if opts.FlapCalm <= 0 {
		opts.FlapCalm = 15 * time.Minute
	}
	if opts.Jitter <= 0 {
		opts.Jitter = 0.1
	}
	if runner == nil {
		runner = checks.NewRunner()
	}
	return &Scheduler{st: st, notifier: n, runner: runner, log: log.With("module", "scheduler"), opts: opts,
		workers: make(chan struct{}, opts.Workers), entries: map[string]*entry{}, now: func() time.Time { return time.Now().UTC() }}
}

// Start aktiviert den Scheduler; vorher eingetragene Checks starten jetzt.
func (s *Scheduler) Start(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.running = true
	for _, e := range s.entries {
		s.launch(e)
	}
	s.log.Info("scheduler started", "checks", len(s.entries), "workers", s.opts.Workers)
}

// Stop beendet alle Goroutinen und wartet auf laufende Checks.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	s.cancel()
	entries := make([]*entry, 0, len(s.entries))
	for _, e := range s.entries {
		entries = append(entries, e)
	}
	s.mu.Unlock()
	for _, e := range entries {
		close(e.stop)
	}
	s.wg.Wait()
	s.log.Info("scheduler stopped")
}

// Upsert traegt einen Check ein oder ersetzt seine Konfiguration. rt ist der
// gespeicherte Zustand (nil = neu).
func (s *Scheduler) Upsert(c Check, rt *Runtime) {
	// laufende Auswertung des alten Eintrags abwarten und ihn stilllegen: so kommt sein Zustand (offene Stoerung)
	// vollstaendig herueber und er meldet nichts doppelt. Ohne s.mu, weil record s.entries liest (parentDown).
	s.mu.RLock()
	prev := s.entries[c.Token]
	s.mu.RUnlock()
	if prev != nil {
		prev.rec.Lock()
		prev.mu.Lock()
		prev.replaced = true
		prev.mu.Unlock()
		prev.rec.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.entries[c.Token]; ok {
		close(old.stop)
		old.mu.Lock()
		old.replaced = true
		cp := old.rt
		old.mu.Unlock()
		if rt == nil {
			rt = &cp
		} else {
			// offene Stoerung fuehrt der laufende Eintrag (ein uebergebener Stand kann aelter sein)
			given := *rt
			given.Incident, given.Unalerted = cp.Incident, cp.Unalerted
			rt = &given
		}
		delete(s.entries, c.Token)
	}
	e := &entry{check: c, wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}), immediate: rt == nil}
	if rt != nil {
		e.rt = *rt
	}
	if e.rt.State == "" {
		e.rt.State = StatePending
		e.rt.Since = s.now()
	}
	if c.Paused && e.rt.State != StatePaused {
		e.rt.State = StatePaused
		e.rt.Since = s.now()
	}
	if !c.Paused && e.rt.State == StatePaused {
		e.rt.State = StatePending
		e.rt.Since = s.now()
		e.rt.ConsecutiveFail, e.rt.ConsecutiveOK = 0, 0
		e.immediate = true
	}
	s.entries[c.Token] = e
	if s.running {
		s.launch(e)
	}
}

// Remove nimmt einen Check heraus und stoppt seine Goroutine.
func (s *Scheduler) Remove(token string) {
	s.mu.Lock()
	e, ok := s.entries[token]
	if ok {
		delete(s.entries, token)
	}
	s.mu.Unlock()
	if ok {
		close(e.stop)
		<-e.done
	}
}

// RunNow fuehrt einen Check sofort aus (Button "jetzt pruefen").
func (s *Scheduler) RunNow(token string) bool {
	s.mu.RLock()
	e, ok := s.entries[token]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	select {
	case e.wake <- struct{}{}:
	default:
	}
	return true
}

// Runtime liefert den aktuellen Zustand eines Checks.
func (s *Scheduler) Runtime(token string) (Runtime, bool) {
	s.mu.RLock()
	e, ok := s.entries[token]
	s.mu.RUnlock()
	if !ok {
		return Runtime{}, false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	rt := e.rt
	rt.Transitions = append([]time.Time{}, e.rt.Transitions...)
	return rt, true
}

// Push verarbeitet eine Heartbeat-Meldung. status leer = up.
func (s *Scheduler) Push(ctx context.Context, token string, status checks.Status, msg string, details map[string]any) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	// Zustand, Stoerung und Benachrichtigung nicht am Abbruch der Anfrage scheitern lassen
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	for try := 0; try < 2; try++ {
		s.mu.RLock()
		e, ok := s.entries[token]
		s.mu.RUnlock()
		if !ok || e.check.Def.Type != checks.TypePush {
			return false
		}
		now := s.now()
		m := Measurement{Token: token, Time: now, Status: checks.Up, Reason: checks.ReasonOK, Message: "push received", Details: details}
		if status == checks.Down {
			m.Status, m.Reason, m.Message = checks.Down, checks.ReasonPushDown, "push reported down"
		}
		if msg != "" {
			m.Message = msg
		}
		e.mu.Lock()
		e.rt.LastPush = now
		e.mu.Unlock()
		if !s.record(ctx, e, m) {
			continue // Eintrag eben ersetzt: beim neuen auswerten
		}
		select {
		case e.wake <- struct{}{}:
		default:
		}
		return true
	}
	return false
}

func (s *Scheduler) launch(e *entry) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer close(e.done)
		if e.check.Def.Type == checks.TypePush {
			s.pushLoop(e)
		} else {
			s.loop(e)
		}
	}()
}

// loop ist die Goroutine eines aktiven Checks.
func (s *Scheduler) loop(e *entry) {
	first := true
	for {
		e.mu.Lock()
		paused := e.check.Paused
		next := e.rt.NextCheck
		e.mu.Unlock()
		var wait time.Duration
		switch {
		case paused:
			wait = 24 * time.Hour
		case first && e.immediate:
			wait = 0
		case first && (next.IsZero() || next.Before(s.now())):
			// Beim Start verteilen, damit nicht alle Checks gleichzeitig loslaufen
			wait = time.Duration(rand.Float64() * float64(min(e.check.Interval, 10*time.Second)))
		default:
			wait = time.Until(next)
			if wait < 0 {
				wait = 0
			}
		}
		first = false
		t := time.NewTimer(wait)
		select {
		case <-e.stop:
			t.Stop()
			return
		case <-e.wake:
			t.Stop()
		case <-t.C:
		}
		if e.check.Paused {
			continue
		}
		// Worker-Slot
		select {
		case s.workers <- struct{}{}:
		case <-e.stop:
			return
		}
		s.runOnce(e)
		<-s.workers
	}
}

// runOnce fuehrt den Check aus und verarbeitet das Ergebnis.
func (s *Scheduler) runOnce(e *entry) {
	ctx := s.ctx
	if s.opts.Allow != nil && !s.opts.Allow(e.check.Token, e.check.Def.Type == checks.TypePush) {
		e.mu.Lock()
		e.rt.NextCheck = s.now().Add(e.check.Interval) // ausgelassen, Zustand bleibt
		e.mu.Unlock()
		return
	}
	if s.opts.Throttle != nil && e.check.Def.Type != checks.TypePush && !s.opts.Throttle(e.check) {
		e.mu.Lock()
		e.rt.NextCheck = s.now().Add(e.check.Interval)
		e.mu.Unlock()
		return
	}
	results := s.runner.Run(ctx, e.check.Def)
	if ctx.Err() != nil {
		return
	}
	m := combine(e.check, results, s.now())
	s.record(ctx, e, m)
}

// combine fasst Teilergebnisse (v4/v6) zu einem Messpunkt zusammen und wendet
// die Invertierung an.
func combine(c Check, results []checks.Result, now time.Time) Measurement {
	m := Measurement{Token: c.Token, Time: now, Status: checks.Up, Reason: checks.ReasonOK, Results: results, Details: map[string]any{}}
	if len(results) == 0 {
		m.Status, m.Reason, m.Message = checks.Down, checks.ReasonInternal, "no result"
		return m
	}
	var msgs []string
	var lat time.Duration
	for _, r := range results {
		if r.Status == checks.Down && m.Status == checks.Up {
			m.Status, m.Reason = checks.Down, r.Reason
		}
		if r.Latency > lat {
			lat = r.Latency
		}
		if len(results) > 1 {
			msgs = append(msgs, r.Family+": "+r.Message)
		} else {
			msgs = append(msgs, r.Message)
			m.Family = r.Family
			m.Details = r.Details
		}
	}
	if len(results) > 1 {
		for _, r := range results {
			m.Details[r.Family] = r.Details
		}
	}
	m.Latency = lat
	m.Message = strings.Join(msgs, " | ")
	if c.Invert {
		if m.Status == checks.Up {
			m.Status = checks.Down
			m.Message = "inverted: " + m.Message
		} else {
			m.Status, m.Reason = checks.Up, checks.ReasonOK
			m.Message = "inverted: " + m.Message
		}
	}
	return m
}

// record wendet den Zustandsautomaten an, speichert und benachrichtigt. false = Eintrag inzwischen ersetzt
// (Upsert), nichts ausgewertet.
func (s *Scheduler) record(ctx context.Context, e *entry, m Measurement) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	e.rec.Lock()
	defer e.rec.Unlock()
	e.mu.Lock()
	replaced := e.replaced
	e.mu.Unlock()
	if replaced {
		return false
	}
	m.Maintenance = s.st.InMaintenance(ctx, e.check.Token, m.Time)
	parentDown := s.parentDown(e.check)

	e.mu.Lock()
	events := s.transition(e, &m, parentDown)
	e.rt.LastCheck = m.Time
	e.rt.LastStatus = m.Status
	e.rt.LastLatency = m.Latency
	e.rt.LastReason = m.Reason
	e.rt.LastMessage = m.Message
	e.rt.NextCheck = m.Time.Add(s.nextInterval(e))
	rt := e.rt
	e.mu.Unlock()

	if err := s.st.SaveMeasurement(ctx, m); err != nil {
		s.log.Error("measurement not saved", "token", checks.TokenHint(e.check.Token), "err", err)
	}
	setIncident := func(id int64) {
		e.mu.Lock()
		e.rt.Incident = id
		rt.Incident = id
		e.mu.Unlock()
	}
	closeIncident := func(at time.Time) {
		if err := s.st.CloseIncident(ctx, rt.Incident, at); err != nil {
			// ID behalten, naechster Messpunkt versucht es erneut
			s.log.Error("incident not closed", "token", checks.TokenHint(e.check.Token), "err", err)
			return
		}
		setIncident(0)
	}
	closeTried := false
	for i := range events {
		ev := &events[i]
		switch {
		case ev.Kind == EventDown && rt.Incident != 0:
			ev.Incident = rt.Incident // Stoerung laeuft schon (Pause, Flattern, Wartung, abhaengig): weiterfuehren
		case ev.Kind == EventDown:
			if id, err := s.st.OpenIncident(ctx, e.check.Token, ev.Time, ev.Reason, ev.Message); err == nil {
				ev.Incident = id
				setIncident(id)
			}
		case ev.To == StateUp && rt.Incident != 0:
			// jeder Wechsel nach up beendet die Stoerung (auch Ende des Flatterns, erste Messung nach Pause)
			ev.Incident = rt.Incident
			closeTried = true
			closeIncident(ev.Time)
		}
		if err := s.st.SaveEvent(ctx, *ev); err != nil {
			s.log.Error("event not saved", "token", checks.TokenHint(e.check.Token), "err", err)
		}
		s.log.Info("check state changed", "token", checks.TokenHint(e.check.Token), "name", e.check.Name, "from", ev.From, "to", ev.To, "kind", ev.Kind, "reason", ev.Reason, "silent", ev.Silent)
		if s.notifier != nil {
			s.notifier.Notify(ctx, *ev, e.check)
		}
	}
	if !closeTried && rt.State == StateUp && rt.Incident != 0 {
		closeIncident(rt.Since) // frueher fehlgeschlagen: Ende ist der Wechsel nach up
	}
	if err := s.st.SaveRuntime(ctx, e.check.Token, rt); err != nil {
		s.log.Error("runtime not saved", "token", checks.TokenHint(e.check.Token), "err", err)
	}
	s.log.Debug("check measured", "token", checks.TokenHint(e.check.Token), "status", m.Status, "latency_ms", m.Latency.Milliseconds(), "reason", m.Reason, "state", rt.State)
	return true
}

// transition ist der Zustandsautomat; e.mu ist gehalten.
func (s *Scheduler) transition(e *entry, m *Measurement, parentDown bool) []Event {
	rt := &e.rt
	var events []Event
	newEvent := func(kind EventKind, to State, reason checks.Reason, msg string) *Event {
		ev := Event{ID: newID(), Token: e.check.Token, Kind: kind, Time: m.Time, From: rt.State, To: to, Reason: reason, Message: msg, Maintenance: m.Maintenance, Silent: m.Maintenance}
		wasDown := rt.State == StateDown || rt.State == StateDependent || rt.State == StateStabilizing || rt.State == StateFlapping
		if (to == StateDown || to == StateDependent) && !wasDown {
			rt.DownSince = m.Time
		}
		rt.State, rt.Since = to, m.Time
		events = append(events, ev)
		return &events[len(events)-1]
	}
	// Flattern beenden, wenn lange ruhig
	if rt.State == StateFlapping && !rt.FlapSince.IsZero() {
		last := rt.FlapSince
		if n := len(rt.Transitions); n > 0 {
			last = rt.Transitions[n-1]
		}
		if m.Time.Sub(last) >= s.opts.FlapCalm {
			flaps := len(rt.Transitions)
			rt.FlapSince = time.Time{}
			rt.Transitions = nil
			switch {
			case rt.LastStatus != checks.Down:
				ev := newEvent(EventFlappingEnd, StateUp, m.Reason, fmt.Sprintf("stable again after %d changes", flaps))
				ev.Flaps = flaps
				rt.Unalerted = false
			case parentDown:
				newEvent(EventDependent, StateDependent, checks.ReasonDependencyDown, "parent check is down: "+rt.LastMessage).Silent = true
			default:
				// ruhig, aber gestoert: als Ausfall melden, nicht als "wieder stabil"
				ev := newEvent(EventDown, StateDown, rt.LastReason, rt.LastMessage)
				ev.Flaps = flaps
				rt.Unalerted = ev.Silent // in der Wartung: nach dem Fenster melden
			}
		}
	}
	ok := m.Status == checks.Up
	if ok {
		rt.ConsecutiveFail = 0
		rt.ConsecutiveOK++
	} else {
		rt.ConsecutiveOK = 0
		rt.ConsecutiveFail++
	}
	markFlap := func(ev *Event) {
		// up<->down-Wechsel zaehlen; zu viele im Fenster = flattern
		rt.Transitions = append(rt.Transitions, m.Time)
		cut := m.Time.Add(-s.opts.FlapWindow)
		for len(rt.Transitions) > 0 && rt.Transitions[0].Before(cut) {
			rt.Transitions = rt.Transitions[1:]
		}
		if len(rt.Transitions) > s.opts.FlapThreshold && rt.State != StateFlapping {
			ev.Silent = true // Einzelmeldung geht in der Sammelmeldung auf (vor newEvent: append kann ev verschieben)
			fev := newEvent(EventFlappingStart, StateFlapping, m.Reason, fmt.Sprintf("%d state changes within %s", len(rt.Transitions), s.opts.FlapWindow))
			fev.Flaps = len(rt.Transitions)
			rt.FlapSince = m.Time
		}
	}
	// upEvent beendet eine Stoerung: gemeldet, wenn auch der Ausfall gemeldet wurde (auch in der Wartung),
	// still, wenn er nie gemeldet wurde (begann in der Wartung, nur abhaengig gestoert)
	upEvent := func() *Event {
		ev := newEvent(EventUp, StateUp, checks.ReasonOK, m.Message)
		ev.Duration = m.Time.Sub(rt.DownSince)
		ev.Silent = rt.Unalerted
		rt.Unalerted = false
		return ev
	}

	switch rt.State {
	case StatePaused:
		return nil
	case StateFlapping:
		// Zustand bleibt flattern; nur Wechsel zaehlen
		if (ok && rt.LastStatus == checks.Down) || (!ok && rt.LastStatus == checks.Up) {
			rt.Transitions = append(rt.Transitions, m.Time)
		}
		m.Dependent = !ok && parentDown
		return events
	case StatePending, StateUp:
		if ok {
			if rt.State == StatePending {
				newEvent(EventUp, StateUp, checks.ReasonOK, m.Message).Silent = true
				rt.Unalerted = false
			}
			return events
		}
		if rt.ConsecutiveFail <= e.check.Retries {
			return events // noch im Retry
		}
		if parentDown {
			m.Dependent = true
			newEvent(EventDependent, StateDependent, checks.ReasonDependencyDown, "parent check is down: "+m.Message).Silent = true
			rt.Unalerted = true // kein eigener Alarm, also spaeter auch kein "wieder erreichbar"
			return events
		}
		ev := newEvent(EventDown, StateDown, m.Reason, m.Message)
		rt.Unalerted = m.Maintenance // in der Wartung still: nach dem Fenster melden
		markFlap(ev)
		return events
	case StateDown, StateDependent:
		if !ok {
			m.Dependent = rt.State == StateDependent || parentDown
			switch {
			case rt.State == StateDown && parentDown:
				// Ursache liegt weiter oben: ab jetzt abhaengig
				m.Dependent = true
				newEvent(EventDependent, StateDependent, checks.ReasonDependencyDown, "parent check is down").Silent = true
			case rt.State == StateDependent && !parentDown && rt.ConsecutiveFail > e.check.Retries:
				// uebergeordneter Check wieder da, dieser weiter gestoert: eigener Ausfall
				m.Dependent = false
				newEvent(EventDown, StateDown, m.Reason, m.Message)
				rt.Unalerted = m.Maintenance
			case rt.State == StateDown && rt.Unalerted && !m.Maintenance:
				// Ausfall begann in der Wartung und dauert nach dem Fenster an: jetzt melden
				newEvent(EventDown, StateDown, m.Reason, m.Message)
				rt.Unalerted = false
			}
			return events
		}
		if e.check.Stabilize <= 1 {
			markFlap(upEvent())
			return events
		}
		newEvent(EventUp, StateStabilizing, checks.ReasonOK, m.Message).Silent = true
		events[len(events)-1].Kind = "stabilizing"
		return events
	case StateStabilizing:
		if !ok {
			// zurueck auf down ohne neuen Alarm; Dauer der Stoerung laeuft weiter
			ev := newEvent(EventDown, StateDown, m.Reason, m.Message)
			ev.Silent = true
			ev.Kind = "unstable"
			if parentDown {
				m.Dependent = true
				rt.State = StateDependent
				ev.To = StateDependent
			}
			return events
		}
		if rt.ConsecutiveOK >= e.check.Stabilize {
			markFlap(upEvent())
		}
		return events
	}
	return events
}

// nextInterval: im gestoerten oder stabilisierenden Zustand das Retry-Intervall,
// sonst das Normalintervall, jeweils mit Jitter.
func (s *Scheduler) nextInterval(e *entry) time.Duration {
	iv := e.check.Interval
	if iv <= 0 {
		iv = checks.DefaultInterval
	}
	retry := e.check.RetryInterval
	if retry <= 0 || retry > iv {
		retry = iv
	}
	switch e.rt.State {
	case StateDown, StateStabilizing, StateDependent:
		iv = retry
	default:
		if e.rt.ConsecutiveFail > 0 {
			iv = retry
		}
	}
	j := float64(iv) * s.opts.Jitter
	return iv + time.Duration((rand.Float64()*2-1)*j)
}

// parentDown prueft die Kette der uebergeordneten Checks.
func (s *Scheduler) parentDown(c Check) bool {
	seen := map[string]bool{c.Token: true}
	parent := c.Parent
	for parent != "" && !seen[parent] {
		seen[parent] = true
		s.mu.RLock()
		pe, ok := s.entries[parent]
		s.mu.RUnlock()
		if !ok {
			return false
		}
		pe.mu.Lock()
		st := pe.rt.State
		next := pe.check.Parent
		pe.mu.Unlock()
		if st == StateDown || st == StateDependent || st == StateFlapping {
			return true
		}
		parent = next
	}
	return false
}

// pushLoop ist der Watchdog eines Heartbeat-Checks.
func (s *Scheduler) pushLoop(e *entry) {
	for {
		period, grace := checks.PushWindow(e.check.Def.Params)
		e.mu.Lock()
		last := e.rt.LastPush
		paused := e.check.Paused
		lastCheck := e.rt.LastCheck
		e.mu.Unlock()
		deadline := last.Add(time.Duration(period+grace) * time.Second)
		if last.IsZero() {
			// Noch nie gemeldet: ab Start der Ueberwachung zaehlen
			base := lastCheck
			if base.IsZero() {
				base = s.now()
			}
			deadline = base.Add(time.Duration(period+grace) * time.Second)
		}
		wait := time.Until(deadline)
		if paused {
			wait = 24 * time.Hour
		}
		if wait < 0 {
			wait = 0
		}
		t := time.NewTimer(wait)
		select {
		case <-e.stop:
			t.Stop()
			return
		case <-e.wake:
			t.Stop()
			continue
		case <-t.C:
		}
		if e.check.Paused {
			continue
		}
		now := s.now()
		e.mu.Lock()
		last = e.rt.LastPush
		e.mu.Unlock()
		if !last.IsZero() && now.Before(last.Add(time.Duration(period+grace)*time.Second)) {
			continue // zwischenzeitlich gemeldet
		}
		m := Measurement{Token: e.check.Token, Time: now, Status: checks.Down, Reason: checks.ReasonPushMissing,
			Message: fmt.Sprintf("no push for more than %s", (time.Duration(period+grace) * time.Second).String())}
		s.record(s.ctx, e, m)
		// Bis zur naechsten Meldung alle period Sekunden erneut als down festhalten
		e.mu.Lock()
		e.rt.LastPush = time.Time{}
		e.rt.LastCheck = now
		e.mu.Unlock()
	}
}

// Snapshot liefert alle Tokens mit Zustand, sortiert.
func (s *Scheduler) Snapshot() map[string]Runtime {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]Runtime, len(s.entries))
	for k, e := range s.entries {
		e.mu.Lock()
		out[k] = e.rt
		e.mu.Unlock()
	}
	return out
}

// Tokens liefert alle eingetragenen Tokens sortiert.
func (s *Scheduler) Tokens() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.entries))
	for k := range s.entries {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// NewID erzeugt eine eindeutige Ereignis-ID.
func NewID() string { return newID() }

func newID() string {
	b := make([]byte, 16)
	_, _ = crand.Read(b)
	return hex.EncodeToString(b)
}
