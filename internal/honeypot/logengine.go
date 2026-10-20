package honeypot

import (
	"container/list"
	"context"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Log-Sensor (Phase H5, Plan Abschnitt 1b/1c): liest Dateien (logtail.go) und nimmt Syslog an (syslog.go), wendet die
// mitgelieferten Regeln an (logrules_*.go) und meldet ein Ereignis, sobald eine IP die Schwelle einer Regel im Fenster
// erreicht. Gemeldet werden nur IP, Art, Dienst, Port, Quelle und Regel – keine Inhalte aus den Logs.

// LogSensor liest Dateien und Syslog, wendet die Regeln an und meldet Ereignisse an die Sink.
type LogSensor struct {
	log *slog.Logger
	eng *logEngine

	applyMu sync.Mutex // Apply/Stop nacheinander
	mu      sync.Mutex // tail, sys*
	tail    *logTailer // nil = keine Dateien
	sys     *SyslogServer
	sysKey  string // Port und erlaubte Absender des laufenden Empfaengers
	sysErr  error  // Fehler beim Start (naechstes Apply versucht es erneut)
	sysStop context.CancelFunc

	feedMu  sync.Mutex                // feed, feedOff
	feed    atomic.Pointer[logFeedCh] // Zeilen von aussen (FeedLine), nil = kein Leser
	feedOff bool                      // nach Stop keine neuen Leser (bis zum naechsten Apply)
}

// logFeedQueue: so viele Zeilen von FeedLine warten hoechstens; mehr werden verworfen.
const logFeedQueue = 4096

// logFeedCh ist die Warteschlange von FeedLine mit ihrem Leser.
type logFeedCh struct {
	ch   chan LogLine
	quit chan struct{}
}

// NewLogSensor legt den Log-Sensor an (noch nichts geoeffnet).
func NewLogSensor(log *slog.Logger) *LogSensor {
	if log == nil {
		log = slog.Default()
	}
	log = log.With("module", Name, "part", "logs")
	return &LogSensor{log: log, eng: newLogEngine(log, LogRules(), time.Now)}
}

// Apply startet, aendert oder stoppt Dateien und Syslog-Empfaenger nach cfg. Leere cfg = alles aus.
func (s *LogSensor) Apply(ctx context.Context, cfg LogConfig, sink Sink) LogStatus {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	s.eng.setSink(sink)
	s.feedMu.Lock()
	s.feedOff = false
	s.feedMu.Unlock()
	s.applyFiles(logCleanFiles(cfg.Files))
	s.applySyslog(ctx, cfg)
	return s.Status()
}

// Stop beendet alles.
func (s *LogSensor) Stop() {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	s.applyFiles(nil)
	s.stopSyslog()
	s.feedMu.Lock()
	s.feedOff = true
	f := s.feed.Swap(nil)
	s.feedMu.Unlock()
	if f != nil {
		close(f.quit)
	}
}

// FeedLine nimmt eine fertig zerlegte Zeile von aussen an (Zugriffe von PROXY64, bridge.go). Kehrt sofort zurueck: die
// Regeln laufen in einem eigenen Leser; ist die Warteschlange voll (oder der Log-Sensor gestoppt), wird die Zeile
// verworfen (false).
func (s *LogSensor) FeedLine(l LogLine) bool {
	f := s.feed.Load()
	if f == nil {
		if f = s.startFeed(); f == nil {
			return false
		}
	}
	select {
	case f.ch <- l:
		return true
	default:
		return false
	}
}

// startFeed startet den Leser von FeedLine (nil = gestoppt).
func (s *LogSensor) startFeed() *logFeedCh {
	s.feedMu.Lock()
	defer s.feedMu.Unlock()
	if f := s.feed.Load(); f != nil || s.feedOff {
		return f
	}
	f := &logFeedCh{ch: make(chan LogLine, logFeedQueue), quit: make(chan struct{})}
	go func() {
		for {
			select {
			case <-f.quit:
				return
			case l := <-f.ch:
				s.eng.feed(l)
			}
		}
	}()
	s.feed.Store(f)
	return f
}

// Status liefert den aktuellen Zustand.
func (s *LogSensor) Status() LogStatus {
	s.mu.Lock()
	t, srv := s.tail, s.sys
	s.mu.Unlock()
	st := LogStatus{Files: []LogFileStatus{}, Lines: s.eng.lines.Load(), Hits: s.eng.hits.Load(), Events: s.eng.events.Load()}
	if t != nil {
		st.Files = t.status()
	}
	if srv != nil {
		ss := srv.Status()
		st.Syslog = &ss
	}
	return st
}

// applyFiles bringt den Dateileser auf den Stand von files (leer = aus). Unveraenderte Dateien lesen an ihrer Stelle
// weiter.
func (s *LogSensor) applyFiles(files []LogFile) {
	s.mu.Lock()
	t := s.tail
	s.mu.Unlock()
	if len(files) == 0 {
		if t != nil {
			t.stop()
			s.mu.Lock()
			s.tail = nil
			s.mu.Unlock()
		}
		return
	}
	if t != nil {
		t.setFiles(files)
		return
	}
	t = newLogTailer(s.log, s.eng.feed, time.Now)
	t.setFiles(files)
	t.start()
	s.mu.Lock()
	s.tail = t
	s.mu.Unlock()
}

// applySyslog startet den Empfaenger neu, wenn sich Port oder erlaubte Absender aendern oder der letzte Start
// gescheitert ist; Port 0 = aus.
func (s *LogSensor) applySyslog(ctx context.Context, cfg LogConfig) {
	key := ""
	if cfg.SyslogPort > 0 {
		key = strconv.Itoa(cfg.SyslogPort) + "|" + strings.Join(cfg.SyslogAllow, ",")
	}
	s.mu.Lock()
	running, same, failed := s.sys != nil, s.sysKey == key, s.sysErr != nil
	s.mu.Unlock()
	if running && same && !failed {
		return
	}
	s.stopSyslog()
	if key == "" {
		return
	}
	srv := NewSyslogServer(s.log, cfg.SyslogPort, logParseAllow(cfg.SyslogAllow), s.eng.feed)
	// eigener Kontext: der Empfaenger lebt bis Stop bzw. bis zur naechsten Aenderung, nicht laenger als ctx
	sctx, cancel := context.WithCancel(ctx)
	err := srv.Start(sctx)
	if err != nil {
		s.log.Warn("honeypot syslog not started", "port", cfg.SyslogPort, "err", err)
	}
	s.mu.Lock()
	s.sys, s.sysKey, s.sysErr, s.sysStop = srv, key, err, cancel
	s.mu.Unlock()
}

func (s *LogSensor) stopSyslog() {
	s.mu.Lock()
	srv, cancel := s.sys, s.sysStop
	s.sys, s.sysKey, s.sysErr, s.sysStop = nil, "", nil, nil
	s.mu.Unlock()
	if srv != nil {
		srv.Stop()
	}
	if cancel != nil {
		cancel()
	}
}

// logCleanFiles entfernt leere und doppelte Eintraege.
func logCleanFiles(in []LogFile) []LogFile {
	var out []LogFile
	seen := map[string]bool{}
	for _, f := range in {
		f.Path = strings.TrimSpace(f.Path)
		f.Format = strings.ToLower(strings.TrimSpace(f.Format))
		if f.Format == "auto" {
			f.Format = ""
		}
		if f.Path == "" || seen[f.Path] {
			continue
		}
		seen[f.Path] = true
		out = append(out, f)
	}
	return out
}

// logParseAllow liest die erlaubten Absender (CIDR oder einzelne IP); ungueltige Eintraege fallen weg.
func logParseAllow(in []string) []netip.Prefix {
	var out []netip.Prefix
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if p, err := netip.ParsePrefix(v); err == nil {
			out = append(out, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(v); err == nil {
			a = a.Unmap().WithZone("")
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

// Engine: Treffer je (Regel, IP) im Fenster zaehlen.

const (
	logDefWindow  = 10 * time.Minute // Fenster, wenn die Regel keins nennt
	logSweepEvery = time.Minute      // abgelaufene Zaehler aufraeumen
	logMaxWeight  = 1000             // Obergrenze fuer LogHit.Weight
)

type logKey struct {
	rule int // Index in logEngine.rules
	src  netip.Addr
}

type logCount struct {
	key   logKey
	start time.Time // Zeit (aus der Zeile) des ersten Treffers im Fenster
	n     int
	touch time.Time // Uhr der Engine beim letzten Treffer (Aufraeumen, Verdraengen)
}

// logEngine wendet die Regeln auf jede Zeile an. Thread-sicher: Dateien und Syslog liefern parallel; Match laeuft
// ohne Sperre, nur das Zaehlen ist gesperrt.
type logEngine struct {
	log    *slog.Logger
	now    func() time.Time
	rules  []*LogRule
	same   [][]int // je Regel: Regeln mit gleichem Dienst (Rueckstellung bei Erfolg)
	minWin time.Duration
	max    int // hoechstens so viele offene Zaehler (LogMaxTracked)

	sink   atomic.Pointer[Sink]
	lines  atomic.Int64
	hits   atomic.Int64
	events atomic.Int64

	mu    sync.Mutex
	m     map[logKey]*list.Element
	lru   *list.List // vorne = zuletzt getroffen
	swept time.Time
}

func newLogEngine(log *slog.Logger, rules []*LogRule, now func() time.Time) *logEngine {
	if log == nil {
		log = slog.Default()
	}
	e := &logEngine{log: log, now: now, rules: rules, max: LogMaxTracked, m: map[logKey]*list.Element{}, lru: list.New()}
	e.same = make([][]int, len(rules))
	for i, r := range rules {
		for j, o := range rules {
			if o.Service == r.Service {
				e.same[i] = append(e.same[i], j)
			}
		}
		if w := logWindow(r); e.minWin == 0 || w < e.minWin {
			e.minWin = w
		}
	}
	return e
}

func (e *logEngine) setSink(s Sink) {
	if s == nil {
		e.sink.Store(nil)
		return
	}
	e.sink.Store(&s)
}

func logWindow(r *LogRule) time.Duration {
	if r.Window > 0 {
		return r.Window
	}
	return logDefWindow
}

func logThreshold(r *LogRule) int {
	if r.Threshold > 0 {
		return r.Threshold
	}
	return 1
}

func logOriginOK(r *LogRule, origin string) bool {
	if len(r.Origins) == 0 {
		return true
	}
	for _, o := range r.Origins {
		if o == origin {
			return true
		}
	}
	return false
}

// feed nimmt eine Zeile entgegen (Dateien und Syslog).
func (e *logEngine) feed(l LogLine) {
	e.lines.Add(1)
	if l.Origin == "" {
		l.Origin = SrcLog
	}
	if l.Time.IsZero() {
		l.Time = e.now().UTC()
	}
	defer func() {
		if p := recover(); p != nil { // eine fehlerhafte Regel darf den Leser nicht beenden
			e.log.Error("honeypot log rule failed", "panic", p)
		}
	}()
	for i, r := range e.rules {
		if r.Match == nil || !logOriginOK(r, l.Origin) {
			continue
		}
		h, ok := r.Match(&l)
		if !ok || !h.Src.IsValid() {
			continue
		}
		e.hit(i, &l, h)
	}
}

// hit zaehlt einen Treffer und gibt bei erreichter Schwelle ein Ereignis an die Sink.
func (e *logEngine) hit(i int, l *LogLine, h LogHit) {
	src := h.Src.Unmap().WithZone("")
	r := e.rules[i]
	now := e.now()
	e.mu.Lock()
	e.sweepLocked(now)
	if h.Success {
		for _, j := range e.same[i] {
			e.dropLocked(logKey{j, src})
		}
		e.mu.Unlock()
		return
	}
	w := h.Weight
	if w < 1 {
		w = 1
	} else if w > logMaxWeight {
		w = logMaxWeight
	}
	fire := e.countLocked(logKey{i, src}, l.Time, now, w, logThreshold(r), logWindow(r))
	e.mu.Unlock()
	e.hits.Add(1)
	if !fire {
		return
	}
	port := h.Port
	if port <= 0 {
		port = r.Port
	}
	// bewusst ohne Username/Password/Path/UA/Payload: nur Regelname im Detail (Plan Abschnitt 1b, 13)
	ev := Event{Time: l.Time, Service: r.Service, Port: port, Kind: r.Kind, Src: src, Source: l.Origin, Rule: r.Tag(), Detail: r.ID}
	if p := e.sink.Load(); p != nil && *p != nil {
		(*p)(ev)
		e.events.Add(1)
	}
}

// countLocked zaehlt w Treffer fuer k; true = Schwelle erreicht (der Zaehler beginnt danach von vorn).
func (e *logEngine) countLocked(k logKey, t, now time.Time, w, thr int, win time.Duration) bool {
	var c *logCount
	if el := e.m[k]; el != nil {
		c = el.Value.(*logCount)
		if t.Sub(c.start) > win { // Fenster abgelaufen: neu beginnen
			c.start, c.n = t, 0
		}
		e.lru.MoveToFront(el)
	} else {
		for len(e.m) >= e.max && e.lru.Len() > 0 { // voll: aelteste fallen weg
			e.dropLocked(e.lru.Back().Value.(*logCount).key)
		}
		c = &logCount{key: k, start: t}
		e.m[k] = e.lru.PushFront(c)
	}
	c.touch = now
	c.n += w
	if c.n < thr {
		return false
	}
	e.dropLocked(k)
	return true
}

func (e *logEngine) dropLocked(k logKey) {
	if el := e.m[k]; el != nil {
		e.lru.Remove(el)
		delete(e.m, k)
	}
}

// sweepLocked entfernt hoechstens einmal je logSweepEvery die Zaehler, deren Fenster abgelaufen ist.
func (e *logEngine) sweepLocked(now time.Time) {
	if now.Sub(e.swept) < logSweepEvery {
		return
	}
	e.swept = now
	for el := e.lru.Back(); el != nil; {
		c := el.Value.(*logCount)
		age := now.Sub(c.touch)
		if age <= e.minWin { // alles weiter vorn ist juenger
			break
		}
		prev := el.Prev()
		if age > logWindow(e.rules[c.key.rule]) {
			e.lru.Remove(el)
			delete(e.m, c.key)
		}
		el = prev
	}
}

// tracked liefert die Zahl offener Zaehler (Tests).
func (e *logEngine) tracked() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.m)
}
