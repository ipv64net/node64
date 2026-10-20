package honeypot

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/metrics"
)

// Zaehler je Dienst und Art fuer Prometheus. Es gibt je Prozess hoechstens einen Honeypot (Modul oder Modus ohne
// Oberflaeche), daher zaehlt CountEvents prozessweit; Prometheus-Zaehler laufen ohnehin seit dem Start.
var metricCounts = struct {
	mu     sync.Mutex
	logins map[string]int64 // Dienst -> Login-Versuche
	kinds  map[string]int64 // Art + "\x00" + Quelle -> Ereignisse
}{logins: map[string]int64{}, kinds: map[string]int64{}}

// CountEvents umhuellt eine Sink und zaehlt jedes Ereignis je Art und Quelle und jeden Login-Versuch je Dienst (fuer
// node64_honeypot_events_total und node64_honeypot_logins_total). Modul und Modus ohne Oberflaeche geben dem
// Sensor und dem Log-Sensor CountEvents(store.Sink()).
func CountEvents(next Sink) Sink {
	return func(e Event) {
		metricCounts.mu.Lock()
		metricCounts.kinds[e.Kind+"\x00"+storeSource(e.Source)]++
		if storeIsLogin(e) {
			metricCounts.logins[e.Service]++
		}
		metricCounts.mu.Unlock()
		next(e)
	}
}

// SensorState ist, was WriteMetrics vom Sensor liest (*Sensor erfuellt es).
type SensorState interface {
	Status() []ServiceStatus
	Counters() *Counters
}

// Kennzahl "verschiedene Quell-IPs (24 h)" kurz zwischenspeichern: Prometheus fragt oft, die Abfrage zaehlt
// ueber alle Ereignisse eines Tages.
const uniqueCacheFor = 30 * time.Second

var uniqueCache = struct {
	mu  sync.Mutex
	st  *Store
	at  time.Time
	val int64
}{}

// WriteMetrics schreibt die Kennzahlen des Honeypots (Modul und Modus ohne Oberflaeche gleich, Plan Abschnitt 2):
// node64_honeypot_connections_total{service,port}, node64_honeypot_logins_total{service},
// node64_honeypot_events_total{kind,source}, node64_honeypot_unique_sources (24 h),
// node64_honeypot_listen_errors{port}, node64_honeypot_buffer_events, node64_honeypot_dropped_total und zur Meldung
// an ipv64 node64_honeypot_report_last_success_timestamp, node64_honeypot_report_errors_total,
// node64_honeypot_report_sources_total. sensor, st und rep duerfen nil sein (dann fehlen die zugehoerigen Werte).
func WriteMetrics(w *metrics.Writer, sensor SensorState, st *Store, rep *Reporter, ctx context.Context) {
	var status []ServiceStatus
	var c *Counters
	if sensor != nil {
		status = sensor.Status()
		c = sensor.Counters()
	}
	open := 0
	for _, s := range status {
		if s.Listen {
			open++
		}
	}
	w.Gauge("node64_honeypot_services", "Eingestellte Fallen-Dienste.", float64(len(status)))
	w.Gauge("node64_honeypot_services_listening", "Fallen-Dienste mit offenem Port.", float64(open))
	for _, s := range status {
		w.Counter("node64_honeypot_connections_total", "Angenommene Verbindungen je Fallen-Dienst seit dem Start.", float64(s.Conns),
			"service", s.Service, "port", strconv.Itoa(s.Port))
	}
	for _, s := range status {
		w.Gauge("node64_honeypot_listen_errors", "Port des Fallen-Dienstes laesst sich nicht oeffnen (belegt, keine Rechte).",
			metrics.Bool(!s.Listen), "port", strconv.Itoa(s.Port))
	}

	metricCounts.mu.Lock()
	logins := sortedCounts(metricCounts.logins)
	kinds := sortedCounts(metricCounts.kinds)
	metricCounts.mu.Unlock()
	for _, x := range logins {
		w.Counter("node64_honeypot_logins_total", "Login-Versuche je Dienst seit dem Start.", float64(x.Count), "service", x.Key)
	}
	for _, x := range kinds {
		kind, source, _ := strings.Cut(x.Key, "\x00")
		w.Counter("node64_honeypot_events_total", "Ereignisse je Art und Quelle seit dem Start.", float64(x.Count), "kind", kind, "source", source)
	}

	var dropped int64
	if c != nil {
		dropped += c.Dropped.Load()
	}
	if st != nil {
		dropped += st.Dropped()
		w.Gauge("node64_honeypot_buffer_events", "Ereignisse, die noch auf das Schreiben warten.", float64(st.Buffered()))
		if n, ok := uniqueSources(ctx, st); ok {
			w.Gauge("node64_honeypot_unique_sources", "Verschiedene Quell-IPs der letzten 24 Stunden.", float64(n))
		}
	}
	if c != nil || st != nil {
		w.Counter("node64_honeypot_dropped_total", "Wegen Ueberlast verworfene Ereignisse bzw. abgewiesene Verbindungen.", float64(dropped))
	}
	if rep != nil {
		last, errs, sources := rep.metricsValues(ctx)
		ts := 0.0
		if !last.IsZero() {
			ts = float64(last.Unix())
		}
		w.Gauge("node64_honeypot_report_last_success_timestamp", "Letzte erfolgreiche Meldung an ipv64 (Unix-Zeit, 0 = noch keine).", ts)
		w.Counter("node64_honeypot_report_errors_total", "Fehlgeschlagene bzw. von ipv64 abgelehnte Meldungen seit dem Start.", float64(errs))
		w.Counter("node64_honeypot_report_sources_total", "An ipv64 gemeldete Quell-IPs seit dem Start (je Meldung gezaehlt).", float64(sources))
	}
}

// WriteLogMetrics schreibt die Kennzahlen von Log-Sensor und Syslog-Empfaenger (Modul und Modus ohne Oberflaeche
// gleich): node64_honeypot_log_lines_total (gelesene Zeilen aus Dateien), node64_honeypot_log_file_ok{path},
// node64_honeypot_syslog_messages_total, node64_honeypot_syslog_denied_total (nur mit eingestelltem Syslog).
// st nil = nichts.
func WriteLogMetrics(w *metrics.Writer, st *LogStatus) {
	if st == nil {
		return
	}
	var lines int64
	for _, f := range st.Files {
		lines += f.Lines
	}
	w.Counter("node64_honeypot_log_lines_total", "Gelesene Zeilen aus Log-Dateien seit dem Start.", float64(lines))
	for _, f := range st.Files {
		w.Gauge("node64_honeypot_log_file_ok", "Log-Datei wird gelesen (1) bzw. Fehler wie fehlende Rechte (0).", metrics.Bool(f.OK), "path", f.Path)
	}
	if sl := st.Syslog; sl != nil {
		w.Counter("node64_honeypot_syslog_messages_total", "Angenommene Syslog-Nachrichten seit dem Start.", float64(sl.Messages))
		w.Counter("node64_honeypot_syslog_denied_total", "Verworfene Syslog-Nachrichten nicht erlaubter Absender seit dem Start.", float64(sl.Denied))
	}
}

func uniqueSources(ctx context.Context, st *Store) (int64, bool) {
	uniqueCache.mu.Lock()
	defer uniqueCache.mu.Unlock()
	if uniqueCache.st == st && time.Since(uniqueCache.at) < uniqueCacheFor {
		return uniqueCache.val, true
	}
	s, err := storeSummary(ctx, st, time.Now().Add(-24*time.Hour))
	if err != nil {
		return 0, false
	}
	uniqueCache.st, uniqueCache.at, uniqueCache.val = st, time.Now(), s.Sources
	return s.Sources, true
}

func sortedCounts(m map[string]int64) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Metrics: Kennzahlen fuer GET /api/metrics (module.MetricsProvider, nur wenn das Modul laeuft).
func (m *Module) Metrics(ctx context.Context, w *metrics.Writer) {
	s := m.running()
	w.Gauge("node64_honeypot_up", "Honeypot64 laeuft.", metrics.Bool(s != nil))
	if s == nil {
		return
	}
	WriteMetrics(w, s, m.st, m.rep, ctx)
	writeBridgeMetrics(w) // Verbindung zu PROXY64 (bridge.go)
	ls := m.LogStatus()
	WriteLogMetrics(w, &ls)
}
