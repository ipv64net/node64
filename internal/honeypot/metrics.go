package honeypot

import (
	"context"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/metrics"
)

// Zaehler je Dienst und Art fuer Prometheus. Es gibt je Prozess hoechstens einen Honeypot (Modul oder Modus ohne
// Oberflaeche), daher zaehlt CountEvents prozessweit; Prometheus-Zaehler laufen ohnehin seit dem Start.
var metricCounts = struct {
	mu     sync.Mutex
	logins map[string]int64 // Dienst -> Login-Versuche
	kinds  map[string]int64 // Art -> Ereignisse
}{logins: map[string]int64{}, kinds: map[string]int64{}}

// CountEvents umhuellt eine Sink und zaehlt jedes Ereignis je Art und jeden Login-Versuch je Dienst (fuer
// node64_honeypot_events_total und node64_honeypot_logins_total). Modul und Modus ohne Oberflaeche geben dem
// Sensor CountEvents(store.Sink()).
func CountEvents(next Sink) Sink {
	return func(e Event) {
		metricCounts.mu.Lock()
		metricCounts.kinds[e.Kind]++
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
// node64_honeypot_listen_errors{port}, node64_honeypot_buffer_events, node64_honeypot_dropped_total.
// sensor und st duerfen nil sein (dann fehlen die zugehoerigen Werte).
func WriteMetrics(w *metrics.Writer, sensor SensorState, st *Store, ctx context.Context) {
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
		w.Counter("node64_honeypot_events_total", "Ereignisse je Art und Quelle seit dem Start.", float64(x.Count), "kind", x.Key, "source", "honeypot")
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
	WriteMetrics(w, s, m.st, ctx)
}
