// Package httpapi ist der HTTP-Server des hub hinter nginx (127.0.0.1:9000).
// Phase 2: /v1/health und /metrics; die Agent-Endpunkte kommen in Phase 3.
package httpapi

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/ipv64net/node64/internal/hub/store"
)

// Status liefert Laufzeitdaten fuer /v1/health.
type Status func() map[string]any

// Server ist der HTTP-Server.
type Server struct {
	srv     *http.Server
	log     *slog.Logger
	metrics *store.Metrics
	status  Status
	started time.Time
}

// New baut den Server.
func New(listen string, log *slog.Logger, metrics *store.Metrics, status Status) *Server {
	s := &Server{log: log.With("module", "http"), metrics: metrics, status: status, started: time.Now().UTC()}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.health)
	mux.HandleFunc("GET /metrics", s.prometheus)
	s.srv = &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}
	return s
}

// Mux gibt den Multiplexer frei, damit weitere Rollen Routen anhaengen.
func (s *Server) Mux() *http.ServeMux { return s.srv.Handler.(*http.ServeMux) }

// ListenAndServe startet den Server (blockierend).
func (s *Server) ListenAndServe() error { return s.srv.ListenAndServe() }

// Shutdown beendet ihn sauber.
func (s *Server) Shutdown(timeout time.Duration) {
	ctx, cancel := contextWithTimeout(timeout)
	defer cancel()
	_ = s.srv.Shutdown(ctx)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	out := map[string]any{"status": "ok", "time": time.Now().UTC().Format(time.RFC3339), "uptime_seconds": int(time.Since(s.started).Seconds())}
	if s.status != nil {
		for k, v := range s.status() {
			out[k] = v
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Server) prometheus(w http.ResponseWriter, _ *http.Request) {
	m := s.metrics.Snapshot()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# TYPE hub_checks gauge\nhub_checks %d\n", m.Checks)
	fmt.Fprintf(w, "# TYPE hub_nodes gauge\nhub_nodes %d\n", m.Nodes)
	fmt.Fprintf(w, "# TYPE hub_slot_index gauge\nhub_slot_index %d\n# TYPE hub_slot_mod gauge\nhub_slot_mod %d\n", m.SlotIndex, m.Slots)
	fmt.Fprintf(w, "# TYPE hub_measurements_total counter\nhub_measurements_total %d\n", m.Measurements)
	fmt.Fprintf(w, "# TYPE hub_measurement_errors_total counter\nhub_measurement_errors_total %d\n", m.MeasurementErrors)
	fmt.Fprintf(w, "# TYPE hub_db_errors_total counter\nhub_db_errors_total %d\n", m.DBErrors)
	fmt.Fprintf(w, "# TYPE hub_verdicts_total counter\nhub_verdicts_total %d\n", m.Verdicts)
	fmt.Fprintf(w, "# TYPE hub_overall_changes_total counter\nhub_overall_changes_total %d\n", m.OverallChanges)
	fmt.Fprintf(w, "# TYPE hub_uptime_seconds gauge\nhub_uptime_seconds %d\n", int(time.Since(s.started).Seconds()))
	s.runtimeMetrics(w)
}
