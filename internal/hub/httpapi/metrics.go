package httpapi

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"sort"
	"time"
)

// Prometheus fuer den Betreiber auf einem eigenen Port (wie die CDN64-Server: 9464), gebunden an die Adresse im
// internen Netz und nur fuer die eingetragenen Absender (z. B. 10.10.0.0/24). /metrics auf listen bleibt (lokal).

// MetricsServer ist der eigene Port fuer /metrics.
type MetricsServer struct {
	srv *http.Server
	ln  net.Listener
}

// ServeMetrics oeffnet addr (z. B. 10.10.0.10:9464) fuer GET /metrics; allow leer = jeder, der die Adresse erreicht.
func (s *Server) ServeMetrics(addr string, allow []netip.Prefix) (*MetricsServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		if !allowed(r.RemoteAddr, allow) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		s.prometheus(w, r)
	})
	m := &MetricsServer{ln: ln, srv: &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}}
	go func() {
		if err := m.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("metrics server", "err", err)
		}
	}()
	return m, nil
}

// Addr ist die tatsaechliche Adresse (Tests: Port 0).
func (m *MetricsServer) Addr() string { return m.ln.Addr().String() }

// Shutdown beendet den Port.
func (m *MetricsServer) Shutdown(timeout time.Duration) {
	ctx, cancel := contextWithTimeout(timeout)
	defer cancel()
	_ = m.srv.Shutdown(ctx)
}

func allowed(remote string, allow []netip.Prefix) bool {
	if len(allow) == 0 {
		return true
	}
	ap, err := netip.ParseAddrPort(remote)
	if err != nil {
		return false
	}
	ip := ap.Addr().Unmap()
	for _, p := range allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// detailMetrics: je Check-Typ (eigene Laeufe dieses hub) und Datenbank; Liste in docs/HUB-PROMETHEUS.md.
func (s *Server) detailMetrics(w io.Writer) {
	d := s.metrics.Detail()
	fmt.Fprint(w, "# TYPE hub_checks_by_type gauge\n")
	for _, t := range sortedKeys(d.Checks) {
		fmt.Fprintf(w, "hub_checks_by_type{type=%q} %d\n", t, d.Checks[t])
	}
	fmt.Fprint(w, "# TYPE hub_check_runs_total counter\n")
	for _, t := range sortedKeys(d.Runs) {
		fmt.Fprintf(w, "hub_check_runs_total{type=%q,result=\"ok\"} %d\nhub_check_runs_total{type=%q,result=\"fail\"} %d\n", t, d.Runs[t].OK, t, d.Runs[t].Fail)
	}
	fmt.Fprint(w, "# TYPE hub_check_duration_seconds summary\n")
	for _, t := range sortedKeys(d.Runs) {
		r := d.Runs[t]
		fmt.Fprintf(w, "hub_check_duration_seconds_sum{type=%q} %g\nhub_check_duration_seconds_count{type=%q} %d\n", t, r.Seconds, t, r.OK+r.Fail)
	}
	fmt.Fprintf(w, "# TYPE hub_ping_packets_sent_total counter\nhub_ping_packets_sent_total %d\n", d.PingSent)
	fmt.Fprintf(w, "# TYPE hub_ping_packets_lost_total counter\nhub_ping_packets_lost_total %d\n", d.PingLost)
	fmt.Fprint(w, "# TYPE hub_db_write_seconds summary\n")
	for _, op := range sortedKeys(d.Writes) {
		fmt.Fprintf(w, "hub_db_write_seconds_sum{op=%q} %g\nhub_db_write_seconds_count{op=%q} %d\n", op, d.Writes[op].Seconds, op, d.Writes[op].Count)
	}
	if d.Pool != nil {
		p := d.Pool
		fmt.Fprintf(w, "# TYPE hub_db_pool_max gauge\nhub_db_pool_max %d\n", p.MaxOpenConnections)
		fmt.Fprintf(w, "# TYPE hub_db_pool_open gauge\nhub_db_pool_open %d\n", p.OpenConnections)
		fmt.Fprintf(w, "# TYPE hub_db_pool_in_use gauge\nhub_db_pool_in_use %d\n", p.InUse)
		fmt.Fprintf(w, "# TYPE hub_db_pool_idle gauge\nhub_db_pool_idle %d\n", p.Idle)
		fmt.Fprintf(w, "# TYPE hub_db_pool_waits_total counter\nhub_db_pool_waits_total %d\n", p.WaitCount)
		fmt.Fprintf(w, "# TYPE hub_db_pool_wait_seconds_total counter\nhub_db_pool_wait_seconds_total %g\n", p.WaitDuration.Seconds())
	}
	if d.BufferCap > 0 {
		fmt.Fprintf(w, "# TYPE hub_measurement_buffer gauge\nhub_measurement_buffer %d\n", d.Buffer)
		fmt.Fprintf(w, "# TYPE hub_measurement_buffer_capacity gauge\nhub_measurement_buffer_capacity %d\n", d.BufferCap)
	}
	var ts int64
	if !d.CleanupAt.IsZero() {
		ts = d.CleanupAt.Unix()
	}
	fmt.Fprintf(w, "# TYPE hub_cleanup_last_success_timestamp_seconds gauge\nhub_cleanup_last_success_timestamp_seconds %d\n", ts)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// runtimeMetrics: Go-Laufzeit und Verbindungen (aus dem Status von /v1/health).
func (s *Server) runtimeMetrics(w io.Writer) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	fmt.Fprintf(w, "# TYPE hub_goroutines gauge\nhub_goroutines %d\n", runtime.NumGoroutine())
	fmt.Fprintf(w, "# TYPE hub_memory_heap_bytes gauge\nhub_memory_heap_bytes %d\n", ms.HeapAlloc)
	fmt.Fprintf(w, "# TYPE hub_memory_sys_bytes gauge\nhub_memory_sys_bytes %d\n", ms.Sys)
	if s.status == nil {
		return
	}
	st := s.status()
	if c, ok := st["connections"].(int); ok {
		fmt.Fprintf(w, "# TYPE hub_gateway_connections gauge\nhub_gateway_connections %d\n", c)
	}
	if n, ok := st["throttled"].(uint64); ok { // von der Bremse ausgelassene Laeufe (je Zielhost bzw. Server)
		fmt.Fprintf(w, "# TYPE hub_checks_throttled_total counter\nhub_checks_throttled_total %d\n", n)
	}
	up := 1
	if v, _ := st["status"].(string); v != "" && v != "ok" {
		up = 0
	}
	fmt.Fprintf(w, "# TYPE hub_db_ok gauge\nhub_db_ok %d\n", up)
}
