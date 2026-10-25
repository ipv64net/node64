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
