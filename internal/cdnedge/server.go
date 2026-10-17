package cdnedge

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"time"
)

// Server ist der laufende Dienst. T0: nur /health auf Port 80; Tunnel und Besucher-Eingang folgen ab T1.
type Server struct {
	cfg     *Config
	log     *slog.Logger
	version string
	started time.Time
	http    *http.Server
}

// New legt den Dienst an.
func New(cfg *Config, log *slog.Logger, version string) *Server {
	s := &Server{cfg: cfg, log: log, version: version, started: time.Now()}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("/", notFound)
	s.http = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	return s
}

// Run oeffnet die Ports und laeuft bis ctx endet; danach sauber beenden (laufende Anfragen bis 20 s).
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ListenHTTP)
	if err != nil {
		return err
	}
	s.log.Info("cdn64-edge listening", "http", ln.Addr().String(), "name", s.cfg.Name, "version", s.version)
	errc := make(chan error, 1)
	go func() { errc <- s.http.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err = s.http.Shutdown(sctx)
	if errors.Is(err, context.DeadlineExceeded) {
		err = nil
	}
	s.log.Info("cdn64-edge stopped")
	return err
}

// Health ist die Antwort von /health. Von aussen nur Status, Name und Version; Einzelheiten nur lokal.
type Health struct {
	Status   string `json:"status"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Location string `json:"location,omitempty"`
	Started  string `json:"started,omitempty"`
	UptimeS  int64  `json:"uptime_s,omitempty"`
	Go       string `json:"go,omitempty"`
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	h := Health{Status: "ok", Name: s.cfg.Name, Version: s.version}
	if local(r) {
		h.Location, h.Started, h.UptimeS, h.Go = s.cfg.Location, s.started.UTC().Format(time.RFC3339), int64(time.Since(s.started).Seconds()), runtime.Version()
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(h)
}

func local(r *http.Request) bool {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	return err == nil && ap.Addr().Unmap().IsLoopback()
}

// notFound: neutrale Antwort ohne Hinweis auf den Dienst.
func notFound(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("404 not found\n"))
}
