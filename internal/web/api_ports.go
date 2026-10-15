package web

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/ports"
)

// Port-Uebersicht und Einstellungen des gemeinsamen Eingangs (80/443) – Kern, nicht Modul.

func (s *Server) portRoutes() {
	if s.Ports == nil || s.Edge == nil {
		return
	}
	s.mux.Handle("GET /api/ports", s.auth(s.apiPorts))
	s.mux.Handle("GET /api/ports/probe", s.auth(s.apiPortProbe))
	s.mux.Handle("GET /api/edge", s.auth(s.apiEdgeGet))
	s.mux.Handle("PUT /api/edge", s.auth(s.apiEdgePut))
	s.mux.Handle("POST /settings/edge", s.auth(s.settingsEdge))
}

func (s *Server) apiPorts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ports": s.Ports.Overview(r.Context()), "edge": s.Edge.Status()})
}

// apiPortProbe prueft, ob ein Port auf dem Host frei ist (ein Port, den Node64 selbst offen hat, gilt als belegt).
func (s *Server) apiPortProbe(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	proto := ports.Proto(strings.ToLower(q.Get("proto")))
	port, err := strconv.Atoi(q.Get("port"))
	if (proto != ports.TCP && proto != ports.UDP) || err != nil || port < 1 || port > 65535 {
		writeErr(w, http.StatusUnprocessableEntity, "proto (tcp|udp) and port (1-65535) required")
		return
	}
	want := ports.Claim{Proto: proto, Port: port, Bind: q.Get("bind")}
	for _, c := range s.Ports.All(r.Context()) {
		if c.Active && ports.Overlap(want, c) {
			writeJSON(w, http.StatusOK, map[string]any{"free": false, "used_by": c.Owner, "purpose": c.Purpose})
			return
		}
	}
	if err := ports.Probe(proto, want.Bind, port); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"free": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"free": true})
}

func (s *Server) apiEdgeGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Edge.Status())
}

// apiEdgePut uebernimmt die Einstellungen des Eingangs (fehlende Felder bleiben, wie sie sind).
func (s *Server) apiEdgePut(w http.ResponseWriter, r *http.Request) {
	cfg := s.Edge.Config()
	if !decodeJSON(w, r, &cfg) {
		return
	}
	if err := s.saveEdge(r, cfg); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.Edge.Status())
}

func (s *Server) saveEdge(r *http.Request, cfg edge.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	ctx := context.WithoutCancel(r.Context())
	for k, v := range cfg.Settings() {
		if err := s.Store.SetSetting(ctx, k, v); err != nil {
			return err
		}
	}
	if err := s.Edge.Configure(cfg); err != nil {
		return err
	}
	s.audit(r, "edge.settings", "", fmt.Sprintf("http=%d https=%d public=%d http3=%v default=%s bind=%q", cfg.HTTPPort, cfg.HTTPSPort,
		cfg.PublicPort, cfg.HTTP3, cfg.Default, cfg.Bind))
	return nil
}

// settingsEdge: Formular in den Einstellungen (Karte Ports).
func (s *Server) settingsEdge(w http.ResponseWriter, r *http.Request) {
	cfg := s.Edge.Config()
	num := func(name string) (int, bool) {
		v := strings.TrimSpace(r.PostFormValue(name))
		if v == "" {
			return 0, true
		}
		n, err := strconv.Atoi(v)
		return n, err == nil && n >= 0 && n <= 65535
	}
	var ok1, ok2, ok3 bool
	cfg.HTTPPort, ok1 = num("http_port")
	cfg.HTTPSPort, ok2 = num("https_port")
	cfg.PublicPort, ok3 = num("public_port")
	cfg.HTTP3 = r.PostFormValue("http3") == "on"
	cfg.Default = r.PostFormValue("default")
	v := s.view(r, "settings.title")
	if !ok1 || !ok2 || !ok3 {
		s.flash(w, r, "danger", v.T("ports.err_port"))
	} else if err := s.saveEdge(r, cfg); err != nil {
		s.flash(w, r, "danger", v.T("ports.err_save", "error", err.Error()))
	} else {
		s.flash(w, r, "success", v.T("common.saved"))
	}
	http.Redirect(w, r, "/settings#ports", http.StatusSeeOther)
}

// portsView: Daten der Karte Ports.
type portsView struct {
	Entries []ports.Entry
	Edge    edge.Status
}

func (s *Server) portsData(ctx context.Context) *portsView {
	if s.Ports == nil || s.Edge == nil {
		return nil
	}
	return &portsView{Entries: s.Ports.Overview(ctx), Edge: s.Edge.Status()}
}
