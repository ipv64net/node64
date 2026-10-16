package web

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/certsui"
)

// Zertifikate fuer andere Geraete abholen (API-Key genuegt): meta fuer den Vergleich, bundle als Datei (ETag =
// Fingerabdruck, If-None-Match -> 304), p12 per POST (Passwort nicht in der URL). Abrufe mit Schluessel im Audit.

func (s *Server) certExportRoutes() {
	s.mux.Handle("GET /api/certs/{id}/meta", s.auth(s.apiCertMeta))
	s.mux.Handle("GET /api/certs/{id}/bundle", s.auth(s.apiCertBundle))
	s.mux.Handle("POST /api/certs/{id}/p12", s.auth(s.apiCertP12))
}

func (s *Server) certBundle(w http.ResponseWriter, r *http.Request) (*certs.Bundle, bool) {
	id, ok := certID(r)
	if !ok {
		writeErr(w, http.StatusNotFound, "certificate not found")
		return nil, false
	}
	b, err := s.Certs.Bundle(r.Context(), id)
	if err != nil {
		certErr(w, err)
		return nil, false
	}
	return b, true
}

func (s *Server) apiCertMeta(w http.ResponseWriter, r *http.Request) {
	b, ok := s.certBundle(w, r)
	if !ok {
		return
	}
	w.Header().Set("ETag", `"`+b.Fingerprint+`"`)
	writeJSON(w, http.StatusOK, b.Meta())
}

func (s *Server) apiCertBundle(w http.ResponseWriter, r *http.Request) {
	b, ok := s.certBundle(w, r)
	if !ok {
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = certs.FormatZIP
	}
	sent, err := certsui.ServeFile(w, r, b, format)
	if err != nil {
		certErr(w, err)
		return
	}
	if sent && certs.HasKey(format) { // 304: nichts ausgeliefert
		s.audit(r, "cert.download", strconv.FormatInt(b.ID, 10), "format="+format+" names="+b.Name+" via=api")
	}
}

func (s *Server) apiCertP12(w http.ResponseWriter, r *http.Request) {
	b, ok := s.certBundle(w, r)
	if !ok {
		return
	}
	in := struct {
		Password string `json:"password"`
		Legacy   bool   `json:"legacy"`
	}{}
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := certsui.ServeP12(w, b, in.Password, in.Legacy); err != nil {
		certErr(w, err)
		return
	}
	s.audit(r, "cert.download", strconv.FormatInt(b.ID, 10), fmt.Sprintf("format=p12 legacy=%v names=%s via=api", in.Legacy, b.Name))
}
