package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/certs"
)

// Eigene CAs (/api/cas) und weitere ACME-Stellen (/api/acme-cas). Eigene Pfade, damit sie sich nicht mit
// /api/certs/{id}/... ueberschneiden.

func (s *Server) certCARoutes() {
	s.mux.Handle("GET /api/cas", s.auth(s.apiCAs))
	s.mux.Handle("POST /api/cas", s.auth(s.apiCACreate))
	s.mux.Handle("POST /api/cas/import", s.auth(s.apiCAImport))
	s.mux.Handle("GET /api/cas/{id}", s.auth(s.apiCAGet))
	s.mux.Handle("PUT /api/cas/{id}", s.auth(s.apiCARename))
	s.mux.Handle("DELETE /api/cas/{id}", s.auth(s.apiCADelete))
	s.mux.Handle("GET /api/cas/{id}/file", s.auth(s.apiCAFile))
	s.mux.Handle("GET /api/acme-cas", s.auth(s.apiACMECAs))
	s.mux.Handle("GET /api/acme-cas/presets", s.auth(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, certs.ACMEPresets) }))
	s.mux.Handle("POST /api/acme-cas", s.auth(s.apiACMECACreate))
	s.mux.Handle("DELETE /api/acme-cas/{id}", s.auth(s.apiACMECADelete))
}

func (s *Server) apiCAs(w http.ResponseWriter, r *http.Request) {
	list, err := s.Certs.CAs(r.Context())
	if err != nil {
		certErr(w, err)
		return
	}
	if list == nil {
		list = []*certs.CA{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) apiCACreate(w http.ResponseWriter, r *http.Request) {
	var in certs.CAInput
	if !decodeJSON(w, r, &in) {
		return
	}
	ca, err := s.Certs.CreateCA(r.Context(), in)
	if err != nil {
		certErr(w, err)
		return
	}
	s.audit(r, "cert.ca.create", strconv.FormatInt(ca.ID, 10), fmt.Sprintf("name=%s constrained=%v", ca.Name, len(ca.PermittedDNS) > 0))
	writeJSON(w, http.StatusCreated, ca)
}

func (s *Server) apiCAImport(w http.ResponseWriter, r *http.Request) {
	in := struct{ Name, Cert, Key string }{}
	if !decodeJSON(w, r, &in) {
		return
	}
	ca, err := s.Certs.ImportCA(r.Context(), in.Name, in.Cert, in.Key)
	if err != nil {
		certErr(w, err)
		return
	}
	s.audit(r, "cert.ca.import", strconv.FormatInt(ca.ID, 10), "name="+ca.Name)
	writeJSON(w, http.StatusCreated, ca)
}

func (s *Server) apiCAGet(w http.ResponseWriter, r *http.Request) {
	id, _ := certID(r)
	ca, err := s.Certs.GetCA(r.Context(), id)
	if err != nil {
		certErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ca)
}

func (s *Server) apiCARename(w http.ResponseWriter, r *http.Request) {
	id, _ := certID(r)
	in := struct{ Name string }{}
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := s.Certs.RenameCA(r.Context(), id, in.Name); err != nil {
		certErr(w, err)
		return
	}
	s.audit(r, "cert.ca.update", strconv.FormatInt(id, 10), "name="+strings.TrimSpace(in.Name))
	s.apiCAGet(w, r)
}

func (s *Server) apiCADelete(w http.ResponseWriter, r *http.Request) {
	id, _ := certID(r)
	ca, err := s.Certs.GetCA(r.Context(), id)
	if err != nil {
		certErr(w, err)
		return
	}
	if err := s.Certs.DeleteCA(r.Context(), id); errors.Is(err, certs.ErrInUse) {
		writeErr(w, http.StatusConflict, "CA still has issued certificates")
		return
	} else if err != nil {
		certErr(w, err)
		return
	}
	s.audit(r, "cert.ca.delete", strconv.FormatInt(id, 10), "name="+ca.Name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiCAFile(w http.ResponseWriter, r *http.Request) {
	id, _ := certID(r)
	data, name, ctype, err := s.Certs.CAFile(r.Context(), id, r.URL.Query().Get("format"))
	if err != nil {
		certErr(w, err)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	_, _ = w.Write(data)
}

func (s *Server) apiACMECAs(w http.ResponseWriter, r *http.Request) {
	list, err := s.Certs.ACMECAs(r.Context())
	if err != nil {
		certErr(w, err)
		return
	}
	if list == nil {
		list = []*certs.ACMECA{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) apiACMECACreate(w http.ResponseWriter, r *http.Request) {
	var in certs.ACMECAInput
	if !decodeJSON(w, r, &in) {
		return
	}
	a, err := s.Certs.AddACMECA(r.Context(), in)
	if err != nil {
		certErr(w, err)
		return
	}
	s.audit(r, "cert.acme_ca.create", strconv.FormatInt(a.ID, 10), fmt.Sprintf("name=%s directory=%s eab=%v", a.Name, a.Directory, a.HasEAB))
	writeJSON(w, http.StatusCreated, a)
}

func (s *Server) apiACMECADelete(w http.ResponseWriter, r *http.Request) {
	id, _ := certID(r)
	a, err := s.Certs.ACMECA(r.Context(), id)
	if err != nil {
		certErr(w, err)
		return
	}
	if err := s.Certs.DeleteACMECA(r.Context(), id); errors.Is(err, certs.ErrInUse) {
		writeErr(w, http.StatusConflict, "ACME CA still has certificates")
		return
	} else if err != nil {
		certErr(w, err)
		return
	}
	s.audit(r, "cert.acme_ca.delete", strconv.FormatInt(id, 10), "name="+a.Name)
	w.WriteHeader(http.StatusNoContent)
}
