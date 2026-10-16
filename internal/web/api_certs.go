package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/certs"
)

// Zertifikatsverwaltung des Kerns (Let's Encrypt, eigene Zertifikate). Die Seite dazu ist /certificates
// (internal/certsui), Downloads und Abruf fuer andere Geraete in api_certs_export.go.

func (s *Server) certRoutes() {
	if s.Certs == nil {
		return
	}
	s.mux.Handle("GET /api/certs", s.auth(s.apiCerts))
	s.mux.Handle("POST /api/certs", s.auth(s.apiCertCreate))
	s.mux.Handle("POST /api/certs/upload", s.auth(s.apiCertUpload))
	s.mux.Handle("GET /api/certs/account", s.auth(s.apiCertAccountGet))
	s.mux.Handle("PUT /api/certs/account", s.auth(s.apiCertAccountPut))
	s.mux.Handle("GET /api/certs/domains", s.auth(s.apiCertDomains))
	s.mux.Handle("GET /api/certs/dns-providers", s.auth(s.apiDNSProviders))
	s.mux.Handle("GET /api/certs/dns-accounts", s.auth(s.apiDNSAccounts))
	s.mux.Handle("POST /api/certs/dns-accounts", s.auth(s.apiDNSAccountSave))
	s.mux.Handle("PUT /api/certs/dns-accounts/{id}", s.auth(s.apiDNSAccountSave))
	s.mux.Handle("DELETE /api/certs/dns-accounts/{id}", s.auth(s.apiDNSAccountDelete))
	s.mux.Handle("GET /api/certs/{id}", s.auth(s.apiCertGet))
	s.mux.Handle("PUT /api/certs/{id}", s.auth(s.apiCertUpdate))
	s.mux.Handle("DELETE /api/certs/{id}", s.auth(s.apiCertDelete))
	s.mux.Handle("POST /api/certs/{id}/renew", s.auth(s.apiCertRenew))
	s.mux.Handle("GET /api/certs/{id}/chain", s.auth(s.apiCertChain))
	s.certExportRoutes()
	s.certCARoutes()
}

// certErr bildet Fehler der Verwaltung auf Statuscodes ab.
func certErr(w http.ResponseWriter, err error) {
	var ve *certs.ValidationError
	switch {
	case errors.As(err, &ve):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": ve.Msg, "field": ve.Field})
	case errors.Is(err, certs.ErrNotFound):
		writeErr(w, http.StatusNotFound, err.Error())
	case errors.Is(err, certs.ErrKeyPassword):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error(), "field": "password"})
	case errors.Is(err, certs.ErrInUse), errors.Is(err, certs.ErrBusy), errors.Is(err, certs.ErrTOS), errors.Is(err, certs.ErrNoKey), errors.Is(err, certs.ErrUpload),
		errors.Is(err, certs.ErrNoCert):
		writeErr(w, http.StatusConflict, err.Error())
	default:
		writeErr(w, http.StatusInternalServerError, err.Error())
	}
}

func certID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

func (s *Server) apiCerts(w http.ResponseWriter, r *http.Request) {
	list, err := s.Certs.List(r.Context())
	if err != nil {
		certErr(w, err)
		return
	}
	if list == nil {
		list = []*certs.Cert{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) apiCertGet(w http.ResponseWriter, r *http.Request) {
	id, ok := certID(r)
	if !ok {
		writeErr(w, http.StatusNotFound, "certificate not found")
		return
	}
	c, err := s.Certs.Get(r.Context(), id)
	if err != nil {
		certErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) apiCertCreate(w http.ResponseWriter, r *http.Request) {
	var req certs.Request
	if !decodeJSON(w, r, &req) {
		return
	}
	c, err := s.Certs.Create(r.Context(), req)
	if err != nil {
		certErr(w, err)
		return
	}
	s.audit(r, "cert.create", strconv.FormatInt(c.ID, 10), fmt.Sprintf("names=%s source=%s staging=%v", strings.Join(c.Names, ","), c.Source, c.Staging))
	writeJSON(w, http.StatusAccepted, c) // der Abruf laeuft im Hintergrund
}

// apiCertUpload nimmt JSON {cert, key, password, p12} oder multipart (cert_file, key_file, key_password) an. Der
// Schluessel darf verschluesselt sein (PKCS#8, PEM mit DEK-Info), cert_file bzw. p12 (Base64) auch PKCS#12.
func (s *Server) apiCertUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var in struct {
		Cert     string `json:"cert"`
		Key      string `json:"key"`
		Password string `json:"password"`
		P12      []byte `json:"p12"` // Base64
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid form")
			return
		}
		read := func(name string) string {
			f, _, err := r.FormFile(name)
			if err != nil {
				return r.FormValue(strings.TrimSuffix(name, "_file"))
			}
			defer f.Close()
			b, _ := io.ReadAll(f)
			return string(b)
		}
		in.Cert, in.Key, in.Password = read("cert_file"), read("key_file"), r.FormValue("key_password")
	} else if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if len(in.P12) > 0 {
		in.Cert, in.Key = string(in.P12), ""
	}
	certPEM, keyPEM, err := certs.PrepareUpload([]byte(in.Cert), []byte(in.Key), in.Password)
	var c *certs.Cert
	if err == nil {
		c, err = s.Certs.Upload(r.Context(), certPEM, keyPEM)
	}
	if err != nil {
		certErr(w, err)
		return
	}
	s.audit(r, "cert.upload", strconv.FormatInt(c.ID, 10), "names="+strings.Join(c.Names, ","))
	writeJSON(w, http.StatusCreated, c)
}

func (s *Server) apiCertUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := certID(r)
	if !ok {
		writeErr(w, http.StatusNotFound, "certificate not found")
		return
	}
	var in struct {
		AutoRenew *bool `json:"auto_renew"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.AutoRenew == nil {
		writeErr(w, http.StatusUnprocessableEntity, "auto_renew required")
		return
	}
	if err := s.Certs.SetAutoRenew(r.Context(), id, *in.AutoRenew); err != nil {
		certErr(w, err)
		return
	}
	s.audit(r, "cert.update", strconv.FormatInt(id, 10), fmt.Sprintf("auto_renew=%v", *in.AutoRenew))
	s.apiCertGet(w, r)
}

func (s *Server) apiCertDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := certID(r)
	if !ok {
		writeErr(w, http.StatusNotFound, "certificate not found")
		return
	}
	c, err := s.Certs.Get(r.Context(), id)
	if err != nil {
		certErr(w, err)
		return
	}
	force := r.URL.Query().Get("force") == "1"
	if err := s.Certs.Delete(r.Context(), id, force); err != nil {
		certErr(w, err)
		return
	}
	s.audit(r, "cert.delete", strconv.FormatInt(id, 10), fmt.Sprintf("names=%s force=%v", strings.Join(c.Names, ","), force))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiCertRenew(w http.ResponseWriter, r *http.Request) {
	id, ok := certID(r)
	if !ok {
		writeErr(w, http.StatusNotFound, "certificate not found")
		return
	}
	if err := s.Certs.Renew(r.Context(), id); err != nil {
		certErr(w, err)
		return
	}
	s.audit(r, "cert.renew", strconv.FormatInt(id, 10), "")
	c, err := s.Certs.Get(r.Context(), id)
	if err != nil {
		certErr(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, c)
}

func (s *Server) apiCertChain(w http.ResponseWriter, r *http.Request) {
	id, ok := certID(r)
	if !ok {
		writeErr(w, http.StatusNotFound, "certificate not found")
		return
	}
	chain, err := s.Certs.Chain(r.Context(), id)
	if err != nil {
		certErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="cert-%d.pem"`, id))
	_, _ = io.WriteString(w, chain)
}

func (s *Server) apiCertAccountGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Certs.Account(r.Context()))
}

func (s *Server) apiCertAccountPut(w http.ResponseWriter, r *http.Request) {
	acc := s.Certs.Account(r.Context())
	in := struct {
		Email     *string `json:"email"`
		AcceptTOS bool    `json:"accept_tos"`
	}{}
	if !decodeJSON(w, r, &in) {
		return
	}
	email := acc.Email
	if in.Email != nil {
		email = *in.Email
	}
	if err := s.Certs.SetAccount(r.Context(), email, in.AcceptTOS); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	s.audit(r, "cert.account", "", fmt.Sprintf("email_set=%v accept_tos=%v", email != "", in.AcceptTOS))
	writeJSON(w, http.StatusOK, s.Certs.Account(r.Context()))
}

func (s *Server) apiCertDomains(w http.ResponseWriter, r *http.Request) {
	list, err := s.Certs.Domains(r.Context())
	if err != nil {
		certErr(w, err)
		return
	}
	if list == nil {
		list = []string{}
	}
	writeJSON(w, http.StatusOK, list)
}

// ---------------------------------------------------------------- DNS-Zugaenge (andere DNS-Anbieter, lego)

func (s *Server) apiDNSProviders(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, certs.Providers())
}

func (s *Server) apiDNSAccounts(w http.ResponseWriter, r *http.Request) {
	list, err := s.Certs.DNSAccounts(r.Context())
	if err != nil {
		certErr(w, err)
		return
	}
	if list == nil {
		list = []*certs.DNSAccount{}
	}
	writeJSON(w, http.StatusOK, list)
}

// apiDNSAccountSave legt an (POST) oder aendert (PUT). values: Felder des Anbieters; leere geheime Felder bleiben.
func (s *Server) apiDNSAccountSave(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name     string            `json:"name"`
		Provider string            `json:"provider"`
		Values   map[string]string `json:"values"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	a := &certs.DNSAccount{Name: in.Name, Provider: in.Provider}
	status, action := http.StatusCreated, "cert.dns.create"
	if r.Method == http.MethodPut {
		id, ok := certID(r)
		if !ok {
			writeErr(w, http.StatusNotFound, "dns account not found")
			return
		}
		old, err := s.Certs.DNSAccount(r.Context(), id)
		if err != nil {
			certErr(w, err)
			return
		}
		a.ID, status, action = id, http.StatusOK, "cert.dns.update"
		if a.Name == "" {
			a.Name = old.Name
		}
	}
	if err := s.Certs.SaveDNSAccount(r.Context(), a, in.Values); err != nil {
		certErr(w, err)
		return
	}
	s.audit(r, action, strconv.FormatInt(a.ID, 10), "name="+a.Name+" provider="+a.Provider)
	out, err := s.Certs.DNSAccount(r.Context(), a.ID)
	if err != nil {
		certErr(w, err)
		return
	}
	writeJSON(w, status, out)
}

func (s *Server) apiDNSAccountDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := certID(r)
	if !ok {
		writeErr(w, http.StatusNotFound, "dns account not found")
		return
	}
	a, err := s.Certs.DNSAccount(r.Context(), id)
	if err != nil {
		certErr(w, err)
		return
	}
	if err := s.Certs.DeleteDNSAccount(r.Context(), id); err != nil {
		certErr(w, err)
		return
	}
	s.audit(r, "cert.dns.delete", strconv.FormatInt(id, 10), "name="+a.Name)
	w.WriteHeader(http.StatusNoContent)
}
