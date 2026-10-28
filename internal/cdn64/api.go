package cdn64

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/module"
)

func (m *Module) apiRoutes(mux *http.ServeMux, g module.Guards) {
	api := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /api/cdn64/status", api(m.apiStatus))
	mux.Handle("POST /api/cdn64/check", api(m.apiCheck))
	mux.Handle("GET /api/cdn64/hosts", api(m.apiHosts))
	mux.Handle("POST /api/cdn64/hosts", api(m.apiCreate))
	mux.Handle("GET /api/cdn64/hosts/{id}", api(m.apiGet))
	mux.Handle("PUT /api/cdn64/hosts/{id}", api(m.apiUpdate))
	mux.Handle("DELETE /api/cdn64/hosts/{id}", api(m.apiDelete))
	mux.Handle("POST /api/cdn64/hosts/{id}/enable", api(m.apiToggle))
	mux.Handle("POST /api/cdn64/hosts/{id}/disable", api(m.apiToggle))
	mux.Handle("GET /api/cdn64/docker", api(m.apiDocker))
	m.streamAPIRoutes(mux, api)
	m.c4APIRoutes(mux, api)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// apiHost ist ein Host mit Zustand fuer die API.
type apiHost struct {
	*Host
	Reach Reach `json:"reach"`
	Stats struct {
		Requests int64 `json:"requests"`
		Errors   int64 `json:"errors"`
		Blocked  int64 `json:"blocked"`
	} `json:"stats"` // seit dem Start des Moduls
	Cert struct {
		State    string `json:"state"` // http, ok, soon, expired, missing
		Name     string `json:"name,omitempty"`
		DaysLeft int    `json:"days_left,omitempty"`
		Missing  string `json:"missing,omitempty"` // Name ohne passendes Zertifikat
	} `json:"certificate"`
	RouteError   string  `json:"route_error,omitempty"`
	Healthchecks []Watch `json:"healthchecks,omitempty"` // Checks auf genau dieses Ziel
}

func toAPI(r hostRow) apiHost {
	a := apiHost{Host: r.Host, Reach: r.Reach, RouteError: r.RouteErr, Healthchecks: r.Watch}
	a.Stats.Requests, a.Stats.Errors, a.Stats.Blocked = r.Requests, r.Errors, r.Blocked
	a.Cert.State, a.Cert.Name, a.Cert.Missing = r.Cert.State, r.Cert.Name, r.Cert.Miss
	if r.Cert.State != "http" && r.Cert.State != "missing" {
		a.Cert.DaysLeft = r.Cert.Days
	}
	return a
}

func (m *Module) apiHosts(w http.ResponseWriter, r *http.Request) {
	rows, err := m.rows(r.Context())
	if k := r.URL.Query().Get("kind"); k != "" && err == nil {
		rows, err = m.rowsOf(r.Context(), k)
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]apiHost, 0, len(rows))
	for _, x := range rows {
		out = append(out, toAPI(x))
	}
	writeJSON(w, http.StatusOK, out)
}

func (m *Module) apiRow(w http.ResponseWriter, r *http.Request, id int64, status int) {
	rows, err := m.rows(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, x := range rows {
		if x.ID == id {
			writeJSON(w, status, toAPI(x))
			return
		}
	}
	writeErr(w, http.StatusNotFound, "host not found")
}

// apiRowExtra: wie apiRow, dazu Ergebnisse von Zertifikat und DNS-Eintrag (Host ist trotzdem gespeichert).
func (m *Module) apiRowExtra(w http.ResponseWriter, r *http.Request, id int64, status int, extra map[string]any) {
	if len(extra) == 0 {
		m.apiRow(w, r, id, status)
		return
	}
	rows, err := m.rows(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, x := range rows {
		if x.ID == id {
			b, _ := json.Marshal(toAPI(x))
			var merged map[string]any
			_ = json.Unmarshal(b, &merged)
			for k, v := range extra {
				merged[k] = v
			}
			writeJSON(w, status, merged)
			return
		}
	}
	writeErr(w, http.StatusNotFound, "host not found")
}

func pathID(r *http.Request) int64 {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id
}

func (m *Module) apiGet(w http.ResponseWriter, r *http.Request) {
	m.apiRow(w, r, pathID(r), http.StatusOK)
}

// certRequest: Zertifikat beim Speichern gleich mit anfordern (optional).
type certRequest struct {
	Source      string `json:"source"` // auto (Standard), ipv64, alias, http
	AliasZone   string `json:"alias_zone"`
	AliasPrefix string `json:"alias_prefix"`
	DNSAccount  int64  `json:"dns_account"`
	Staging     bool   `json:"staging"`
}

// extras: was beim Speichern zusaetzlich passieren soll.
type extras struct {
	cert *certRequest
	dns  *DNSRequest
}

// decode liest JSON in h (fehlende Felder behalten ihren Wert), dazu request_certificate und create_dns_record.
func decode(w http.ResponseWriter, r *http.Request, h *Host) (extras, bool) {
	in := struct {
		*Host
		RequestCertificate *certRequest `json:"request_certificate"`
		CreateDNSRecord    *DNSRequest  `json:"create_dns_record"`
	}{Host: h}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return extras{}, false
	}
	return extras{cert: in.RequestCertificate, dns: in.CreateDNSRecord}, true
}

// afterSaveAll: Zertifikat und DNS-Eintrag (Fehler stehen in der Antwort, der Host ist gespeichert).
func (m *Module) afterSaveAll(r *http.Request, h *Host, x extras) map[string]any {
	out := map[string]any{}
	if e := m.afterSave(r, h, x.cert); e != "" {
		out["certificate_error"] = e
	}
	if x.dns != nil {
		res, err := m.createRecords(r.Context(), h.Names, *x.dns)
		if err != nil {
			out["dns_error"] = err.Error()
		} else {
			_, text := dnsSummary(res)
			m.g.Audit(r, "certs.dns.create", strings.Join(h.Names, ","), text)
			out["dns_records"] = res
		}
	}
	return out
}

// afterSave fordert ein Zertifikat an, wenn gewuenscht; Fehler stehen in der Antwort (der Host ist gespeichert).
func (m *Module) afterSave(r *http.Request, h *Host, req *certRequest) string {
	if req == nil || m.certs == nil {
		return ""
	}
	c, err := m.requestCert(r.Context(), h.Names, req.Source, req.AliasZone, req.AliasPrefix, req.DNSAccount, req.Staging)
	if err != nil {
		return certErrText(err)
	}
	m.auditCert(r, c)
	return ""
}

func certErrText(err error) string {
	var ve *certs.ValidationError
	if errors.As(err, &ve) {
		return ve.Field + ": " + ve.Msg
	}
	return err.Error()
}

func (m *Module) apiFail(w http.ResponseWriter, err error) {
	var fe *FieldError
	switch {
	case errors.As(err, &fe):
		msg := fe.Key
		if m.g.Translate != nil {
			msg = m.g.Translate("en", fe.Key, "name", fe.Name)
		}
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": msg, "field": fe.Field})
	case errors.Is(err, errNotFound):
		writeErr(w, http.StatusNotFound, "host not found")
	default:
		writeErr(w, http.StatusInternalServerError, err.Error())
	}
}

func (m *Module) apiCreate(w http.ResponseWriter, r *http.Request) {
	var probe struct {
		Kind string `json:"kind"`
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "request too large")
		return
	}
	_ = json.Unmarshal(body, &probe)
	kind := probe.Kind
	if kind == "" {
		kind = KindProxy
	}
	if !validKind(kind) {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "kind must be proxy, redirect, dead, passthrough or status", "field": "kind"})
		return
	}
	h := newHostKind(kind)
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	req, ok := decode(w, r, h)
	if !ok {
		return
	}
	h.ID = 0
	h.DockerContainer, h.DockerRouter = "", "" // Docker-Hosts legt nur der Abgleich an
	if err := m.saveHost(r.Context(), h); err != nil {
		m.apiFail(w, err)
		return
	}
	m.g.Audit(r, "cdn64.host.create", strings.Join(h.Names, ","), h.summary())
	m.apiRowExtra(w, r, h.ID, http.StatusCreated, m.afterSaveAll(r, h, req))
}

func (m *Module) apiUpdate(w http.ResponseWriter, r *http.Request) {
	h, err := m.host(r.Context(), pathID(r))
	if err != nil {
		m.apiFail(w, err)
		return
	}
	id, kind := h.ID, h.Kind
	dc, dr := h.DockerContainer, h.DockerRouter
	names, scheme, thost, tport := slices.Clone(h.Names), h.Scheme, h.TargetHost, h.TargetPort
	req, ok := decode(w, r, h)
	if !ok {
		return
	}
	h.ID, h.Kind = id, kind // die Art bleibt
	h.DockerContainer, h.DockerRouter = dc, dr
	if dc != "" { // Docker-Host: Namen, Schema und Ziel kommen aus den Labels
		h.Names, h.Scheme, h.TargetHost, h.TargetPort = names, scheme, thost, tport
	}
	if err := m.saveHost(r.Context(), h); err != nil {
		m.apiFail(w, err)
		return
	}
	m.g.Audit(r, "cdn64.host.update", strings.Join(h.Names, ","), h.summary())
	m.apiRowExtra(w, r, h.ID, http.StatusOK, m.afterSaveAll(r, h, req))
}

func (m *Module) apiDelete(w http.ResponseWriter, r *http.Request) {
	h, err := m.host(r.Context(), pathID(r))
	if err != nil {
		m.apiFail(w, err)
		return
	}
	if h.DockerContainer != "" && m.dockerOn(r.Context()) { // Label bzw. Container entfernen (Schalter aus: loeschbar)
		msg := "cdn64.docker.err.delete"
		if m.g.Translate != nil {
			msg = m.g.Translate("en", msg, "name", m.dockerHostLabel(h))
		}
		writeErr(w, http.StatusConflict, msg)
		return
	}
	if err := m.deleteHost(r.Context(), h.ID); err != nil {
		m.apiFail(w, err)
		return
	}
	m.g.Audit(r, "cdn64.host.delete", strings.Join(h.Names, ","), "target="+h.Target())
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) apiToggle(w http.ResponseWriter, r *http.Request) {
	h, err := m.host(r.Context(), pathID(r))
	if err != nil {
		m.apiFail(w, err)
		return
	}
	on := strings.HasSuffix(r.URL.Path, "/enable")
	if err := m.setEnabled(r.Context(), h.ID, on); err != nil {
		m.apiFail(w, err)
		return
	}
	action := "cdn64.host.disable"
	if on {
		action = "cdn64.host.enable"
	}
	m.g.Audit(r, action, strings.Join(h.Names, ","), "")
	m.apiRow(w, r, h.ID, http.StatusOK)
}

// apiDocker: Stand des Abgleichs mit den Docker-Labels.
func (m *Module) apiDocker(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, m.dockerView(r.Context()))
}

func (m *Module) apiCheck(w http.ResponseWriter, r *http.Request) {
	m.checkSoon(0)
	m.g.Audit(r, "cdn64.check", "", "")
	writeJSON(w, http.StatusAccepted, map[string]bool{"checking": true})
}

func (m *Module) apiStatus(w http.ResponseWriter, r *http.Request) {
	n, b, hits, miss := m.cache.stats()
	out := map[string]any{"version": Version, "cache": map[string]any{"entries": n, "bytes": b, "hits": hits, "misses": miss}}
	m.mu.Lock()
	out["started_at"] = m.startedAt.UTC().Format(time.RFC3339)
	m.mu.Unlock()
	if m.edge != nil {
		var ls []edge.ListenerStatus
		for _, l := range m.edge.Status().Listeners {
			ls = append(ls, l)
		}
		out["listeners"] = ls
	}
	list, err := m.hosts(r.Context())
	if err == nil {
		on, down := 0, 0
		for _, h := range list {
			if h.Enabled {
				on++
				if m.reach.get(h.ID).State == ReachDown {
					down++
				}
			}
		}
		out["hosts"], out["enabled"], out["targets_down"] = len(list), on, down
	}
	writeJSON(w, http.StatusOK, out)
}
