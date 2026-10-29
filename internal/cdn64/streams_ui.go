package cdn64

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/edge"
)

// Seiten und API fuer Streams, TLS durchreichen (Hosts der Art passthrough) und die Standardseite.

func (m *Module) streamRoutes(mux *http.ServeMux, page func(http.HandlerFunc) http.Handler) {
	mux.Handle("GET /cdn64/streams", page(m.pageStreams))
	mux.Handle("GET /cdn64/streams/new", page(m.pageStreamNew))
	mux.Handle("POST /cdn64/streams", page(m.pageStreamCreate))
	mux.Handle("GET /cdn64/streams/{id}", page(m.pageStreamEdit))
	mux.Handle("POST /cdn64/streams/{id}", page(m.pageStreamUpdate))
	mux.Handle("POST /cdn64/streams/{id}/delete", page(m.pageStreamDelete))
	mux.Handle("POST /cdn64/streams/{id}/enable", page(m.pageStreamToggle))
	mux.Handle("POST /cdn64/streams/{id}/disable", page(m.pageStreamToggle))
}

func (m *Module) streamAPIRoutes(mux *http.ServeMux, api func(http.HandlerFunc) http.Handler) {
	mux.Handle("GET /api/cdn64/streams", api(m.apiStreams))
	mux.Handle("POST /api/cdn64/streams", api(m.apiStreamCreate))
	mux.Handle("GET /api/cdn64/streams/{id}", api(m.apiStreamGet))
	mux.Handle("PUT /api/cdn64/streams/{id}", api(m.apiStreamUpdate))
	mux.Handle("DELETE /api/cdn64/streams/{id}", api(m.apiStreamDelete))
	mux.Handle("POST /api/cdn64/streams/{id}/enable", api(m.apiStreamToggle))
	mux.Handle("POST /api/cdn64/streams/{id}/disable", api(m.apiStreamToggle))
	mux.Handle("GET /api/cdn64/default", api(m.apiDefaultGet))
	mux.Handle("PUT /api/cdn64/default", api(m.apiDefaultPut))
}

type streamRow struct {
	*Stream
	Reach   Reach             `json:"reach"`
	Errors  map[string]string `json:"listen_errors,omitempty"`
	Running bool              `json:"running"`
	Stats   struct {
		Conns   int64 `json:"connections"`
		Active  int64 `json:"active"`
		BytesIn int64 `json:"bytes_in"`
		BytesUp int64 `json:"bytes_out"`
	} `json:"stats"`
	CertName string `json:"cert_name,omitempty"`
	// CDN64: angemeldete Ports der Server (Portmapper Modus 1/2) und Fehler beim Anmelden
	Online    []onlinePortView `json:"cdn64_ports,omitempty"`
	OnlineErr string           `json:"cdn64_error,omitempty"` // Code (cdn64.online.e.<code>)
}

// onlinePortView: oeffentlicher Port eines Streams ueber CDN64.
type onlinePortView struct {
	Name       string `json:"name"`
	ListenPort int    `json:"listen_port"`
	Transport  string `json:"transport"`
}

func (m *Module) streamRows(ctx context.Context) ([]streamRow, error) {
	list, err := m.streams(ctx)
	if err != nil {
		return nil, err
	}
	names := map[int64]string{}
	if m.certs != nil {
		if cl, err := m.certs.List(ctx); err == nil {
			for _, c := range cl {
				names[c.ID] = c.Title()
			}
		}
	}
	ports, perr := m.onlinePortsOf(ctx)
	out := make([]streamRow, 0, len(list))
	for _, s := range list {
		r := streamRow{Stream: s, Reach: m.sreach.get(s.ID), Errors: m.streamErrs(s.ID), CertName: names[s.TLSCertID]}
		for _, p := range ports[s.ID] {
			r.Online = append(r.Online, onlinePortView{Name: p.Name, ListenPort: p.ListenPort, Transport: p.Transport})
		}
		if c := perr[s.ID]; c != "" && s.OnlineName != "" {
			r.OnlineErr = c
		}
		m.smu.Lock()
		if run := m.runs[s.ID]; run != nil {
			r.Running = run.tcp != nil || run.udp != nil
		}
		m.smu.Unlock()
		st := m.streamStatsOf(s.ID)
		r.Stats.Conns, r.Stats.Active, r.Stats.BytesIn, r.Stats.BytesUp = st.conns.Load(), st.active.Load(), st.bytesIn.Load(), st.bytesUp.Load()
		out = append(out, r)
	}
	return out, nil
}

type streamsData struct {
	Tabs    []tab
	Streams []streamRow
	Pass    []hostRow

	// eine Tabelle: Namen nur fuer Streams mit CDN64 und ihren Ports, danach die Streams ohne eigenen Namen
	Names    []streamName
	Local    []streamRow
	OnlineOn bool   // CDN64 verfuegbar (ipv64 angebunden)
	OnlineL  string // Texte fuer cdn64-online.js (JSON)
}

// streamName: Name nur fuer Streams (Host der Art stream) und die Streams, die ihn als CDN64-Namen nutzen.
type streamName struct {
	Row     hostRow
	Streams []streamRow
}

// groupStreams ordnet die Streams ihren Namen nur fuer Streams zu; die uebrigen (nur hier oder Name eines anderen
// Hosts) bleiben fuer sich.
func groupStreams(names []hostRow, list []streamRow) ([]streamName, []streamRow) {
	out := make([]streamName, len(names))
	idx := map[string]int{}
	for i, n := range names {
		out[i].Row = n
		for _, name := range n.Names {
			idx[name] = i
		}
	}
	var local []streamRow
	for _, s := range list {
		if i, ok := idx[strings.ToLower(s.OnlineName)]; ok && s.OnlineName != "" {
			out[i].Streams = append(out[i].Streams, s)
			continue
		}
		local = append(local, s)
	}
	return out, local
}

func (m *Module) pageStreams(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	st, err := m.streamRows(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	pass, err := m.rowsOf(ctx, KindPass)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	names, err := m.rowsOf(ctx, KindStream)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	d := streamsData{Tabs: m.tabs("/cdn64/streams"), Streams: st, Pass: pass, OnlineOn: m.online.api != nil && m.edge != nil}
	d.Names, d.Local = groupStreams(names, st)
	if d.OnlineOn {
		d.OnlineL = m.onlineStrings(r)
	}
	m.g.Render(w, r, http.StatusOK, Name+"/streams", "cdn64.title", d)
}

type streamForm struct {
	Tabs   []tab
	S      *Stream
	New    bool
	Certs  []*certs.Cert
	Errors map[string]string

	GeoText   string       // Laender der Laendersperre (Komma)
	Countries []geoCountry // Auswahl aus index.json

	OnlineOn    bool         // CDN64 verfuegbar (ipv64 angebunden)
	OnlineNames []onlineName // CDN64-Namen der Node (Auswahl fuer den Portmapper)
}

func (m *Module) streamFormData(ctx context.Context, s *Stream, isNew bool) streamForm {
	d := streamForm{Tabs: m.tabs("/cdn64/streams"), S: s, New: isNew, Errors: map[string]string{}, GeoText: strings.Join(s.GeoCountries, ", ")}
	m.bl.mu.Lock()
	d.Countries = m.bl.countries
	m.bl.mu.Unlock()
	if m.certs != nil {
		d.Certs, _ = m.certs.List(ctx)
	}
	d.OnlineOn = m.online.api != nil && m.edge != nil
	d.OnlineNames, _ = m.onlineNames(ctx)
	return d
}

func (m *Module) pageStreamNew(w http.ResponseWriter, r *http.Request) {
	s := newStream()
	s.OnlineName = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("online_name"))) // "Port hinzufuegen" am Namen
	m.g.Render(w, r, http.StatusOK, Name+"/stream_form", "cdn64.streams.new", m.streamFormData(r.Context(), s, true))
}

func (m *Module) streamFromPath(w http.ResponseWriter, r *http.Request) (*Stream, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		if s, err := m.stream(r.Context(), id); err == nil {
			return s, true
		}
	}
	http.NotFound(w, r)
	return nil, false
}

func (m *Module) pageStreamEdit(w http.ResponseWriter, r *http.Request) {
	s, ok := m.streamFromPath(w, r)
	if !ok {
		return
	}
	m.g.Render(w, r, http.StatusOK, Name+"/stream_form", "cdn64.streams.edit", m.streamFormData(r.Context(), s, false))
}

func streamFromForm(r *http.Request, s *Stream) {
	on := func(k string) bool { return r.PostFormValue(k) == "on" }
	s.Name = r.PostFormValue("name")
	s.ListenPort, _ = strconv.Atoi(strings.TrimSpace(r.PostFormValue("listen_port")))
	s.TCP, s.UDP, s.Enabled = on("tcp"), on("udp"), on("enabled")
	s.TargetHost = strings.TrimSpace(r.PostFormValue("target_host"))
	s.TargetPort, _ = strconv.Atoi(strings.TrimSpace(r.PostFormValue("target_port")))
	s.TLSCertID, _ = strconv.ParseInt(r.PostFormValue("tls_cert_id"), 10, 64)
	if r.PostFormValue("has_online") == "1" { // CDN64 war im Formular
		s.OnlineName = strings.ToLower(strings.TrimSpace(r.PostFormValue("online_name")))
	}
	if r.PostFormValue("has_geo") == "1" { // Laendersperre war im Formular
		s.GeoMode, s.GeoCountries = r.PostFormValue("geo_mode"), lines(r.PostFormValue("geo_countries"))
	}
	if r.PostFormValue("has_bw") == "1" { // Bandbreite war im Formular
		s.BWDownMbit, _ = strconv.Atoi(strings.TrimSpace(r.PostFormValue("bw_down")))
		s.BWUpMbit, _ = strconv.Atoi(strings.TrimSpace(r.PostFormValue("bw_up")))
	}
}

func (s *Stream) summary() string {
	return fmt.Sprintf("listen=%d tcp=%v udp=%v target=%s tls_cert=%d enabled=%v geo=%s:%s bw=%d/%d", s.ListenPort, s.TCP, s.UDP, s.target(), s.TLSCertID, s.Enabled,
		s.GeoMode, strings.Join(s.GeoCountries, ","), s.BWDownMbit, s.BWUpMbit)
}

func (m *Module) pageStreamCreate(w http.ResponseWriter, r *http.Request) {
	s := newStream()
	streamFromForm(r, s)
	m.saveStreamForm(w, r, s, true)
}

func (m *Module) pageStreamUpdate(w http.ResponseWriter, r *http.Request) {
	s, ok := m.streamFromPath(w, r)
	if !ok {
		return
	}
	streamFromForm(r, s)
	m.saveStreamForm(w, r, s, false)
}

func (m *Module) saveStreamForm(w http.ResponseWriter, r *http.Request, s *Stream, isNew bool) {
	if err := m.saveStream(r.Context(), s); err != nil {
		d := m.streamFormData(r.Context(), s, isNew)
		var fe *FieldError
		if errors.As(err, &fe) {
			d.Errors[fe.Field] = m.g.T(r, fe.Key, "name", fe.Name)
		} else {
			d.Errors["_"] = err.Error()
		}
		m.g.Render(w, r, http.StatusUnprocessableEntity, Name+"/stream_form", "cdn64.streams.new", d)
		return
	}
	action := "cdn64.stream.update"
	if isNew {
		action = "cdn64.stream.create"
	}
	m.g.Audit(r, action, strconv.Itoa(s.ListenPort), s.summary())
	if errs := m.streamErrs(s.ID); len(errs) > 0 {
		for p, e := range errs {
			m.g.Flash(w, r, "warning", m.g.T(r, "cdn64.streams.not_open", "proto", p, "error", e))
			break
		}
	} else {
		m.g.Flash(w, r, "success", m.g.T(r, "common.saved"))
	}
	http.Redirect(w, r, "/cdn64/streams", http.StatusSeeOther)
}

func (m *Module) pageStreamDelete(w http.ResponseWriter, r *http.Request) {
	s, ok := m.streamFromPath(w, r)
	if !ok {
		return
	}
	if err := m.deleteStream(r.Context(), s.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	m.g.Audit(r, "cdn64.stream.delete", strconv.Itoa(s.ListenPort), "target="+s.target())
	http.Redirect(w, r, "/cdn64/streams", http.StatusSeeOther)
}

func (m *Module) pageStreamToggle(w http.ResponseWriter, r *http.Request) {
	s, ok := m.streamFromPath(w, r)
	if !ok {
		return
	}
	on := strings.HasSuffix(r.URL.Path, "/enable")
	if err := m.setStreamEnabled(r.Context(), s.ID, on); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	action := "cdn64.stream.disable"
	if on {
		action = "cdn64.stream.enable"
	}
	m.g.Audit(r, action, strconv.Itoa(s.ListenPort), "")
	http.Redirect(w, r, "/cdn64/streams", http.StatusSeeOther)
}

// ---------------------------------------------------------------- Standardseite (Einstellung des Eingangs)

type defaultData struct {
	Tabs  []tab
	Cfg   edge.Config
	Error string
}

func (m *Module) pageDefault(w http.ResponseWriter, r *http.Request) {
	d := defaultData{Tabs: m.tabs("/cdn64/default")}
	if m.edge != nil {
		d.Cfg = m.edge.Config()
	}
	m.g.Render(w, r, http.StatusOK, Name+"/default", "cdn64.default.title", d)
}

// saveDefault speichert die Standardseite (Einstellungen des Eingangs, wie unter Einstellungen > Ports).
func (m *Module) saveDefault(ctx context.Context, mode, url, html string) (edge.Config, error) {
	if m.edge == nil {
		return edge.Config{}, errors.New("edge not available")
	}
	cfg := m.edge.Config()
	cfg.Default, cfg.DefaultURL, cfg.DefaultPage = mode, strings.TrimSpace(url), html
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	for k, v := range cfg.Settings() {
		if err := m.core.SetSetting(ctx, k, v); err != nil {
			return cfg, err
		}
	}
	return cfg, m.edge.Configure(cfg)
}

func (m *Module) pageDefaultSave(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	cfg, err := m.saveDefault(r.Context(), r.PostFormValue("default"), r.PostFormValue("default_url"), r.PostFormValue("default_html"))
	if err != nil {
		cfg.Default, cfg.DefaultURL, cfg.DefaultPage = r.PostFormValue("default"), r.PostFormValue("default_url"), r.PostFormValue("default_html")
		m.g.Render(w, r, http.StatusUnprocessableEntity, Name+"/default", "cdn64.default.title", defaultData{Tabs: m.tabs("/cdn64/default"), Cfg: cfg, Error: err.Error()})
		return
	}
	m.g.Audit(r, "edge.default", "", fmt.Sprintf("default=%s url=%q html_bytes=%d", cfg.Default, cfg.DefaultURL, len(cfg.DefaultPage)))
	m.g.Flash(w, r, "success", m.g.T(r, "common.saved"))
	http.Redirect(w, r, "/cdn64/default", http.StatusSeeOther)
}

// ---------------------------------------------------------------- API

func (m *Module) apiStreams(w http.ResponseWriter, r *http.Request) {
	rows, err := m.streamRows(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (m *Module) apiStreamRow(w http.ResponseWriter, r *http.Request, id int64, status int) {
	rows, err := m.streamRows(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, x := range rows {
		if x.ID == id {
			writeJSON(w, status, x)
			return
		}
	}
	writeErr(w, http.StatusNotFound, "stream not found")
}

func (m *Module) apiStreamGet(w http.ResponseWriter, r *http.Request) {
	m.apiStreamRow(w, r, pathID(r), http.StatusOK)
}

func decodeStream(w http.ResponseWriter, r *http.Request, s *Stream) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(s); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return false
	}
	return true
}

func (m *Module) apiStreamFail(w http.ResponseWriter, err error) {
	if errors.Is(err, errNotFound) {
		writeErr(w, http.StatusNotFound, "stream not found")
		return
	}
	m.apiFail(w, err)
}

func (m *Module) apiStreamCreate(w http.ResponseWriter, r *http.Request) {
	s := newStream()
	if !decodeStream(w, r, s) {
		return
	}
	s.ID = 0
	if err := m.saveStream(r.Context(), s); err != nil {
		m.apiStreamFail(w, err)
		return
	}
	m.g.Audit(r, "cdn64.stream.create", strconv.Itoa(s.ListenPort), s.summary())
	m.apiStreamRow(w, r, s.ID, http.StatusCreated)
}

func (m *Module) apiStreamUpdate(w http.ResponseWriter, r *http.Request) {
	s, err := m.stream(r.Context(), pathID(r))
	if err != nil {
		m.apiStreamFail(w, err)
		return
	}
	id := s.ID
	if !decodeStream(w, r, s) {
		return
	}
	s.ID = id
	if err := m.saveStream(r.Context(), s); err != nil {
		m.apiStreamFail(w, err)
		return
	}
	m.g.Audit(r, "cdn64.stream.update", strconv.Itoa(s.ListenPort), s.summary())
	m.apiStreamRow(w, r, s.ID, http.StatusOK)
}

func (m *Module) apiStreamDelete(w http.ResponseWriter, r *http.Request) {
	s, err := m.stream(r.Context(), pathID(r))
	if err != nil {
		m.apiStreamFail(w, err)
		return
	}
	if err := m.deleteStream(r.Context(), s.ID); err != nil {
		m.apiStreamFail(w, err)
		return
	}
	m.g.Audit(r, "cdn64.stream.delete", strconv.Itoa(s.ListenPort), "target="+s.target())
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) apiStreamToggle(w http.ResponseWriter, r *http.Request) {
	s, err := m.stream(r.Context(), pathID(r))
	if err != nil {
		m.apiStreamFail(w, err)
		return
	}
	on := strings.HasSuffix(r.URL.Path, "/enable")
	if err := m.setStreamEnabled(r.Context(), s.ID, on); err != nil {
		m.apiStreamFail(w, err)
		return
	}
	action := "cdn64.stream.disable"
	if on {
		action = "cdn64.stream.enable"
	}
	m.g.Audit(r, action, strconv.Itoa(s.ListenPort), "")
	m.apiStreamRow(w, r, s.ID, http.StatusOK)
}

func (m *Module) apiDefaultGet(w http.ResponseWriter, r *http.Request) {
	if m.edge == nil {
		writeErr(w, http.StatusServiceUnavailable, "edge not available")
		return
	}
	c := m.edge.Config()
	writeJSON(w, http.StatusOK, map[string]string{"default": c.Default, "default_url": c.DefaultURL, "default_html": c.DefaultPage})
}

func (m *Module) apiDefaultPut(w http.ResponseWriter, r *http.Request) {
	if m.edge == nil {
		writeErr(w, http.StatusServiceUnavailable, "edge not available")
		return
	}
	c := m.edge.Config()
	in := map[string]string{"default": c.Default, "default_url": c.DefaultURL, "default_html": c.DefaultPage}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10)).Decode(&in); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	cfg, err := m.saveDefault(r.Context(), in["default"], in["default_url"], in["default_html"])
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	m.g.Audit(r, "edge.default", "", fmt.Sprintf("default=%s url=%q html_bytes=%d", cfg.Default, cfg.DefaultURL, len(cfg.DefaultPage)))
	writeJSON(w, http.StatusOK, map[string]string{"default": cfg.Default, "default_url": cfg.DefaultURL, "default_html": cfg.DefaultPage})
}
