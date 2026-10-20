package healthchecks

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Statusseiten: JSON-API /api/status-pages (Anmeldung wie die uebrigen /api-Routen). Ein- und Ausgabe ist
// StatusPage; das Passwort wird nur gesetzt ("password": Klartext, "-" = entfernen, leer = unveraendert) und nie
// ausgegeben (nur "has_password").

func (m *Module) statusPagesAPIRoutes(mux *http.ServeMux, api func(http.HandlerFunc) http.Handler) {
	mux.Handle("GET /api/status-pages", api(m.apiStatusPages))
	mux.Handle("POST /api/status-pages", api(m.apiStatusPageCreate))
	mux.Handle("GET /api/status-pages/{id}", api(m.apiStatusPageGet))
	mux.Handle("PUT /api/status-pages/{id}", api(m.apiStatusPageUpdate))
	mux.Handle("DELETE /api/status-pages/{id}", api(m.apiStatusPageDelete))
	mux.Handle("PUT /api/status-pages/{id}/logo", api(m.apiStatusLogoPut))
	mux.Handle("DELETE /api/status-pages/{id}/logo", api(m.apiStatusLogoDelete))
	mux.Handle("GET /api/status-pages/{id}/notices", api(m.apiStatusNotices))
	mux.Handle("POST /api/status-pages/{id}/notices", api(m.apiStatusNoticeCreate))
	mux.Handle("PUT /api/status-pages/{id}/notices/{nid}", api(m.apiStatusNoticeUpdate))
	mux.Handle("DELETE /api/status-pages/{id}/notices/{nid}", api(m.apiStatusNoticeDelete))
}

// statusAPIError ist die Antwort bei Feldfehlern (422, Slug vergeben 409).
type statusAPIError struct {
	Error string `json:"error"`
	Field string `json:"field,omitempty"`
	Key   string `json:"key,omitempty"` // i18n-Schluessel (hc.status.err.*)
}

// writeStatusErr beantwortet einen Fehler (Feldfehler 422, Slug vergeben 409, unbekannt 404).
func (m *Module) writeStatusErr(w http.ResponseWriter, err error) {
	var fe *StatusFieldError
	switch {
	case errors.As(err, &fe):
		code := http.StatusUnprocessableEntity
		if fe.Key == "hc.status.err.slug_taken" {
			code = http.StatusConflict
		}
		writeJSON(w, code, statusAPIError{Error: m.translator("en")(fe.Key), Field: fe.Field, Key: fe.Key})
	case errors.Is(err, ErrStatusPageNotFound):
		writeErr(w, http.StatusNotFound, "status page not found")
	default:
		m.log.Error("status page", "err", err)
		writeErr(w, http.StatusInternalServerError, "database error")
	}
}

// apiStatusPage liest die Seite aus dem Pfad; nil = schon beantwortet.
func (m *Module) apiStatusPage(w http.ResponseWriter, r *http.Request) *StatusPage {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	p, err := m.st.StatusPage(r.Context(), id)
	if err != nil {
		m.writeStatusErr(w, err)
		return nil
	}
	return p
}

func (m *Module) apiStatusPages(w http.ResponseWriter, r *http.Request) {
	list, err := m.st.StatusPages(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	out := make([]*StatusPage, 0, len(list))
	for _, p := range list {
		full, err := m.st.StatusPage(r.Context(), p.ID) // mit Gruppen, wie GET /api/status-pages/{id}
		if err != nil {
			continue
		}
		out = append(out, full)
	}
	writeJSON(w, http.StatusOK, out)
}

func (m *Module) apiStatusPageGet(w http.ResponseWriter, r *http.Request) {
	if p := m.apiStatusPage(w, r); p != nil {
		writeJSON(w, http.StatusOK, p)
	}
}

func (m *Module) apiStatusPageCreate(w http.ResponseWriter, r *http.Request) {
	p := newStatusPage()
	if err := readJSON(r, p); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	p.ID = 0
	if err := m.saveStatusPage(r.Context(), p); err != nil {
		m.writeStatusErr(w, err)
		return
	}
	m.auditText(r, "status_page.create", p.Title+" ("+p.Slug+")")
	m.apiStatusPageOut(w, r, http.StatusCreated, p.ID)
}

// apiStatusPageOut gibt die gespeicherte Seite frisch aus der Datenbank aus (Passwort nie).
func (m *Module) apiStatusPageOut(w http.ResponseWriter, r *http.Request, status int, id int64) {
	p, err := m.st.StatusPage(r.Context(), id)
	if err != nil {
		m.writeStatusErr(w, err)
		return
	}
	writeJSON(w, status, p)
}

func (m *Module) apiStatusPageUpdate(w http.ResponseWriter, r *http.Request) {
	old := m.apiStatusPage(w, r)
	if old == nil {
		return
	}
	var raw map[string]json.RawMessage
	if err := readJSON(r, &raw); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	b, _ := json.Marshal(raw)
	// Felder, die fehlen, bleiben; Gruppen nur ersetzen, wenn "groups" mitkommt (frische Struktur, damit alte
	// Eintraege nicht durch das Dekodieren in den vorhandenen Slice weiterleben)
	p := *old
	p.Groups = nil
	if err := json.Unmarshal(b, &p); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if _, ok := raw["groups"]; !ok {
		p.Groups = old.Groups
	}
	if p.Groups == nil {
		p.Groups = []StatusGroup{}
	}
	p.ID = old.ID
	if err := m.saveStatusPage(r.Context(), &p); err != nil {
		m.writeStatusErr(w, err)
		return
	}
	m.auditText(r, "status_page.update", p.Title+" ("+p.Slug+")")
	m.apiStatusPageOut(w, r, http.StatusOK, p.ID)
}

func (m *Module) apiStatusPageDelete(w http.ResponseWriter, r *http.Request) {
	p := m.apiStatusPage(w, r)
	if p == nil {
		return
	}
	if err := m.st.DeleteStatusPage(r.Context(), p.ID); err != nil {
		m.writeStatusErr(w, err)
		return
	}
	m.auditText(r, "status_page.delete", p.Title+" ("+p.Slug+")")
	w.WriteHeader(http.StatusNoContent)
}

// apiStatusLogoPut setzt das Logo: Body = Bild (PNG, JPEG, WebP, SVG; Format nach Inhalt), 413 zu gross, 415 falscher Typ.
func (m *Module) apiStatusLogoPut(w http.ResponseWriter, r *http.Request) {
	p := m.apiStatusPage(w, r)
	if p == nil {
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, StatusLogoMax+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	if len(data) > StatusLogoMax {
		writeJSON(w, http.StatusRequestEntityTooLarge, statusAPIError{Error: "logo larger than 256 KiB", Field: "logo", Key: "hc.status.err.logo"})
		return
	}
	ctype, ok := statusLogoType(data)
	// ein angegebener Bildtyp muss zum Inhalt passen (application/octet-stream oder leer = nur nach Inhalt)
	if hdr, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";"); ok && strings.HasPrefix(strings.TrimSpace(hdr), "image/") && strings.TrimSpace(hdr) != ctype {
		ok = false
	}
	if !ok {
		writeJSON(w, http.StatusUnsupportedMediaType, statusAPIError{Error: "logo must be png, jpeg, webp or svg", Field: "logo", Key: "hc.status.err.logo"})
		return
	}
	if err := m.st.SetStatusLogo(r.Context(), p.ID, data, ctype); err != nil {
		m.writeStatusErr(w, err)
		return
	}
	m.auditText(r, "status_page.logo", p.Title+" ("+p.Slug+")")
	m.apiStatusPageOut(w, r, http.StatusOK, p.ID)
}

func (m *Module) apiStatusLogoDelete(w http.ResponseWriter, r *http.Request) {
	p := m.apiStatusPage(w, r)
	if p == nil {
		return
	}
	if err := m.st.SetStatusLogo(r.Context(), p.ID, nil, ""); err != nil {
		m.writeStatusErr(w, err)
		return
	}
	m.auditText(r, "status_page.logo_remove", p.Title+" ("+p.Slug+")")
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- Ankuendigungen

func (m *Module) apiStatusNotices(w http.ResponseWriter, r *http.Request) {
	p := m.apiStatusPage(w, r)
	if p == nil {
		return
	}
	list, err := m.st.StatusNotices(r.Context(), p.ID, time.Time{})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	if list == nil {
		list = []StatusNotice{}
	}
	writeJSON(w, http.StatusOK, list)
}

// apiNoticeOut gibt eine Ankuendigung mit Updates aus.
func (m *Module) apiNoticeOut(w http.ResponseWriter, r *http.Request, status int, pageID, nid int64) {
	list, err := m.st.StatusNotices(r.Context(), pageID, time.Time{})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	for _, n := range list {
		if n.ID == nid {
			writeJSON(w, status, n)
			return
		}
	}
	writeJSON(w, status, map[string]int64{"id": nid, "page_id": pageID})
}

func (m *Module) apiStatusNoticeCreate(w http.ResponseWriter, r *http.Request) {
	p := m.apiStatusPage(w, r)
	if p == nil {
		return
	}
	var in struct {
		Title string `json:"title"`
		Level string `json:"level"`
		Text  string `json:"text"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	nid, err := m.st.AddStatusNotice(r.Context(), p.ID, in.Title, in.Level, in.Text)
	if err != nil {
		m.writeStatusErr(w, err)
		return
	}
	m.auditText(r, "status_notice.create", p.Slug+": "+in.Title)
	m.apiNoticeOut(w, r, http.StatusCreated, p.ID, nid)
}

// apiNotice liefert die ID der Ankuendigung im Pfad, wenn sie zur Seite gehoert (sonst 404, 0).
func (m *Module) apiNotice(w http.ResponseWriter, r *http.Request, p *StatusPage) int64 {
	nid, _ := strconv.ParseInt(r.PathValue("nid"), 10, 64)
	if nid == 0 || m.noticePage(r.Context(), nid) != p.ID {
		writeErr(w, http.StatusNotFound, "notice not found")
		return 0
	}
	return nid
}

func (m *Module) apiStatusNoticeUpdate(w http.ResponseWriter, r *http.Request) {
	p := m.apiStatusPage(w, r)
	if p == nil {
		return
	}
	nid := m.apiNotice(w, r, p)
	if nid == 0 {
		return
	}
	var in struct {
		Level   string `json:"level"`
		Text    string `json:"text"`
		Resolve bool   `json:"resolve"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if in.Level != "" && !validNoticeLevel(in.Level) {
		writeJSON(w, http.StatusUnprocessableEntity, statusAPIError{Error: "level must be info, warning or danger", Field: "level"})
		return
	}
	if err := m.st.UpdateStatusNotice(r.Context(), nid, in.Level, in.Text, in.Resolve); err != nil {
		m.writeStatusErr(w, err)
		return
	}
	m.auditText(r, map[bool]string{true: "status_notice.resolve", false: "status_notice.update"}[in.Resolve], p.Slug+": #"+strconv.FormatInt(nid, 10))
	m.apiNoticeOut(w, r, http.StatusOK, p.ID, nid)
}

func (m *Module) apiStatusNoticeDelete(w http.ResponseWriter, r *http.Request) {
	p := m.apiStatusPage(w, r)
	if p == nil {
		return
	}
	nid := m.apiNotice(w, r, p)
	if nid == 0 {
		return
	}
	if err := m.st.DeleteStatusNotice(r.Context(), nid); err != nil {
		m.writeStatusErr(w, err)
		return
	}
	m.auditText(r, "status_notice.delete", p.Slug+": #"+strconv.FormatInt(nid, 10))
	w.WriteHeader(http.StatusNoContent)
}
