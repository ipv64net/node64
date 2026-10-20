package honeypot

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/module"
)

// Lokale JSON-API des Moduls (Doku: internal/web/static/openapi.json, Tag "Honeypot64"). Ist das Modul aus: 404.

func (m *Module) apiRoutes(mux *http.ServeMux, g module.Guards) {
	api := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /api/honeypot/status", api(m.apiStatus))
	mux.Handle("GET /api/honeypot/stats", api(m.apiStats))
	mux.Handle("GET /api/honeypot/events", api(m.apiEvents))
	mux.Handle("DELETE /api/honeypot/events", api(m.apiClear))
	mux.Handle("GET /api/honeypot/config", api(m.apiConfig))
	mux.Handle("PUT /api/honeypot/config", api(m.apiConfigPut))
}

// StatusInfo ist der Zustand fuer GET /api/honeypot/status.
type StatusInfo struct {
	Version   string          `json:"version"`
	Running   bool            `json:"running"`
	StartedAt time.Time       `json:"started_at,omitzero"`
	Profile   string          `json:"profile"`
	Scan      bool            `json:"scan"`
	Services  []ServiceStatus `json:"services"`
	Warnings  []Warning       `json:"warnings"`
	Counters  CounterValues   `json:"counters"`
	Buffered  int             `json:"buffered"`
	Dropped   int64           `json:"dropped"` // im Speicher verworfen (Puffer voll, Schreibfehler)
	Report    ReportStatus    `json:"report"`  // Meldung an ipv64
}

// CounterValues sind die Zaehler des Sensors seit dem Start.
type CounterValues struct {
	Connections int64 `json:"connections"`
	Logins      int64 `json:"logins"`
	Events      int64 `json:"events"`
	Dropped     int64 `json:"dropped"`
}

func (m *Module) statusInfo(r *http.Request) StatusInfo {
	cfg := m.loadConfig(r.Context())
	out := StatusInfo{Version: version, Profile: cfg.Profile, Scan: cfg.Scan, Services: []ServiceStatus{}, Warnings: m.Warnings(),
		Buffered: m.st.Buffered(), Dropped: m.st.Dropped(), Report: m.rep.Status(r.Context())}
	if out.Warnings == nil {
		out.Warnings = []Warning{}
	}
	if s := m.running(); s != nil {
		m.mu.Lock()
		out.StartedAt = m.started
		m.mu.Unlock()
		out.Running = true
		if st := s.Status(); st != nil {
			out.Services = st
		}
		if c := s.Counters(); c != nil {
			out.Counters = CounterValues{Connections: c.Connections.Load(), Logins: c.Logins.Load(), Events: c.Events.Load(), Dropped: c.Dropped.Load()}
		}
	}
	return out
}

func (m *Module) apiStatus(w http.ResponseWriter, r *http.Request) {
	apiJSON(w, http.StatusOK, m.statusInfo(r))
}

// parseSince: "24h" (Standard), "7d" oder eine Go-Dauer ("12h"); hoechstens die Aufbewahrung (Store kuerzt).
func parseSince(v string) (time.Duration, bool) {
	v = strings.TrimSpace(strings.ToLower(v))
	switch v {
	case "", "24h", "1d":
		return 24 * time.Hour, true
	case "7d":
		return 7 * 24 * time.Hour, true
	}
	if d, ok := strings.CutSuffix(v, "d"); ok {
		n, err := strconv.Atoi(d)
		if err != nil || n < 1 || n > maxRetentionDays {
			return 0, false
		}
		return time.Duration(n) * 24 * time.Hour, true
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, false
	}
	return d, true
}

func (m *Module) apiStats(w http.ResponseWriter, r *http.Request) {
	d, ok := parseSince(r.URL.Query().Get("since"))
	if !ok {
		apiErr(w, http.StatusBadRequest, "since: use 24h, 7d or a duration")
		return
	}
	top, _ := strconv.Atoi(r.URL.Query().Get("top"))
	if top > 100 {
		top = 100
	}
	_ = m.st.Flush(r.Context())
	st, err := m.st.Stats(r.Context(), time.Now().Add(-d), top)
	if err != nil {
		m.fail(w, err)
		return
	}
	apiJSON(w, http.StatusOK, st)
}

// EventView ist ein Ereignis fuer API und Oberflaeche: Payload als Hex und als lesbarer, escapter Text.
type EventView struct {
	Time        time.Time `json:"time"`
	Service     string    `json:"service"`
	Port        int       `json:"port"`
	Kind        string    `json:"kind"`
	Src         string    `json:"src"`
	SrcPort     int       `json:"src_port"`
	Username    string    `json:"username,omitempty"`
	Password    string    `json:"password,omitempty"`
	Method      string    `json:"method,omitempty"`
	Path        string    `json:"path,omitempty"`
	Host        string    `json:"host,omitempty"`
	UA          string    `json:"user_agent,omitempty"`
	Client      string    `json:"client,omitempty"`
	Page        string    `json:"page,omitempty"`
	Detail      string    `json:"detail,omitempty"`
	PayloadHex  string    `json:"payload_hex,omitempty"`
	PayloadText string    `json:"payload_text,omitempty"` // Go-Escapes (\x00, \r\n …), nur ASCII
	PayloadDump string    `json:"-"`                      // hex.Dump fuer die Seite
}

func eventView(e Event) EventView {
	v := EventView{Time: e.Time, Service: e.Service, Port: e.Port, Kind: e.Kind, Src: storeSrc(e.Src), SrcPort: e.SrcPort, Username: e.Username,
		Password: e.Password, Method: e.Method, Path: e.Path, Host: e.Host, UA: e.UA, Client: e.Client, Page: e.Page, Detail: e.Detail}
	if len(e.Payload) > 0 {
		v.PayloadHex = hex.EncodeToString(e.Payload)
		q := strconv.QuoteToASCII(string(e.Payload))
		v.PayloadText = q[1 : len(q)-1]
		v.PayloadDump = strings.TrimRight(hex.Dump(e.Payload), "\n")
	}
	return v
}

func (m *Module) recent(r *http.Request, limit int) ([]EventView, error) {
	_ = m.st.Flush(r.Context())
	list, err := m.st.Recent(r.Context(), limit)
	if err != nil {
		return nil, err
	}
	out := make([]EventView, 0, len(list))
	for _, e := range list {
		out = append(out, eventView(e))
	}
	return out, nil
}

func (m *Module) apiEvents(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	list, err := m.recent(r, limit)
	if err != nil {
		m.fail(w, err)
		return
	}
	apiJSON(w, http.StatusOK, list)
}

func (m *Module) apiClear(w http.ResponseWriter, r *http.Request) {
	n, err := m.ClearEvents(r.Context())
	if err != nil {
		m.fail(w, err)
		return
	}
	m.log.Info("events cleared", "count", n, "via", "api", "by", m.g.Actor(r))
	m.g.Audit(r, "honeypot.clear", "", strconv.FormatInt(n, 10))
	apiJSON(w, http.StatusOK, map[string]int64{"deleted": n})
}

func (m *Module) apiConfig(w http.ResponseWriter, r *http.Request) {
	apiJSON(w, http.StatusOK, m.loadConfig(r.Context()))
}

// apiConfigPut uebernimmt die angegebenen Felder (fehlende bleiben), prueft und wendet sofort an.
func (m *Module) apiConfigPut(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c := m.loadConfig(ctx)
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&c); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	c, err := m.SaveConfig(ctx, c)
	var fe FieldErrors
	if errors.As(err, &fe) {
		fields := map[string]string{}
		for k, v := range fe {
			fields[k] = m.errText(r, v)
		}
		apiJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid settings", "fields": fields})
		return
	}
	if err != nil {
		m.fail(w, err)
		return
	}
	m.log.Info("settings saved", "via", "api", "by", m.g.Actor(r))
	m.g.Audit(r, "honeypot.config", c.Profile, configDetails(c))
	apiJSON(w, http.StatusOK, c)
}

// configDetails fasst die Einstellung fuer das Audit-Log zusammen (ohne Geheimnisse, es gibt keine).
func configDetails(c ModuleConfig) string {
	var ps []string
	list := c.Services
	if c.Profile != ProfileCustom {
		list = Profiles[c.Profile]
	}
	for _, s := range list {
		ps = append(ps, s.Service+"/"+strconv.Itoa(s.Port))
	}
	return strings.Join(ps, " ") + " scan=" + strconv.FormatBool(c.Scan) + " days=" + strconv.Itoa(c.RetentionDays) + " notify=" + strconv.FormatBool(c.NotifyNew) + " report=" + strconv.FormatBool(c.Report)
}

// errText uebersetzt einen Fehlerschluessel aus validate ("schluessel|wert1|wert2", mehrere je Zeile).
func (m *Module) errText(r *http.Request, s string) string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		parts := strings.Split(line, "|")
		args := []any{}
		for i, v := range parts[1:] {
			args = append(args, "v"+strconv.Itoa(i+1), v)
		}
		if m.g.T != nil {
			out = append(out, m.g.T(r, parts[0], args...))
		} else {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

func apiJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func apiErr(w http.ResponseWriter, status int, msg string) {
	apiJSON(w, status, map[string]string{"error": msg})
}

func (m *Module) fail(w http.ResponseWriter, err error) {
	m.log.Error("api", "err", err)
	apiErr(w, http.StatusInternalServerError, "internal error")
}
