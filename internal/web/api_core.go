package web

import (
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/logging"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/notify"
)

// Lokale JSON-API des Kerns: Status, Kanaele, Zustellprotokoll, Einstellungen,
// Audit, Logs, Backup. Auth: Sitzung (mit X-CSRF-Token bei Aenderungen) oder
// API-Key. Die Module registrieren ihre eigenen /api/-Pfade.

func (s *Server) apiRoutes() {
	s.mux.Handle("GET /api/status", s.auth(s.apiStatus))
	s.mux.Handle("GET /api/version", s.auth(s.apiVersion))
	s.mux.Handle("GET /api/openapi.json", s.auth(s.apiOpenAPI))
	s.mux.Handle("GET /api/docs", s.auth(s.apiDocs))
	s.mux.Handle("GET /api/audit", s.auth(s.apiAudit))
	s.mux.Handle("GET /api/logs", s.auth(s.apiLogs))
	s.mux.Handle("GET /api/backup", s.auth(s.backupDownload))
	s.mux.Handle("GET /api/settings", s.auth(s.apiSettingsGet))
	s.mux.Handle("PUT /api/settings", s.auth(s.apiSettingsPut))
	s.mux.Handle("GET /api/modules", s.auth(s.apiModules))
	s.mux.Handle("POST /api/modules/{name}/enable", s.auth(s.apiModuleToggle))
	s.mux.Handle("POST /api/modules/{name}/disable", s.auth(s.apiModuleToggle))
	if s.Notify != nil {
		s.mux.Handle("GET /api/channels", s.auth(s.apiChannels))
		s.mux.Handle("POST /api/channels", s.auth(s.apiChannelCreate))
		s.mux.Handle("GET /api/channels/{id}", s.auth(s.apiChannelGet))
		s.mux.Handle("PUT /api/channels/{id}", s.auth(s.apiChannelUpdate))
		s.mux.Handle("DELETE /api/channels/{id}", s.auth(s.apiChannelDelete))
		s.mux.Handle("POST /api/channels/{id}/test", s.auth(s.apiChannelTest))
		s.mux.Handle("GET /api/channel-types", s.auth(s.apiChannelTypes))
		s.mux.Handle("GET /api/deliveries", s.auth(s.apiDeliveries))
	}
}

type apiErr struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, apiErr{Error: msg})
}

func (s *Server) apiVersion(w http.ResponseWriter, r *http.Request) {
	host, _ := os.Hostname()
	writeJSON(w, 200, map[string]any{"version": s.Version, "started_at": s.StartedAt.UTC(), "hostname": host, "time": time.Now().UTC()})
}

func (s *Server) apiStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	out := map[string]any{
		"node": map[string]any{
			"id": s.Store.SettingOr(ctx, SettingNodeID, ""), "name": s.Store.SettingOr(ctx, SettingNodeName, ""),
			"location": s.Store.SettingOr(ctx, SettingNodeLocation, ""), "timezone": s.Store.SettingOr(ctx, SettingNodeTimezone, ""),
			"version": s.Version, "started_at": s.StartedAt.UTC(), "uptime_seconds": int(time.Since(s.StartedAt).Seconds()),
			"database_bytes": s.Store.Size(), "log_level": logging.LevelName(s.Log.Level()),
		},
		"link": s.Sync.State(),
	}
	var mods []map[string]any
	for _, st := range s.Modules.List(ctx) {
		m := map[string]any{"name": st.Info.Name, "version": st.Info.Version, "available": st.Info.Available, "enabled": st.Enabled, "running": st.Running, "path": st.Info.Path}
		if st.LastError != "" {
			m["last_error"] = st.LastError
		}
		mods = append(mods, m)
	}
	out["modules"] = mods
	var boards []any
	for _, m := range s.Modules.Modules() {
		if p, ok := m.(module.DashboardProvider); ok && s.Modules.IsRunning(m.Info().Name) {
			if info, err := p.Dashboard(ctx); err == nil && info != nil {
				boards = append(boards, map[string]any{"module": info.Module, "ok": info.OK, "down": info.Down, "paused": info.Paused, "other": info.Other})
			}
		}
	}
	out["summary"] = boards
	writeJSON(w, 200, out)
}

func (s *Server) apiModules(w http.ResponseWriter, r *http.Request) {
	var mods []map[string]any
	for _, st := range s.Modules.List(r.Context()) {
		m := map[string]any{"name": st.Info.Name, "version": st.Info.Version, "available": st.Info.Available, "enabled": st.Enabled, "running": st.Running, "path": st.Info.Path, "last_error": st.LastError}
		if d := st.Info.LastChange(); !d.IsZero() {
			m["changed"] = d.Format("2006-01-02")
		}
		if r.URL.Query().Get("changelog") == "1" {
			m["changelog"] = st.Info.Changelog
		}
		mods = append(mods, m)
	}
	writeJSON(w, 200, mods)
}

func (s *Server) apiModuleToggle(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var err error
	if strings.HasSuffix(r.URL.Path, "/enable") {
		err = s.Modules.Enable(r.Context(), name)
	} else {
		err = s.Modules.Disable(r.Context(), name)
	}
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	s.audit(r, "module."+strings.TrimPrefix(r.URL.Path[strings.LastIndex(r.URL.Path, "/"):], "/"), name, "api")
	s.apiModules(w, r)
}

func (s *Server) apiAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	list, err := s.Store.AuditList(r.Context(), limit, before)
	if err != nil {
		writeErr(w, 500, "database error")
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, e := range list {
		out = append(out, map[string]any{"id": e.ID, "time": e.Time.UTC(), "actor": e.Actor, "action": e.Action, "target": e.Target, "details": e.Details, "ip": e.IP, "origin": e.Origin})
	}
	writeJSON(w, 200, out)
}

func (s *Server) apiLogs(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("lines"))
	if n <= 0 || n > 2000 {
		n = 200
	}
	writeJSON(w, 200, map[string]any{"level": logging.LevelName(s.Log.Level()), "lines": s.Log.Lines(n)})
}

var apiSettingKeys = []string{SettingNodeName, SettingNodeLocation, SettingNodeTimezone, notify.SetBaseURL, notify.SetQuietEnabled, notify.SetQuietFrom,
	notify.SetQuietTo, notify.SetQuietDays, notify.SetQuietTZ, notify.SetRatePerHour, notify.SetBatchThreshold, notify.SetBatchWindow, "updates.check"}

func (s *Server) apiSettingsGet(w http.ResponseWriter, r *http.Request) {
	out := map[string]string{}
	for _, k := range apiSettingKeys {
		out[k] = s.Store.SettingOr(r.Context(), k, "")
	}
	writeJSON(w, 200, out)
}

func (s *Server) apiSettingsPut(w http.ResponseWriter, r *http.Request) {
	var in map[string]string
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, 400, "invalid json")
		return
	}
	for k, v := range in {
		allowed := false
		for _, x := range apiSettingKeys {
			if x == k {
				allowed = true
			}
		}
		if !allowed {
			writeErr(w, http.StatusUnprocessableEntity, "unknown setting "+k)
			return
		}
		if k == SettingNodeName && (strings.TrimSpace(v) == "" || len(v) > 64) {
			writeErr(w, http.StatusUnprocessableEntity, "node.name must be 1-64 characters")
			return
		}
		if k == SettingNodeTimezone || k == notify.SetQuietTZ {
			if v != "" && !validTimezone(v) {
				writeErr(w, http.StatusUnprocessableEntity, "invalid timezone for "+k)
				return
			}
		}
		if notify.IsSyncedSetting(k) {
			nv, err := notify.NormalizeSetting(k, v)
			if err != nil {
				writeErr(w, http.StatusUnprocessableEntity, err.Error())
				return
			}
			in[k] = nv
		}
	}
	synced := false
	for k, v := range in {
		if err := s.Store.SetSetting(r.Context(), k, v); err != nil {
			writeErr(w, 500, "database error")
			return
		}
		synced = synced || notify.IsSyncedSetting(k)
	}
	if synced && s.Linker != nil {
		s.Linker.NotifySettingsChanged()
	}
	_, nameSet := in[SettingNodeName]
	_, locSet := in[SettingNodeLocation]
	if (nameSet || locSet) && s.Linker != nil {
		s.Linker.NodeInfoChanged() // an ipv64 und die anderen Nodes weitergeben (wie die Oberflaeche)
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	s.audit(r, "settings.api", "", strings.Join(keys, ","))
	s.apiSettingsGet(w, r)
}

// ---------------------------------------------------------------- Kanaele

type channelJSON struct {
	ID         int64             `json:"id,omitempty"`
	Type       string            `json:"type"`
	Name       string            `json:"name"`
	Config     map[string]string `json:"config"`
	Enabled    *bool             `json:"enabled,omitempty"`
	Default    *bool             `json:"default,omitempty"`
	Lang       string            `json:"lang,omitempty"`
	NotifyDown *bool             `json:"notify_down,omitempty"`
	NotifyUp   *bool             `json:"notify_up,omitempty"`
	Execution  string            `json:"execution,omitempty"`
	Revision   int64             `json:"revision,omitempty"`
	CreatedAt  *time.Time        `json:"created_at,omitempty"`
	UpdatedAt  *time.Time        `json:"updated_at,omitempty"`
	LastUsedAt *time.Time        `json:"last_used_at,omitempty"`
	LastError  string            `json:"last_error,omitempty"`
}

func channelOut(c *notify.Channel, secrets bool) channelJSON {
	cfg := c.Masked()
	if secrets {
		cfg = c.Config
	}
	en, def, nd, nu := c.Enabled, c.Default, c.NotifyDown, c.NotifyUp
	created, updated := c.CreatedAt, c.UpdatedAt
	out := channelJSON{ID: c.ID, Type: string(c.Type), Name: c.Name, Config: cfg, Enabled: &en, Default: &def, Lang: c.Lang, NotifyDown: &nd, NotifyUp: &nu,
		Execution: c.Execution, Revision: c.Revision, CreatedAt: &created, UpdatedAt: &updated, LastError: c.LastError}
	if !c.LastUsedAt.IsZero() {
		u := c.LastUsedAt
		out.LastUsedAt = &u
	}
	return out
}

func (s *Server) apiChannels(w http.ResponseWriter, r *http.Request) {
	list, err := s.Notify.Channels(r.Context())
	if err != nil {
		writeErr(w, 500, "database error")
		return
	}
	secrets := r.URL.Query().Get("include_secrets") == "true"
	out := make([]channelJSON, 0, len(list))
	for _, c := range list {
		out = append(out, channelOut(c, secrets))
	}
	writeJSON(w, 200, out)
}

func (s *Server) apiChannelTypes(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{}
	for _, t := range notify.Types {
		var fields []map[string]any
		for _, f := range notify.Fields[t] {
			fields = append(fields, map[string]any{"key": f.Key, "required": f.Required, "secret": f.Secret, "kind": orStr(f.Kind, "text"), "default": f.Default, "options": f.Options})
		}
		out[string(t)] = fields
	}
	writeJSON(w, 200, map[string]any{"types": out, "planned": notify.Planned})
}

func orStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func (s *Server) loadAPIChannel(w http.ResponseWriter, r *http.Request) *notify.Channel {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	ch, err := s.Notify.Channel(r.Context(), id)
	if err != nil {
		writeErr(w, 500, "database error")
		return nil
	}
	if ch == nil {
		writeErr(w, 404, "channel not found")
		return nil
	}
	return ch
}

func (s *Server) apiChannelGet(w http.ResponseWriter, r *http.Request) {
	if ch := s.loadAPIChannel(w, r); ch != nil {
		writeJSON(w, 200, channelOut(ch, r.URL.Query().Get("include_secrets") == "true"))
	}
}

func (s *Server) applyChannel(ch *notify.Channel, in channelJSON, create bool) error {
	if create {
		ch.Type = notify.Type(in.Type)
		ch.Enabled, ch.NotifyDown, ch.NotifyUp, ch.Lang = true, true, true, "de"
	}
	if in.Name != "" {
		ch.Name = in.Name
	}
	for k, v := range in.Config {
		if notify.IsSecret(ch.Type, k) && strings.TrimSpace(v) == "" && !create {
			continue
		}
		ch.Config[k] = v
	}
	if in.Enabled != nil {
		ch.Enabled = *in.Enabled
	}
	if in.Default != nil {
		ch.Default = *in.Default
	}
	if in.NotifyDown != nil {
		ch.NotifyDown = *in.NotifyDown
	}
	if in.NotifyUp != nil {
		ch.NotifyUp = *in.NotifyUp
	}
	if in.Lang != "" && s.I18n.Has(in.Lang) {
		ch.Lang = in.Lang
	}
	if !create && serverOnly(ch) {
		return ch.ValidateKeepSecrets() // Kanal von ipv64: Geheimnisse liegen beim hub
	}
	return ch.Validate()
}

func (s *Server) apiChannelCreate(w http.ResponseWriter, r *http.Request) {
	var in channelJSON
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, 400, "invalid json")
		return
	}
	ch := &notify.Channel{Config: map[string]string{}}
	if err := s.applyChannel(ch, in, true); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := s.Notify.Insert(r.Context(), ch); err != nil {
		writeErr(w, 500, "database error")
		return
	}
	s.audit(r, "channel.create", ch.Name, string(ch.Type))
	if stored, err := s.Notify.Channel(r.Context(), ch.ID); err == nil && stored != nil {
		ch = stored // mit Zeitstempeln
	}
	writeJSON(w, 201, channelOut(ch, false))
}

func (s *Server) apiChannelUpdate(w http.ResponseWriter, r *http.Request) {
	ch := s.loadAPIChannel(w, r)
	if ch == nil {
		return
	}
	var in channelJSON
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, 400, "invalid json")
		return
	}
	if err := s.applyChannel(ch, in, false); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := s.Notify.Update(r.Context(), ch); err != nil {
		writeErr(w, 500, "database error")
		return
	}
	s.audit(r, "channel.update", ch.Name, string(ch.Type))
	ch, _ = s.Notify.Channel(r.Context(), ch.ID)
	writeJSON(w, 200, channelOut(ch, false))
}

func (s *Server) apiChannelDelete(w http.ResponseWriter, r *http.Request) {
	ch := s.loadAPIChannel(w, r)
	if ch == nil {
		return
	}
	if err := s.Notify.Delete(r.Context(), ch.ID); err != nil {
		writeErr(w, 500, "database error")
		return
	}
	s.audit(r, "channel.delete", ch.Name, string(ch.Type))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiChannelTest(w http.ResponseWriter, r *http.Request) {
	ch := s.loadAPIChannel(w, r)
	if ch == nil {
		return
	}
	var err error
	if serverOnly(ch) && s.Linker != nil { // Mail, SMS, App stellt nur ipv64 zu: Test ueber den hub (wie die Oberflaeche)
		err = s.Linker.TestServerChannel(r.Context(), ch.RemoteID, s.lang(r))
	} else {
		err = s.Dispatcher.Test(r.Context(), ch)
	}
	s.audit(r, "channel.test", ch.Name, string(ch.Type))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": notify.RedactURLs(err.Error())})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) apiDeliveries(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	channel, _ := strconv.ParseInt(r.URL.Query().Get("channel"), 10, 64)
	list, err := s.Notify.Deliveries(r.Context(), limit, before, channel)
	if err != nil {
		writeErr(w, 500, "database error")
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, d := range list {
		out = append(out, map[string]any{"id": d.ID, "time": d.Time.UTC(), "event_id": d.EventID, "channel_id": d.ChannelID, "channel": d.Channel, "kind": d.Kind, "check_token": d.CheckToken, "subject": d.Subject, "ok": d.OK, "error": d.Error})
	}
	writeJSON(w, 200, out)
}

// ---------------------------------------------------------------- OpenAPI und Doku

func (s *Server) apiOpenAPI(w http.ResponseWriter, r *http.Request) {
	b, err := staticFS.ReadFile("static/openapi.json")
	if err != nil {
		writeErr(w, 500, "openapi document missing")
		return
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	b = []byte(strings.Replace(string(b), `"url": "/api"`, `"url": "`+scheme+`://`+r.Host+`/api"`, 1))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(b)
}

func (s *Server) apiDocs(w http.ResponseWriter, r *http.Request) {
	b, err := staticFS.ReadFile("static/openapi.json")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var spec struct {
		Info  map[string]any            `json:"info"`
		Tags  []map[string]any          `json:"tags"`
		Paths map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(b, &spec); err != nil {
		s.fail(w, r, err)
		return
	}
	type op struct {
		Method, Path, Summary, Description string
		Public                             bool
	}
	groups := map[string][]op{}
	var order []string
	methodRank := map[string]int{"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3}
	for path, methods := range spec.Paths {
		for method, raw := range methods {
			method = strings.ToUpper(method)
			o, isOp := raw.(map[string]any)
			if _, ok := methodRank[method]; !ok || !isOp {
				continue // z. B. "parameters" auf Pfadebene
			}
			tag := "other"
			if tags, ok := o["tags"].([]any); ok && len(tags) > 0 {
				tag, _ = tags[0].(string)
			}
			if _, seen := groups[tag]; !seen {
				order = append(order, tag)
			}
			summary, _ := o["summary"].(string)
			desc, _ := o["description"].(string)
			_, pub := o["security"]
			groups[tag] = append(groups[tag], op{Method: method, Path: path, Summary: summary, Description: desc, Public: pub})
		}
	}
	// Gruppen in Dokumentreihenfolge (Node zuerst), Operationen nach Pfad und Methode
	tagRank := map[string]int{}
	for i, t := range spec.Tags {
		if n, _ := t["name"].(string); n != "" {
			tagRank[n] = i
		}
	}
	sort.SliceStable(order, func(i, j int) bool { return tagRank[order[i]] < tagRank[order[j]] })
	for _, g := range groups {
		sort.SliceStable(g, func(i, j int) bool {
			if g[i].Path != g[j].Path {
				return g[i].Path < g[j].Path
			}
			return methodRank[g[i].Method] < methodRank[g[j].Method]
		})
	}
	v := s.view(r, "api.title")
	v.Data = map[string]any{"Groups": groups, "Order": order, "Info": spec.Info}
	s.render(w, r, http.StatusOK, "api_docs", v)
}
