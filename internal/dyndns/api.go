package dyndns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/module"
)

// Lokale JSON-API des Moduls (Doku: internal/web/static/openapi.json, Tag "DynDNS").
// Tokens werden nie ausgegeben, nur angenommen.

func (m *Module) apiRoutes(mux *http.ServeMux, g module.Guards) {
	api := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /api/dyndns/status", api(m.apiStatus))
	mux.Handle("POST /api/dyndns/check", api(m.apiCheck))
	mux.Handle("GET /api/dyndns/targets", api(m.apiTargets))
	mux.Handle("POST /api/dyndns/targets", api(m.apiTargetCreate))
	mux.Handle("GET /api/dyndns/targets/{id}", api(m.apiTargetGet))
	mux.Handle("PUT /api/dyndns/targets/{id}", api(m.apiTargetUpdate))
	mux.Handle("DELETE /api/dyndns/targets/{id}", api(m.apiTargetDelete))
	mux.Handle("POST /api/dyndns/targets/{id}/update", api(m.apiTargetUpdateNow))
	mux.Handle("GET /api/dyndns/history", api(m.apiHistory))
	mux.Handle("GET /api/dyndns/settings", api(m.apiSettingsGet))
	mux.Handle("PUT /api/dyndns/settings", api(m.apiSettingsPut))
	mux.Handle("GET /api/dyndns/account/names", api(m.apiAccountNames))
	mux.Handle("POST /api/dyndns/targets/from-account", api(m.apiFromAccount))
	mux.Handle("POST /api/dyndns/targets/{id}/token", api(m.apiTargetToken))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func ts(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// targetJSON ist ein Ziel in der API (Token nur als Eingabe).
type targetJSON struct {
	ID         int64      `json:"id"`
	Domain     string     `json:"domain"`
	Host       string     `json:"host"`
	FQDN       string     `json:"fqdn"`
	RecordID   int64      `json:"record_id"`
	TokenKind  string     `json:"token_kind"`
	Token      string     `json:"token,omitempty"`
	TokenHint  string     `json:"token_hint,omitempty"`
	Mode4      string     `json:"mode4"`
	Fixed4     string     `json:"fixed4"`
	Mode6      string     `json:"mode6"`
	Fixed6     string     `json:"fixed6"`
	Suffix6    string     `json:"suffix6"`
	Iface      string     `json:"iface"`
	Enabled    *bool      `json:"enabled,omitempty"`
	Paused     string     `json:"paused"`
	Status     string     `json:"status"`
	LastIP4    string     `json:"last_ipv4"`
	LastIP6    string     `json:"last_ipv6"`
	LastPrefix string     `json:"last_prefix"`
	LastOKAt   *time.Time `json:"last_ok_at"`
	LastError  string     `json:"last_error"`
	LastErrAt  *time.Time `json:"last_error_at"`
	DNSState   string     `json:"dns_state"` // unknown, ok, differs, redirected
}

func targetOut(t *Target) targetJSON {
	on := t.Enabled
	return targetJSON{ID: t.ID, Domain: t.Domain, Host: t.Host, FQDN: t.FQDN(), RecordID: t.RecordID, TokenKind: t.TokenKind, TokenHint: t.TokenMasked(),
		Mode4: t.Mode4, Fixed4: t.Fixed4, Mode6: t.Mode6, Fixed6: t.Fixed6, Suffix6: t.Suffix6, Iface: t.Iface, Enabled: &on, Paused: t.Paused, Status: t.Status(),
		LastIP4: t.LastIP4, LastIP6: t.LastIP6, LastPrefix: t.LastPrefix, LastOKAt: ts(t.LastOKAt), LastError: t.LastError, LastErrAt: ts(t.LastErrAt),
		DNSState: []string{"unknown", "ok", "differs", "redirected"}[min(max(t.DNSState, 0), 3)]}
}

// apply uebertraegt eine Eingabe auf ein Ziel (Token leer = unveraendert).
func (in targetJSON) apply(t *Target) {
	t.Domain, t.Host, t.Mode4, t.Fixed4, t.Mode6, t.Fixed6, t.Suffix6, t.Iface = in.Domain, in.Host, in.Mode4, in.Fixed4, in.Mode6, in.Fixed6, in.Suffix6, in.Iface
	if in.TokenKind != "" {
		t.TokenKind = in.TokenKind
	}
	if in.Token != "" {
		t.Token = in.Token
	}
	if in.RecordID != 0 {
		t.RecordID = in.RecordID
	}
	if in.Enabled != nil {
		t.Enabled = *in.Enabled
		if t.Enabled {
			t.Paused = ""
		}
	}
	if t.Mode4 == "" {
		t.Mode4 = Mode4Off
	}
	if t.Mode6 == "" {
		t.Mode6 = Mode6Off
	}
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (m *Module) apiStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	fam := func(n int) map[string]any {
		s := m.state(n)
		out := map[string]any{"ip": nil, "source": s.Source, "checked_at": ts(s.CheckedAt), "changed_at": ts(s.ChangedAt), "error": s.Err, "no_route": s.NoRoute}
		if s.IP.IsValid() {
			out["ip"] = s.IP.String()
			if n == 6 {
				out["prefix"] = prefix64(s.IP).String()
			}
		}
		return out
	}
	ni := m.lastNetInfo(ctx)
	counts := map[string]int{}
	list, _ := m.Targets(ctx)
	for _, t := range list {
		counts[t.Status()]++
	}
	out := map[string]any{"ipv4": fam(4), "ipv6": fam(6), "interval_minutes": int(m.interval() / time.Minute),
		"connection": map[string]any{"suspect": ni.Kind, "hop": ni.Hop, "checked_at": ts(ni.At)}, "targets": map[string]any{"total": len(list), "by_status": counts}}
	if m.keyOf(ctx) != "" {
		m.refreshLimit(ctx, limitPage)
		l := m.limit(ctx)
		out["limit"] = map[string]any{"known": l.Known, "used": l.Used, "limit": l.Limit, "own_24h": l.Own24h, "checked_at": ts(l.At), "error": l.Err}
	}
	if v := m.clusterView(ctx); v.On { // im Cluster: zustaendige Node ("" = wird gerade bestimmt)
		out["cluster"] = map[string]any{"leader": v.Leader, "this_node": v.Here, "preferred_node": v.Preferred}
	}
	writeJSON(w, http.StatusOK, out)
}

func (m *Module) apiCheck(w http.ResponseWriter, r *http.Request) {
	m.audit(r, "dyndns.check", "", "")
	if !m.checkNow(45 * time.Second) {
		writeErr(w, http.StatusAccepted, "check still running")
		return
	}
	m.apiStatus(w, r)
}

func (m *Module) apiTargets(w http.ResponseWriter, r *http.Request) {
	list, err := m.Targets(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := []targetJSON{}
	for _, t := range list {
		out = append(out, targetOut(t))
	}
	writeJSON(w, http.StatusOK, out)
}

func (m *Module) apiLoad(w http.ResponseWriter, r *http.Request) *Target {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	t, err := m.Target(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return nil
	}
	if t == nil {
		writeErr(w, http.StatusNotFound, "target not found")
		return nil
	}
	return t
}

func (m *Module) apiTargetGet(w http.ResponseWriter, r *http.Request) {
	if t := m.apiLoad(w, r); t != nil {
		writeJSON(w, http.StatusOK, targetOut(t))
	}
}

func fieldError(err error) string {
	if errors.Is(err, ErrExists) {
		return "a target with this domain and host exists already"
	}
	return "invalid field: " + err.Error()
}

func (m *Module) apiTargetCreate(w http.ResponseWriter, r *http.Request) {
	var in targetJSON
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	t := &Target{Enabled: true, TokenKind: "record"}
	in.apply(t)
	if err := m.InsertTarget(r.Context(), t); err != nil {
		status := http.StatusUnprocessableEntity
		if errors.Is(err, ErrExists) {
			status = http.StatusConflict
		}
		writeErr(w, status, fieldError(err))
		return
	}
	m.audit(r, "dyndns.target_add", t.FQDN(), "")
	writeJSON(w, http.StatusCreated, targetOut(t))
}

func (m *Module) apiTargetUpdate(w http.ResponseWriter, r *http.Request) {
	t := m.apiLoad(w, r)
	if t == nil {
		return
	}
	var in targetJSON
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if in.Domain == "" {
		in.Domain, in.Host = t.Domain, t.Host
	}
	if in.Domain != t.Domain || in.Host != t.Host {
		writeErr(w, http.StatusUnprocessableEntity, "domain and host cannot be changed; create a new target")
		return
	}
	in.apply(t)
	if err := m.UpdateTarget(r.Context(), t); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, fieldError(err))
		return
	}
	m.audit(r, "dyndns.target_edit", t.FQDN(), "")
	writeJSON(w, http.StatusOK, targetOut(t))
}

func (m *Module) apiTargetDelete(w http.ResponseWriter, r *http.Request) {
	t := m.apiLoad(w, r)
	if t == nil {
		return
	}
	if err := m.DeleteTarget(r.Context(), t.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	m.audit(r, "dyndns.target_delete", t.FQDN(), "")
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) apiTargetUpdateNow(w http.ResponseWriter, r *http.Request) {
	t := m.apiLoad(w, r)
	if t == nil {
		return
	}
	res, err := m.UpdateNow(r.Context(), t)
	if errors.Is(err, ErrBusy) {
		writeErr(w, http.StatusConflict, "an update round is running, try again in a few seconds")
		return
	}
	if res == NowOther {
		writeErr(w, http.StatusConflict, "another node of the cluster updates the names: "+m.clusterView(r.Context()).Leader)
		return
	}
	m.audit(r, "dyndns.update_now", t.FQDN(), "")
	if got, _ := m.Target(r.Context(), t.ID); got != nil {
		t = got
	}
	out := map[string]any{"result": res, "target": targetOut(t)}
	writeJSON(w, http.StatusOK, out)
}

func (m *Module) apiHistory(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	days, err := strconv.Atoi(q.Get("days"))
	if err != nil || days < 0 {
		days = 7
	}
	var where []string
	var args []any
	if days > 0 {
		where, args = append(where, "time >= ?"), append(args, time.Now().AddDate(0, 0, -days).UTC().Format(time.RFC3339Nano))
	}
	if q.Get("type") == "checks" {
		if f := q.Get("family"); f == "4" || f == "6" {
			where, args = append(where, "family = ?"), append(args, f)
		}
		list, more := m.queryChecks(r.Context(), where, args)
		out := []map[string]any{}
		for _, c := range list {
			out = append(out, map[string]any{"time": c.Time.UTC(), "family": c.Family, "ip": c.IP, "error": c.Err, "source": c.Source, "duration_ms": c.Ms, "changed": c.Changed})
		}
		writeJSON(w, http.StatusOK, map[string]any{"type": "checks", "items": out, "truncated": more})
		return
	}
	if id, err := strconv.ParseInt(q.Get("target"), 10, 64); err == nil && id > 0 {
		where, args = append(where, "target_id = ?"), append(args, id)
	}
	list, more := m.queryUpdates(r.Context(), where, args)
	out := []map[string]any{}
	for _, u := range list {
		out = append(out, map[string]any{"time": u.Time.UTC(), "target_id": u.TargetID, "target": u.Target, "trigger": u.Trigger, "sent_ipv4": u.Sent4, "sent_ipv6": u.Sent6,
			"sent_prefix": u.Prefix, "http_status": u.HTTP, "status": u.Status, "info": u.Info, "ok": u.OK, "error": u.Err, "duration_ms": u.Ms})
	}
	writeJSON(w, http.StatusOK, map[string]any{"type": "updates", "items": out, "truncated": more})
}

// ---------------------------------------------------------------- Einstellungen, Account, Token

func (m *Module) apiSettingsGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, m.getSettings(r.Context()))
}

// apiSettingsPut: Vollupdate; weggelassene Felder behalten ihren Wert.
func (m *Module) apiSettingsPut(w http.ResponseWriter, r *http.Request) {
	s := m.getSettings(r.Context())
	if err := readJSON(r, &s); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if err := m.saveSettings(r.Context(), s); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	m.audit(r, "dyndns.settings", "settings", "")
	writeJSON(w, http.StatusOK, m.getSettings(r.Context()))
}

// pickJSON ist ein waehlbarer Name aus dem Account (ohne Token).
type pickJSON struct {
	Key          string   `json:"key"`
	Domain       string   `json:"domain"`
	Host         string   `json:"host"`
	FQDN         string   `json:"fqdn"`
	Kind         string   `json:"kind"`
	A            []string `json:"a"`
	AAAA         []string `json:"aaaa"`
	SuffixOf     string   `json:"suffix_of,omitempty"`
	DefaultMode4 string   `json:"default_mode4"`
	DefaultMode6 string   `json:"default_mode6"`
	Exists       bool     `json:"exists"`
	Blocked      string   `json:"blocked,omitempty"`
}

func (m *Module) apiAccountNames(w http.ResponseWriter, r *http.Request) {
	key := m.keyOf(r.Context())
	if key == "" {
		writeErr(w, http.StatusConflict, "the ipv64 API key is needed (settings)")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	names, err := m.accountNames(ctx, key)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	out := []pickJSON{}
	for _, p := range names {
		out = append(out, pickJSON{Key: p.Key, Domain: p.Domain, Host: p.Host, FQDN: p.FQDN, Kind: p.Kind, A: p.A, AAAA: p.AAAA, SuffixOf: p.SuffixOf,
			DefaultMode4: p.Def4, DefaultMode6: p.Def6, Exists: p.Exists, Blocked: p.Blocked})
	}
	writeJSON(w, http.StatusOK, out)
}

// apiFromAccount legt Ziele aus dem Account an: [{"key":"home.ipv64.net|nas","mode4":"auto","mode6":"off"}].
func (m *Module) apiFromAccount(w http.ResponseWriter, r *http.Request) {
	key := m.keyOf(r.Context())
	if key == "" {
		writeErr(w, http.StatusConflict, "the ipv64 API key is needed (settings)")
		return
	}
	var in []struct {
		Key   string `json:"key"`
		Mode4 string `json:"mode4"`
		Mode6 string `json:"mode6"`
	}
	if err := readJSON(r, &in); err != nil || len(in) == 0 {
		writeErr(w, http.StatusBadRequest, "expected a JSON list of {key, mode4, mode6}")
		return
	}
	picks := map[string]pickChoice{}
	for _, p := range in {
		picks[p.Key] = pickChoice{Mode4: p.Mode4, Mode6: p.Mode6}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	added, failed, err := m.addPicked(ctx, key, picks)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	out := []targetJSON{}
	for _, t := range added {
		m.audit(r, "dyndns.target_add", t.FQDN(), "")
		out = append(out, targetOut(t))
	}
	if failed == nil {
		failed = []string{}
	}
	writeJSON(w, http.StatusCreated, map[string]any{"added": out, "failed": failed})
}

func (m *Module) apiTargetToken(w http.ResponseWriter, r *http.Request) {
	t := m.apiLoad(w, r)
	if t == nil {
		return
	}
	switch err := m.refreshToken(r.Context(), t); {
	case errors.Is(err, ipv64api.ErrNoKey):
		writeErr(w, http.StatusConflict, "the ipv64 API key is needed (settings)")
	case errors.Is(err, errNoRecord):
		writeErr(w, http.StatusNotFound, err.Error())
	case err != nil:
		writeErr(w, http.StatusBadGateway, err.Error())
	default:
		m.audit(r, "dyndns.token_refresh", t.FQDN(), "")
		writeJSON(w, http.StatusOK, targetOut(t))
	}
}

// ---------------------------------------------------------------- Export / Import (module.Exporter)

var exportSettings = []string{SetInterval, SetSource4, SetSource6, SetKeepChecks, SetKeepUpdates, SetNotifyIP, SetNotifyFail, SetNotifyLimit}

type exportData struct {
	Settings map[string]string `json:"settings"`
	Targets  []targetJSON      `json:"targets"` // ohne Tokens
}

// Export liefert Einstellungen und Ziele, aber keine Tokens (die holt der Import mit dem API-Key neu).
func (m *Module) Export(ctx context.Context) (any, error) {
	out := exportData{Settings: map[string]string{}, Targets: []targetJSON{}}
	for _, k := range exportSettings {
		if v, ok, _ := m.core.Setting(ctx, k); ok {
			out.Settings[k] = v
		}
	}
	list, err := m.Targets(ctx)
	if err != nil {
		return nil, err
	}
	for _, t := range list {
		j := targetOut(t)
		j.TokenHint, j.Status, j.LastIP4, j.LastIP6, j.LastPrefix, j.LastOKAt, j.LastError, j.LastErrAt, j.DNSState, j.Paused = "", "", "", "", "", nil, "", nil, "", ""
		out.Targets = append(out.Targets, j)
	}
	return out, nil
}

// Import uebernimmt Einstellungen und legt fehlende Ziele an; ihre Tokens kommen ueber den zentralen API-Key.
func (m *Module) Import(ctx context.Context, raw json.RawMessage) (int, error) {
	var in exportData
	if err := json.Unmarshal(raw, &in); err != nil {
		return 0, fmt.Errorf("dyndns: %w", err)
	}
	n := 0
	for _, k := range exportSettings {
		if v, ok := in.Settings[k]; ok && m.core.SetSetting(ctx, k, v) == nil {
			n++
		}
	}
	if n > 0 {
		m.clusterChanged(ctx, clusterSettingsID, false)
	}
	if len(in.Targets) == 0 {
		return n, nil
	}
	key := m.keyOf(ctx)
	if key == "" {
		return n, fmt.Errorf("dyndns: %d targets not imported, the ipv64 API key is needed to fetch their tokens", len(in.Targets))
	}
	names, err := m.accountNames(ctx, key)
	if err != nil {
		return n, fmt.Errorf("dyndns: %w", err)
	}
	byName := map[string]*pickName{}
	for _, p := range names {
		byName[p.Domain+"|"+p.Host] = p
	}
	var missing []string
	for _, j := range in.Targets {
		p := byName[strings.ToLower(j.Domain)+"|"+strings.ToLower(j.Host)]
		if p == nil {
			missing = append(missing, j.FQDN)
			continue
		}
		if p.Exists {
			continue
		}
		t := &Target{Enabled: true}
		j.Token, j.TokenKind, j.RecordID = p.token, "record", p.recordID
		j.apply(t)
		if err := m.InsertTarget(ctx, t); err != nil {
			missing = append(missing, j.FQDN)
			continue
		}
		n++
	}
	if len(missing) > 0 {
		return n, fmt.Errorf("dyndns: not imported (not in the account or invalid): %s", strings.Join(missing, ", "))
	}
	return n, nil
}
