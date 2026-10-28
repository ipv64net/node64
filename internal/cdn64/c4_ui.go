package cdn64

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Seiten und API fuer Zugriffslisten, Zugriffs-Log/Statistik und "Healthcheck anlegen".

func (m *Module) c4Routes(mux *http.ServeMux, page func(http.HandlerFunc) http.Handler) {
	mux.Handle("GET /cdn64/access", page(m.pageACLs))
	mux.Handle("GET /cdn64/access/new", page(m.pageACLNew))
	mux.Handle("POST /cdn64/access", page(m.pageACLCreate))
	mux.Handle("GET /cdn64/access/{id}", page(m.pageACLEdit))
	mux.Handle("POST /cdn64/access/{id}", page(m.pageACLUpdate))
	mux.Handle("POST /cdn64/access/{id}/delete", page(m.pageACLDelete))
	mux.Handle("GET /cdn64/log", page(m.pageLog))
	mux.Handle("POST /cdn64/log/settings", page(m.pageLogSettings))
	mux.Handle("POST /cdn64/hosts/{id}/healthcheck", page(m.pageHostCheck))
	mux.Handle("POST /cdn64/hosts/{id}/localdns", page(m.pageHostLocalDNS))
	mux.Handle("POST /cdn64/streams/{id}/healthcheck", page(m.pageStreamCheck))
	mux.Handle("POST /cdn64/blocklists", page(m.pageBlocklistsSave))
	mux.Handle("POST /cdn64/blocklists/refresh", page(m.pageBlocklistsRefresh))
	mux.Handle("POST /cdn64/blocklists/token/delete", page(m.pageBlocklistsTokenDelete))
	mux.Handle("POST /cdn64/limits", page(m.pageLimitsSave))
	mux.Handle("POST /cdn64/limits/unban", page(m.pageLimitsUnban))
	mux.Handle("POST /cdn64/honeypot", page(m.pageHoneypotSave))
	mux.Handle("POST /cdn64/honeypot/unblock", page(m.pageHoneypotUnblock))
}

func (m *Module) c4APIRoutes(mux *http.ServeMux, api func(http.HandlerFunc) http.Handler) {
	mux.Handle("GET /api/cdn64/access-lists", api(m.apiACLs))
	mux.Handle("POST /api/cdn64/access-lists", api(m.apiACLCreate))
	mux.Handle("GET /api/cdn64/access-lists/{id}", api(m.apiACLGet))
	mux.Handle("PUT /api/cdn64/access-lists/{id}", api(m.apiACLUpdate))
	mux.Handle("DELETE /api/cdn64/access-lists/{id}", api(m.apiACLDelete))
	mux.Handle("GET /api/cdn64/log", api(m.apiLog))
	mux.Handle("GET /api/cdn64/stats", api(m.apiStats))
	mux.Handle("GET /api/cdn64/blocklists", api(m.apiBlocklistsGet))
	mux.Handle("PUT /api/cdn64/blocklists", api(m.apiBlocklistsPut))
	mux.Handle("POST /api/cdn64/blocklists/refresh", api(m.apiBlocklistsRefresh))
	mux.Handle("GET /api/cdn64/limits", api(m.apiLimitsGet))
	mux.Handle("PUT /api/cdn64/limits", api(m.apiLimitsPut))
	mux.Handle("DELETE /api/cdn64/limits/bans/{ip...}", api(m.apiLimitsUnban))
	mux.Handle("GET /api/cdn64/honeypot", api(m.apiHoneypotGet))
	mux.Handle("PUT /api/cdn64/honeypot", api(m.apiHoneypotPut))
	mux.Handle("DELETE /api/cdn64/honeypot/blocks/{ip...}", api(m.apiHoneypotUnblock))
	mux.Handle("GET /api/cdn64/online", api(m.apiOnlineGet))
	mux.Handle("PUT /api/cdn64/online", api(m.apiOnlinePut))
	mux.Handle("DELETE /api/cdn64/online", api(m.apiOnlineDelete))
	mux.Handle("POST /api/cdn64/online/tunnel", api(m.apiOnlineTunnel))
	mux.Handle("POST /api/cdn64/hosts/{id}/online", api(m.apiOnlineEnable))
	mux.Handle("DELETE /api/cdn64/hosts/{id}/online", api(m.apiOnlineDisable))
	mux.Handle("POST /api/cdn64/hosts/{id}/online/test", api(m.apiOnlineTest))
	mux.Handle("POST /api/cdn64/hosts/{id}/online/pause", api(m.apiOnlinePause))
	mux.Handle("POST /api/cdn64/online/names/{rid}/pause", api(m.apiOnlineRemotePause))
	mux.Handle("GET /api/cdn64/settings", api(m.apiSettingsGet))
	mux.Handle("PUT /api/cdn64/settings", api(m.apiSettingsPut))
	mux.Handle("POST /api/cdn64/hosts/{id}/healthcheck", api(m.apiHostCheck))
	mux.Handle("POST /api/cdn64/streams/{id}/healthcheck", api(m.apiStreamCheck))
}

// ---------------------------------------------------------------- Zugriffslisten

type aclRow struct {
	*AccessList
	UsedBy []string
}

type aclsData struct {
	Tabs []tab
	Rows []aclRow
	BL   blocklistsView
	Lim  limitsView
	HP   honeypotView
}

func (m *Module) pageACLs(w http.ResponseWriter, r *http.Request) {
	list, err := m.accessLists(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	d := aclsData{Tabs: m.tabs("/cdn64/access"), BL: m.blView(r), Lim: m.limView(r.Context()), HP: m.hpView()}
	for _, a := range list {
		d.Rows = append(d.Rows, aclRow{AccessList: a.public(), UsedBy: m.aclInUse(r.Context(), a.ID)})
	}
	m.g.Render(w, r, http.StatusOK, Name+"/access", "cdn64.title", d)
}

type aclForm struct {
	Tabs    []tab
	A       *AccessList
	New     bool
	Rules   string
	Error   string
	Errors  map[string]string
	Auths   []aclAuth // Auswahl "Anmeldung"
	Headers string    // Antwort-Header des Anmeldedienstes, je Zeile
	NewKey  string    // eben angelegter API-Key (nur in dieser Antwort, nie in einem Cookie)
}

// aclAuth ist eine Wahl unter "Anmeldung" (Beispiel-Adresse fuer das Feld).
type aclAuth struct{ Value, Example string }

func aclAuths() []aclAuth {
	out := []aclAuth{{Value: AuthUsers}}
	for _, k := range []string{AuthAuthentik, AuthAuthelia, AuthOAuth2, AuthCustom} {
		out = append(out, aclAuth{Value: k, Example: fwdPresets[k].Example})
	}
	return out
}

func (m *Module) aclFormData(a *AccessList, isNew bool, rules string) aclForm {
	return aclForm{Tabs: m.tabs("/cdn64/access"), A: a, New: isNew, Rules: rules, Errors: map[string]string{}, Auths: aclAuths(),
		Headers: strings.Join(a.Forward.Headers, "\n")}
}

func rulesText(rules []AccessRule) string {
	var b strings.Builder
	for _, r := range rules {
		b.WriteString(r.Action + " " + r.CIDR + "\n")
	}
	return b.String()
}

func (m *Module) pageACLNew(w http.ResponseWriter, r *http.Request) {
	a := &AccessList{Users: []AccessUser{}, Rules: []AccessRule{}, Keys: []AccessKey{}}
	m.g.Render(w, r, http.StatusOK, Name+"/access_form", "cdn64.acl.new", m.aclFormData(a, true,
		"allow 192.168.0.0/16\nallow 10.0.0.0/8\nallow 172.16.0.0/12\nallow fc00::/7\n"))
}

func (m *Module) aclFromPath(w http.ResponseWriter, r *http.Request) (*AccessList, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		if a, err := m.accessList(r.Context(), id); err == nil {
			return a, true
		}
	}
	http.NotFound(w, r)
	return nil, false
}

func (m *Module) pageACLEdit(w http.ResponseWriter, r *http.Request) {
	a, ok := m.aclFromPath(w, r)
	if !ok {
		return
	}
	m.g.Render(w, r, http.StatusOK, Name+"/access_form", "cdn64.acl.edit", m.aclFormData(a.public(), false, rulesText(a.Rules)))
}

// parseRules: eine Regel je Zeile, "allow 192.168.0.0/16" oder "deny all".
func parseRules(text string) []AccessRule {
	var out []AccessRule
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		r := AccessRule{Action: strings.ToLower(f[0])}
		if len(f) > 1 {
			r.CIDR = f[1]
		}
		out = append(out, r)
	}
	return out
}

// usersFromForm: bestehende Benutzer (behalten, ausser "entfernen"), neue als "name:passwort" je Zeile.
func usersFromForm(r *http.Request, a *AccessList) []UserInput {
	var out []UserInput
	remove := map[string]bool{}
	for _, n := range r.PostForm["remove_user"] {
		remove[n] = true
	}
	at := map[string]int{} // bestehender Benutzer -> Stelle in out
	for _, u := range a.Users {
		if !remove[u.Username] {
			at[u.Username] = len(out)
			out = append(out, UserInput{Username: u.Username})
		}
	}
	for _, line := range strings.Split(r.PostFormValue("new_users"), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		name, pass, _ := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		if i, ok := at[name]; ok && pass != "" { // "anna:neu" fuer einen bestehenden Benutzer = neues Passwort
			out[i].Password = pass
			continue
		}
		out = append(out, UserInput{Username: name, Password: pass})
	}
	return out
}

func (m *Module) pageACLCreate(w http.ResponseWriter, r *http.Request) {
	a := &AccessList{}
	m.saveACLForm(w, r, a, true)
}

func (m *Module) pageACLUpdate(w http.ResponseWriter, r *http.Request) {
	a, ok := m.aclFromPath(w, r)
	if !ok {
		return
	}
	m.saveACLForm(w, r, a, false)
}

func (m *Module) saveACLForm(w http.ResponseWriter, r *http.Request, a *AccessList, isNew bool) {
	_ = r.ParseForm()
	users := usersFromForm(r, a)
	a.Name, a.SatisfyAny, a.PassAuth = r.PostFormValue("name"), r.PostFormValue("satisfy_any") == "1", r.PostFormValue("pass_auth") == "on"
	a.LoginPage = r.PostFormValue("login_page") == "on"
	a.Rules = parseRules(r.PostFormValue("rules"))
	a.Auth, a.PassUser = r.PostFormValue("auth"), r.PostFormValue("pass_user") == "on"
	a.Forward = ForwardAuth{Address: r.PostFormValue("fwd_address"), Headers: strings.Fields(r.PostFormValue("fwd_headers")),
		Callback: r.PostFormValue("fwd_callback")}
	// API-Keys: bestehende behalten (ausser "entfernen"), ein neuer mit Namen wird erzeugt und einmal angezeigt
	removeKey := map[string]bool{}
	for _, h := range r.PostForm["remove_key"] {
		removeKey[h] = true
	}
	var keys []AccessKey
	for _, k := range a.Keys {
		if !removeKey[k.Hint] {
			keys = append(keys, k)
		}
	}
	newKey := ""
	if n := strings.TrimSpace(r.PostFormValue("new_key")); n != "" {
		var k AccessKey
		k, newKey = newAccessKey(n)
		keys = append(keys, k)
	}
	a.Keys = keys
	if err := m.saveAccessList(r.Context(), a, users); err != nil {
		d := m.aclFormData(a.public(), isNew, r.PostFormValue("rules"))
		d.Headers = r.PostFormValue("fwd_headers")
		var fe *FieldError
		if errors.As(err, &fe) {
			d.Errors[fe.Field] = m.g.T(r, fe.Key, "name", fe.Name)
		} else {
			d.Error = err.Error()
		}
		m.g.Render(w, r, http.StatusUnprocessableEntity, Name+"/access_form", "cdn64.acl.new", d)
		return
	}
	action := "cdn64.acl.update"
	if isNew {
		action = "cdn64.acl.create"
	}
	m.g.Audit(r, action, a.Name, fmt.Sprintf("users=%d rules=%d satisfy_any=%v pass_auth=%v login_page=%v auth=%s keys=%d pass_user=%v", len(a.Users),
		len(a.Rules), a.SatisfyAny, a.PassAuth, a.LoginPage, a.Auth, len(a.Keys), a.PassUser))
	if newKey != "" { // nur in dieser Antwort sichtbar (kein Flash: der liegt in einem Cookie)
		d := m.aclFormData(a.public(), false, rulesText(a.Rules))
		d.NewKey = newKey
		m.g.Render(w, r, http.StatusOK, Name+"/access_form", "cdn64.acl.edit", d)
		return
	}
	m.g.Flash(w, r, "success", m.g.T(r, "common.saved"))
	http.Redirect(w, r, "/cdn64/access", http.StatusSeeOther)
}

func (m *Module) pageACLDelete(w http.ResponseWriter, r *http.Request) {
	a, ok := m.aclFromPath(w, r)
	if !ok {
		return
	}
	if err := m.deleteAccessList(r.Context(), a.ID); err != nil {
		var fe *FieldError
		if errors.As(err, &fe) {
			m.g.Flash(w, r, "danger", m.g.T(r, fe.Key, "name", fe.Name))
		} else {
			m.g.Flash(w, r, "danger", err.Error())
		}
	} else {
		m.g.Audit(r, "cdn64.acl.delete", a.Name, "")
		m.g.Flash(w, r, "success", m.g.T(r, "cdn64.deleted", "name", a.Name))
	}
	http.Redirect(w, r, "/cdn64/access", http.StatusSeeOther)
}

// ---------------------------------------------------------------- Zugriffs-Log und Statistik

type logData struct {
	Tabs     []tab
	Hosts    []*Host
	HostName map[int64]string
	Entries  []LogEntry
	Filter   LogFilter
	Next     int64
	Days     int
	Anon     bool
	Sums     map[int64]HostStat
	Total    HostStat
	Enabled  int // Hosts mit Einzel-Log
	NoDB     bool
	// DecoyActive: Honeypot-Koeder aktiv (Kennzahl "an den Honeypot" auch ohne Werte zeigen)
	DecoyActive bool
}

func (m *Module) pageLog(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	f := LogFilter{Query: q.Get("q"), Limit: 100, Rejected: q.Get("status") == "r", Decoy: q.Get("status") == "d"}
	f.HostID, _ = strconv.ParseInt(q.Get("host"), 10, 64)
	f.Status, _ = strconv.Atoi(q.Get("status"))
	f.Before, _ = strconv.ParseInt(q.Get("before"), 10, 64)
	d := logData{Tabs: m.tabs("/cdn64/log"), HostName: map[int64]string{}, Filter: f, Days: m.logDays(ctx),
		Anon: m.core.SettingOr(ctx, setAnonymize, "off") == "mask"}
	hosts, err := m.hosts(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	d.Hosts = hosts
	for _, h := range hosts {
		d.HostName[h.ID] = h.Names[0]
		if h.Advanced.AccessLog {
			d.Enabled++
		}
	}
	sdb := m.stats2.Load()
	if sdb == nil {
		d.NoDB = true
	} else {
		if d.Entries, err = sdb.entries(ctx, f); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(d.Entries) == f.Limit {
			d.Next = d.Entries[len(d.Entries)-1].ID
		}
		d.DecoyActive = m.hpDecoyActive()
		d.Sums, _ = sdb.sums(ctx, time.Now().Add(-24*time.Hour))
		for _, s := range d.Sums {
			d.Total.Requests += s.Requests
			d.Total.S2 += s.S2
			d.Total.S3 += s.S3
			d.Total.S4 += s.S4
			d.Total.S5 += s.S5
			d.Total.Bytes += s.Bytes
			d.Total.BytesIn += s.BytesIn
			d.Total.Blocked += s.Blocked
			d.Total.Decoy += s.Decoy
		}
	}
	m.g.Render(w, r, http.StatusOK, Name+"/log", "cdn64.title", d)
}

func (m *Module) saveLogSettings(ctx context.Context, days int, anon bool) error {
	if days < 1 || days > 90 {
		return ferr("days", "cdn64.err.log_days")
	}
	if err := m.core.SetSetting(ctx, setLogDays, strconv.Itoa(days)); err != nil {
		return err
	}
	v := "off"
	if anon {
		v = "mask"
	}
	return m.core.SetSetting(ctx, setAnonymize, v)
}

func (m *Module) pageLogSettings(w http.ResponseWriter, r *http.Request) {
	days, _ := strconv.Atoi(r.PostFormValue("days"))
	anon := r.PostFormValue("anonymize") == "on"
	if err := m.saveLogSettings(r.Context(), days, anon); err != nil {
		m.g.Flash(w, r, "danger", m.g.T(r, "cdn64.err.log_days"))
	} else {
		m.g.Audit(r, "cdn64.settings", "", fmt.Sprintf("log_days=%d anonymize=%v", days, anon))
		m.g.Flash(w, r, "success", m.g.T(r, "common.saved"))
	}
	http.Redirect(w, r, "/cdn64/log", http.StatusSeeOther)
}

// ---------------------------------------------------------------- Healthcheck anlegen

// checkBody: JSON fuer einen Healthcheck auf ein Ziel (http fuer http-Ziele und gepruefte https-Ziele, sonst tcp).
func checkBody(name, scheme, host string, port int, verify bool) []byte {
	body := map[string]any{"name": trunc(name, 100), "tags": []string{"cdn64"}, "description": "PROXY64"}
	if scheme == "http" || (scheme == "https" && verify) {
		u := scheme + "://" + host
		if strings.Contains(host, ":") {
			u = scheme + "://[" + host + "]"
		}
		body["type"], body["target"] = "http", u+":"+strconv.Itoa(port)+"/"
	} else {
		body["type"], body["target"], body["params"] = "tcp", host, map[string]int{"port": port}
	}
	b, _ := json.Marshal(body)
	return b
}

func (m *Module) createCheck(r *http.Request, name, scheme, host string, port int, verify bool) (string, error) {
	if m.checks == nil {
		return "", errors.New("healthchecks not running")
	}
	return m.checks(r, checkBody("PROXY64: "+name, scheme, host, port, verify))
}

func (m *Module) hostCheck(r *http.Request) (*Host, string, error) {
	h, err := m.host(r.Context(), pathID(r))
	if err != nil {
		return nil, "", err
	}
	if !h.probed() {
		return h, "", ferr("kind", "cdn64.err.no_target")
	}
	scheme := h.Scheme
	if h.Kind == KindPass { // TLS gehoert dem Ziel: Verbindung genuegt
		scheme = "tcp"
	}
	tok, err := m.createCheck(r, h.Names[0], scheme, h.TargetHost, h.TargetPort, h.VerifyTarget)
	return h, tok, err
}

func (m *Module) pageHostCheck(w http.ResponseWriter, r *http.Request) {
	h, tok, err := m.hostCheck(r)
	back := "/cdn64"
	if h != nil {
		back = listPath(h.Kind)
	}
	if err != nil {
		m.g.Flash(w, r, "danger", m.g.T(r, "cdn64.check_failed", "error", err.Error()))
	} else {
		m.g.Flash(w, r, "success", m.g.T(r, "cdn64.check_created", "name", h.Names[0], "token", tok))
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

func (m *Module) pageStreamCheck(w http.ResponseWriter, r *http.Request) {
	s, err := m.stream(r.Context(), pathID(r))
	if err == nil {
		var tok string
		name := s.Name
		if name == "" {
			name = "Stream " + strconv.Itoa(s.ListenPort)
		}
		if tok, err = m.createCheck(r, name, "tcp", s.TargetHost, s.TargetPort, false); err == nil {
			m.g.Flash(w, r, "success", m.g.T(r, "cdn64.check_created", "name", name, "token", tok))
		}
	}
	if err != nil {
		m.g.Flash(w, r, "danger", m.g.T(r, "cdn64.check_failed", "error", err.Error()))
	}
	http.Redirect(w, r, "/cdn64/streams", http.StatusSeeOther)
}

// ---------------------------------------------------------------- API

func (m *Module) apiACLs(w http.ResponseWriter, r *http.Request) {
	list, err := m.accessLists(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, a := range list {
		out = append(out, map[string]any{"access_list": a.public(), "used_by": m.aclInUse(r.Context(), a.ID)})
	}
	writeJSON(w, http.StatusOK, out)
}

func (m *Module) apiACLGet(w http.ResponseWriter, r *http.Request) {
	a, err := m.accessList(r.Context(), pathID(r))
	if err != nil {
		m.apiFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a.public())
}

// aclInput: wie AccessList, Benutzer mit Klartext-Passwort (leer = behalten).
type aclInput struct {
	Name       *string      `json:"name"`
	SatisfyAny *bool        `json:"satisfy_any"`
	PassAuth   *bool        `json:"pass_auth"`
	LoginPage  *bool        `json:"login_page"`
	Users      []UserInput  `json:"users"`
	Rules      []AccessRule `json:"rules"`
	Auth       *string      `json:"auth"`
	Forward    *ForwardAuth `json:"forward"`
	PassUser   *bool        `json:"pass_user"`
	AddKey     string       `json:"add_key"`     // Name eines neuen API-Keys (der Key steht einmal in der Antwort)
	RemoveKeys []string     `json:"remove_keys"` // Anfang (hint) der zu loeschenden Keys
}

func (m *Module) apiACLSave(w http.ResponseWriter, r *http.Request, a *AccessList, status int) {
	var in aclInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if in.Name != nil {
		a.Name = *in.Name
	}
	if in.SatisfyAny != nil {
		a.SatisfyAny = *in.SatisfyAny
	}
	if in.PassAuth != nil {
		a.PassAuth = *in.PassAuth
	}
	if in.LoginPage != nil {
		a.LoginPage = *in.LoginPage
	}
	if in.Rules != nil {
		a.Rules = in.Rules
	}
	if in.Auth != nil {
		a.Auth = *in.Auth
	}
	if in.Forward != nil {
		a.Forward = *in.Forward
	}
	if in.PassUser != nil {
		a.PassUser = *in.PassUser
	}
	var keys []AccessKey
	for _, k := range a.Keys {
		if !slices.Contains(in.RemoveKeys, k.Hint) {
			keys = append(keys, k)
		}
	}
	newKey := ""
	if n := strings.TrimSpace(in.AddKey); n != "" {
		var k AccessKey
		k, newKey = newAccessKey(n)
		keys = append(keys, k)
	}
	a.Keys = keys
	users := in.Users
	if users == nil { // unveraendert
		for _, u := range a.Users {
			users = append(users, UserInput{Username: u.Username})
		}
	}
	if err := m.saveAccessList(r.Context(), a, users); err != nil {
		m.apiFail(w, err)
		return
	}
	action := "cdn64.acl.update"
	if status == http.StatusCreated {
		action = "cdn64.acl.create"
	}
	m.g.Audit(r, action, a.Name, fmt.Sprintf("users=%d rules=%d auth=%s keys=%d", len(a.Users), len(a.Rules), a.Auth, len(a.Keys)))
	writeJSON(w, status, struct {
		*AccessList
		Key string `json:"key,omitempty"` // neuer API-Key, nur in dieser Antwort
	}{a.public(), newKey})
}

func (m *Module) apiACLCreate(w http.ResponseWriter, r *http.Request) {
	m.apiACLSave(w, r, &AccessList{}, http.StatusCreated)
}

func (m *Module) apiACLUpdate(w http.ResponseWriter, r *http.Request) {
	a, err := m.accessList(r.Context(), pathID(r))
	if err != nil {
		m.apiFail(w, err)
		return
	}
	m.apiACLSave(w, r, a, http.StatusOK)
}

func (m *Module) apiACLDelete(w http.ResponseWriter, r *http.Request) {
	a, err := m.accessList(r.Context(), pathID(r))
	if err != nil {
		m.apiFail(w, err)
		return
	}
	if err := m.deleteAccessList(r.Context(), a.ID); err != nil {
		var fe *FieldError
		if errors.As(err, &fe) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "access list in use by " + fe.Name})
			return
		}
		m.apiFail(w, err)
		return
	}
	m.g.Audit(r, "cdn64.acl.delete", a.Name, "")
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) apiLog(w http.ResponseWriter, r *http.Request) {
	sdb := m.stats2.Load()
	if sdb == nil {
		writeErr(w, http.StatusServiceUnavailable, "statistics not available")
		return
	}
	q := r.URL.Query()
	f := LogFilter{Query: q.Get("q"), Rejected: q.Get("rejected") == "1" || q.Get("status") == "r", Decoy: q.Get("decoy") == "1" || q.Get("status") == "d"}
	f.HostID, _ = strconv.ParseInt(q.Get("host"), 10, 64)
	f.Status, _ = strconv.Atoi(q.Get("status"))
	f.Before, _ = strconv.ParseInt(q.Get("before"), 10, 64)
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	list, err := sdb.entries(r.Context(), f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if list == nil {
		list = []LogEntry{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (m *Module) apiStats(w http.ResponseWriter, r *http.Request) {
	sdb := m.stats2.Load()
	if sdb == nil {
		writeErr(w, http.StatusServiceUnavailable, "statistics not available")
		return
	}
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if hours < 1 || hours > 24*90 {
		hours = 24
	}
	host, _ := strconv.ParseInt(r.URL.Query().Get("host"), 10, 64)
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	sums, err := sdb.sums(r.Context(), since)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	pts, err := sdb.hours(r.Context(), host, since)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	byHost := map[string]HostStat{}
	for id, s := range sums {
		byHost[strconv.FormatInt(id, 10)] = s
	}
	if pts == nil {
		pts = []HourPoint{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"hours": hours, "hosts": byHost, "timeline": pts, "dropped": sdb.dropped.Load(),
		"decoy_active": m.hpDecoyActive()})
}

func (m *Module) apiSettingsGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"log_days": m.logDays(r.Context()), "anonymize": m.core.SettingOr(r.Context(), setAnonymize, "off") == "mask"})
}

func (m *Module) apiSettingsPut(w http.ResponseWriter, r *http.Request) {
	in := struct {
		LogDays   *int  `json:"log_days"`
		Anonymize *bool `json:"anonymize"`
	}{}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&in); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	days, anon := m.logDays(r.Context()), m.core.SettingOr(r.Context(), setAnonymize, "off") == "mask"
	if in.LogDays != nil {
		days = *in.LogDays
	}
	if in.Anonymize != nil {
		anon = *in.Anonymize
	}
	if err := m.saveLogSettings(r.Context(), days, anon); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "log_days must be 1-90", "field": "log_days"})
		return
	}
	m.g.Audit(r, "cdn64.settings", "", fmt.Sprintf("log_days=%d anonymize=%v", days, anon))
	m.apiSettingsGet(w, r)
}

func (m *Module) apiHostCheck(w http.ResponseWriter, r *http.Request) {
	h, tok, err := m.hostCheck(r)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeErr(w, http.StatusNotFound, "host not found")
			return
		}
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"token": tok, "host": h.Names[0]})
}

func (m *Module) apiStreamCheck(w http.ResponseWriter, r *http.Request) {
	s, err := m.stream(r.Context(), pathID(r))
	if err != nil {
		writeErr(w, http.StatusNotFound, "stream not found")
		return
	}
	name := s.Name
	if name == "" {
		name = "Stream " + strconv.Itoa(s.ListenPort)
	}
	tok, err := m.createCheck(r, name, "tcp", s.TargetHost, s.TargetPort, false)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"token": tok, "stream": name})
}
