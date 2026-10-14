package healthchecks

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/module"
)

// Online-Checks direkt ueber die ipv64 API v2: Ist die Node nicht ueber den Healthchecks-Sync mit den hubs
// verknuepft, aber ein zentraler API-Key hinterlegt, verwaltet sie die Online-Checks des Accounts direkt
// (anlegen, aendern, pausieren, pruefen, loeschen). Gemessen wird bei ipv64; die Zustaende kommen beim Laden
// der Seite. Hybrid-Checks, Live-Zustaende und Benachrichtigungen ueber ipv64 brauchen den Sync.

// SetAPI haengt den zentralen API-Key an (nil = keine Online-Checks ueber die API).
func (m *Module) SetAPI(k *ipv64api.Key) { m.api = k }

// apiMode liefert Key und Client, wenn die Online-Checks ueber die API laufen (Key da, kein Sync).
func (m *Module) apiMode(ctx context.Context) (string, *ipv64api.Client) {
	if m.api == nil || (m.linked != nil && m.linked()) {
		return "", nil
	}
	key := m.api.Get(ctx)
	if key == "" {
		return "", nil
	}
	return key, m.api.Client()
}

// onlineRow ist ein Online-Check fuer die Uebersicht.
type onlineRow struct {
	Token, Name, Type, State, Message string
	Badge                             Badge
	Target                            string
	Interval                          int
	Locs                              string
	LastCheck                         time.Time
	Paused                            bool
}

type onlineCache struct {
	mu   sync.Mutex
	at   time.Time
	rows []onlineRow
	err  string
}

// onlineChecks holt die Online-Checks des Accounts (20 s zwischengespeichert, die Uebersicht laedt
// sich regelmaessig neu).
func (m *Module) onlineChecks(ctx context.Context, key string, cl *ipv64api.Client) ([]onlineRow, string) {
	c := &m.onl
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.at.IsZero() && time.Since(c.at) < 20*time.Second {
		return c.rows, c.err
	}
	lctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	list, err := cl.HC2Checks(lctx, key, "?execution=online")
	c.at = time.Now()
	if err != nil {
		c.err = err.Error()
		return c.rows, c.err
	}
	c.rows, c.err = nil, ""
	for _, raw := range list {
		var j checkJSON
		if json.Unmarshal(raw, &j) != nil {
			continue
		}
		tmp := &Check{Type: checks.Type(j.Type), Target: j.Target, Params: j.Params}
		r := onlineRow{Token: j.Token, Name: j.Name, Type: j.Type, Badge: tmp.TargetBadge(), Target: tmp.DisplayTarget(), Locs: strings.Join(j.Locations, ", "), State: "pending"}
		if j.IntervalSeconds != nil {
			r.Interval = *j.IntervalSeconds
		}
		if j.Paused != nil {
			r.Paused = *j.Paused
		}
		if j.State != nil {
			r.State, r.LastCheck, r.Message = j.State.State, j.State.LastCheckAt, j.State.LastMessage
		}
		if r.Locs == "" {
			r.Locs = "fsn, nbg"
		}
		c.rows = append(c.rows, r)
	}
	return c.rows, ""
}

func (m *Module) onlineInvalidate() {
	m.onl.mu.Lock()
	m.onl.at = time.Time{}
	m.onl.mu.Unlock()
}

func (m *Module) onlineRoutes(mux *http.ServeMux, g module.Guards) {
	page := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /healthchecks/online/new", page(m.onlineForm))
	mux.Handle("POST /healthchecks/online/new", page(m.onlineSubmit))
	mux.Handle("GET /healthchecks/online/{token}/edit", page(m.onlineForm))
	mux.Handle("POST /healthchecks/online/{token}/edit", page(m.onlineSubmit))
	mux.Handle("POST /healthchecks/online/{token}/{action}", page(m.onlineAction))
}

// onlineForm zeigt das Check-Formular fuer einen Online-Check (Werte von ipv64 beim Bearbeiten).
func (m *Module) onlineForm(w http.ResponseWriter, r *http.Request) {
	key, cl := m.apiMode(r.Context())
	if key == "" {
		http.Redirect(w, r, "/healthchecks", http.StatusSeeOther)
		return
	}
	d := formData{Form: formDefaults(), APIMode: true}
	d.Form["execution"] = "online"
	if t := r.PathValue("token"); t != "" {
		j, err := m.remoteCheck(r.Context(), key, cl, t)
		if err != nil {
			m.g.Flash(w, r, "danger", m.g.T(r, "hc.api.error")+": "+err.Error())
			http.Redirect(w, r, "/healthchecks#online", http.StatusSeeOther)
			return
		}
		tmp := &Check{Token: t}
		j.Execution = "local" // nur fuer die lokale Umwandlung; gemessen wird online
		if err := m.apply(tmp, j, true); err != nil {
			d.Error = err.Error()
		}
		d.Edit, d.Token, d.Form = true, t, formFromCheck(tmp)
		d.Form["execution"], d.Form["locations"] = "online", strings.Join(j.Locations, ",")
	}
	m.formPage(w, r, http.StatusOK, d)
}

func (m *Module) remoteCheck(ctx context.Context, key string, cl *ipv64api.Client, token string) (checkJSON, error) {
	var j checkJSON
	raw, err := cl.HC2Check(ctx, key, token)
	if err == nil {
		err = json.Unmarshal(raw, &j)
	}
	return j, err
}

// onlineSubmit prueft die Eingaben wie bei lokalen Checks und speichert sie bei ipv64.
func (m *Module) onlineSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	key, cl := m.apiMode(ctx)
	if key == "" {
		http.Redirect(w, r, "/healthchecks", http.StatusSeeOther)
		return
	}
	token := r.PathValue("token")
	in, err := checkFromForm(r)
	if err == nil {
		tmp := &Check{Token: "online"}
		if err = splitPort(tmp, &in); err == nil {
			vin := in
			vin.Execution = "local" // Pruefung der Eingaben wie lokal; die Regel "online nur mit Sync" gilt hier nicht
			err = m.apply(tmp, vin, true)
		}
		in.Execution = "online"
	}
	if err == nil {
		body := map[string]any{}
		raw, _ := json.Marshal(in)
		_ = json.Unmarshal(raw, &body)
		for _, k := range []string{"token", "owner", "nodes", "revision", "created_at", "updated_at", "push_url", "state", "channels", "parent"} {
			delete(body, k) // lokale Kanaele und Eltern-Checks gelten bei ipv64 nicht
		}
		body["execution"] = "online"
		if token != "" {
			if old, gerr := m.remoteCheck(ctx, key, cl, token); gerr == nil {
				body["channels"], body["force_move"] = old.Channels, true // Kanaele bei ipv64 behalten, Standorte ohne Testlauf
				if old.Parent != nil {
					body["parent"] = *old.Parent
				}
			}
		}
		_, err = cl.HC2SaveCheck(ctx, key, token, body)
	}
	if err != nil {
		m.log.Warn("online check not saved via ipv64 API", "token", token, "err", err)
		_ = r.ParseForm()
		d := formData{Form: formDefaults(), APIMode: true, Edit: token != "", Token: token, Error: err.Error()}
		for k := range r.PostForm {
			d.Form[k] = r.PostFormValue(k)
		}
		m.formPage(w, r, http.StatusUnprocessableEntity, d)
		return
	}
	m.onlineInvalidate()
	if token == "" {
		m.auditText(r, "check.online_create", in.Name)
	} else {
		m.auditText(r, "check.online_update", in.Name+" ("+token+")")
	}
	m.g.Flash(w, r, "success", m.g.T(r, "common.saved"))
	http.Redirect(w, r, "/healthchecks#online", http.StatusSeeOther)
}

// onlineAction: pausieren, fortsetzen, jetzt pruefen, loeschen.
func (m *Module) onlineAction(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	key, cl := m.apiMode(ctx)
	token, action := r.PathValue("token"), r.PathValue("action")
	if key == "" {
		http.Redirect(w, r, "/healthchecks", http.StatusSeeOther)
		return
	}
	var err error
	switch action {
	case "pause", "resume", "run":
		err = cl.HC2CheckAction(ctx, key, token, action)
	case "delete":
		err = cl.HC2DeleteCheck(ctx, key, token)
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		m.log.Warn("online check action via ipv64 API failed", "token", token, "action", action, "err", err)
		m.g.Flash(w, r, "danger", m.g.T(r, "hc.api.error")+": "+err.Error())
	} else {
		m.auditText(r, "check.online_"+action, token)
		m.onlineInvalidate()
		m.g.Flash(w, r, "success", m.g.T(r, "hc.api.done_"+action))
	}
	http.Redirect(w, r, "/healthchecks#online", http.StatusSeeOther)
}
