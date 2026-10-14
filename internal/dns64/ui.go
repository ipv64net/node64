package dns64

import (
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/dns64/filter"
	"github.com/ipv64net/node64/internal/dns64/upstream"
	"github.com/ipv64net/node64/internal/module"
)

//go:embed templates
var templateFS embed.FS

// Templates liefert die Seiten des Moduls (module.Templater).
func (m *Module) Templates() fs.FS {
	sub, _ := fs.Sub(templateFS, "templates")
	return sub
}

func (m *Module) uiRoutes(mux *http.ServeMux, g module.Guards) {
	m.g = g
	page := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /dns64", page(m.pageTab("overview", "dns64.title")))
	mux.Handle("GET /dns64/log", page(m.pageTab("log", "dns64.log.title")))
	mux.Handle("GET /dns64/lists", page(m.pageTab("lists", "dns64.lists.title")))
	mux.Handle("GET /dns64/records", page(m.pageTab("records", "dns64.records.title")))
	mux.Handle("GET /dns64/encrypted", page(m.pageTab("encrypted", "dns64.enc.title")))
	mux.Handle("POST /dns64/encrypted", page(m.pageEncryptedSave))
	mux.Handle("GET /dns64/ca.crt", page(m.pageCA))
	mux.Handle("POST /dns64/acme", page(m.pageACME))
	mux.Handle("POST /dns64/acme/renew", page(m.pageACMERenew))
	mux.Handle("GET /dns64/dns64.mobileconfig", page(m.pageProfile))
	mux.Handle("GET /dns64/settings", page(m.pageTab("settings", "dns64.settings.title")))
	mux.Handle("POST /dns64/settings", page(m.pageSettingsSave))
	mux.Handle("POST /dns64/upstreams", page(m.pageUpstreamsSave))
	mux.Handle("POST /dns64/upstreams/add", page(m.pageUpstreamAdd))
	mux.Handle("POST /dns64/upstreams/remove", page(m.pageUpstreamRemove))
	mux.Handle("POST /dns64/lists", page(m.pageListsSave))
	mux.Handle("POST /dns64/lists/add", page(m.pageListAdd))
	mux.Handle("POST /dns64/lists/remove", page(m.pageListRemove))
	mux.Handle("POST /dns64/allowlist/import", page(m.pageAllowImport))
	mux.Handle("POST /dns64/records", page(m.pageRecordAdd))
	mux.Handle("POST /dns64/records/{id}/delete", page(m.pageRecordDelete))
	mux.Handle("POST /dns64/records/{id}/toggle", page(m.pageRecordToggle))
}

// tab ist ein Reiter der Modulseiten.
type tab struct {
	Key, Path, TitleKey, Icon string
	Active                    bool
}

type pageData struct {
	Tabs    []tab
	Running bool
	Err     string // DNS-Dienst laeuft nicht: Grund
	Listen  string
	Started time.Time
	Router  string
	Source  string // config | auto
	JS      map[string]any
	Cfg     config
	Hours   []int
	Records []Record
	Types   []string
	Enc     encView
}

var tabs = []tab{{"overview", "/dns64", "dns64.tab.overview", "bi-speedometer2", false}, {"log", "/dns64/log", "dns64.tab.log", "bi-list-ul", false},
	{"lists", "/dns64/lists", "dns64.tab.lists", "bi-funnel", false}, {"records", "/dns64/records", "dns64.tab.records", "bi-signpost-split", false},
	{"encrypted", "/dns64/encrypted", "dns64.tab.encrypted", "bi-lock", false}, {"settings", "/dns64/settings", "dns64.tab.settings", "bi-gear", false}}

func (m *Module) pageTab(key, titleKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		d := pageData{Cfg: m.loadConfig(ctx), Hours: listHours, Types: recordTypes}
		for _, t := range tabs {
			t.Active = t.Key == key
			d.Tabs = append(d.Tabs, t)
		}
		if e := m.running(); e != nil {
			d.Running, d.Listen, d.Started, d.Router, d.Source = true, e.addr, e.started, e.local.Addr(), e.local.Source()
		}
		d.Err = m.startError()
		if key == "encrypted" {
			d.Enc = m.encView(r, d.Cfg)
		}
		if key == "records" {
			var err error
			if d.Records, err = m.Records(ctx); err != nil {
				m.g.Flash(w, r, "danger", err.Error())
			}
		}
		d.JS = map[string]any{"csrf": m.g.CSRF(r), "lang": m.g.Lang(r), "t": m.jsTexts(r)}
		m.g.Render(w, r, http.StatusOK, Name+"/"+key, titleKey, d)
	}
}

// jsKeys sind die Texte, die dns64.js braucht (Schluessel unter "dns64.js.").
var jsKeys = []string{"status.allowed", "status.blocked", "status.cached", "status.local", "status.error", "status.custom",
	"released", "release", "release_title", "release_confirm", "unrelease_confirm", "released_toast", "unreleased_toast", "remove",
	"no_releases", "ready", "online", "disturbed", "avg", "fastest", "requests", "errors", "last_error", "router_auto", "router_config", "router_none",
	"of", "failed", "just_now", "min_ago", "hours_ago", "days_ago", "per_hour", "pct_all", "pct_cache", "loaded", "no_data", "empty_chart",
	"blocked_n", "no_entries", "via", "entries", "page", "live_paused", "flush_confirm", "flushed", "error", "active", "loading",
	"sec", "min", "hours", "uptime", "allowed", "blocked", "no_conn", "reason_stale", "reason_released", "mode_parallel", "mode_ordered", "off",
	"proto.udp", "proto.tcp", "proto.doh", "proto.dot", "proto.doq"}

func (m *Module) jsTexts(r *http.Request) map[string]string {
	out := make(map[string]string, len(jsKeys))
	for _, k := range jsKeys {
		out[k] = m.g.T(r, "dns64.js."+k)
	}
	return out
}

// errText uebersetzt Eingabefehler (cfgError) und gibt andere Fehler als Text zurueck.
func (m *Module) errText(r *http.Request, err error) string {
	var ce *cfgError
	if errors.As(err, &ce) {
		return m.g.T(r, "dns64.err."+strings.TrimPrefix(ce.Key, "err_"), ce.Args...)
	}
	if errors.Is(err, errNotFound) {
		return m.g.T(r, "dns64.err.not_found")
	}
	return err.Error()
}

// apply speichert die Einstellungen, startet den DNS-Dienst neu und leitet mit Meldung zurueck.
func (m *Module) apply(w http.ResponseWriter, r *http.Request, back string, c config) {
	ctx := r.Context()
	if err := m.saveConfig(ctx, c); err != nil {
		m.g.Flash(w, r, "danger", m.errText(r, err))
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	m.log.Info("settings saved", "page", back, "by", m.g.Actor(r))
	if err := m.restart(ctx); err != nil {
		m.log.Error("restart after settings failed", "err", err)
		m.g.Flash(w, r, "danger", m.g.T(r, "dns64.err.restart", "err", err.Error()))
	} else {
		m.g.Flash(w, r, "success", m.g.T(r, "common.saved"))
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

func formInt(r *http.Request, key string) int {
	n, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue(key)))
	if err != nil {
		return -1
	}
	return n
}

func (m *Module) pageSettingsSave(w http.ResponseWriter, r *http.Request) {
	c := m.loadConfig(r.Context())
	c.Port, c.Bind, c.Router, c.Retention = formInt(r, "port"), r.PostFormValue("bind"), r.PostFormValue("router"), formInt(r, "retention")
	c.CacheSize, c.BlockMode, c.Anonymize = formInt(r, "cache_size"), r.PostFormValue("block_mode"), r.PostFormValue("anonymize")
	c.NotifyUp, c.NotifyLst = r.PostFormValue("notify_upstream") != "", r.PostFormValue("notify_lists") != ""
	c.AllowNets = splitLines(r.PostFormValue("allow_nets"))
	m.apply(w, r, "/dns64/settings", c)
}

// pageUpstreamsSave uebernimmt die Haken (on_<index>) und die Betriebsart.
func (m *Module) pageUpstreamsSave(w http.ResponseWriter, r *http.Request) {
	c := m.loadConfig(r.Context())
	for i := range c.Upstreams {
		c.Upstreams[i].Enabled = r.PostFormValue("on_"+strconv.Itoa(i)) != ""
	}
	c.UpMode = r.PostFormValue("mode")
	m.apply(w, r, "/dns64/settings#upstreams", c)
}

func (m *Module) pageUpstreamAdd(w http.ResponseWriter, r *http.Request) {
	c := m.loadConfig(r.Context())
	s := upstream.Server{Name: r.PostFormValue("name"), URL: r.PostFormValue("url"), IPs: splitLines(r.PostFormValue("ips"))}
	c.Upstreams = append(c.Upstreams, upstreamSetting{Server: s, Enabled: true, Custom: true})
	m.apply(w, r, "/dns64/settings#upstreams", c)
}

func (m *Module) pageUpstreamRemove(w http.ResponseWriter, r *http.Request) {
	c := m.loadConfig(r.Context())
	if i := formInt(r, "remove"); i >= 0 && i < len(c.Upstreams) && c.Upstreams[i].Custom {
		c.Upstreams = append(c.Upstreams[:i], c.Upstreams[i+1:]...)
	}
	m.apply(w, r, "/dns64/settings#upstreams", c)
}

func (m *Module) pageListsSave(w http.ResponseWriter, r *http.Request) {
	c := m.loadConfig(r.Context())
	for i := range c.Lists {
		c.Lists[i].Enabled = r.PostFormValue("on_"+strconv.Itoa(i)) != ""
	}
	c.ListHours = formInt(r, "hours")
	m.apply(w, r, "/dns64/lists", c)
}

func (m *Module) pageListAdd(w http.ResponseWriter, r *http.Request) {
	c := m.loadConfig(r.Context())
	u, name := strings.TrimSpace(r.PostFormValue("url")), strings.TrimSpace(r.PostFormValue("name"))
	if err := checkListURL(u); err != nil {
		m.g.Flash(w, r, "danger", m.errText(r, err))
		http.Redirect(w, r, "/dns64/lists", http.StatusSeeOther)
		return
	}
	for _, l := range c.Lists {
		if l.URL == u {
			m.g.Flash(w, r, "danger", m.g.T(r, "dns64.err.list_dup"))
			http.Redirect(w, r, "/dns64/lists", http.StatusSeeOther)
			return
		}
	}
	if name == "" {
		name = u
	}
	c.Lists = append(c.Lists, listSetting{List: filter.List{Name: name, URL: u}, Enabled: true, Custom: true})
	m.apply(w, r, "/dns64/lists", c)
}

func (m *Module) pageListRemove(w http.ResponseWriter, r *http.Request) {
	c := m.loadConfig(r.Context())
	if i := formInt(r, "remove"); i >= 0 && i < len(c.Lists) && c.Lists[i].Custom {
		c.Lists = append(c.Lists[:i], c.Lists[i+1:]...)
	}
	m.apply(w, r, "/dns64/lists", c)
}

// pageAllowImport uebernimmt Freigaben aus einer Liste (eine Domain je Zeile; allowlist.txt des alten
// Containers, Pi-hole-Whitelist; Kommentare und Zeitstempel werden ignoriert).
func (m *Module) pageAllowImport(w http.ResponseWriter, r *http.Request) {
	a, err := m.allowlist()
	n, bad := 0, 0
	if err == nil {
		for _, line := range strings.Split(r.PostFormValue("domains"), "\n") {
			line = strings.TrimSpace(line)
			if i := strings.IndexAny(line, "#\t "); i >= 0 {
				line = strings.TrimSpace(line[:i])
			}
			if line == "" {
				continue
			}
			if _, err := a.Add(line); err != nil {
				bad++
				continue
			}
			n++
		}
	}
	if err != nil {
		m.g.Flash(w, r, "danger", err.Error())
	} else {
		m.log.Info("allowlist imported", "domains", n, "invalid", bad, "by", m.g.Actor(r))
		m.g.Flash(w, r, "success", m.g.T(r, "dns64.allow.imported", "n", n, "bad", bad))
	}
	http.Redirect(w, r, "/dns64/lists", http.StatusSeeOther)
}

func (m *Module) recordBack(w http.ResponseWriter, r *http.Request, err error, okKey string) {
	if err != nil {
		m.g.Flash(w, r, "danger", m.errText(r, err))
	} else if okKey != "" {
		m.g.Flash(w, r, "success", m.g.T(r, okKey))
	}
	http.Redirect(w, r, "/dns64/records", http.StatusSeeOther)
}

func (m *Module) pageRecordAdd(w http.ResponseWriter, r *http.Request) {
	ttl := formInt(r, "ttl")
	if ttl < 0 {
		ttl = 0
	}
	rec, err := m.AddRecord(r.Context(), Record{Name: r.PostFormValue("name"), Type: r.PostFormValue("type"), Value: r.PostFormValue("value"), TTL: ttl})
	if err == nil {
		m.log.Info("record added", "name", rec.Name, "type", rec.Type, "value", rec.Value, "by", m.g.Actor(r))
	}
	m.recordBack(w, r, err, "dns64.records.added")
}

func (m *Module) pageRecordDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	err := m.DeleteRecord(r.Context(), id)
	if err == nil {
		m.log.Info("record deleted", "id", id, "by", m.g.Actor(r))
	}
	m.recordBack(w, r, err, "dns64.records.deleted")
}

func (m *Module) pageRecordToggle(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	m.recordBack(w, r, m.SetRecordEnabled(r.Context(), id, r.PostFormValue("on") == "1"), "")
}
