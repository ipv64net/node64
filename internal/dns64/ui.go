package dns64

import (
	"embed"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

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
	mux.Handle("GET /dns64/settings", page(m.pageTab("settings", "dns64.settings.title")))
	mux.Handle("POST /dns64/settings", page(m.pageSettingsSave))
}

// tab ist ein Reiter der Modulseiten.
type tab struct {
	Key, Path, TitleKey, Icon string
	Active                    bool
}

type pageData struct {
	Tabs    []tab
	Running bool
	Err     string // Resolver laeuft nicht: Grund
	Listen  string
	Started time.Time
	Router  string
	Source  string // config | auto
	JS      map[string]any
	// Einstellungen
	Port      int
	Bind      string
	RouterSet string
	Retention int
}

func (m *Module) pageTab(key, titleKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		d := pageData{Port: m.port(ctx), Bind: m.core.SettingOr(ctx, setBind, ""), RouterSet: m.core.SettingOr(ctx, setRouter, ""), Retention: m.retention(ctx)}
		for _, t := range []tab{{"overview", "/dns64", "dns64.tab.overview", "bi-speedometer2", false}, {"log", "/dns64/log", "dns64.tab.log", "bi-list-ul", false},
			{"lists", "/dns64/lists", "dns64.tab.lists", "bi-funnel", false}, {"settings", "/dns64/settings", "dns64.tab.settings", "bi-gear", false}} {
			t.Active = t.Key == key
			d.Tabs = append(d.Tabs, t)
		}
		if e := m.running(); e != nil {
			d.Running, d.Listen, d.Started, d.Router, d.Source = true, e.addr, e.started, e.local.Addr(), e.local.Source()
		}
		d.Err = m.startError()
		d.JS = map[string]any{"csrf": m.g.CSRF(r), "lang": m.g.Lang(r), "t": m.jsTexts(r)}
		m.g.Render(w, r, http.StatusOK, Name+"/"+key, titleKey, d)
	}
}

// jsKeys sind die Texte, die dns64.js braucht (Schluessel unter "dns64.js.").
var jsKeys = []string{"status.allowed", "status.blocked", "status.cached", "status.local", "status.error",
	"released", "release", "release_title", "release_confirm", "unrelease_confirm", "released_toast", "unreleased_toast", "remove",
	"no_releases", "ready", "online", "disturbed", "avg", "fastest", "requests", "errors", "last_error", "router_auto", "router_config", "router_none",
	"of", "failed", "just_now", "min_ago", "hours_ago", "days_ago", "per_hour", "pct_all", "pct_cache", "loaded", "no_data", "empty_chart",
	"blocked_n", "no_entries", "via", "entries", "page", "live_paused", "flush_confirm", "flushed", "error", "active", "loading",
	"sec", "min", "hours", "uptime", "allowed", "blocked", "no_conn"}

func (m *Module) jsTexts(r *http.Request) map[string]string {
	out := make(map[string]string, len(jsKeys))
	for _, k := range jsKeys {
		out[k] = m.g.T(r, "dns64.js."+k)
	}
	return out
}

func (m *Module) pageSettingsSave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	back := func(kind, msg string) {
		m.g.Flash(w, r, kind, msg)
		http.Redirect(w, r, "/dns64/settings", http.StatusSeeOther)
	}
	port, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("port")))
	if err != nil || port < 1 || port > 65535 {
		back("danger", m.g.T(r, "dns64.settings.err_port"))
		return
	}
	bind := strings.Trim(strings.TrimSpace(r.PostFormValue("bind")), "[]")
	if bind != "" && net.ParseIP(bind) == nil {
		back("danger", m.g.T(r, "dns64.settings.err_bind"))
		return
	}
	router := strings.TrimSpace(r.PostFormValue("router"))
	if router != "" {
		host := router
		if h, p, err := net.SplitHostPort(router); err == nil {
			if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
				back("danger", m.g.T(r, "dns64.settings.err_router"))
				return
			}
			host = h
		}
		if net.ParseIP(strings.Trim(host, "[]")) == nil {
			back("danger", m.g.T(r, "dns64.settings.err_router"))
			return
		}
	}
	days, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("retention")))
	if err != nil || days < 1 || days > 90 {
		back("danger", m.g.T(r, "dns64.settings.err_retention"))
		return
	}
	for k, v := range map[string]string{setPort: strconv.Itoa(port), setBind: bind, setRouter: router, setRetention: strconv.Itoa(days)} {
		if err := m.core.SetSetting(ctx, k, v); err != nil {
			back("danger", err.Error())
			return
		}
	}
	m.log.Info("settings saved", "port", port, "bind", bind, "router", router, "retention", days, "by", m.g.Actor(r))
	if err := m.restart(ctx); err != nil {
		m.log.Error("restart after settings failed", "err", err)
		back("danger", m.g.T(r, "dns64.settings.err_restart", "err", err.Error()))
		return
	}
	back("success", m.g.T(r, "common.saved"))
}
