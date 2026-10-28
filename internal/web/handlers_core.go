package web

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ipv64net/node64/internal/healthchecks"
	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/netstat"
	"github.com/ipv64net/node64/internal/peer"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/logging"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/selfupdate"
	"github.com/ipv64net/node64/internal/store"
	nodesync "github.com/ipv64net/node64/internal/sync"
)

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{3,64}$`)

// Einstellungs-Schluessel in der Tabelle settings
const (
	SettingNodeID       = "node.id"
	SettingNodeName     = "node.name"
	SettingNodeLocation = "node.location"
	SettingNodeTimezone = "node.timezone"
)

// ---------------------------------------------------------------- API

func (s *Server) apiHealth(w http.ResponseWriter, r *http.Request) {
	status := http.StatusOK
	body := map[string]any{"status": "ok", "version": s.Version, "time": time.Now().UTC().Format(time.RFC3339)}
	if err := s.Store.Reader().PingContext(r.Context()); err != nil {
		status = http.StatusServiceUnavailable
		body["status"] = "degraded"
		body["database"] = "unreachable"
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// ---------------------------------------------------------------- Setup

func (s *Server) setupForm(w http.ResponseWriter, r *http.Request) {
	if n, _ := s.Store.UserCount(r.Context()); n > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if l := r.URL.Query().Get("lang"); s.I18n.Has(l) {
		s.setCookie(w, r, langCookie, l, 365*24*3600)
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	v := s.view(r, "setup.title")
	v.SetupRun = true
	host, _ := os.Hostname()
	tz := DefaultTimezone
	v.Form = map[string]string{"username": "admin", "timezone": tz, "node_name": host, "location": ""}
	s.render(w, r, http.StatusOK, "setup", v)
}

func (s *Server) setupSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if n, _ := s.Store.UserCount(ctx); n > 0 {
		s.errorPage(w, r, http.StatusForbidden, "errors.setup_done")
		return
	}
	v := s.view(r, "setup.title")
	v.SetupRun = true
	lang := r.PostFormValue("lang")
	if s.I18n.Has(lang) {
		v.Lang = lang
	}
	f := s.formValues(r, "username", "password", "password2", "timezone", "node_name", "location")
	v.Form = f
	s.validateUser(v, f["username"], f["password"], f["password2"])
	s.validateTimezone(v, f["timezone"])
	s.validateNode(v, f["node_name"])
	if len(v.Errors) > 0 {
		v.Flash = &Flash{Kind: "danger", Text: v.T("errors.validation")}
		s.render(w, r, http.StatusUnprocessableEntity, "setup", v)
		return
	}
	hash, err := HashPassword(f["password"])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	u, err := s.Store.CreateUser(ctx, f["username"], hash, v.Lang, f["timezone"])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if f["timezone"] != "" {
		_ = s.Store.SetSetting(ctx, SettingNodeTimezone, f["timezone"])
	}
	if err := s.ensureNodeIdentity(r, f["node_name"], f["location"]); err != nil {
		s.fail(w, r, err)
		return
	}
	s.auditEntry(ctx, store.AuditEntry{Actor: u.Username, Action: "setup", Details: "initial setup completed", IP: s.clientIP(r)})
	s.setCookie(w, r, langCookie, v.Lang, 365*24*3600)
	if err := s.startSession(w, r, u.ID, false); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.TouchUserLogin(ctx, u.ID)
	s.flash(w, r, "success", v.T("setup.done"))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) ensureNodeIdentity(r *http.Request, name, location string) error {
	ctx := r.Context()
	if _, ok, _ := s.Store.Setting(ctx, SettingNodeID); !ok {
		if err := s.Store.SetSetting(ctx, SettingNodeID, randomToken(24)); err != nil {
			return err
		}
	}
	if err := s.Store.SetSetting(ctx, SettingNodeName, name); err != nil {
		return err
	}
	return s.Store.SetSetting(ctx, SettingNodeLocation, location)
}

// ---------------------------------------------------------------- Login

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	if n, _ := s.Store.UserCount(r.Context()); n == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if currentUser(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	v := s.view(r, "login.title")
	v.Form["next"] = safeNext(r.URL.Query().Get("next"))
	s.loginOptions(r, v)
	s.render(w, r, http.StatusOK, "login", v)
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v := s.view(r, "login.title")
	f := s.formValues(r, "username", "password", "next")
	v.Form = map[string]string{"username": f["username"], "next": safeNext(f["next"])}
	s.loginOptions(r, v)
	ip := s.clientIP(r)
	keys := []string{"ip:" + ipKey(ip), "user:" + strings.ToLower(f["username"])}
	// Versuch vor der Passwortpruefung verbuchen (bei Erfolg zurueck): sonst kaemen parallele Anfragen alle durch
	if wait := s.limiter.take(keys...); wait > 0 {
		secs := int(wait.Seconds()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		v.Flash = &Flash{Kind: "warning", Text: v.T("login.ratelimited", "seconds", secs)}
		s.render(w, r, http.StatusTooManyRequests, "login", v)
		return
	}
	u, err := s.Store.UserByName(ctx, f["username"])
	if err != nil {
		s.limiter.refund(keys...)
		s.fail(w, r, err)
		return
	}
	if u == nil || !VerifyPassword(u.PasswordHash, f["password"]) {
		if u == nil {
			// Zeit angleichen, damit Benutzernamen nicht ueber die Antwortzeit erratbar sind
			VerifyPassword("$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", f["password"])
		}
		s.loginFailed(r, ip)
		s.auditEntry(ctx, store.AuditEntry{Actor: truncate(f["username"], 64), Action: "login.failed", IP: ip})
		s.log.Warn("login failed", "user", f["username"], "ip", ip)
		v.Flash = &Flash{Kind: "danger", Text: v.T("login.failed")}
		s.render(w, r, http.StatusUnauthorized, "login", v)
		return
	}
	s.limiter.refund(keys...)
	pending := u.TOTPSecret != ""
	if err := s.startSession(w, r, u.ID, pending); err != nil {
		s.fail(w, r, err)
		return
	}
	if s.I18n.Has(u.Lang) {
		s.setCookie(w, r, langCookie, u.Lang, 365*24*3600)
	}
	if pending {
		http.Redirect(w, r, "/login/totp?next="+url.QueryEscape(v.Form["next"]), http.StatusSeeOther)
		return
	}
	_ = s.Store.TouchUserLogin(ctx, u.ID)
	s.auditEntry(ctx, store.AuditEntry{Actor: u.Username, Action: "login", IP: ip})
	s.log.Info("login", "user", u.Username, "ip", ip)
	http.Redirect(w, r, v.Form["next"], http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if sess := currentSession(r); sess != nil {
		_ = s.Store.DeleteSession(r.Context(), sess.ID)
		s.audit(r, "logout", "", "")
	} else if sess := pendingSession(r); sess != nil {
		_ = s.Store.DeleteSession(r.Context(), sess.ID)
	}
	s.clearCookie(w, r, sessionCookie)
	s.clearCookie(w, r, csrfCookie)
	v := s.view(r, "login.title")
	s.flash(w, r, "success", v.T("login.logged_out"))
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// safeNext: nur ein Pfad dieser Node. Steuer- und Leerzeichen nie, weil Browser z. B. TAB entfernen
// ("/<TAB>/evil.example" wuerde zu "//evil.example").
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.ContainsRune(next, '\\') {
		return "/"
	}
	for _, c := range next {
		if c <= ' ' || c == 0x7f {
			return "/"
		}
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		return "/"
	}
	return next
}

// ---------------------------------------------------------------- Dashboard

// dashCluster: Kachel und Hinweis zum Cluster (nur mit Mitgliedern).
type dashCluster struct {
	Members []peer.Member
	Online  int
	Down    []string // Namen der Nodes, die laenger weg oder ausgesetzt sind
}

func (s *Server) dashClusterData(ctx context.Context) *dashCluster {
	if s.Peer == nil {
		return nil
	}
	list, err := s.Peer.Members(ctx)
	if err != nil || len(list) == 0 {
		return nil
	}
	c := &dashCluster{Members: list}
	now := time.Now()
	for _, x := range list {
		if x.Online() {
			c.Online++
		}
		if x.MemberDown(now) {
			c.Down = append(c.Down, x.Name)
		}
	}
	return c
}

type dashboardData struct {
	NodeID    string
	NodeName  string
	Location  string
	StartedAt time.Time
	DBSize    int64
	Modules   []module.Status
	Boards    []module.DashboardInfo
	Data      store.DataStats
	// Netzverkehr des Containers: seit Start und gesamt (ueber Neustarts)
	NetOK              bool
	NetRx, NetTx       int64
	NetRxTot, NetTxTot int64
	NetSince           time.Time
	// Checks nach Besitzer (verknuepft)
	Own, Hybrid, OnlineOnly, Other, OnlinePoints int
	ChecksProj                                   int // Tageskontingent: hochgerechneter Verbrauch pro Tag
	// ipv64-Account direkt ueber die API v2 (nil = kein Key)
	API                             *ipv64api.Overview
	Mismatch                        bool      // API-Key gehoert zu einem anderen Account als der Healthchecks-Sync
	NodeRemoved                     time.Time // auf ipv64.net entfernt (Null = nein)
	ConnectedAt, LastSync, LinkedAt time.Time
	Peers, PeersOnline              int            // Nodes dieser Verknuepfung
	Cluster                         *dashCluster   // nil = kein Cluster (keine Mitglieder)
	Layout                          []dashItem     // Kacheln in der Reihenfolge des Benutzers (dashboard_layout.go)
	JS                              map[string]any // Daten fuer dashboard.js (CSRF, Sprache, Texte)
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v := s.view(r, "dashboard.title")
	v.Data = dashboardData{
		NodeID:    s.Store.SettingOr(ctx, SettingNodeID, ""),
		NodeName:  s.Store.SettingOr(ctx, SettingNodeName, ""),
		Location:  s.Store.SettingOr(ctx, SettingNodeLocation, ""),
		StartedAt: s.StartedAt,
		DBSize:    s.Store.Size(),
		Modules:   s.Modules.List(ctx),
	}
	d := v.Data.(dashboardData)
	d.Data = s.Store.Stats(ctx)
	d.NetRx, d.NetTx, d.NetOK = netstat.Read()
	d.NetRxTot, d.NetTxTot, d.NetSince = netstat.Totals(ctx, s.Store)
	if d.NetRxTot < d.NetRx { // erste Minute nach dem allerersten Start
		d.NetRxTot, d.NetTxTot = d.NetRx, d.NetTx
	}
	hcOn := s.HC != nil && s.Modules != nil && s.Modules.IsRunning(healthchecks.Name) // aus: keine Abfragen
	if hcOn {
		for _, p := range s.HC.Peers(ctx) {
			d.Peers++
			if p.Online {
				d.PeersOnline++
			}
		}
	}
	if hcOn {
		if list, err := s.HC.AllChecks(ctx); err == nil {
			for _, c := range list {
				switch c.Where().Key { // wo gemessen wird, wie in der Uebersicht
				case "hc.where.online":
					d.OnlineOnly++
				case "hc.where.hybrid":
					d.Hybrid++
				case "hc.where.local":
					d.Own++
				default:
					d.Other++
				}
				d.ChecksProj += healthchecks.CheckDailyCost(c, v.Sync.Locations)
				d.OnlinePoints += healthchecks.CheckOnlinePoints(c, v.Sync.Locations) // wie der hub zaehlt (ein Standort je Check, wenn der Account nur einen hat)
			}
		}
	}
	if s.IPv64 != nil {
		if r.URL.Query().Get("refresh") == "account" {
			s.IPv64.ResetOverview()
		}
		d.API = s.IPv64.Overview(ctx, 5*time.Minute)
		d.NodeRemoved = s.IPv64.Removed(ctx)
		d.Mismatch = d.API != nil && v.Sync.Linked && v.API.ID != 0 && v.Sync.AccountID != "" && v.Sync.AccountID != strconv.Itoa(v.API.ID)
	}
	st := v.Sync
	d.ConnectedAt, _ = time.Parse(time.RFC3339, st.ConnectedAt)
	d.LastSync, _ = time.Parse(time.RFC3339, st.LastSyncAt)
	d.LinkedAt, _ = time.Parse(time.RFC3339, st.LinkedAt)
	for _, m := range s.Modules.Modules() {
		p, ok := m.(module.DashboardProvider)
		if !ok || !s.Modules.IsRunning(m.Info().Name) {
			continue
		}
		info, err := p.Dashboard(ctx)
		if err != nil {
			s.log.Error("dashboard data", "module", m.Info().Name, "err", err)
			continue
		}
		if info != nil {
			if g, ok := m.(module.BoardGroupsProvider); ok {
				info.Groups = g.BoardGroups(ctx)
			}
			d.Boards = append(d.Boards, *info)
		}
	}
	var cards []namedCard
	for _, m := range s.Modules.Modules() {
		p, ok := m.(module.CardProvider)
		if !ok || !s.Modules.IsRunning(m.Info().Name) {
			continue
		}
		if c, err := p.Card(ctx); err != nil {
			s.log.Error("dashboard card", "module", m.Info().Name, "err", err)
		} else if c != nil {
			cards = append(cards, namedCard{Module: m.Info().Name, Card: *c})
		}
	}
	avail := dashAvailable(d.Boards, cards, s.Modules.IsRunning("dns64"), s.Modules.IsRunning("cdn64"))
	if d.Cluster = s.dashClusterData(ctx); d.Cluster != nil {
		avail = append(avail, dashItem{ID: "cluster", Size: "s", Kind: "cluster"})
	}
	d.Layout = dashMerge(avail, s.dashSaved(ctx, v.User.ID))
	texts := map[string]string{}
	for _, k := range []string{"saved", "save_err", "allowed", "blocked", "rejected", "requests", "bytes", "download", "upload", "no_data", "size", "hide", "show", "up", "down", "c4", "errors", "decoy"} {
		texts[k] = v.T("dashboard.js." + k)
	}
	d.JS = map[string]any{"csrf": v.CSRF, "lang": v.Lang, "t": texts}
	v.Data = d
	s.render(w, r, http.StatusOK, "dashboard", v)
}

// ---------------------------------------------------------------- Settings

type settingsData struct {
	Linked     bool // mit ipv64 verknuepft (Zuruecksetzen trennt die Verknuepfung)
	IPv64On    bool // zentraler API-Key verfuegbar
	IPv64Set   bool // API-Key eingetragen
	IPv64      ipv64api.AccountInfo
	Removed    time.Time // Node auf ipv64.net entfernt (Null = nein)
	Own, Other int       // Checks nur dieser Node / uebrige im Account
	NodeName   string
	Location   string
	Modules    []module.Status
	LogLevel   string
	LogResetAt time.Time
	LogDefault string
	DBPath     string
	DBSize     int64
	BackupDir  string
	GoVersion  string
	TOTP       bool
	UpdateOn   bool
	Update     map[string]any
	Upd        *updateView // Selbst-Update (nil = nicht verfuegbar)
	LogModules map[string]string
	Modules2   []string
	HTTPSPort  int
	Reach      *reachView        // Karte Erreichbarkeit dieser Node
	Moved      map[string]string // alte Sprungmarken -> neue Seite (Weiterleitung in app.js)
	// lokale Datenhaltung (Healthchecks)
	RawDays, HourlyDays       int
	ChartDetail               string
	RawOptions, HourlyOptions []int
	ChartOptions              []string
	AuditDays                 int   // Audit-Log aufbewahren (0 = unbegrenzt)
	AuditOptions              []int //
}

func (s *Server) settingsView(r *http.Request) *View {
	ctx := r.Context()
	v := s.view(r, "settings.title")
	d := settingsData{
		NodeName:   s.Store.SettingOr(ctx, SettingNodeName, ""),
		Location:   s.Store.SettingOr(ctx, SettingNodeLocation, ""),
		Modules:    s.Modules.List(ctx),
		LogLevel:   logging.LevelName(s.Log.Level()),
		LogResetAt: s.Log.ResetAt(),
		LogDefault: s.Cfg.LogLevel,
		DBPath:     s.Store.Path(),
		DBSize:     s.Store.Size(),
		BackupDir:  s.Cfg.BackupDir(),
		TOTP:       v.User.TOTPSecret != "",
		HTTPSPort:  s.Cfg.HTTPSPort,
	}
	d.RawDays, d.HourlyDays, d.ChartDetail = healthchecks.RawDays(s.Store), healthchecks.HourlyDays(s.Store), healthchecks.ChartDetail(s.Store)
	d.RawOptions, d.HourlyOptions, d.ChartOptions = healthchecks.RawDayOptions, healthchecks.HourlyDayOptions, healthchecks.ChartDetailOptions
	d.AuditDays, d.AuditOptions = AuditDays(s.Store), AuditDayOptions
	d.UpdateOn = s.Store.SettingOr(ctx, "updates.check", "0") == "1"
	if s.IPv64 != nil {
		d.IPv64On = true
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		s.IPv64.RefreshIfStale(rctx, 24*time.Hour) // Name und Ablauf des Keys aktuell halten
		cancel()
		d.Removed = s.IPv64.Removed(ctx)
		if d.IPv64Set = s.IPv64.Get(ctx) != ""; d.IPv64Set {
			d.IPv64 = s.IPv64.Info(ctx)
		}
	}
	d.Linked = s.Linker != nil && s.Store.SettingOr(ctx, nodesync.SetToken, "") != ""
	if d.Linked && s.HC != nil {
		d.Own, d.Other = s.HC.LinkScope(ctx)
	}
	if raw := s.Store.SettingOr(ctx, "updates.latest", ""); raw != "" {
		_ = json.Unmarshal([]byte(raw), &d.Update)
	}
	d.Upd = s.updateViewOf(ctx)
	d.LogModules = map[string]string{}
	for k, l := range s.Log.ModuleLevels() {
		d.LogModules[k] = logging.LevelName(l)
	}
	d.Modules2 = logModuleNames
	d.Reach, d.Moved = s.reachData(ctx), settingsMoved
	v.Data = d
	v.Form = map[string]string{"node_name": d.NodeName, "location": d.Location, "lang": v.User.Lang, "timezone": v.User.Timezone, "level": d.LogLevel}
	if v.Form["lang"] == "" {
		v.Form["lang"] = v.Lang // noch nicht gespeichert: die angezeigte Sprache
	}
	if v.Form["timezone"] == "" {
		v.Form["timezone"] = DefaultTimezone
	}
	return v
}

func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "settings", s.settingsView(r))
}

func (s *Server) settingsUpdates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	mode := r.PostFormValue("updates_mode")
	if mode == "" { // altes Formular: nur der Schalter "pruefen"
		mode = map[bool]string{true: "notify", false: "off"}[r.PostFormValue("updates_check") == "on"]
	}
	if !containsString(selfupdate.Modes, mode) {
		mode = "off"
	}
	_ = s.Store.SetSetting(ctx, selfupdate.SetMode, mode)
	on := mode != "off"
	_ = s.Store.SetSetting(ctx, "updates.check", map[bool]string{true: "1", false: "0"}[on])
	if ch := r.PostFormValue("updates_channel"); containsString(selfupdate.Channels, ch) {
		_ = s.Store.SetSetting(ctx, selfupdate.SetChannel, ch)
	}
	if win := strings.TrimSpace(r.PostFormValue("updates_window")); selfupdate.ValidWindow(win) {
		_ = s.Store.SetSetting(ctx, selfupdate.SetWindow, win)
	}
	if !on {
		_ = s.Store.SetSetting(ctx, "updates.latest", "")
	}
	s.audit(r, "settings.updates", "", fmt.Sprintf("mode=%s", mode))
	v := s.view(r, "settings.title")
	s.flash(w, r, "success", v.T("common.saved"))
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) settingsNode(w http.ResponseWriter, r *http.Request) {
	f := s.formValues(r, "node_name", "location")
	v := s.settingsView(r)
	v.Form["node_name"], v.Form["location"] = f["node_name"], f["location"]
	s.validateNode(v, f["node_name"])
	if len(v.Errors) > 0 {
		s.render(w, r, http.StatusUnprocessableEntity, "settings", v)
		return
	}
	if err := s.ensureNodeIdentity(r, f["node_name"], f["location"]); err != nil {
		s.fail(w, r, err)
		return
	}
	if s.Linker != nil {
		s.Linker.NodeInfoChanged() // an ipv64 und die anderen Nodes weitergeben
	}
	s.audit(r, "settings.node", "", fmt.Sprintf("name=%q location=%q", f["node_name"], f["location"]))
	s.flash(w, r, "success", v.T("common.saved"))
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) settingsUser(w http.ResponseWriter, r *http.Request) {
	f := s.formValues(r, "lang", "timezone")
	v := s.settingsView(r)
	v.Form["lang"], v.Form["timezone"] = f["lang"], f["timezone"]
	if !s.I18n.Has(f["lang"]) {
		v.Errors["lang"] = v.T("errors.validation")
	}
	s.validateTimezone(v, f["timezone"])
	if len(v.Errors) > 0 {
		s.render(w, r, http.StatusUnprocessableEntity, "settings", v)
		return
	}
	if err := s.Store.UpdateUserPrefs(r.Context(), v.User.ID, f["lang"], f["timezone"]); err != nil {
		s.fail(w, r, err)
		return
	}
	if f["timezone"] != "" {
		_ = s.Store.SetSetting(r.Context(), SettingNodeTimezone, f["timezone"])
	}
	s.setCookie(w, r, langCookie, f["lang"], 365*24*3600)
	s.audit(r, "settings.user", v.User.Username, "lang="+f["lang"]+" timezone="+f["timezone"])
	s.flash(w, r, "success", s.I18n.T(f["lang"], "common.saved"))
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) settingsPassword(w http.ResponseWriter, r *http.Request) {
	f := s.formValues(r, "current", "password", "password2")
	v := s.settingsView(r)
	if !VerifyPassword(v.User.PasswordHash, f["current"]) {
		v.Errors["current"] = v.T("settings.password_wrong")
	}
	if err := checkPassword(f["password"]); err != nil {
		v.Errors["password"] = v.T("errors.password_short")
	} else if f["password"] != f["password2"] {
		v.Errors["password2"] = v.T("errors.password_mismatch")
	}
	if len(v.Errors) > 0 {
		s.render(w, r, http.StatusUnprocessableEntity, "settings", v)
		return
	}
	hash, err := HashPassword(f["password"])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.UpdateUserPassword(r.Context(), v.User.ID, hash); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.DeleteUserSessions(r.Context(), v.User.ID, sessionID(r))
	s.audit(r, "settings.password", v.User.Username, "")
	s.flash(w, r, "success", v.T("settings.password_changed"))
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) settingsModules(w http.ResponseWriter, r *http.Request) {
	f := s.formValues(r, "module", "action")
	v := s.settingsView(r)
	name := f["module"]
	title := v.T("module." + name)
	var err error
	switch f["action"] {
	case "enable":
		err = s.Modules.Enable(r.Context(), name)
	case "disable":
		err = s.Modules.Disable(r.Context(), name)
	default:
		err = module.ErrUnknown
	}
	if err != nil {
		s.log.Error("module change failed", "name", name, "action", f["action"], "err", err)
		s.flash(w, r, "danger", v.T("settings.module_error", "name", title, "error", err.Error()))
	} else {
		s.audit(r, "module."+f["action"], name, "")
		key := "settings.module_enabled"
		if f["action"] == "disable" {
			key = "settings.module_disabled"
		}
		s.flash(w, r, "success", v.T(key, "name", title))
	}
	http.Redirect(w, r, "/settings/modules", http.StatusSeeOther)
}

// settingsData speichert die lokale Datenhaltung (nur diese Node; ipv64 behaelt eigene Fristen).
func (s *Server) settingsData(w http.ResponseWriter, r *http.Request) {
	f := s.formValues(r, "raw_days", "hourly_days", "chart_detail", "audit_days")
	v := s.settingsView(r)
	inInts := func(val string, opts []int) bool {
		n, err := strconv.Atoi(val)
		for _, o := range opts {
			if err == nil && o == n {
				return true
			}
		}
		return false
	}
	okDetail := false
	for _, o := range healthchecks.ChartDetailOptions {
		okDetail = okDetail || o == f["chart_detail"]
	}
	auditSet := r.PostForm.Has("audit_days") // Audit-Log: nur, wenn das Formular das Feld enthaelt
	if !inInts(f["raw_days"], healthchecks.RawDayOptions) || !inInts(f["hourly_days"], healthchecks.HourlyDayOptions) || !okDetail ||
		(auditSet && !inInts(f["audit_days"], AuditDayOptions)) {
		s.flash(w, r, "danger", v.T("errors.validation"))
		http.Redirect(w, r, "/settings/data#retention", http.StatusSeeOther)
		return
	}
	set := map[string]string{healthchecks.SettingRawDays: f["raw_days"], healthchecks.SettingHourlyDays: f["hourly_days"], healthchecks.SettingChartDetail: f["chart_detail"]}
	if auditSet {
		set[SettingAuditDays] = f["audit_days"]
	}
	for k, val := range set {
		if err := s.Store.SetSetting(r.Context(), k, val); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	s.audit(r, "settings.data", "", fmt.Sprintf("raw_days=%s hourly_days=%s chart=%s audit_days=%s", f["raw_days"], f["hourly_days"], f["chart_detail"], f["audit_days"]))
	s.flash(w, r, "success", v.T("common.saved"))
	http.Redirect(w, r, "/settings/data#retention", http.StatusSeeOther)
}

// logModuleNames: Module mit eigenem Log-Level (Oberflaeche und API).
var logModuleNames = []string{"core", "web", "store", "scheduler", "notify", "healthchecks", "dyndns", "dns64", "sync", "peer"}

func (s *Server) settingsLogging(w http.ResponseWriter, r *http.Request) {
	f := s.formValues(r, "level", "reset_minutes", "module")
	v := s.settingsView(r)
	mins, _ := strconv.Atoi(f["reset_minutes"])
	if mins < 0 || mins > 1440 {
		mins = 0
	}
	if mod := f["module"]; mod != "" && mod != "global" {
		if f["level"] == "inherit" {
			s.Log.SetModuleLevel(mod, nil)
		} else {
			lvl := logging.ParseLevel(f["level"])
			s.Log.SetModuleLevel(mod, &lvl)
		}
		s.audit(r, "logging.module", mod, f["level"])
		s.flash(w, r, "success", v.T("settings.log_changed"))
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	lvl := logging.ParseLevel(f["level"])
	var reset time.Duration
	if lvl == slog.LevelDebug && mins > 0 {
		reset = time.Duration(mins) * time.Minute
	}
	s.Log.SetLevel(lvl, reset)
	s.audit(r, "logging.level", logging.LevelName(lvl), fmt.Sprintf("reset_minutes=%d", mins))
	s.flash(w, r, "success", v.T("settings.log_changed"))
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// ---------------------------------------------------------------- Audit und Logs

func (s *Server) auditLog(w http.ResponseWriter, r *http.Request) {
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	area := r.URL.Query().Get("area")
	if auditAreas[area] == nil {
		area = ""
	}
	entries, err := s.Store.AuditListFiltered(r.Context(), 100, before, auditAreas[area])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var next int64
	if len(entries) == 100 {
		next = entries[len(entries)-1].ID
	}
	v := s.view(r, "audit.title")
	v.Data = map[string]any{"Entries": entries, "Next": next, "Area": area, "Areas": auditAreaOrder}
	s.render(w, r, http.StatusOK, "audit", v)
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	lines := s.Log.Lines(500)
	v := s.view(r, "logs.title")
	v.Data = map[string]any{"Lines": lines, "Count": len(lines), "Level": logging.LevelName(s.Log.Level())}
	s.render(w, r, http.StatusOK, "logs", v)
}

func (s *Server) logsDownload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="agent-`+time.Now().UTC().Format("20060102-150405")+`.log"`)
	for _, l := range s.Log.Lines(0) {
		_, _ = w.Write([]byte(l + "\n"))
	}
}

// ---------------------------------------------------------------- Helfer

func (s *Server) formValues(r *http.Request, keys ...string) map[string]string {
	m := make(map[string]string, len(keys))
	for _, k := range keys {
		m[k] = strings.TrimSpace(r.PostFormValue(k))
	}
	return m
}

func (s *Server) validateUser(v *View, username, pw, pw2 string) {
	if !usernameRe.MatchString(username) {
		v.Errors["username"] = v.T("errors.username_invalid")
	}
	if err := checkPassword(pw); err != nil {
		v.Errors["password"] = v.T("errors.password_short")
	} else if pw != pw2 {
		v.Errors["password2"] = v.T("errors.password_mismatch")
	}
}

func (s *Server) validateTimezone(v *View, tz string) {
	if tz == "" {
		return
	}
	if _, err := time.LoadLocation(tz); err != nil {
		v.Errors["timezone"] = v.T("errors.timezone_invalid")
	}
}

func (s *Server) validateNode(v *View, name string) {
	if name == "" || len(name) > 64 {
		v.Errors["node_name"] = v.T("common.required")
	}
}

// fail loggt einen internen Fehler und zeigt die Fehlerseite.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("request failed", "path", r.URL.Path, "err", err)
	s.errorPage(w, r, http.StatusInternalServerError, "errors.internal")
}
