package web

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/mcp"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/store"
	nodesync "github.com/ipv64net/node64/internal/sync"
)

// View ist der Datensatz, den jedes Template bekommt. Die Methoden stehen in
// den Templates als {{.T "key"}} oder {{$.Time .X}} zur Verfuegung.
type View struct {
	s        *Server
	Lang     string
	Theme    string
	FontSize string // sm, lg, xl oder leer
	Path     string
	Title    string
	User     *store.User
	CSRF     string
	Version  string
	Nav      []NavItem
	Flash    *Flash
	Sync     nodesync.State
	API      ipv64api.AccountInfo // zentraler API-Key (Account leer = keiner)
	APIOk    bool                 // Key hinterlegt und nicht abgelaufen
	SetupRun bool
	Data     any
	Scheme   string
	Host     string
	Errors   map[string]string
	Form     map[string]string
	loc      *time.Location
}

type NavItem struct {
	Key       string
	Path      string
	Icon      string
	Image     string
	Available bool
	Enabled   bool
	Sub       bool // Unterpunkt (eingerueckt)
	Active    bool
	Hidden    bool // Modul in den Einstellungen ausgeschaltet: nicht im Menue
}

// Crumb ist ein Element der Brotkrumen in der Kopfzeile (URL leer = aktuelle Seite).
type Crumb struct {
	Label string
	URL   string
}

// Crumbs: Dashboard > Bereich (Menuepunkt) > aktuelle Seite. Daten koennen mit Crumb() string
// eine eigene letzte Stufe liefern (z. B. den Namen eines Checks).
func (v *View) Crumbs() []Crumb {
	if v.User == nil {
		return nil
	}
	out := []Crumb{{Label: v.T("nav.dashboard"), URL: "/"}}
	if v.Path == "/" {
		out[0].URL = ""
		return out
	}
	var sec *NavItem
	for i := range v.Nav {
		n := &v.Nav[i]
		if n.Path == "/" {
			continue
		}
		if (v.Path == n.Path || strings.HasPrefix(v.Path, n.Path+"/")) && (sec == nil || len(n.Path) > len(sec.Path)) {
			sec = n
		}
	}
	leaf := v.Title
	if c, ok := v.Data.(interface{ Crumb() string }); ok && c.Crumb() != "" {
		leaf = c.Crumb()
	}
	if sec != nil {
		label := v.T(sec.Key)
		if v.Path == sec.Path {
			return append(out, Crumb{Label: label})
		}
		out = append(out, Crumb{Label: label, URL: sec.Path})
		if leaf == label {
			leaf = v.Title
		}
	}
	return append(out, Crumb{Label: leaf})
}

// LastCrumb ist die aktuelle Seite (fuer schmale Bildschirme).
func (v *View) LastCrumb() string {
	c := v.Crumbs()
	if len(c) == 0 {
		return ""
	}
	return c[len(c)-1].Label
}

type Flash struct {
	Kind string // success, warning, danger
	Text string
}

// T uebersetzt in der Sprache der Ansicht.
func (v *View) T(key string, args ...any) string { return v.s.I18n.T(v.Lang, key, args...) }

// Time formatiert Datum und Uhrzeit in der Zeitzone des Nutzers.
func (v *View) Time(t time.Time) string { return v.s.I18n.FormatDateTime(v.Lang, t, v.loc) }

// Date formatiert nur das Datum.
// TimeStr formatiert eine Zeit im Textformat (RFC 3339) in der Zeitzone des Benutzers.
func (v *View) TimeStr(s string) string {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return v.Time(t)
	}
	return s
}

func (v *View) Date(t time.Time) string { return v.s.I18n.FormatDate(v.Lang, t, v.loc) }

// Ago liefert "vor 5 min" fuer eine Zeit.
func (v *View) Ago(t time.Time) string {
	if t.IsZero() {
		return v.T("common.never")
	}
	return v.T("time.ago", "duration", v.s.I18n.FormatDuration(v.Lang, time.Since(t)))
}

// Duration formatiert eine Dauer lesbar.
func (v *View) Duration(d time.Duration) string { return v.s.I18n.FormatDuration(v.Lang, d) }

// Int formatiert eine Zahl nach Locale.
func (v *View) Int(n int64) string { return v.s.I18n.FormatInt(v.Lang, n) }

// Float formatiert eine Kommazahl nach Locale.
func (v *View) Float(f float64, decimals int) string {
	return v.s.I18n.FormatFloat(v.Lang, f, decimals)
}

// Bytes formatiert eine Groesse lesbar.
func (v *View) Bytes(n int64) string {
	const unit = 1024
	if n < unit {
		return v.s.I18n.FormatInt(v.Lang, n) + " B"
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return v.s.I18n.FormatFloat(v.Lang, float64(n)/float64(div), 1) + " " + string("KMGTPE"[exp]) + "B"
}

// GB formatiert eine Datenmenge in GB (Account-Limits): ab 1024 GB in TB wie bei den Account-Klassen, Nachkommastellen
// nach Groesse (unter 10: zwei, unter 100: eine, sonst keine; Nullen am Ende fallen weg), kleine Mengen als "< 0,01 GB".
func (v *View) GB(gb float64) string {
	key := "plans.unit.gb"
	if gb >= 1024 {
		key, gb = "plans.unit.tb", gb/1024
	}
	if gb > 0 && gb < 0.005 {
		return v.T(key, "n", "< "+v.Float(0.01, 2))
	}
	return v.T(key, "n", v.decimal(gb))
}

// decimal: Kommazahl nach Locale mit Nachkommastellen nach Groesse, ohne Nullen am Ende.
func (v *View) decimal(f float64) string {
	d := 0
	switch {
	case f < 10:
		d = 2
	case f < 100:
		d = 1
	}
	s := v.Float(f, d)
	if d > 0 {
		s = strings.TrimRight(s, "0")
		s = strings.TrimRight(s, ".,")
	}
	return s
}

// Err liefert die Fehlermeldung eines Formularfelds oder "".
func (v *View) Err(field string) string { return v.Errors[field] }

// Val liefert den letzten Eingabewert eines Formularfelds.
func (v *View) Val(field string) string { return v.Form[field] }

// Languages liefert die verfuegbaren Sprachen.
func (v *View) Languages() []string { return v.s.I18n.Languages() }

// Timezones liefert eine Auswahl gaengiger Zeitzonen fuer die Datalist.
func (v *View) Timezones() []string { return commonTimezones }

// TimezoneOptions: Auswahlliste der Zeitzonen inklusive eines gespeicherten Werts, der nicht in der Liste steht.
func (v *View) TimezoneOptions() []string {
	cur := v.Form["timezone"]
	for _, z := range commonTimezones {
		if z == cur {
			return commonTimezones
		}
	}
	if cur == "" {
		return commonTimezones
	}
	return append([]string{cur}, commonTimezones...)
}

// DefaultTimezone gilt, solange der Benutzer keine eigene gewaehlt hat (UTC+1/+2, Berlin).
const DefaultTimezone = "Europe/Berlin"

var commonTimezones = []string{
	"UTC", "Europe/Berlin", "Europe/Vienna", "Europe/Zurich", "Europe/Amsterdam", "Europe/Brussels", "Europe/Paris",
	"Europe/London", "Europe/Dublin", "Europe/Madrid", "Europe/Rome", "Europe/Warsaw", "Europe/Prague", "Europe/Stockholm",
	"Europe/Oslo", "Europe/Copenhagen", "Europe/Helsinki", "Europe/Athens", "Europe/Istanbul", "Europe/Moscow",
	"America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles", "America/Toronto", "America/Sao_Paulo",
	"Asia/Tokyo", "Asia/Shanghai", "Asia/Singapore", "Asia/Dubai", "Asia/Kolkata", "Australia/Sydney", "Pacific/Auckland",
}

// lang bestimmt die Sprache: Nutzerprofil, sonst Cookie (Setup/Login), sonst Browser.
func (s *Server) lang(r *http.Request) string {
	if u := currentUser(r); u != nil && s.I18n.Has(u.Lang) {
		return u.Lang
	}
	if c, err := r.Cookie(langCookie); err == nil && s.I18n.Has(c.Value) {
		return c.Value
	}
	return s.I18n.Match(r.Header.Get("Accept-Language"))
}

func (s *Server) location(r *http.Request) *time.Location {
	if u := currentUser(r); u != nil && u.Timezone != "" {
		if loc, err := time.LoadLocation(u.Timezone); err == nil {
			return loc
		}
	}
	if loc, err := time.LoadLocation(DefaultTimezone); err == nil {
		return loc
	}
	return time.UTC
}

func (s *Server) view(r *http.Request, titleKey string) *View {
	v := &View{s: s, Lang: s.lang(r), Path: r.URL.Path, User: currentUser(r), CSRF: csrfToken(r), Version: s.Version,
		Errors: map[string]string{}, Form: map[string]string{}, loc: s.location(r), Sync: s.Sync.State()}
	v.Title = v.T(titleKey)
	if s.IPv64 != nil && s.Store.SettingOr(r.Context(), ipv64api.SetKey, "") != "" {
		v.API = s.IPv64.Info(r.Context())
		v.APIOk = v.API.Account != "" && !v.API.Expired()
	}
	v.Scheme, v.Host = "http", r.Host
	if r.TLS != nil {
		v.Scheme = "https"
	}
	if c, err := r.Cookie(themeCookie); err == nil && (c.Value == "light" || c.Value == "dark") {
		v.Theme = c.Value
	}
	if c, err := r.Cookie(fontCookie); err == nil && (c.Value == "sm" || c.Value == "lg" || c.Value == "xl") {
		v.FontSize = c.Value
	}
	if v.User != nil {
		v.Nav = s.nav(r)
	}
	if c, err := r.Cookie(flashCookie); err == nil && c.Value != "" {
		if kind, text, ok := strings.Cut(c.Value, ":"); ok {
			if t, err := url.QueryUnescape(text); err == nil {
				v.Flash = &Flash{Kind: kind, Text: t}
			}
		}
	}
	return v
}

func (s *Server) nav(r *http.Request) []NavItem {
	items := []NavItem{{Key: "nav.dashboard", Path: "/", Icon: "bi-speedometer2", Available: true, Enabled: true}}
	link := NavItem{Key: "nav.link", Path: "/link", Icon: "bi-cloud", Available: true, Enabled: true, Sub: true}
	placed := false
	for _, m := range s.Modules.List(r.Context()) {
		items = append(items, NavItem{Key: m.Info.TitleKey, Path: m.Info.Path, Icon: m.Info.Icon, Image: m.Info.Image, Available: m.Info.Available, Enabled: m.Running,
			Hidden: m.Info.Available && !m.Enabled})
		if m.Info.Path == "/healthchecks" && m.Enabled { // Healthchecks-Sync gehoert zu den Healthchecks
			items = append(items, NavItem{Key: "nav.status_pages", Path: "/healthchecks/status-pages", Icon: "bi-broadcast", Available: true, Enabled: m.Running, Sub: true},
				NavItem{Key: "nav.proxmox", Path: "/healthchecks/proxmox", Icon: "bi-hdd-rack", Available: true, Enabled: m.Running, Sub: true})
			items, placed = append(items, link), true
		}
	}
	if !placed {
		link.Sub = false
		items = append(items, link)
	}
	if s.Certs != nil {
		items = append(items, NavItem{Key: "nav.certificates", Path: "/certificates", Icon: "bi-shield-lock", Available: true, Enabled: true})
	}
	if s.Peer != nil {
		items = append(items, NavItem{Key: "nav.cluster", Path: "/cluster", Icon: "bi-hdd-network", Available: true, Enabled: true})
	}
	items = append(items,
		NavItem{Key: "nav.notifications", Path: "/notifications", Icon: "bi-bell", Available: true, Enabled: s.Notify != nil},
		NavItem{Key: "nav.settings", Path: "/settings", Icon: "bi-gear", Available: true, Enabled: true},
		NavItem{Key: "nav.audit", Path: "/audit", Icon: "bi-journal-text", Available: true, Enabled: true},
		NavItem{Key: "nav.logs", Path: "/logs", Icon: "bi-terminal", Available: true, Enabled: true},
		NavItem{Key: "nav.api", Path: "/api/docs", Icon: "bi-code-slash", Available: true, Enabled: true},
	)
	best := -1 // nur der genaueste Treffer ist aktiv (Statusseiten unter /healthchecks/...)
	for i := range items {
		p := items[i].Path
		if (p == r.URL.Path || (p != "/" && strings.HasPrefix(r.URL.Path, p+"/"))) && (best < 0 || len(p) > len(items[best].Path)) {
			best = i
		}
	}
	if best >= 0 {
		items[best].Active = true
	}
	return items
}

// render fuehrt ein Seiten-Template aus. Bei Fehlern wird nichts Halbes gesendet.
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, page string, v *View) {
	if v.Flash != nil {
		s.clearCookie(w, r, flashCookie)
	}
	t, ok := s.pages[page]
	if !ok {
		s.log.Error("template missing", "page", page)
		http.Error(w, "template missing", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout.html", v); err != nil {
		s.log.Error("template failed", "page", page, "err", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// flash merkt eine Meldung fuer die naechste Seite (nach Redirect).
func (s *Server) flash(w http.ResponseWriter, r *http.Request, kind, text string) {
	s.setCookie(w, r, flashCookie, kind+":"+url.QueryEscape(text), 60)
}

func (s *Server) errorPage(w http.ResponseWriter, r *http.Request, status int, msgKey string) {
	v := s.view(r, "errors.title")
	v.Data = map[string]any{"Status": status, "Message": v.T(msgKey)}
	s.render(w, r, status, "error", v)
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	s.errorPage(w, r, http.StatusNotFound, "errors.not_found")
}

// auditEntry schreibt einen fertigen Eintrag (z. B. beim Login, wenn noch niemand angemeldet ist) und loggt
// einen Schreibfehler, statt ihn zu verschlucken.
func (s *Server) auditEntry(ctx context.Context, e store.AuditEntry) {
	if err := s.Store.Audit(ctx, e); err != nil {
		s.log.Error("audit write failed", "action", e.Action, "err", err)
	}
}

// audit schreibt einen Eintrag ins Audit-Log mit dem angemeldeten Benutzer.
func (s *Server) audit(r *http.Request, action, target, details string) {
	actor := "-"
	if u := currentUser(r); u != nil {
		actor = u.Username
	}
	origin := "local"
	if k, _ := r.Context().Value(ctxAPIKey).(*store.APIKey); k != nil { // per API-Key: welcher Key
		origin = "api:" + k.Name
		if k.Hint != "" {
			origin += " (" + k.Hint + ")"
		}
	}
	if id, ok := r.Context().Value(ctxMCPKey).(mcp.Identity); ok { // in-process ueber die MCP-Schnittstelle
		origin = mcpOrigin(id.KeyName, id.KeyHint)
	}
	if err := s.Store.Audit(r.Context(), store.AuditEntry{Actor: actor, Action: action, Target: target, Details: details, IP: s.clientIP(r), Origin: origin}); err != nil {
		s.log.Error("audit write failed", "err", err)
	}
}

// moduleStatuses ist eine Hilfe fuer Templates.
func (s *Server) moduleStatuses(r *http.Request) []module.Status { return s.Modules.List(r.Context()) }

// renderModule zeigt eine Modulseite im Layout des Kerns.
func (s *Server) renderModule(w http.ResponseWriter, r *http.Request, status int, page, titleKey string, data any) {
	v := s.view(r, titleKey)
	v.Data = data
	s.render(w, r, status, page, v)
}

// tr uebersetzt fuer die Sprache des Aufrufers (fuer Module).
func (s *Server) tr(r *http.Request, key string, args ...any) string {
	return s.I18n.T(s.lang(r), key, args...)
}

// actor ist der angemeldete Benutzername oder "-".
func (s *Server) actor(r *http.Request) string {
	if u := currentUser(r); u != nil {
		return u.Username
	}
	return "-"
}

// validTimezone prueft einen Zeitzonennamen.
func validTimezone(tz string) bool {
	_, err := time.LoadLocation(tz)
	return err == nil
}
