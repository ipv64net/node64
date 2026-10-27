package honeypot

import (
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/geoip"
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
	page := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /honeypot", page(m.pageOverview))
	mux.Handle("GET /honeypot/settings", page(m.pageSettings))
	mux.Handle("POST /honeypot/settings", page(m.pageSettingsSave))
	mux.Handle("POST /honeypot/clear", page(m.pageClear))
	mux.Handle("POST /honeypot/cert", page(m.pageCert))
}

// uiTab ist ein Reiter der Modulseiten.
type uiTab struct {
	Key, Path, TitleKey, Icon string
	Active                    bool
}

var uiTabs = []uiTab{{"overview", "/honeypot", "honeypot.tab.overview", "bi-speedometer2", false},
	{"settings", "/honeypot/settings", "honeypot.tab.settings", "bi-gear", false}}

func tabsFor(key string) []uiTab {
	out := make([]uiTab, 0, len(uiTabs))
	for _, t := range uiTabs {
		t.Active = t.Key == key
		out = append(out, t)
	}
	return out
}

// uiBar ist ein Balken im Verlauf.
type uiBar struct {
	Label string // Achse (Stunde bzw. Tag), leer = keine Beschriftung
	Title string // Tooltip: Zeitpunkt
	Count int64
	Pct   int // Hoehe in Prozent des groessten Werts
}

// uiRank ist eine Rangliste.
type uiRank struct {
	ID, TitleKey, Icon string
	Mono               bool
	Items              []uiRankItem
}

type uiRankItem struct {
	Key    string
	Count  int64
	Pct    int
	Origin uiCountry // nur Quell-IPs: Land
}

// uiWarning ist ein Hinweis zu einem Port (Text schon uebersetzt).
type uiWarning struct {
	Warning
	OwnerName string
}

type overviewData struct {
	Tabs     []uiTab
	Running  bool
	Started  time.Time
	Profile  string
	Scan     bool
	Services []ServiceStatus
	Warnings []uiWarning
	Counters CounterValues
	Range    string // 24h oder 7d
	Day      summaryCounts
	Week     summaryCounts
	Bars     []uiBar
	BarsMax  int64
	Ranks    []uiRank
	Events   []EventView
	Report   ReportStatus
	Err      string
	Source   string    // Filter der Ereignisliste: "" (alle), honeypot, log, syslog
	Sources  []string  // Auswahl des Filters
	Logs     LogStatus // Log-Sensor und Syslog-Empfaenger
	Login    loginView // Angriffe auf die Node64-Anmeldung (login.go)

	// Herkunft und „Was wurde angegriffen“ (geo.go)
	Countries      []uiCountryRank
	CountryCount   int   // Laender mit Ereignissen
	CountryUnknown int64 // Ereignisse ohne Land
	Geo            geoip.Status
	Targets        uiTargets
	Decoys         []uiDecoy

	// Laenderkarte und Filter der Ereignisliste nach Land (geomap.go)
	Map     MapView
	Country uiCountry // Filter country=XX ("" Code = alle)
}

// URL baut einen Link der Uebersicht mit Zeitraum, Sensor-Filter und Land (leere Werte fallen weg).
func (overviewData) URL(rng, source, country string) string {
	q := url.Values{}
	if rng == "7d" {
		q.Set("range", rng)
	}
	if source != "" {
		q.Set("source", source)
	}
	if country != "" {
		q.Set("country", country)
	}
	if len(q) == 0 {
		return "/honeypot"
	}
	return "/honeypot?" + q.Encode()
}

func (m *Module) warnViews(r *http.Request, list []Warning) []uiWarning {
	out := make([]uiWarning, 0, len(list))
	for _, w := range list {
		out = append(out, uiWarning{Warning: w, OwnerName: m.ownerName(r, w.Owner)})
	}
	return out
}

// ownerName: Teil der Node lesbar (honeypot.owner.<owner>, unbekannt = Kennung).
func (m *Module) ownerName(r *http.Request, owner string) string {
	key := "honeypot.owner." + owner
	if t := m.g.T(r, key); t != key {
		return t
	}
	return owner
}

func (m *Module) pageOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	info := m.statusInfo(r)
	d := overviewData{Tabs: tabsFor("overview"), Running: info.Running, Started: info.StartedAt, Profile: info.Profile, Scan: info.Scan,
		Services: info.Services, Warnings: m.warnViews(r, info.Warnings), Counters: info.Counters, Range: "24h", Report: info.Report,
		Sources: []string{SrcHoneypot, SrcLog, SrcSyslog}, Logs: info.Logs, Login: m.loginOverview(ctx, m.loadConfig(ctx).Login)}
	span := 24 * time.Hour
	if r.URL.Query().Get("range") == "7d" {
		d.Range, span = "7d", 7*24*time.Hour
	}
	d.Source, _ = eventSource(r.URL.Query().Get("source")) // unbekannt = alle
	// Filter nach Land (ungueltig = alle)
	if cc, ok := validCountry(r.URL.Query().Get("country")); ok {
		d.Country = countryView(cc, m.lang(r))
	}
	d.Geo = geoip.Current()
	_ = m.st.Flush(ctx)
	now := time.Now()
	var err error
	if d.Day, err = m.summary(ctx, now.Add(-24*time.Hour)); err == nil {
		d.Week, err = m.summary(ctx, now.Add(-7*24*time.Hour))
	}
	var st *Stats
	if err == nil {
		st, err = m.st.Stats(ctx, now.Add(-span), 10)
	}
	if err == nil {
		d.Bars, d.BarsMax = m.bars(r, st.Timeline, d.Range == "7d")
		lang := m.lang(r)
		d.Ranks = ranks(st, lang)
		d.Countries, d.CountryCount, d.CountryUnknown = countryRanks(st.ByCountry, lang, 15), len(st.ByCountry), st.CountryUnknown
		d.Map = BuildMap(st.ByCountry, lang)
		d.Decoys = decoyRanks(st.ByDecoy)
		var rows []targetRow
		if rows, err = m.st.targets(ctx, storeTime(st.Since)); err == nil {
			d.Targets = buildTargets(rows, 10)
			d.Events, err = m.recent(r, 50, d.Source, d.Country.Code)
		}
	}
	if err != nil {
		m.log.Error("honeypot page", "err", err)
		d.Err = err.Error()
	}
	m.g.Render(w, r, http.StatusOK, Name+"/overview", "honeypot.title", d)
}

// bars macht aus dem Verlauf Balken (Hoehe relativ zum groessten Wert, Beschriftung in der Zeitzone des Benutzers).
func (m *Module) bars(r *http.Request, tl []TimePoint, daily bool) ([]uiBar, int64) {
	loc := time.Local
	if m.g.Timezone != nil {
		if l := m.g.Timezone(r); l != nil {
			loc = l
		}
	}
	var max int64
	for _, p := range tl {
		max = maxInt64(max, p.Events)
	}
	out := make([]uiBar, 0, len(tl))
	for i, p := range tl {
		t := p.Time.In(loc)
		b := uiBar{Count: p.Events, Title: t.Format("02.01. 15:04")}
		if daily {
			b.Label, b.Title = t.Format("02.01."), t.Format("02.01.2006")
		} else if i%3 == 0 {
			b.Label = t.Format("15")
		}
		if max > 0 {
			b.Pct = int(p.Events * 100 / max)
			if p.Events > 0 && b.Pct < 2 {
				b.Pct = 2 // sichtbar
			}
		}
		out = append(out, b)
	}
	return out, max
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// lang: Sprache des Aufrufers (Laendernamen), ohne Oberflaeche "en".
func (m *Module) lang(r *http.Request) string {
	if m.g.Lang != nil {
		return m.g.Lang(r)
	}
	return "en"
}

// ranks baut die Ranglisten; Dienste, Ports und Arten stehen farbig unter „Was wurde angegriffen“ (buildTargets).
func ranks(st *Stats, lang string) []uiRank {
	mk := func(id, key, icon string, mono bool, list []Count) uiRank {
		r := uiRank{ID: id, TitleKey: key, Icon: icon, Mono: mono, Items: []uiRankItem{}}
		var max int64
		for _, c := range list {
			max = maxInt64(max, c.Count)
		}
		for _, c := range list {
			it := uiRankItem{Key: c.Key, Count: c.Count, Origin: countryView(c.Country, lang)}
			if max > 0 {
				it.Pct = int(c.Count * 100 / max)
			}
			r.Items = append(r.Items, it)
		}
		return r
	}
	return []uiRank{
		mk("sources", "honeypot.top.sources", "bi-geo-alt", true, st.TopSources),
		mk("origins", "honeypot.top.origins", "bi-diagram-3", true, st.BySource),
		mk("users", "honeypot.top.users", "bi-person", true, st.TopUsers),
		mk("passwords", "honeypot.top.passwords", "bi-key", true, st.TopPass),
		mk("credentials", "honeypot.top.credentials", "bi-person-lock", true, st.TopCreds),
		mk("paths", "honeypot.top.paths", "bi-signpost", true, st.TopPaths),
		mk("uas", "honeypot.top.user_agents", "bi-window", true, st.TopUAs),
		mk("fingerprints", "honeypot.top.fingerprints", "bi-fingerprint", true, st.TopFingerprints),
	}
}

type settingsData struct {
	Tabs      []uiTab
	Running   bool
	Cfg       ModuleConfig
	Lines     string // eigene Dienste, je Zeile "dienst port [koeder]"
	Profiles  []profileView
	Pages     []string
	Errors    map[string]string
	Warnings  []uiWarning
	MaxDays   int
	MinEvents int
	MaxEvents int
	KeySet    bool         // zentraler ipv64-API-Key eingetragen (sonst Meldung an ipv64 gesperrt)
	Report    ReportStatus // Zustand der Meldung an ipv64

	// Einfacher Modus: Vorlagen mit den Ports, die im Router weiterzuleiten sind, und Startseite der Web-Falle
	Simple     []simpleProfile
	StartPages []string
	Countries  []countryOpt // Standort des Sensors (Live-Karte, Meldung an ipv64)
	Detected   string       // automatisch erkanntes Land ("Flagge Name", "" = noch keins)

	// Dienste-Katalog (catalog.go)
	CatRows     []uiCatRow
	CatExtras   []uiCatRow
	CatServices []string // Auswahl der eigenen Zeilen
	CatPresets  []string
	CatUnsaved  bool   // Vorlage uebernommen, noch nicht gespeichert
	CatLow      bool   // Auswahl enthaelt Ports unter 1024
	SavedAs     string // gespeichertes Profil (custom = eigene Auswahl)
	UIPorts     string // Ports der Oberflaeche ("" = unbekannt)
	TextOpen    bool   // Textliste aufgeklappt (dort gespeichert)
	ServiceList string // bekannte Dienste (Hinweis der Textliste)
	HostAuto    string // erzeugter Hostname der Fallen (Platzhalter, wenn keiner eingestellt ist)

	// Log-Sensor und Syslog (H5)
	LogRows     []LogFile     // Zeilen des Formulars (eingestellte Dateien + leere Zeilen)
	SyslogPort  string        // Formularwert ("" = aus)
	SyslogAllow string        // erlaubte Absender, je Zeile ein Netz
	LogFormats  []string      // Auswahl (leer = automatisch)
	LogRoots    string        // erlaubte Wurzeln (Hinweis)
	LogSuggest  []LogFile     // Vorschlaege (Knoepfe)
	LogFiles    []uiLogFile   // Zustand je Datei
	Syslog      *SyslogStatus // Zustand des Empfaengers (nil = aus)
	LogLines    int64
	LogEvents   int64
	Unsaved     bool // Vorschlag uebernommen, noch nicht gespeichert

	// Zertifikat fuer Koeder-Namen (decoy_cert.go) und Ueberwachung der Anmeldung (login.go)
	CertAvail   bool     // zentrale Zertifikatsverwaltung vorhanden
	CertDNS     bool     // DNS-01 ueber ipv64 moeglich (API-Key)
	Certs       []uiCert // Auswahl
	CertPorts   string   // Formularwert
	CertUses    []string // Dienste, die das Zertifikat zeigen
	CertDomains []string // ipv64-Domains (neues Zertifikat)
	LoginThr    int      // Standard (Platzhalter)
	LoginWin    int
}

// uiLogFile ist der Zustand einer Datei mit Hinweis zum Fehler (i18n-Schluessel, "" = keiner).
type uiLogFile struct {
	LogFileStatus
	Hint string
}

// logSuggestions sind gaengige Pfade (Mount -v /var/log:/host/log:ro), als Knoepfe in den Einstellungen.
var logSuggestions = []LogFile{
	{Path: "/host/log/auth.log", Format: "syslog"},             // sshd, sudo (Debian, Ubuntu)
	{Path: "/host/log/secure", Format: "syslog"},               // sshd (RHEL, Rocky, Alma)
	{Path: "/host/log/mail.log", Format: "syslog"},             // Postfix, Dovecot
	{Path: "/host/log/nginx/access.log", Format: "nginx"},      // nginx
	{Path: "/host/log/apache2/access.log", Format: "apache"},   // Apache (Debian)
	{Path: "/host/log/caddy/access.log", Format: "caddy"},      // Caddy (JSON)
	{Path: "/host/log/daemon.log", Format: "proxmox"},          // Proxmox (pvedaemon)
	{Path: "/host/log/vaultwarden.log", Format: "vaultwarden"}, // Vaultwarden (LOG_FILE)
}

// logHint: Hinweis zu einem Fehler beim Lesen (Rechte, Datei fehlt).
func logHint(err string) string {
	e := strings.ToLower(err)
	switch {
	case e == "":
		return ""
	case strings.Contains(e, "permission denied"):
		return "honeypot.logs.hint_perm"
	case strings.Contains(e, "no such file") || strings.Contains(e, "not exist") || strings.Contains(e, "no files match"):
		return "honeypot.logs.hint_missing"
	}
	return ""
}

// logForm ist der Log-Teil des Formulars, so wie eingegeben (fuer die erneute Anzeige bei Fehlern).
type logForm struct {
	Files []LogFile
	Port  string
	Allow string
}

func logFormFrom(c LogConfig) logForm {
	f := logForm{Files: append([]LogFile(nil), c.Files...), Allow: strings.Join(c.SyslogAllow, "\n")}
	if c.SyslogPort > 0 {
		f.Port = strconv.Itoa(c.SyslogPort)
	}
	return f
}

// parseLogForm liest Dateien (log_path/log_format je Zeile), Syslog-Port und erlaubte Absender.
func parseLogForm(r *http.Request) logForm {
	paths, formats := r.PostForm["log_path"], r.PostForm["log_format"]
	f := logForm{Port: strings.TrimSpace(r.PostFormValue("syslog_port")), Allow: r.PostFormValue("syslog_allow")}
	for i, p := range paths {
		lf := LogFile{Path: strings.TrimSpace(p)}
		if i < len(formats) {
			lf.Format = formats[i]
		}
		if lf.Path != "" {
			f.Files = append(f.Files, lf)
		}
	}
	return f
}

// apply uebertraegt das Formular in die Einstellung (ungueltiger Port = -1, validate meldet es).
func (f logForm) apply(c *LogConfig) {
	c.Files = append([]LogFile(nil), f.Files...)
	c.SyslogPort = 0
	if f.Port != "" {
		if n, err := strconv.Atoi(f.Port); err == nil {
			c.SyslogPort = n
		} else {
			c.SyslogPort = -1
		}
	}
	c.SyslogAllow = strings.FieldsFunc(f.Allow, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t' })
}

type profileView struct {
	Key   string
	Ports string // "ssh 22, http 80 …"
}

func profileViews() []profileView {
	var out []profileView
	for _, p := range []string{ProfileMinimal, ProfileStandard, ProfileFull} {
		var parts []string
		for _, s := range Profiles[p] {
			parts = append(parts, s.Service+" "+strconv.Itoa(s.Port))
		}
		out = append(out, profileView{Key: p, Ports: strings.Join(parts, ", ")})
	}
	return out
}

// simpleProfile: Vorlage im einfachen Modus mit den Ports fuer die Weiterleitung im Router ("22/tcp").
type simpleProfile struct {
	Key   string
	Ports []string
	Low   bool // Ports unter 1024 dabei
}

func simpleProfiles() []simpleProfile {
	var out []simpleProfile
	for _, p := range []string{ProfileProxy, ProfileMinimal, ProfileStandard, ProfileFull} {
		sp := simpleProfile{Key: p}
		for _, s := range Profiles[p] {
			sp.Ports = append(sp.Ports, strconv.Itoa(s.Port)+"/"+string(svcProto(s.Service)))
			sp.Low = sp.Low || s.Port < 1024
		}
		out = append(out, sp)
	}
	return out
}

// servicesText: eigene Dienste als Text fuer das Formular.
func servicesText(list []Service) string {
	var b strings.Builder
	for _, s := range list {
		b.WriteString(s.Service + " " + strconv.Itoa(s.Port))
		if s.Page != "" {
			b.WriteString(" " + s.Page)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// parseServices liest "dienst port [koeder]" je Zeile (auch "dienst:port", Kommentare mit #). Unlesbare Zeilen
// kommen als Dienst mit Port 0 an und fallen in validate auf.
func parseServices(text string) []Service {
	out := []Service{}
	for _, line := range strings.Split(text, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(strings.NewReplacer(":", " ", ",", " ", "/", " ").Replace(line))
		if len(f) == 0 {
			continue
		}
		s := Service{Service: strings.ToLower(f[0])}
		if len(f) > 1 {
			s.Port, _ = strconv.Atoi(f[1])
		}
		if len(f) > 2 {
			s.Page = strings.ToLower(f[2])
		}
		out = append(out, s)
	}
	return out
}

// settingsView baut die Einstellungsseite. cf = Katalog wie eingegeben (nil = aus der Einstellung c).
func (m *Module) settingsView(r *http.Request, c ModuleConfig, lines string, errs map[string]string, lf *logForm, cf *catForm) settingsData {
	d := settingsData{Tabs: tabsFor("settings"), Running: m.running() != nil, Cfg: c, Lines: lines, Profiles: profileViews(), Pages: Pages,
		Simple: simpleProfiles(), StartPages: StartPages, Countries: countryOptions(m.lang(r)),
		Errors: errs, MaxDays: maxRetentionDays, MinEvents: minMaxEvents, MaxEvents: maxMaxEvents,
		LogFormats: cfgLogFormats, LogRoots: strings.Join(cfgLogRoots, ", "), LogSuggest: logSuggestions}
	if d.Errors == nil {
		d.Errors = map[string]string{}
	}
	if cc := ownCC.cached(); cc != "" {
		d.Detected = geoip.Flag(cc) + " " + geoip.Name(cc, m.lang(r))
	}
	form := logFormFrom(c.Log)
	if lf != nil {
		form = *lf
	}
	d.LogRows = append(form.Files, LogFile{}, LogFile{}) // zwei leere Zeilen zum Ergaenzen
	d.SyslogPort, d.SyslogAllow = form.Port, form.Allow
	ls := m.LogStatus()
	for _, f := range ls.Files {
		d.LogFiles = append(d.LogFiles, uiLogFile{LogFileStatus: f, Hint: logHint(f.Error)})
	}
	d.Syslog, d.LogLines, d.LogEvents = ls.Syslog, ls.Lines, ls.Events
	_, key := m.api(r.Context())
	d.KeySet, d.Report = key != "", m.rep.Status(r.Context())
	catf := catFormFrom(effectiveServices(c))
	catf.withPersonas(c.Personas)
	if cf != nil {
		catf = *cf
	}
	auto := c
	auto.Hostname = ""
	d.HostAuto = m.ident(r.Context(), auto).host
	d.CatRows, d.CatExtras, d.CatLow = m.catView(r, catf, m.catStates(r.Context()))
	d.CatServices, d.CatPresets, d.ServiceList = KnownServices(), catPresets, strings.Join(KnownServices(), ", ")
	d.SavedAs, d.UIPorts = m.loadConfig(r.Context()).Profile, m.uiPorts(r.Context())
	if d.Lines == "" {
		d.Lines = servicesText(catf.services()) // Textliste = Auswahl der Tabelle
	}
	// Hinweise fuer die aktuelle Auswahl (auch fuer ein Profil, das noch nicht gespeichert ist)
	_, warns := m.resolve(r.Context(), c)
	d.Warnings = m.warnViews(r, warns)
	d.CertAvail, d.CertPorts, d.LoginThr, d.LoginWin = m.certs != nil, portsText(c.CertPorts), LoginDefThreshold, LoginDefWindow
	if d.CertAvail {
		d.Certs = m.certViews(r.Context())
		d.CertUses = CertUses(c.Config, effectiveServices(c), m.seed(r.Context()))
		if d.CertDNS = m.certs.DNSReady(r.Context()); d.CertDNS {
			d.CertDomains, _ = m.certs.Domains(r.Context())
		}
	}
	return d
}

func (m *Module) pageSettings(w http.ResponseWriter, r *http.Request) {
	m.g.Render(w, r, http.StatusOK, Name+"/settings", "honeypot.settings.title", m.settingsView(r, m.loadConfig(r.Context()), "", nil, nil, nil))
}

func formInt(r *http.Request, name string) int {
	v := strings.TrimSpace(r.PostFormValue(name))
	if v == "" {
		return 0 // leer = Standard
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return -1 // ungueltig: validate meldet es
	}
	return n
}

func (m *Module) pageSettingsSave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c := m.loadConfig(ctx)
	if v := r.PostFormValue("ui_mode"); v != "" { // Einfach/Experte umschalten (nur die Ansicht, sonst nichts)
		c.Expert = v == "expert"
		m.saveSettings(w, r, c, "", nil, nil, false)
		return
	}
	_, key := m.api(ctx)
	if r.PostFormValue("simple") != "" { // einfacher Modus: Vorlage, Startseite, Benachrichtigung, Meldung an ipv64
		if p := r.PostFormValue("profile"); p != ProfileCustom && p != c.Profile {
			if _, ok := Profiles[p]; ok {
				selectionConfig(&c, Profiles[p])
				if p == ProfileProxy {
					c.Profile = ProfileProxy
				}
			}
		}
		c.StartPage = r.PostFormValue("start_page")
		c.Country = r.PostFormValue("country")
		c.NotifyNew = r.PostFormValue("notify_new") != ""
		if key != "" { // ohne Key ist der Schalter gesperrt und kommt nicht mit
			c.Report = r.PostFormValue("report") != ""
		}
		m.saveSettings(w, r, c, "", nil, nil, false)
		return
	}
	lines := r.PostFormValue("services")
	var cf *catForm
	textOpen := false
	switch {
	case r.PostFormValue("use_text") != "": // Textliste (Erweitert) speichern
		sel := parseServices(lines)
		f := catFormFrom(sel)
		f.withPersonas(c.Personas)
		cf, textOpen = &f, true
		selectionConfig(&c, sel)
	case r.PostFormValue("catalog") != "": // Tabelle der Dienste
		f := parseCatForm(r)
		cf = &f
		selectionConfig(&c, f.services())
		if len(f.services()) == 0 && r.PostFormValue("proxy_only") != "" { // Vorlage "Nur ueber PROXY64" (keine Dienste)
			c.Profile = ProfileProxy
		}
		c.Personas = f.personas()
		lines = ""
	default: // Formular ohne Tabelle (Profil und Textliste, z. B. aus Skripten)
		c.Profile = r.PostFormValue("profile")
		if c.Profile == ProfileCustom {
			c.Services = parseServices(lines)
		}
	}
	if _, ok := r.PostForm["hostname"]; ok {
		c.Hostname = r.PostFormValue("hostname")
	}
	c.Scan = r.PostFormValue("scan") != ""
	c.NotifyNew = r.PostFormValue("notify_new") != ""
	if key != "" { // ohne Key ist der Schalter gesperrt und kommt nicht mit
		c.Report = r.PostFormValue("report") != ""
	}
	if _, ok := r.PostForm["start_page"]; ok {
		c.StartPage = r.PostFormValue("start_page")
	}
	if _, ok := r.PostForm["country"]; ok {
		c.Country = r.PostFormValue("country")
	}
	if r.PostFormValue("cert_form") != "" { // Zertifikat fuer Koeder-Namen (nur mit diesem Teil des Formulars)
		c.CertID = int64(formInt(r, "cert_id"))
		c.CertPorts = parsePorts(r.PostFormValue("cert_ports"))
	}
	if r.PostFormValue("login_form") != "" { // Ueberwachung der Anmeldung
		c.Login = LoginConfig{Off: r.PostFormValue("login_watch") == "", NoNotify: r.PostFormValue("login_notify") == "",
			Threshold: formInt(r, "login_threshold"), Window: formInt(r, "login_window")}
	}
	c.MaxConnsPerIP, c.MaxConnsTotal = formInt(r, "max_conns_per_ip"), formInt(r, "max_conns_total")
	c.RetentionDays, c.MaxEvents = formInt(r, "retention_days"), int64(formInt(r, "max_events"))
	lf := parseLogForm(r)
	if v := r.PostFormValue("log_remove"); v != "" { // Datei bzw. Muster entfernen und gleich speichern
		lf.Files = slices.DeleteFunc(lf.Files, func(f LogFile) bool { return f.Path == v })
	}
	if v := r.PostFormValue("log_suggest"); v != "" { // Vorschlag als Zeile uebernehmen, noch nicht speichern
		if i, err := strconv.Atoi(v); err == nil && i >= 0 && i < len(logSuggestions) &&
			!slices.ContainsFunc(lf.Files, func(f LogFile) bool { return f.Path == logSuggestions[i].Path }) {
			lf.Files = append(lf.Files, logSuggestions[i])
		}
		d := m.settingsView(r, c, lines, nil, &lf, cf)
		d.Unsaved, d.Cfg.Expert = true, true // Knopf im Expertenformular
		m.g.Render(w, r, http.StatusOK, Name+"/settings", "honeypot.settings.title", d)
		return
	}
	if p := r.PostFormValue("preset"); p != "" && cf != nil { // Vorlage in die Tabelle uebernehmen, noch nicht speichern
		cf.preset(p, m.catStates(ctx))
		selectionConfig(&c, cf.services())
		if p == ProfileProxy {
			c.Profile = ProfileProxy
		}
		d := m.settingsView(r, c, "", nil, &lf, cf)
		d.CatUnsaved, d.Cfg.Expert = true, true // Knopf im Expertenformular
		m.g.Render(w, r, http.StatusOK, Name+"/settings", "honeypot.settings.title", d)
		return
	}
	lf.apply(&c.Log)
	m.saveSettings(w, r, c, lines, &lf, cf, textOpen)
}

// saveSettings speichert c; bei Fehlern zeigt es das Formular wieder (lf/cf wie eingegeben, nil = aus c).
func (m *Module) saveSettings(w http.ResponseWriter, r *http.Request, c ModuleConfig, lines string, lf *logForm, cf *catForm, textOpen bool) {
	saved, err := m.SaveConfig(r.Context(), c)
	var fe FieldErrors
	if errors.As(err, &fe) {
		errs := map[string]string{}
		for k, v := range fe {
			errs[k] = m.errText(r, v)
		}
		d := m.settingsView(r, saved, lines, errs, lf, cf)
		d.TextOpen = textOpen
		d.Cfg.Expert = d.Cfg.Expert || (r.PostFormValue("simple") == "" && r.PostFormValue("ui_mode") == "") // Fehler im Expertenformular dort zeigen
		m.g.Render(w, r, http.StatusUnprocessableEntity, Name+"/settings", "honeypot.settings.title", d)
		return
	}
	if err != nil {
		m.log.Error("honeypot settings", "err", err)
		m.g.Flash(w, r, "danger", err.Error())
		http.Redirect(w, r, "/honeypot/settings", http.StatusSeeOther)
		return
	}
	m.log.Info("settings saved", "via", "ui", "by", m.g.Actor(r))
	m.g.Audit(r, "honeypot.config", saved.Profile, configDetails(saved))
	m.g.Flash(w, r, "success", m.g.T(r, "honeypot.settings.saved"))
	http.Redirect(w, r, "/honeypot/settings", http.StatusSeeOther)
}

func (m *Module) pageClear(w http.ResponseWriter, r *http.Request) {
	n, err := m.ClearEvents(r.Context())
	if err != nil {
		m.log.Error("honeypot clear", "err", err)
		m.g.Flash(w, r, "danger", err.Error())
	} else {
		m.log.Info("events cleared", "count", n, "via", "ui", "by", m.g.Actor(r))
		m.g.Audit(r, "honeypot.clear", "", strconv.FormatInt(n, 10))
		m.g.Flash(w, r, "success", m.g.T(r, "honeypot.clear.done", "count", n))
	}
	http.Redirect(w, r, "/honeypot/settings", http.StatusSeeOther)
}
