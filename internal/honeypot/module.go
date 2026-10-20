package honeypot

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/ports"
	"github.com/ipv64net/node64/internal/store"
)

// changelog wird unter Einstellungen > Module angezeigt (Version siehe Info).
//
//go:embed CHANGELOG.md
var changelog string

//go:embed CHANGELOG.en.md
var changelogEN string

const (
	version = "0.2.1"

	setConfig = "honeypot.config" // Einstellung des Moduls als JSON (ModuleConfig)

	// Profile; "custom" = eigene Auswahl der Dienste.
	ProfileMinimal  = "minimal"
	ProfileStandard = "standard"
	ProfileFull     = "full"
	ProfileCustom   = "custom"

	defaultRetentionDays = 7
	maxRetentionDays     = 90
	minMaxEvents         = 1000
	maxMaxEvents         = 5000000

	notifyEvery = time.Hour // hoechstens eine gebuendelte Meldung je Stunde
	notifyIPs   = 5         // so viele IPs nennt die Meldung
)

// KindNotifyNew ist die Art der Meldung "neue Angreifer" (gebuendelt, hoechstens stuendlich).
const KindNotifyNew = notify.KindHoneypotNew

// ModuleConfig ist die Einstellung des Moduls (Datenbank der Node, Schluessel honeypot.config). Config wird
// eingebettet: Dienste, Port-Scan-Erkennung und Limits stehen im JSON auf oberster Ebene.
type ModuleConfig struct {
	Profile string `json:"profile"` // minimal, standard, full oder custom (dann gilt Services)
	Config
	RetentionDays int   `json:"retention_days"` // Aufbewahrung der Ereignisse, Standard 7
	MaxEvents     int64 `json:"max_events"`     // Obergrenze der gespeicherten Ereignisse, Standard 200000
	NotifyNew     bool  `json:"notify_new"`     // Benachrichtigung bei neuen Angreifern (Standard aus)
	Report        bool  `json:"report"`         // Meldung an ipv64 (Opt-in, Standard aus; braucht den zentralen API-Key)
}

// DefaultConfig: Profil standard mit Port-Scan-Erkennung, 7 Tage, ohne Benachrichtigung.
func DefaultConfig() ModuleConfig {
	return ModuleConfig{Profile: ProfileStandard, Config: Config{Scan: true}, RetentionDays: defaultRetentionDays, MaxEvents: DefaultMaxRows}
}

// sensorAPI ist, was das Modul vom Sensor braucht (Tests setzen einen Ersatz ein).
type sensorAPI interface {
	SetPortCheck(func(service string, port int) error)
	Apply(ctx context.Context, cfg Config, sink Sink) []ServiceStatus
	Stop()
	Status() []ServiceStatus
	Counters() *Counters
}

// Module implementiert module.Module.
type Module struct {
	core    *store.Store
	log     *slog.Logger
	dataDir string
	version string
	st      *Store
	sink    Sink

	ports     *ports.Registry    // Port-Verwaltung des Kerns (nil = keine Pruefung)
	notifier  func(notify.Alert) // Meldungen (nil = keine)
	key       *ipv64api.Key      // zentraler ipv64-API-Key (nil = keiner, dann keine Meldung an ipv64)
	rep       *Reporter          // Meldung an ipv64 (report.go)
	newSensor func(*slog.Logger, string) sensorAPI
	every     time.Duration // Abstand der Meldungen bei neuen Angreifern

	g module.Guards

	ctl      sync.Mutex // serialisiert Start, Stop und das Uebernehmen der Einstellungen
	mu       sync.Mutex // die Felder darunter
	sensor   sensorAPI  // nil = Modul aus
	life     context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	started  time.Time
	status   []ServiceStatus // Stand nach dem letzten Apply (fuer Claims, ohne den Sensor zu fragen)
	warnings []Warning       // vom Profil weggelassene bzw. riskante Ports
}

// Warning ist ein Hinweis zu einem Port der Einstellung (Profil laesst ihn weg oder ein anderer Teil will ihn).
type Warning struct {
	Service string `json:"service"`
	Port    int    `json:"port"`
	Owner   string `json:"owner"`   // anderer Teil (web, edge, dns64, cdn64 …)
	Purpose string `json:"purpose"` // z. B. HTTPS
	Skipped bool   `json:"skipped"` // true = nicht geoeffnet (Port belegt), false = geoeffnet, anderer Teil kann ihn spaeter nicht nutzen
}

// New erzeugt das Modul. dataDir ist das Datenverzeichnis von Node64 (Daten unter <dataDir>/honeypot).
func New(core *store.Store, log *slog.Logger, dataDir, nodeVersion string) *Module {
	l := log.With("module", Name)
	st := NewStore(core, log)
	m := &Module{core: core, log: l, dataDir: dataDir, version: nodeVersion, st: st, sink: CountEvents(st.Sink()), every: notifyEvery,
		newSensor: func(log *slog.Logger, dir string) sensorAPI { return NewSensor(log, dir) }}
	m.rep = NewReporter(ReporterConfig{Store: st, API: m.api, Enabled: func(ctx context.Context) bool { return m.loadConfig(ctx).Report },
		Profile:  func(ctx context.Context) string { return m.loadConfig(ctx).Profile },
		SensorID: func(ctx context.Context) (string, error) { return SensorIDFromSettings(ctx, core) },
		State:    SettingsReportState(core), Mode: "module", Version: nodeVersion, Log: l})
	return m
}

// SetKey verbindet das Modul mit dem zentralen ipv64-API-Key (Meldung an ipv64).
func (m *Module) SetKey(k *ipv64api.Key) { m.key = k }

// api liefert Client und Key fuer die Meldung ("" = kein Key eingetragen).
func (m *Module) api(ctx context.Context) (*ipv64api.Client, string) {
	if m.key == nil {
		return nil, ""
	}
	return m.key.Client(), m.key.Get(ctx)
}

// Reporter liefert den Sender der Meldungen an ipv64.
func (m *Module) Reporter() *Reporter { return m.rep }

// SetPorts verbindet das Modul mit der Port-Verwaltung des Kerns.
func (m *Module) SetPorts(r *ports.Registry) { m.ports = r }

// SetNotifier installiert den Versand (Dispatcher des Kerns).
func (m *Module) SetNotifier(f func(notify.Alert)) { m.notifier = f }

// Store liefert den Speicher der Ereignisse.
func (m *Module) Store() *Store { return m.st }

func (m *Module) Info() module.Info {
	return module.Info{Name: Name, TitleKey: "nav.honeypot", Icon: "bi-bug", Path: "/honeypot", Available: true, Order: 50,
		Version: version, Changelog: changelog, ChangelogEN: changelogEN}
}

// Migrations: Tabelle der Ereignisse in node64.db (Scope honeypot).
func (m *Module) Migrations() []store.Migration { return Migrations() }

func (m *Module) Routes(mux *http.ServeMux, g module.Guards) {
	m.g = g
	m.uiRoutes(mux, g)
	m.apiRoutes(mux, g)
}

func (m *Module) dir() string { return filepath.Join(m.dataDir, Name) }

// Start schreibt den Puffer weg (Store.Run), oeffnet die Fallen-Dienste und startet die Benachrichtigung.
// Ein Port, der nicht geht, haelt das Modul nicht auf (steht als Fehler am Dienst).
func (m *Module) Start(ctx context.Context) error {
	m.ctl.Lock()
	defer m.ctl.Unlock()
	m.mu.Lock()
	if m.sensor != nil {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()
	if err := os.MkdirAll(m.dir(), 0o750); err != nil {
		return err
	}
	lctx, cancel := context.WithCancel(context.Background())
	s := m.newSensor(m.log, m.dir())
	s.SetPortCheck(m.portCheck)
	m.mu.Lock()
	m.sensor, m.life, m.cancel, m.started = s, lctx, cancel, time.Now()
	m.mu.Unlock()
	m.wg.Add(3)
	go func() { defer m.wg.Done(); m.st.Run(lctx) }()
	go func() { defer m.wg.Done(); m.notifyLoop(lctx) }()
	go func() { defer m.wg.Done(); m.rep.Run(lctx) }() // tut nichts, solange die Meldung aus ist
	m.applyLocked(ctx)
	m.log.Info("honeypot started", "services", len(m.Status()))
	return nil
}

// Stop schliesst alle Fallen-Dienste und schreibt die restlichen Ereignisse.
func (m *Module) Stop(ctx context.Context) error {
	m.ctl.Lock()
	defer m.ctl.Unlock()
	m.mu.Lock()
	s, cancel := m.sensor, m.cancel
	m.sensor, m.cancel, m.life, m.status, m.warnings = nil, nil, nil, nil, nil
	m.mu.Unlock()
	if s == nil {
		return nil
	}
	s.Stop() // zuerst: danach kommen keine Ereignisse mehr
	cancel()
	done := make(chan struct{})
	go func() { m.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	m.log.Info("honeypot stopped")
	return nil
}

// running liefert den laufenden Sensor (nil = aus).
func (m *Module) running() sensorAPI {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sensor
}

// apply uebernimmt die gespeicherte Einstellung in den laufenden Sensor (aus = nichts zu tun).
func (m *Module) apply(ctx context.Context) {
	m.ctl.Lock()
	defer m.ctl.Unlock()
	m.applyLocked(ctx)
}

// applyLocked: apply mit gehaltenem m.ctl. Der Sensor bekommt den Lebens-Kontext des Moduls (nicht ctx der
// Anfrage), damit die Ports nach der Anfrage offen bleiben.
func (m *Module) applyLocked(ctx context.Context) {
	m.mu.Lock()
	s, life := m.sensor, m.life
	m.mu.Unlock()
	if s == nil {
		return
	}
	cfg := m.loadConfig(ctx)
	m.st.SetLimits(time.Duration(cfg.RetentionDays)*24*time.Hour, cfg.MaxEvents)
	svcs, warns := m.resolve(ctx, cfg)
	run := cfg.Config
	run.Services = svcs
	if m.core.SettingOr(ctx, setConfig, "") == "" { // nie eingestellt: nichts oeffnen, bis die Auswahl gespeichert ist
		run.Services = nil
	}
	status := s.Apply(life, run, m.sink)
	m.mu.Lock()
	m.status, m.warnings = status, warns
	m.mu.Unlock()
}

// Status liefert den Zustand je Dienst (leer = Modul aus).
func (m *Module) Status() []ServiceStatus {
	s := m.running()
	if s == nil {
		return nil
	}
	return s.Status()
}

// Warnings liefert die Hinweise des letzten Uebernehmens (Ports, die das Profil weggelassen hat u. ae.).
func (m *Module) Warnings() []Warning {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Warning(nil), m.warnings...)
}

// Claims liefert die Ports des Honeypots fuer die Port-Verwaltung (aus = keine; aktiv = Port offen). Fragt den
// Sensor nicht (Stand nach dem letzten Apply), damit eine Port-Pruefung waehrend Apply nicht haengt.
func (m *Module) Claims(context.Context) []ports.Claim {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sensor == nil {
		return nil
	}
	out := make([]ports.Claim, 0, len(m.status))
	for _, s := range m.status {
		out = append(out, ports.Claim{Owner: Name, Purpose: "Honeypot " + strings.ToUpper(s.Service), Proto: ports.TCP, Port: s.Port, Active: s.Listen})
	}
	return out
}

// portCheck fragt die Port-Verwaltung vor dem Oeffnen (Sensor.SetPortCheck).
func (m *Module) portCheck(service string, port int) error {
	if m.ports == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return m.ports.Check(ctx, Name, []ports.Claim{{Owner: Name, Purpose: "Honeypot " + strings.ToUpper(service), Proto: ports.TCP, Port: port}})
}

// others liefert die Ports der anderen Teile (TCP).
func (m *Module) others(ctx context.Context) []ports.Claim {
	if m.ports == nil {
		return nil
	}
	var out []ports.Claim
	for _, c := range m.ports.All(ctx) {
		if c.Owner != Name && c.Proto == ports.TCP {
			out = append(out, c)
		}
	}
	return out
}

// portConflict sucht einen anderen Teil auf dem Port: zuerst einen, der ihn offen hat (active), sonst einen, der ihn
// eingestellt hat (spaeter oeffnen will).
func portConflict(others []ports.Claim, port int) (c ports.Claim, found bool) {
	want := ports.Claim{Proto: ports.TCP, Port: port}
	for _, o := range others {
		if ports.Overlap(want, o) {
			if o.Active {
				return o, true
			}
			if !found {
				c, found = o, true
			}
		}
	}
	return c, found
}

// resolve liefert die Dienste, die geoeffnet werden: beim Profil ohne Ports, die ein anderer Teil offen hat
// (mit Hinweis); bei eigener Auswahl alle (die Pruefung beim Speichern hat Konflikte schon abgelehnt; was seitdem
// belegt wurde, meldet der Sensor als Fehler am Dienst).
func (m *Module) resolve(ctx context.Context, cfg ModuleConfig) ([]Service, []Warning) {
	others := m.others(ctx)
	var out []Service
	var warns []Warning
	list := cfg.Services
	if cfg.Profile != ProfileCustom {
		list = Profiles[cfg.Profile]
	}
	for _, s := range list {
		if c, ok := portConflict(others, s.Port); ok {
			w := Warning{Service: s.Service, Port: s.Port, Owner: c.Owner, Purpose: c.Purpose, Skipped: c.Active && cfg.Profile != ProfileCustom}
			warns = append(warns, w)
			if w.Skipped {
				continue
			}
		}
		out = append(out, s)
	}
	return out, warns
}

// FieldErrors sind Fehler der Einstellung je Feld (Schluessel = Feldname im Formular bzw. JSON).
type FieldErrors map[string]string

func (f FieldErrors) Error() string {
	keys := make([]string, 0, len(f))
	for k := range f {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(k + ": " + f[k])
	}
	return b.String()
}

// validate prueft und normalisiert die Einstellung (Standardwerte fuer leere Felder). Port-Konflikte mit Ports,
// die ein anderer Teil offen hat, sind bei eigener Auswahl Fehler; beim Profil werden sie weggelassen.
// Die Texte sind i18n-Schluessel (mit Werten nach "|", siehe errText).
func (m *Module) validate(ctx context.Context, c *ModuleConfig) FieldErrors {
	errs := FieldErrors{}
	c.Profile = strings.ToLower(strings.TrimSpace(c.Profile))
	if c.Profile == "" {
		c.Profile = ProfileStandard
	}
	if _, ok := Profiles[c.Profile]; !ok && c.Profile != ProfileCustom {
		errs["profile"] = "honeypot.err.profile"
	}
	if c.RetentionDays == 0 {
		c.RetentionDays = defaultRetentionDays
	}
	if c.RetentionDays < 1 || c.RetentionDays > maxRetentionDays {
		errs["retention_days"] = "honeypot.err.retention|" + strconv.Itoa(maxRetentionDays)
	}
	if c.MaxEvents == 0 {
		c.MaxEvents = DefaultMaxRows
	}
	if c.MaxEvents < minMaxEvents || c.MaxEvents > maxMaxEvents {
		errs["max_events"] = "honeypot.err.max_events|" + strconv.Itoa(minMaxEvents) + "|" + strconv.Itoa(maxMaxEvents)
	}
	if c.MaxConnsPerIP < 0 || c.MaxConnsPerIP > 1000 {
		errs["max_conns_per_ip"] = "honeypot.err.limit|1000"
	}
	if c.MaxConnsTotal < 0 || c.MaxConnsTotal > 100000 {
		errs["max_conns_total"] = "honeypot.err.limit|100000"
	}
	if c.Services == nil {
		c.Services = []Service{}
	}
	if c.Profile != ProfileCustom {
		return errs
	}
	if len(c.Services) == 0 {
		errs["services"] = "honeypot.err.no_services"
		return errs
	}
	if len(c.Services) > 64 {
		errs["services"] = "honeypot.err.too_many|64"
		return errs
	}
	others := m.others(ctx)
	seen := map[int]bool{}
	var problems []string
	for i := range c.Services {
		s := &c.Services[i]
		s.Service = strings.ToLower(strings.TrimSpace(s.Service))
		s.Page = strings.ToLower(strings.TrimSpace(s.Page))
		switch {
		case !cfgService(s.Service):
			problems = append(problems, "honeypot.err.service|"+s.Service)
		case s.Port < 1 || s.Port > 65535:
			problems = append(problems, "honeypot.err.port|"+strconv.Itoa(s.Port))
		case seen[s.Port]:
			problems = append(problems, "honeypot.err.port_twice|"+strconv.Itoa(s.Port))
		case s.Page != "" && ((s.Service != SvcHTTP && s.Service != SvcHTTPS) || !cfgPage(s.Page)):
			problems = append(problems, "honeypot.err.page|"+s.Page)
		default:
			if o, ok := portConflict(others, s.Port); ok && o.Active {
				problems = append(problems, "honeypot.err.port_used|"+strconv.Itoa(s.Port)+"|"+o.Owner+" ("+o.Purpose+")")
			}
		}
		seen[s.Port] = true
	}
	if len(problems) > 0 {
		errs["services"] = strings.Join(problems, "\n")
	}
	return errs
}

func cfgService(s string) bool {
	switch s {
	case SvcSSH, SvcTelnet, SvcHTTP, SvcHTTPS, SvcTCP:
		return true
	}
	return false
}

func cfgPage(p string) bool {
	for _, x := range Pages {
		if x == p {
			return true
		}
	}
	return false
}

// loadConfig liest die Einstellung (fehlt sie oder ist sie kaputt: Standard).
func (m *Module) loadConfig(ctx context.Context) ModuleConfig {
	c := DefaultConfig()
	if raw := m.core.SettingOr(ctx, setConfig, ""); raw != "" {
		var x ModuleConfig
		if err := json.Unmarshal([]byte(raw), &x); err == nil {
			c = x
		} else {
			m.log.Warn("honeypot: settings unreadable, using defaults", "err", err)
		}
	}
	if c.Profile == "" {
		c.Profile = ProfileStandard
	}
	if c.RetentionDays <= 0 {
		c.RetentionDays = defaultRetentionDays
	}
	if c.MaxEvents <= 0 {
		c.MaxEvents = DefaultMaxRows
	}
	if c.Services == nil {
		c.Services = []Service{}
	}
	return c
}

// SaveConfig prueft und speichert die Einstellung und uebernimmt sie sofort (laeuft das Modul).
// Fehler je Feld kommen als FieldErrors.
func (m *Module) SaveConfig(ctx context.Context, c ModuleConfig) (ModuleConfig, error) {
	old := m.loadConfig(ctx)
	errs := m.validate(ctx, &c)
	if _, key := m.api(ctx); c.Report && !old.Report && key == "" {
		errs["report"] = "honeypot.err.report_key"
	}
	if len(errs) > 0 {
		return c, errs
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return c, err
	}
	if err := m.core.SetSetting(ctx, setConfig, string(raw)); err != nil {
		return c, err
	}
	if c.Report && !old.Report { // Opt-in: gemeldet wird erst ab jetzt, nichts von vorher
		if err := m.rep.ResetWindow(ctx); err != nil {
			m.log.Warn("honeypot report: state not saved", "err", err)
		}
	}
	m.apply(ctx)
	return c, nil
}

// ClearEvents loescht alle gespeicherten Ereignisse (Puffer vorher geschrieben, damit nichts nachkommt).
func (m *Module) ClearEvents(ctx context.Context) (int64, error) {
	_ = m.st.Flush(ctx)
	res, err := m.core.Writer().ExecContext(ctx, `DELETE FROM hp_events`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// Export liefert die Einstellung (die Ereignisse bleiben lokal).
func (m *Module) Export(ctx context.Context) (any, error) { return m.loadConfig(ctx), nil }

// Import uebernimmt die Einstellung. Eigene Dienste, deren Port hier belegt ist, fallen weg (mit Fehler).
func (m *Module) Import(ctx context.Context, raw json.RawMessage) (int, error) {
	c := DefaultConfig()
	if err := json.Unmarshal(raw, &c); err != nil {
		return 0, fmt.Errorf("honeypot: %w", err)
	}
	if _, key := m.api(ctx); key == "" && !m.loadConfig(ctx).Report {
		c.Report = false // ohne API-Key hier nicht einschaltbar
	}
	_, err := m.SaveConfig(ctx, c)
	var fe FieldErrors
	if errors.As(err, &fe) && len(fe) == 1 && fe["services"] != "" && c.Profile == ProfileCustom {
		// nur Port-Konflikte u. ae. bei eigenen Diensten: die gueltigen uebernehmen
		others := m.others(ctx)
		var keep []Service
		for _, s := range c.Services {
			if o, ok := portConflict(others, s.Port); (!ok || !o.Active) && cfgService(s.Service) && s.Port > 0 && s.Port < 65536 {
				keep = append(keep, s)
			}
		}
		c.Services = keep
		if len(keep) == 0 {
			c.Profile = ProfileMinimal
		}
		if _, err2 := m.SaveConfig(ctx, c); err2 == nil {
			return 1, fmt.Errorf("honeypot: %s", fe.Error())
		}
	}
	if err != nil {
		return 0, fmt.Errorf("honeypot: %w", err)
	}
	return 1, nil
}

// Card liefert die Dashboard-Karte (module.CardProvider): Zahlen der letzten 24 Stunden.
func (m *Module) Card(ctx context.Context) (*module.Card, error) {
	c := &module.Card{TitleKey: "nav.honeypot", Icon: "bi-bug", Path: "/honeypot"}
	open, errs := 0, 0
	for _, s := range m.Status() {
		if s.Listen {
			open++
		} else if s.Error != "" {
			errs++
		}
	}
	sum, err := m.summary(ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		return nil, err
	}
	c.Stats = []module.CardStat{
		{LabelKey: "honeypot.card.services", Value: int64(open)},
		{LabelKey: "honeypot.card.events", Value: sum.Events},
		{LabelKey: "honeypot.card.sources", Value: sum.Sources},
		{LabelKey: "honeypot.card.logins", Value: sum.Logins},
	}
	if errs > 0 {
		c.Stats = append(c.Stats, module.CardStat{LabelKey: "honeypot.card.errors", Value: int64(errs), Class: "text-danger"})
	}
	return c, nil
}

// summaryCounts sind die Kennzahlen eines Zeitraums ohne Ranglisten (guenstig fuer Karte und Prometheus).
type summaryCounts struct {
	Events, Sources, Logins int64
}

func (m *Module) summary(ctx context.Context, since time.Time) (summaryCounts, error) {
	return storeSummary(ctx, m.st, since)
}

func storeSummary(ctx context.Context, st *Store, since time.Time) (summaryCounts, error) {
	var s summaryCounts
	err := st.st.Reader().QueryRowContext(ctx, `SELECT COUNT(*), COUNT(DISTINCT NULLIF(src, '')), COALESCE(SUM(login), 0) FROM hp_events WHERE ts >= ?`,
		storeTime(since)).Scan(&s.Events, &s.Sources, &s.Logins)
	return s, err
}

// notifyLoop prueft stuendlich auf neue Angreifer und schickt hoechstens eine gebuendelte Meldung.
func (m *Module) notifyLoop(ctx context.Context) {
	last := time.Now()
	t := time.NewTicker(m.every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		last = m.notifyNew(ctx, last)
	}
}

// notifyNew meldet die seit since neuen Quell-IPs (wenn eingeschaltet) und liefert den neuen Stichzeitpunkt.
func (m *Module) notifyNew(ctx context.Context, since time.Time) time.Time {
	now := time.Now()
	if m.notifier == nil || !m.loadConfig(ctx).NotifyNew {
		return now
	}
	_ = m.st.Flush(ctx)
	list, err := m.st.NewSources(ctx, since, 1000)
	if err != nil {
		if ctx.Err() == nil {
			m.log.Warn("honeypot: new sources", "err", err)
		}
		return since // beim naechsten Mal nachholen
	}
	if len(list) == 0 {
		return now
	}
	ips := make([]string, 0, notifyIPs)
	for i, c := range list {
		if i == notifyIPs {
			break
		}
		ips = append(ips, c.Key)
	}
	msg := strconv.Itoa(len(list)) + " IPs: " + strings.Join(ips, ", ")
	if len(list) > notifyIPs {
		msg += ", …"
	}
	m.log.Info("notification", "kind", KindNotifyNew, "new_sources", len(list))
	m.notifier(notify.Alert{EventID: "honeypot-new-" + strconv.FormatInt(now.UnixNano(), 36), Kind: KindNotifyNew, Time: now.UTC(),
		Check: notify.CheckInfo{Name: "Honeypot64", NotifyDown: true, NotifyUp: true, Local: true}, Message: msg})
	return now
}
