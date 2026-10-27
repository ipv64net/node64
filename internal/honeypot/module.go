package honeypot

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/geoip"
	"github.com/ipv64net/node64/internal/hpbridge"
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
	version = "0.14.6"

	setConfig = "honeypot.config" // Einstellung des Moduls als JSON (ModuleConfig)

	// Profile; "custom" = eigene Auswahl der Dienste.
	ProfileMinimal  = "minimal"
	ProfileStandard = "standard"
	ProfileFull     = "full"
	ProfileProxy    = "proxy" // keine eigenen Ports: nur, was PROXY64 weitergibt (unzuordenbar oder als schaedlich erkannt)
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
	Profile string `json:"profile"` // minimal, standard, full, proxy oder custom (dann gilt Services)
	Config
	RetentionDays int   `json:"retention_days"`   // Aufbewahrung der Ereignisse, Standard 7
	MaxEvents     int64 `json:"max_events"`       // Obergrenze der gespeicherten Ereignisse, Standard 200000
	NotifyNew     bool  `json:"notify_new"`       // Benachrichtigung bei neuen Angreifern (Standard aus)
	Report        bool  `json:"report"`           // Meldung an ipv64 (Standard an; wirkt erst mit dem zentralen API-Key)
	Expert        bool  `json:"expert,omitempty"` // Oberflaeche im Expertenmodus (alle Einstellungen); sonst einfacher Modus
	// Standort des Sensors fuer die Live-Karte (ISO 3166-1, "" = automatisch aus der oeffentlichen IPv4); geht mit
	// der Meldung an ipv64 (Ziel der Portal-Live-Karte), nicht in die Bewertung
	Country string `json:"country,omitempty"`
	// Ueberwachung der eigenen Anmeldung (login.go, Regel node64/login@1); leer = an mit Standardwerten
	Login LoginConfig `json:"login,omitzero"`
}

// DefaultConfig: nur ueber PROXY64 mit Port-Scan-Erkennung, 7 Tage, ohne Benachrichtigung, Meldung an ipv64 an
// (gemeldet wird ab dem ersten Durchlauf, nichts von vorher).
func DefaultConfig() ModuleConfig {
	return ModuleConfig{Profile: ProfileProxy, Config: Config{Scan: true}, RetentionDays: defaultRetentionDays, MaxEvents: DefaultMaxRows, Report: true}
}

// sensorAPI ist, was das Modul vom Sensor braucht (Tests setzen einen Ersatz ein).
type sensorAPI interface {
	SetPortCheck(func(service string, port int) error)
	Apply(ctx context.Context, cfg Config, sink Sink) []ServiceStatus
	Stop()
	Status() []ServiceStatus
	Counters() *Counters
}

// logSensorAPI ist, was das Modul vom Log-Sensor braucht (*LogSensor; Tests setzen einen Ersatz ein).
type logSensorAPI interface {
	Apply(ctx context.Context, cfg LogConfig, sink Sink) LogStatus
	Stop()
	Status() LogStatus
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
	newLogs   func(*slog.Logger) logSensorAPI
	every     time.Duration // Abstand der Meldungen bei neuen Angreifern

	g module.Guards

	ctl      sync.Mutex // serialisiert Start, Stop und das Uebernehmen der Einstellungen
	mu       sync.Mutex // die Felder darunter
	sensor   sensorAPI  // nil = Modul aus
	logs     logSensorAPI
	life     context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	started  time.Time
	status   []ServiceStatus // Stand nach dem letzten Apply (fuer Claims, ohne den Sensor zu fragen)
	warnings []Warning       // vom Profil weggelassene bzw. riskante Ports
	logState LogStatus       // Log-Sensor/Syslog nach dem letzten Apply (fuer Claims)
	logErr   string          // Syslog nicht geoeffnet, weil ein anderer Teil den Port inzwischen belegt
	geoStop  func()          // gibt die Laenderdaten zurueck (geo.go), nil = nicht angefordert

	certs  certManager // zentrale Zertifikatsverwaltung (decoy_cert.go), nil = keine
	dnsrec decoyDNS    // Tests: Ersatz fuer die ipv64-Records (sonst ueber key)
	login  *loginWatch // Ueberwachung der eigenen Anmeldung (login.go)
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
	m := &Module{core: core, log: l, dataDir: dataDir, version: nodeVersion, st: st, sink: bridgeBlockSink(CountEvents(st.Sink())), every: notifyEvery, login: newLoginWatch(),
		newSensor: func(log *slog.Logger, dir string) sensorAPI { return NewSensor(log, dir) },
		newLogs:   func(log *slog.Logger) logSensorAPI { return NewLogSensor(log) }}
	m.rep = NewReporter(ReporterConfig{Store: st, API: m.api, Enabled: func(ctx context.Context) bool { return m.loadConfig(ctx).Report },
		Profile:  func(ctx context.Context) string { return m.loadConfig(ctx).Profile },
		SensorID: func(ctx context.Context) (string, error) { return SensorIDFromSettings(ctx, core) },
		Country:  func(ctx context.Context) string { return m.loadConfig(ctx).Country },
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
	m.watchRoutes(mux, g)
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
	if cs, ok := s.(certSourcer); ok { // Zertifikate fuer Koeder-Namen (decoy_cert.go)
		cs.SetCertSource(m.certSource())
	}
	ls := m.newLogs(m.log)
	m.mu.Lock()
	m.sensor, m.logs, m.life, m.cancel, m.started = s, ls, lctx, cancel, time.Now()
	m.geoStop = geoStart(m.dataDir, "Node64/"+m.version, m.log) // Herkunft der Angreifer (laedt im Hintergrund)
	m.mu.Unlock()
	m.wg.Add(4)
	go func() { defer m.wg.Done(); m.st.Run(lctx) }()
	go func() { defer m.wg.Done(); m.watchLoop(lctx) }()
	go func() { defer m.wg.Done(); m.notifyLoop(lctx) }()
	go func() { defer m.wg.Done(); m.rep.Run(lctx) }() // tut nichts, solange die Meldung aus ist
	m.applyLocked(ctx)
	bridgeStart(m.log, ls, m.sink, m.seed(ctx)) // Verbindung zu PROXY64 (bridge.go; PROXY64 nutzt sie nur mit eigenem Opt-in)
	m.log.Info("honeypot started", "services", len(m.Status()))
	return nil
}

// Stop schliesst alle Fallen-Dienste und schreibt die restlichen Ereignisse.
func (m *Module) Stop(ctx context.Context) error {
	m.ctl.Lock()
	defer m.ctl.Unlock()
	m.mu.Lock()
	s, ls, cancel, geoStop := m.sensor, m.logs, m.cancel, m.geoStop
	m.sensor, m.logs, m.cancel, m.life, m.status, m.warnings, m.geoStop = nil, nil, nil, nil, nil, nil, nil
	m.logState, m.logErr = LogStatus{}, ""
	m.mu.Unlock()
	m.login.cfg.Store(nil) // Anmeldung nicht mehr ueberwachen
	if s == nil {
		return nil
	}
	if geoStop != nil {
		geoStop()
	}
	bridgeStop() // PROXY64 gibt danach nichts mehr ab
	s.Stop()     // zuerst: danach kommen keine Ereignisse mehr
	if ls != nil {
		ls.Stop()
	}
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
	s, ls, life := m.sensor, m.logs, m.life
	m.mu.Unlock()
	if s == nil {
		return
	}
	cfg := m.loadConfig(ctx)
	hpbridge.SetWanted(cfg.Profile == ProfileProxy) // PROXY64 gibt dann seine unzuordenbaren/schaedlichen Anfragen ab
	m.st.SetLimits(time.Duration(cfg.RetentionDays)*24*time.Hour, cfg.MaxEvents)
	svcs, warns := m.resolve(ctx, cfg)
	run := cfg.Config
	run.Services = svcs
	run.Seed = m.seed(ctx)
	run.Log = LogConfig{} // Log-Sensor und Syslog laufen getrennt (unten)
	logs := cfg.Log
	if m.core.SettingOr(ctx, setConfig, "") == "" { // nie eingestellt: nichts oeffnen, bis die Auswahl gespeichert ist
		run.Services, logs = nil, LogConfig{}
	}
	logErr := ""
	if logs.SyslogPort > 0 { // seit dem Speichern von einem anderen Teil belegt: Syslog nicht oeffnen
		if err := m.syslogCheck(ctx, logs.SyslogPort); err != nil {
			logErr, logs.SyslogPort = err.Error(), 0
		}
	}
	status := s.Apply(life, run, m.sink)
	var lst LogStatus
	if ls != nil {
		lst = ls.Apply(life, logs, m.sink) // gleiche Sink wie die Fallen (Zaehler und Speicher)
	}
	if logErr != "" {
		lst.Syslog = &SyslogStatus{Port: cfg.Log.SyslogPort, Error: logErr}
	}
	m.mu.Lock()
	m.status, m.warnings = status, warns
	m.logState, m.logErr = lst, logErr
	m.mu.Unlock()
	lc := cfg.Login
	m.login.cfg.Store(&lc)
}

// seed liefert den Seed der Dienst-Profile: die Sensor-Kennung (stabil ueber Neustarts, je Node verschieden).
func (m *Module) seed(ctx context.Context) string {
	id, err := SensorIDFromSettings(ctx, m.core)
	if err != nil {
		m.log.Warn("honeypot: sensor id not saved, profiles vary until restart", "err", err)
	}
	return id
}

// ident liefert die Identitaet der Fallen (Hostname usw.) fuer die Oberflaeche.
func (m *Module) ident(ctx context.Context, c ModuleConfig) *sensorIdent {
	return newSensorPersonas(m.seed(ctx), c.Hostname, c.Personas).id
}

// syslogCheck fragt die Port-Verwaltung, ob UDP und TCP auf port frei sind (aktive Ports anderer Teile).
func (m *Module) syslogCheck(ctx context.Context, port int) error {
	if m.ports == nil {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return m.ports.Check(cctx, Name, []ports.Claim{{Owner: Name, Purpose: "Honeypot Syslog", Proto: ports.UDP, Port: port},
		{Owner: Name, Purpose: "Honeypot Syslog", Proto: ports.TCP, Port: port}})
}

// LogStatus liefert den Zustand von Log-Sensor und Syslog-Empfaenger (leer = Modul aus bzw. nichts eingestellt).
func (m *Module) LogStatus() LogStatus {
	m.mu.Lock()
	ls, logErr, port := m.logs, m.logErr, 0
	if m.logState.Syslog != nil {
		port = m.logState.Syslog.Port
	}
	m.mu.Unlock()
	out := LogStatus{}
	if ls != nil {
		out = ls.Status()
	}
	if out.Files == nil {
		out.Files = []LogFileStatus{}
	}
	if logErr != "" {
		out.Syslog = &SyslogStatus{Port: port, Error: logErr}
	}
	return out
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
	out := make([]ports.Claim, 0, len(m.status)+2)
	for _, s := range m.status {
		out = append(out, ports.Claim{Owner: Name, Purpose: "Honeypot " + strings.ToUpper(s.Service), Proto: svcProto(s.Service), Port: s.Port, Active: s.Listen, Error: s.Error})
	}
	if sl := m.logState.Syslog; sl != nil && sl.Port > 0 { // Syslog-Empfaenger: UDP und TCP
		// nicht geoeffnet, weil ein anderer Teil den Port belegt (logErr): nur eingestellt, mit Fehler (Anzeige)
		udp, tcp, e := sl.UDP && m.logErr == "", sl.TCP && m.logErr == "", sl.Error
		out = append(out, ports.Claim{Owner: Name, Purpose: "Honeypot Syslog", Proto: ports.UDP, Port: sl.Port, Active: udp, Error: errIf(!udp, e)},
			ports.Claim{Owner: Name, Purpose: "Honeypot Syslog", Proto: ports.TCP, Port: sl.Port, Active: tcp, Error: errIf(!tcp, e)})
	}
	return out
}

// errIf: Fehlertext nur fuer einen nicht offenen Port.
func errIf(cond bool, e string) string {
	if cond {
		return e
	}
	return ""
}

// portCheck fragt die Port-Verwaltung vor dem Oeffnen (Sensor.SetPortCheck).
func (m *Module) portCheck(service string, port int) error {
	if m.ports == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return m.ports.Check(ctx, Name, []ports.Claim{{Owner: Name, Purpose: "Honeypot " + strings.ToUpper(service), Proto: svcProto(service), Port: port}})
}

// others liefert die Ports der anderen Teile (TCP und UDP; die Dienste pruefen mit svcProto).
func (m *Module) others(ctx context.Context) []ports.Claim { return m.othersProto(ctx, "") }

// svcProto: Transportprotokoll eines Fallen-Dienstes (UDP-Dienste aus sensor_proto.go, sonst TCP).
func svcProto(service string) ports.Proto {
	if ProtoUDP(service) {
		return ports.UDP
	}
	return ports.TCP
}

// othersProto liefert die Ports der anderen Teile fuer ein Protokoll ("" = alle).
func (m *Module) othersProto(ctx context.Context, proto ports.Proto) []ports.Claim {
	if m.ports == nil {
		return nil
	}
	var out []ports.Claim
	for _, c := range m.ports.All(ctx) {
		if c.Owner != Name && (proto == "" || c.Proto == proto) {
			out = append(out, c)
		}
	}
	return out
}

// portConflict sucht einen anderen Teil auf dem Port: zuerst einen, der ihn offen hat (active), sonst einen, der ihn
// eingestellt hat (spaeter oeffnen will).
func portConflict(others []ports.Claim, port int) (c ports.Claim, found bool) {
	return portConflictProto(others, ports.TCP, port)
}

// portConflictProto wie portConflict fuer ein Protokoll (others muss dieses Protokoll enthalten).
func portConflictProto(others []ports.Claim, proto ports.Proto, port int) (c ports.Claim, found bool) {
	want := ports.Claim{Proto: proto, Port: port}
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
		if c, ok := portConflictProto(others, svcProto(s.Service), s.Port); ok {
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
		c.Profile = ProfileProxy
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
	if c.StartPage == StartGateway {
		c.StartPage = "" // Standard
	}
	if c.StartPage != "" && c.StartPage != StartNeutral {
		errs["start_page"] = "honeypot.err.start_page"
	}
	if c.Country = strings.ToUpper(strings.TrimSpace(c.Country)); c.Country != "" && !ValidCountry(c.Country) {
		errs["country"] = "honeypot.err.country"
	}
	for _, p := range PersonaProblems(&c.Config) {
		key := "personas"
		if strings.HasPrefix(p, "honeypot.err.hostname") {
			key = "hostname"
		}
		errs[key] = strings.TrimPrefix(errs[key]+"\n"+p, "\n")
	}
	m.validateLog(ctx, c, errs)
	for k, v := range m.certProblems(ctx, &c.Config) {
		errs[k] = v
	}
	for k, v := range loginProblems(c.Login) {
		errs[k] = v
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
	seen := map[ports.Claim]bool{} // Protokoll und Port: udp 161 und tcp 161 sind kein Konflikt
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
		case seen[ports.Claim{Proto: svcProto(s.Service), Port: s.Port}]:
			problems = append(problems, "honeypot.err.port_twice|"+portLabel(s.Service, s.Port))
		case s.Page != "" && ((s.Service != SvcHTTP && s.Service != SvcHTTPS) || !cfgPage(s.Page)):
			problems = append(problems, "honeypot.err.page|"+s.Page)
		default:
			if o, ok := portConflictProto(others, svcProto(s.Service), s.Port); ok && o.Active {
				problems = append(problems, "honeypot.err.port_used|"+portLabel(s.Service, s.Port)+"|"+o.Owner+" ("+o.Purpose+")")
			}
		}
		seen[ports.Claim{Proto: svcProto(s.Service), Port: s.Port}] = true
	}
	if len(problems) > 0 {
		errs["services"] = strings.Join(problems, "\n")
	}
	return errs
}

// portLabel: Port fuer Meldungen, bei UDP-Diensten mit "/udp".
func portLabel(service string, port int) string {
	if svcProto(service) == ports.UDP {
		return strconv.Itoa(port) + "/udp"
	}
	return strconv.Itoa(port)
}

func cfgService(s string) bool {
	switch s {
	case SvcSSH, SvcTelnet, SvcHTTP, SvcHTTPS, SvcTCP:
		return true
	}
	return ProtoKnown(s)
}

func cfgPage(p string) bool {
	for _, x := range Pages {
		if x == p {
			return true
		}
	}
	return false
}

// Log-Sensor und Syslog (H5): erlaubte Formate (LogLine.Format; "" = automatisch) und Wurzeln der Dateien.
//
// Wurzeln: /host/log ist der empfohlene Mount der Host-Logs (-v /var/log:/host/log:ro), /var/log gilt fuer das
// Binary ohne Docker (dort die echten Logs) bzw. Logs des Containers selbst, /data/logs fuer Logs, die andere
// Container in ein gemeinsames Volume schreiben. Alles andere (z. B. /data/node64.db, /etc, /proc) ist gesperrt:
// Der Sensor liest nur Logs, und eine Einstellung darf keine beliebigen Dateien der Node anfassen.
var (
	cfgLogFormats = []string{"syslog", "nginx", "apache", "caddy", "nextcloud", "vaultwarden", "gitea", "proxmox", "homeassistant"}
	cfgLogRoots   = []string{"/host/log", "/var/log", "/data/logs"}
)

const (
	logMaxPath  = 512 // Zeichen je Pfad
	logMaxAllow = 64  // Eintraege in SyslogAllow
)

// logProblems prueft und normalisiert die Log-Einstellung ohne Port-Verwaltung (Modul und Modus ohne Oberflaeche):
// leere Eintraege fallen weg, Formate klein, CIDR maskiert, Doppelte entfernt. Liefert je Feld (log_files,
// syslog_port, syslog_allow) die Fehler als i18n-Schluessel mit Werten nach "|".
func logProblems(c *LogConfig) map[string][]string {
	out := map[string][]string{}
	files := []LogFile{}
	seen := map[string]bool{}
	for _, f := range c.Files {
		p := strings.TrimSpace(f.Path)
		if p == "" {
			continue
		}
		f.Format = strings.ToLower(strings.TrimSpace(f.Format))
		if f.Format == "auto" {
			f.Format = ""
		}
		switch {
		case !logPathOK(p):
			out["log_files"] = append(out["log_files"], "honeypot.err.log_path|"+storeClip(p, 80))
			continue
		case !logUnderRoot(path.Clean(p)):
			out["log_files"] = append(out["log_files"], "honeypot.err.log_root|"+storeClip(p, 80)+"|"+strings.Join(cfgLogRoots, ", "))
			continue
		case f.Format != "" && !slices.Contains(cfgLogFormats, f.Format):
			out["log_files"] = append(out["log_files"], "honeypot.err.log_format|"+storeClip(f.Format, 40)+"|"+strings.Join(cfgLogFormats, ", "))
			continue
		}
		f.Path = path.Clean(p)
		if seen[f.Path] {
			out["log_files"] = append(out["log_files"], "honeypot.err.log_twice|"+f.Path)
			continue
		}
		seen[f.Path] = true
		files = append(files, f)
	}
	if len(files) > LogMaxFiles {
		out["log_files"] = append(out["log_files"], "honeypot.err.log_many|"+strconv.Itoa(LogMaxFiles))
	}
	c.Files = files
	if len(c.Files) == 0 {
		c.Files = nil
	}
	if c.SyslogPort < 0 || c.SyslogPort > 65535 {
		out["syslog_port"] = append(out["syslog_port"], "honeypot.err.syslog_port")
	}
	var allow []string
	for _, a := range c.SyslogAllow {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		p, ok := logParseCIDR(a)
		if !ok {
			out["syslog_allow"] = append(out["syslog_allow"], "honeypot.err.syslog_allow|"+storeClip(a, 60))
			continue
		}
		if !slices.Contains(allow, p.String()) {
			allow = append(allow, p.String())
		}
	}
	if len(allow) > logMaxAllow {
		out["syslog_allow"] = append(out["syslog_allow"], "honeypot.err.syslog_allow_many|"+strconv.Itoa(logMaxAllow))
	}
	c.SyslogAllow = allow
	return out
}

// logPathOK: absolut (Container-Pfad mit /), ohne "..", ohne Steuerzeichen, gueltiges Muster (filepath.Glob).
func logPathOK(p string) bool {
	if len(p) > logMaxPath || !strings.HasPrefix(p, "/") || strings.ContainsRune(p, '\\') {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return false
		}
	}
	_, err := path.Match(p, "")
	return err == nil
}

// logUnderRoot: der (bereinigte) Pfad liegt unterhalb einer erlaubten Wurzel (die Wurzel selbst ist keine Datei).
func logUnderRoot(p string) bool {
	for _, r := range cfgLogRoots {
		if strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
}

// logParseCIDR liest ein Netz ("192.168.0.0/16") oder eine einzelne Adresse ("10.0.0.1" = /32 bzw. /128).
func logParseCIDR(s string) (netip.Prefix, bool) {
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return netip.Prefix{}, false
		}
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	if p.Addr().Is4In6() {
		a := p.Addr().Unmap()
		bits := p.Bits() - 96
		if bits < 0 {
			return netip.Prefix{}, false
		}
		p = netip.PrefixFrom(a, bits)
	}
	return p.Masked(), true
}

// SyslogAllowPrefixes liefert die erlaubten Absender als Netze (ungueltige fallen weg; leer = Standard des Empfaengers).
func SyslogAllowPrefixes(list []string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range list {
		if p, ok := logParseCIDR(strings.TrimSpace(s)); ok {
			out = append(out, p)
		}
	}
	return out
}

// logErrEN: englische Texte der Log-Fehler fuer den Modus ohne Oberflaeche (dort gibt es keine Uebersetzung).
var logErrEN = map[string]string{
	"honeypot.err.log_path":          "%s is not an absolute path (no .., no control characters, valid glob pattern)",
	"honeypot.err.log_root":          "%s is outside the allowed directories (%s)",
	"honeypot.err.log_format":        "format %q is unknown (%s or empty = automatic)",
	"honeypot.err.log_twice":         "%s is listed twice",
	"honeypot.err.log_many":          "at most %s log files",
	"honeypot.err.syslog_port":       "syslog port must be 0 (off) or 1-65535",
	"honeypot.err.syslog_allow":      "%q is not an IP address or network (CIDR)",
	"honeypot.err.syslog_allow_many": "at most %s allowed senders",
}

// ValidateLogConfig prueft und normalisiert die Log-Einstellung wie das Modul (ohne Port-Verwaltung), Fehler auf
// Englisch (Modus ohne Oberflaeche).
func ValidateLogConfig(c *LogConfig) error {
	probs := logProblems(c)
	var msgs []string
	for _, field := range []string{"log_files", "syslog_port", "syslog_allow"} {
		for _, p := range probs[field] {
			parts := strings.Split(p, "|")
			args := make([]any, 0, len(parts)-1)
			for _, v := range parts[1:] {
				args = append(args, v)
			}
			msgs = append(msgs, fmt.Sprintf(logErrEN[parts[0]], args...))
		}
	}
	if len(msgs) == 0 {
		return nil
	}
	return errors.New(strings.Join(msgs, "; "))
}

// validateLog prueft die Log-Einstellung des Moduls (Fehler in errs): wie logProblems, dazu der Syslog-Port gegen
// die Ports anderer Teile (UDP und TCP, aktiv = Fehler) und gegen die eigenen Fallen-Dienste.
func (m *Module) validateLog(ctx context.Context, c *ModuleConfig, errs FieldErrors) {
	for k, v := range logProblems(&c.Log) {
		errs[k] = strings.Join(v, "\n")
	}
	port := c.Log.SyslogPort
	if port <= 0 || port > 65535 {
		return
	}
	list := c.Services
	if c.Profile != ProfileCustom {
		list = Profiles[c.Profile]
	}
	for _, s := range list {
		if s.Port == port {
			errs["syslog_port"] = "honeypot.err.syslog_trap|" + strconv.Itoa(port) + "|" + s.Service
			return
		}
	}
	others := m.othersProto(ctx, "")
	for _, proto := range []ports.Proto{ports.UDP, ports.TCP} {
		if o, ok := portConflictProto(others, proto, port); ok && o.Active {
			errs["syslog_port"] = "honeypot.err.port_used|" + strconv.Itoa(port) + "/" + string(proto) + "|" + o.Owner + " (" + o.Purpose + ")"
			return
		}
	}
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
	if c.CertID > 0 && m.certs != nil { // Kennung gilt nur auf dieser Node: fehlt das Zertifikat hier, selbst signiert
		if crt, err := m.certs.Get(ctx, c.CertID); err != nil || crt == nil {
			c.CertID = 0
		}
	}
	_, err := m.SaveConfig(ctx, c)
	var fe FieldErrors
	if errors.As(err, &fe) && fe["syslog_port"] != "" && c.Log.SyslogPort != 0 {
		// Syslog-Port hier belegt: Syslog aus, den Rest uebernehmen (Fehler wird gemeldet)
		skipped := "syslog_port: " + fe["syslog_port"]
		c.Log.SyslogPort = 0
		if _, err = m.SaveConfig(ctx, c); err == nil {
			return 1, fmt.Errorf("honeypot: %s", skipped)
		}
	}
	if errors.As(err, &fe) && len(fe) == 1 && fe["services"] != "" && c.Profile == ProfileCustom {
		// nur Port-Konflikte u. ae. bei eigenen Diensten: die gueltigen uebernehmen
		others := m.others(ctx)
		var keep []Service
		for _, s := range c.Services {
			if o, ok := portConflictProto(others, svcProto(s.Service), s.Port); (!ok || !o.Active) && cfgService(s.Service) && s.Port > 0 && s.Port < 65536 {
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

// Card liefert die Dashboard-Karte (module.CardProvider): Zahlen der letzten 24 Stunden mit Trend gegenueber den
// 24 Stunden davor, Top-3-Laender, meistangegriffener Dienst, Fallen-Ports, Meldung an ipv64 und PROXY64.
func (m *Module) Card(ctx context.Context) (*module.Card, error) {
	c := &module.Card{TitleKey: "nav.honeypot", Icon: "bi-bug", Path: "/honeypot"}
	open, errs := 0, 0
	var errText []string
	for _, s := range m.Status() {
		if s.Listen {
			open++
		} else if s.Error != "" {
			errs++
			errText = append(errText, strings.ToUpper(s.Service)+" "+strconv.Itoa(s.Port)+": "+s.Error)
		}
	}
	_ = m.st.Flush(ctx)
	now := time.Now()
	sum, err := m.summary(ctx, now.Add(-24*time.Hour))
	if err != nil {
		return nil, err
	}
	prev, err := storeCountBetween(ctx, m.st, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	if err != nil {
		return nil, err
	}
	ev := module.CardStat{LabelKey: "honeypot.card.events", Value: sum.Events}
	ev.Note, ev.NoteClass = cardTrend(sum.Events, prev)
	c.Stats = []module.CardStat{ev,
		{LabelKey: "honeypot.card.sources", Value: sum.Sources},
		{LabelKey: "honeypot.card.logins", Value: sum.Logins},
	}
	from := storeTime(now.Add(-24 * time.Hour))
	if list, _, err := m.st.byCountry(ctx, from); err == nil && len(list) > 0 {
		var flags, title []string
		for i, cc := range list {
			if i == 3 {
				break
			}
			flags = append(flags, geoip.Flag(cc.Key))
			title = append(title, cc.Key+" "+strconv.FormatInt(cc.Count, 10))
		}
		c.Stats = append(c.Stats, module.CardStat{LabelKey: "honeypot.card.countries", Text: strings.Join(flags, " "), Title: strings.Join(title, " · ")})
	}
	if svc, n, err := storeTopService(ctx, m.st, from); err == nil && svc != "" && sum.Events > 0 {
		c.Stats = append(c.Stats, module.CardStat{LabelKey: "honeypot.card.top_service", Text: strings.ToUpper(svc),
			Note: strconv.FormatInt(n*100/sum.Events, 10) + " %", NoteClass: "text-body-secondary"})
	}
	c.Stats = append(c.Stats, module.CardStat{LabelKey: "honeypot.card.services", Value: int64(open)})
	if errs > 0 {
		c.Stats = append(c.Stats, module.CardStat{LabelKey: "honeypot.card.errors", Value: int64(errs), Class: "text-danger", Title: strings.Join(errText, "\n")})
		c.Err = errText[0]
		if errs > 1 {
			c.Err += " (+" + strconv.Itoa(errs-1) + ")"
		}
	}
	c.Stats = append(c.Stats, cardReport(m.rep.Status(ctx)))
	if p := (overviewData{}).Proxy64(); p.Connected {
		c.Stats = append(c.Stats, module.CardStat{LabelKey: "honeypot.card.proxy64", Value: p.Decoy + p.Access})
	}
	return c, nil
}

// cardTrend: Pfeil und Prozent gegenueber dem Zeitraum davor (mehr Angriffe = rot, weniger = gruen).
func cardTrend(cur, prev int64) (note, class string) {
	switch {
	case prev == 0 && cur == 0:
		return "", ""
	case prev == 0:
		return "▲", "text-danger"
	}
	pct := (cur - prev) * 100 / prev
	if pct == 0 && cur != prev { // kleine Aenderung: nicht „▲ 0 %“
		if cur > prev {
			return "▲ < 1 %", "text-danger"
		}
		return "▼ < 1 %", "text-success"
	}
	switch {
	case cur > prev:
		return "▲ " + strconv.FormatInt(pct, 10) + " %", "text-danger"
	case cur < prev:
		return "▼ " + strconv.FormatInt(-pct, 10) + " %", "text-success"
	}
	return "± 0 %", "text-body-secondary"
}

// cardReport: Zeile „Meldung an ipv64“ (aus, ohne Key, wartet, ok mit Zeitpunkt, Fehler mit Zeitpunkt und Text).
func cardReport(rs ReportStatus) module.CardStat {
	st := module.CardStat{LabelKey: "honeypot.card.report"}
	switch {
	case !rs.Enabled:
		st.TextKey, st.Class = "honeypot.card.report_off", "text-body-secondary"
	case !rs.KeySet:
		st.TextKey, st.Class = "honeypot.card.report_nokey", "text-warning-emphasis"
	case rs.LastError != "" && rs.LastErrorAt.After(rs.LastSuccess):
		st.TextKey, st.Class, st.Title, st.Ago = "honeypot.card.report_error", "text-danger", rs.LastError, rs.LastErrorAt
	case rs.LastSuccess.IsZero():
		st.TextKey, st.Class = "honeypot.card.report_wait", "text-body-secondary"
	default:
		st.TextKey, st.Class, st.Ago = "honeypot.card.report_ok", "text-success", rs.LastSuccess
	}
	return st
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

// storeCountBetween zaehlt die Ereignisse in [from, to) (Trend der Dashboard-Karte).
func storeCountBetween(ctx context.Context, st *Store, from, to time.Time) (int64, error) {
	var n int64
	err := st.st.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM hp_events WHERE ts >= ? AND ts < ?`, storeTime(from), storeTime(to)).Scan(&n)
	return n, err
}

// storeTopService liefert den Dienst mit den meisten Ereignissen ab from ("" = keine).
func storeTopService(ctx context.Context, st *Store, from string) (string, int64, error) {
	var svc string
	var n int64
	err := st.st.Reader().QueryRowContext(ctx, `SELECT service, COUNT(*) AS n FROM hp_events WHERE ts >= ? GROUP BY service ORDER BY n DESC, service LIMIT 1`, from).Scan(&svc, &n)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, nil
	}
	return svc, n, err
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
		ip := c.Key
		if cc := countryOf(c.Key); cc != "" {
			ip += " (" + strings.TrimSpace(geoip.Flag(cc)+" "+cc) + ")"
		}
		ips = append(ips, ip)
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
