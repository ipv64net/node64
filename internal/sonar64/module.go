// Package sonar64 ist das optionale Node64-Modul von Sonar64, dem verteilten Community-Messnetz (Plan
// docs/PLAN-NODE64-SONAR64.md, Vertrag docs/SONAR64-VERTRAG.md Abschnitt 9). Es bindet den Kern internal/sonar ein:
// Teilnahme per Opt-in mit dem zentralen ipv64-API-Key (daraus ein eigenes Sonar-Token), Rolle, Budget, Ruhezeit,
// Profil des Knotens bei ipv64 und Live-Tabellen der eigenen Pings und der Pings gegen die Node.
//
// Standard aus: ausgeschaltet gibt es keinen Menuepunkt, keinen Port und keinen Verkehr. Eingeschaltet, aber ohne
// Teilnahme, laeuft ebenfalls nichts (nur die Seite). UDP 6464 nur bei „auch gemessen“, ueber die Port-Verwaltung.
package sonar64

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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/ports"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/sonar"
	"github.com/ipv64net/node64/internal/store"
)

// changelog wird unter Einstellungen > Module angezeigt (Version siehe Info).
//
//go:embed CHANGELOG.md
var changelog string

//go:embed CHANGELOG.en.md
var changelogEN string

// Name ist der technische Schluessel des Moduls.
const Name = "sonar64"

const (
	version = "0.1.0"

	setConfig   = "sonar64.config" // lokale Einstellung als JSON (Settings)
	setToken    = "sonar64.token"  // Sonar-Token, verschluesselt
	setNodeName = "node.name"      // Name der Node (Einstellung des Kerns, web.SettingNodeName)

	publicNodeURL = "https://ipv64.net/sonar/node.php?slug="

	apiTimeout  = 20 * time.Second // Anfragen an ipv64 aus der Oberflaeche
	meEvery     = 15 * time.Minute // eigenen Knoten neu holen
	meRetry     = 30 * time.Second // solange nicht angemeldet bzw. Fehler
	inboundTTL  = time.Minute      // Pings gegen mich (aus den Ergebnissen bei ipv64) zwischenspeichern
	inboundBack = time.Hour        // Standard-Zeitraum der Pings gegen mich
	stopWait    = 10 * time.Second // so lange auf das Ende des Knotens warten
	maxBackoff  = 15 * time.Minute // Neustart des Knotens nach Fehler hoechstens so selten
	recentMax   = 200
)

// syncFirst: erster Abgleich mit ipv64 nach dem Start des Knotens (Tests verkuerzen).
var syncFirst = 5 * time.Second

var (
	tokenRe = regexp.MustCompile(`^s64_[A-Za-z0-9]{40}$`)
	nameRe  = regexp.MustCompile(`^[A-Za-z0-9 ._-]{3,32}$`)
	slugRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,40}$`)
	quietRe = regexp.MustCompile(`^([01]?[0-9]|2[0-3])-([01]?[0-9]|2[0-3])$`)

	// Budgets, Anschlussarten und Geraete (Vertrag, Me)
	Budgets  = []string{sonar.BudgetLow, sonar.BudgetNormal, sonar.BudgetHigh}
	Accesses = []string{"fiber", "dsl", "cable", "mobile", "satellite", "datacenter", "other"}
	Devices  = []string{"node64", "pi", "mikrotik", "linux", "other"}
)

// Fehler der Teilnahme (Texte ueber errKey).
var (
	ErrNoKey     = errors.New("sonar64: no ipv64 api key")
	ErrToken     = errors.New("sonar64: sonar token could not be created")
	ErrNotReady  = errors.New("sonar64: node not registered yet")
	ErrNotJoined = errors.New("sonar64: not participating")
)

// Settings ist die lokale Einstellung (Datenbank der Node, Schluessel sonar64.config). Name, Standort, Anschlussart
// und Geraet stehen nur bei ipv64 (Me).
type Settings struct {
	Participate bool   `json:"participate"`     // Opt-in
	Measured    bool   `json:"measured"`        // auch gemessen werden (UDP 6464 offen, oeffentliche IP im Plan anderer)
	Budget      string `json:"budget"`          // sparsam | normal | grosszuegig
	Quiet       string `json:"quiet,omitempty"` // Ruhezeit "23-6" (lokale Zeit), leer = keine
}

// DefaultSettings: keine Teilnahme, nur ausgehend, sparsam, keine Ruhezeit.
func DefaultSettings() Settings { return Settings{Budget: sonar.BudgetLow} }

// FieldErrors sind Fehler je Formularfeld (Wert = i18n-Schluessel).
type FieldErrors map[string]string

func (f FieldErrors) Error() string {
	parts := make([]string, 0, len(f))
	for k, v := range f {
		parts = append(parts, k+": "+v)
	}
	return "invalid settings: " + strings.Join(parts, ", ")
}

// runnerAPI ist, was das Modul vom Kern braucht (*sonar.Runner; Tests setzen einen Ersatz ein).
type runnerAPI interface {
	Run(ctx context.Context) error
	Status() sonar.Status
	Recent(n int) ([]sonar.Result, []sonar.Inbound)
	Me(ctx context.Context) (*sonar.Me, error)
	UpdateMe(ctx context.Context, m sonar.Me) (*sonar.Me, error)
	Inbound(ctx context.Context, since time.Time) ([]sonar.InboundRow, error)
}

// runState ist ein laufender Knoten (Teilnahme an).
type runState struct {
	cancel       context.CancelFunc
	done         chan struct{}
	cfg          sonar.Config // ohne Ausgabe: enthaelt das Token
	wantMeasured bool         // eingestellt (cfg.Measured kann wegen Port-Konflikt aus sein)
	r            runnerAPI    // nil, solange der Kern nicht angelegt ist (m.mu)
}

// Module implementiert module.Module.
type Module struct {
	core        *store.Store
	log         *slog.Logger
	box         *secrets.Box // Token verschluesselt (nil = unverschluesselt, nur Tests)
	dataDir     string
	nodeVersion string
	key         *ipv64api.Key   // zentraler ipv64-API-Key (nil = keiner)
	ports       *ports.Registry // Port-Verwaltung (nil = keine Pruefung)
	apiBase     string          // leer = ipv64.net (NODE64_IPV64_API wie der Client des Kerns)

	newRunner   func(sonar.Config) (runnerAPI, error)
	createToken func(ctx context.Context, apiBase, apiKey, name string) (string, error)
	keyOf       func(ctx context.Context) string // Tests: API-Key ohne ipv64api.Key

	g module.Guards

	ctl     sync.Mutex // serialisiert Start, Stop, Teilnahme und Einstellungen
	mu      sync.Mutex // die Felder darunter
	life    context.Context
	cancel  context.CancelFunc
	started time.Time
	run     *runState // nil = kein Knoten
	runErr  string    // letzter Fehler des Knotens (Anlegen bzw. Run)
	portErr string    // UDP 6464 belegt: nur ausgehend gestartet
	me      *sonar.Me // zuletzt geholter eigener Knoten
	meAt    time.Time
	meErr   string
	inRows  []sonar.InboundRow // Pings gegen mich (Zwischenspeicher)
	inKey   string
	inAt    time.Time
}

// New erzeugt das Modul. dataDir ist das Datenverzeichnis von Node64 (Schluessel und Zustand unter <dataDir>/sonar64).
func New(core *store.Store, log *slog.Logger, box *secrets.Box, dataDir, nodeVersion string) *Module {
	return &Module{core: core, log: log.With("module", Name), box: box, dataDir: dataDir, nodeVersion: nodeVersion,
		apiBase: strings.TrimSpace(os.Getenv("NODE64_IPV64_API")),
		newRunner: func(c sonar.Config) (runnerAPI, error) {
			r, err := sonar.New(c)
			if err != nil {
				return nil, err
			}
			return r, nil
		},
		createToken: sonar.CreateToken}
}

// SetKey verbindet das Modul mit dem zentralen ipv64-API-Key (Teilnahme legt damit das Sonar-Token an).
func (m *Module) SetKey(k *ipv64api.Key) { m.key = k }

// SetPorts verbindet das Modul mit der Port-Verwaltung des Kerns (UDP 6464).
func (m *Module) SetPorts(r *ports.Registry) { m.ports = r }

func (m *Module) Info() module.Info {
	return module.Info{Name: Name, TitleKey: "nav.sonar64", Icon: "bi-broadcast-pin", Path: "/sonar64", Available: true, Order: 55,
		Version: version, Changelog: changelog, ChangelogEN: changelogEN}
}

// Migrations: keine eigenen Tabellen (Einstellungen im Kern, Messdaten bei ipv64).
func (m *Module) Migrations() []store.Migration { return nil }

func (m *Module) Routes(mux *http.ServeMux, g module.Guards) {
	m.g = g
	m.uiRoutes(mux, g)
	m.apiRoutes(mux, g)
}

func (m *Module) dir() string { return filepath.Join(m.dataDir, Name) }

// Start startet den Knoten, wenn die Teilnahme eingeschaltet ist (sonst laeuft nichts).
func (m *Module) Start(ctx context.Context) error {
	m.ctl.Lock()
	defer m.ctl.Unlock()
	m.mu.Lock()
	if m.life != nil {
		m.mu.Unlock()
		return nil
	}
	m.life, m.cancel = context.WithCancel(context.Background())
	m.started = time.Now()
	m.mu.Unlock()
	m.startRunnerLocked(ctx)
	return nil
}

// Stop beendet den Knoten (Antworter auf UDP 6464 eingeschlossen).
func (m *Module) Stop(ctx context.Context) error {
	m.ctl.Lock()
	defer m.ctl.Unlock()
	err := m.stopRunnerLocked(ctx)
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
	}
	m.life, m.cancel = nil, nil
	m.me, m.meAt, m.meErr, m.inRows, m.inKey, m.inAt = nil, time.Time{}, "", nil, "", time.Time{}
	m.mu.Unlock()
	return err
}

// running sagt, ob das Modul laeuft.
func (m *Module) running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.life != nil
}

// runner liefert den angelegten Kern (nil = keine Teilnahme oder noch nicht angelegt).
func (m *Module) runner() runnerAPI {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.run == nil {
		return nil
	}
	return m.run.r
}

// startRunnerLocked startet den Knoten neu nach der gespeicherten Einstellung (m.ctl gehalten). Ohne Teilnahme,
// ohne Token oder bei ausgeschaltetem Modul bleibt er aus.
func (m *Module) startRunnerLocked(ctx context.Context) {
	_ = m.stopRunnerLocked(ctx)
	m.mu.Lock()
	life := m.life
	m.mu.Unlock()
	s := m.LoadSettings(ctx)
	if life == nil || !s.Participate {
		return
	}
	tok := m.token(ctx)
	if tok == "" {
		m.setRunErr(ErrToken)
		return
	}
	measured, portErr := s.Measured, ""
	if measured {
		if err := m.portCheck(ctx); err != nil { // belegt: nur ausgehend, Hinweis in Status und Port-Uebersicht
			measured, portErr = false, err.Error()
		}
	}
	from, to, _ := parseQuiet(s.Quiet)
	cfg := sonar.Config{APIBase: m.apiBase, Token: tok, DataDir: m.dir(), Mode: "module", Version: m.runVersion(),
		Measured: measured, Budget: s.Budget, Quiet: [2]int{from, to}, Log: m.log}
	if m.dataDir == "" {
		cfg.DataDir = ""
	} else if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		m.setRunErr(err)
		return
	}
	rctx, cancel := context.WithCancel(life)
	rs := &runState{cancel: cancel, done: make(chan struct{}), cfg: cfg, wantMeasured: s.Measured}
	m.mu.Lock()
	m.run, m.runErr, m.portErr = rs, "", portErr
	m.mu.Unlock()
	go m.loop(rctx, rs)
	m.log.Info("sonar64 node started", "measured", measured, "budget", s.Budget)
}

// stopRunnerLocked beendet den laufenden Knoten (m.ctl gehalten) und wartet hoechstens stopWait.
func (m *Module) stopRunnerLocked(ctx context.Context) error {
	m.mu.Lock()
	rs := m.run
	m.run, m.portErr = nil, ""
	m.mu.Unlock()
	if rs == nil {
		return nil
	}
	rs.cancel()
	t := time.NewTimer(stopWait)
	defer t.Stop()
	select {
	case <-rs.done:
	case <-t.C:
		m.log.Warn("sonar64 node did not stop in time")
	case <-ctx.Done():
		return ctx.Err()
	}
	m.log.Info("sonar64 node stopped")
	return nil
}

// loop legt den Kern an und laesst ihn laufen; nach einem Fehler neu mit wachsendem Abstand (1 min bis 15 min).
func (m *Module) loop(ctx context.Context, rs *runState) {
	defer close(rs.done)
	wait := time.Minute
	for {
		began := time.Now()
		r, err := m.newRunner(rs.cfg)
		if err == nil {
			m.mu.Lock()
			rs.r = r
			m.mu.Unlock()
			sctx, scancel := context.WithCancel(ctx)
			syncDone := make(chan struct{})
			go func() { defer close(syncDone); m.syncLoop(sctx, rs, r) }()
			err = r.Run(ctx)
			scancel()
			<-syncDone
			m.mu.Lock()
			rs.r = nil
			m.mu.Unlock()
		}
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			err = errors.New("sonar: node stopped")
		}
		m.setRunErr(err)
		m.log.Warn("sonar64 node failed, retrying", "err", err, "in", wait)
		if time.Since(began) > maxBackoff { // lief lange: wieder schnell neu starten
			wait = time.Minute
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		wait = min(wait*2, maxBackoff)
	}
}

// syncLoop holt den eigenen Knoten von ipv64 (nach der Anmeldung, dann alle 15 min) und gleicht Rolle und Budget
// an die lokale Einstellung an (lokal gilt).
func (m *Module) syncLoop(ctx context.Context, rs *runState, r runnerAPI) {
	wait := syncFirst
	for {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		wait = meRetry
		if !r.Status().Registered {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, apiTimeout)
		me, err := r.Me(cctx)
		if err == nil && me != nil && (me.Measured != rs.cfg.Measured || me.Budget != rs.cfg.Budget) {
			want := *me
			want.Measured, want.Budget = rs.cfg.Measured, rs.cfg.Budget
			me, err = r.UpdateMe(cctx, want)
		}
		cancel()
		if ctx.Err() != nil {
			return
		}
		m.setMe(me, err)
		if err == nil && me != nil {
			wait = meEvery
		}
	}
}

func (m *Module) setRunErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err == nil {
		m.runErr = ""
		return
	}
	m.runErr = err.Error()
}

func (m *Module) setMe(me *sonar.Me, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.meErr = err.Error()
		return
	}
	if me != nil {
		c := *me
		m.me, m.meAt, m.meErr = &c, time.Now(), ""
	}
}

// cachedMe liefert eine Kopie des zuletzt geholten Knotens (nil = keiner).
func (m *Module) cachedMe() *sonar.Me {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.me == nil {
		return nil
	}
	c := *m.me
	return &c
}

// runVersion ist die Version im Health und beim Anmelden (hoechstens 32 Zeichen wie die Spalte bei ipv64).
func (m *Module) runVersion() string {
	v := version + "/node64-" + m.nodeVersion
	if len(v) > 32 {
		v = v[:32]
	}
	return v
}

// portCheck fragt die Port-Verwaltung, ob UDP 6464 frei ist (aktive Ports anderer Teile).
func (m *Module) portCheck(ctx context.Context) error {
	if m.ports == nil {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return m.ports.Check(cctx, Name, []ports.Claim{{Owner: Name, Purpose: "Sonar64 Echo", Proto: ports.UDP, Port: sonar.Port}})
}

// Claims liefert UDP 6464 fuer die Port-Verwaltung: nur bei Teilnahme mit „auch gemessen“; aktiv, solange der
// Antworter offen ist.
func (m *Module) Claims(context.Context) []ports.Claim {
	m.mu.Lock()
	rs, portErr := m.run, m.portErr
	var r runnerAPI
	if rs != nil {
		r = rs.r
	}
	m.mu.Unlock()
	if rs == nil || !rs.wantMeasured {
		return nil
	}
	c := ports.Claim{Owner: Name, Purpose: "Sonar64 Echo", Proto: ports.UDP, Port: sonar.Port, Error: portErr}
	c.Active = rs.cfg.Measured && r != nil && r.Status().Responder
	return []ports.Claim{c}
}

// LoadSettings liest die lokale Einstellung (fehlerhaft oder leer = Standard).
func (m *Module) LoadSettings(ctx context.Context) Settings {
	s := DefaultSettings()
	if raw := m.core.SettingOr(ctx, setConfig, ""); raw != "" {
		if err := json.Unmarshal([]byte(raw), &s); err != nil {
			m.log.Warn("sonar64 settings not readable, using defaults", "err", err)
			s = DefaultSettings()
		}
	}
	if !validBudget(s.Budget) {
		s.Budget = sonar.BudgetLow
	}
	if _, _, ok := parseQuiet(s.Quiet); !ok {
		s.Quiet = ""
	}
	return s
}

func (m *Module) saveSettings(ctx context.Context, s Settings) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return m.core.SetSetting(ctx, setConfig, string(b))
}

// token liefert das Sonar-Token im Klartext ("" = keins oder nicht lesbar).
func (m *Module) token(ctx context.Context) string {
	v := m.core.SettingOr(ctx, setToken, "")
	if v != "" && m.box != nil {
		plain, err := m.box.Decrypt(v)
		if err != nil {
			m.log.Error("sonar64 token not readable", "err", err)
			return ""
		}
		v = plain
	}
	if !tokenRe.MatchString(v) {
		return ""
	}
	return v
}

func (m *Module) saveToken(ctx context.Context, tok string) error {
	v := tok
	if m.box != nil {
		v = m.box.Encrypt(tok)
	}
	return m.core.SetSetting(ctx, setToken, v)
}

// apiKey liefert den zentralen ipv64-API-Key ("" = keiner).
func (m *Module) apiKey(ctx context.Context) string {
	if m.keyOf != nil {
		return m.keyOf(ctx)
	}
	if m.key == nil {
		return ""
	}
	return m.key.Get(ctx)
}

// tokenName ist der Name des Sonar-Tokens bei ipv64 (Name der Node, hoechstens 32 erlaubte Zeichen).
func (m *Module) tokenName(ctx context.Context) string {
	var b strings.Builder
	b.WriteString("Node64 ")
	for _, c := range m.core.SettingOr(ctx, setNodeName, "") {
		if b.Len() >= 32 {
			break
		}
		if nameChar(c) {
			b.WriteRune(c)
		}
	}
	return strings.TrimSpace(b.String())
}

// SetParticipate schaltet die Teilnahme. Einschalten braucht den zentralen ipv64-API-Key und legt beim ersten Mal
// das Sonar-Token an (verschluesselt gespeichert); Ausschalten beendet den Knoten, das Token bleibt (gleiche Node-ID
// beim naechsten Mal).
func (m *Module) SetParticipate(ctx context.Context, on bool) error {
	m.ctl.Lock()
	defer m.ctl.Unlock()
	s := m.LoadSettings(ctx)
	if on {
		key := m.apiKey(ctx)
		if key == "" {
			return ErrNoKey
		}
		if m.token(ctx) == "" {
			cctx, cancel := context.WithTimeout(ctx, apiTimeout)
			tok, err := m.createToken(cctx, m.apiBase, key, m.tokenName(ctx))
			cancel()
			if err != nil {
				return fmt.Errorf("%w: %v", ErrToken, err)
			}
			if !tokenRe.MatchString(tok) {
				return fmt.Errorf("%w: unexpected token format", ErrToken)
			}
			if err := m.saveToken(ctx, tok); err != nil {
				return err
			}
		}
	}
	s.Participate = on
	if err := m.saveSettings(ctx, s); err != nil {
		return err
	}
	if !on {
		m.mu.Lock()
		m.runErr, m.me, m.meAt, m.meErr, m.inRows, m.inKey = "", nil, time.Time{}, "", nil, ""
		m.mu.Unlock()
	}
	m.startRunnerLocked(ctx)
	return nil
}

// SaveSettings prueft und speichert Rolle, Budget und Ruhezeit und startet den Knoten damit neu (Teilnahme bleibt).
func (m *Module) SaveSettings(ctx context.Context, in Settings) (Settings, error) {
	m.ctl.Lock()
	defer m.ctl.Unlock()
	cur := m.LoadSettings(ctx)
	in.Quiet = strings.TrimSpace(in.Quiet)
	fe := checkSettings(in)
	if in.Measured && !cur.Measured {
		if err := m.portCheck(ctx); err != nil {
			fe["measured"] = "sonar64.err.port"
		}
	}
	if len(fe) > 0 {
		return cur, fe
	}
	in.Participate = cur.Participate
	if in == cur {
		return cur, nil
	}
	if err := m.saveSettings(ctx, in); err != nil {
		return cur, err
	}
	m.startRunnerLocked(ctx)
	return in, nil
}

// checkSettings prueft Budget und Ruhezeit (Fehler je Feld; leer = in Ordnung).
func checkSettings(s Settings) FieldErrors {
	fe := FieldErrors{}
	if !validBudget(s.Budget) {
		fe["budget"] = "sonar64.err.budget"
	}
	if _, _, ok := parseQuiet(strings.TrimSpace(s.Quiet)); !ok {
		fe["quiet"] = "sonar64.err.quiet"
	}
	return fe
}

// Profile ist, was der Teilnehmer bei ipv64 ueber seinen Knoten angibt (leer = unveraendert; Standort: beide nil =
// unveraendert, ClearLoc = loeschen).
type Profile struct {
	Name     string   `json:"name,omitempty"`
	Lat      *float64 `json:"lat,omitempty"`
	Lon      *float64 `json:"lon,omitempty"`
	ClearLoc bool     `json:"clear_location,omitempty"`
	Access   string   `json:"access,omitempty"`
	Device   string   `json:"device,omitempty"`
}

// validate prueft die Angaben (Fehler je Feld).
func (p *Profile) validate() FieldErrors {
	fe := FieldErrors{}
	p.Name = strings.TrimSpace(p.Name)
	if p.Name != "" && !nameRe.MatchString(p.Name) {
		fe["name"] = "sonar64.err.name"
	}
	if (p.Lat == nil) != (p.Lon == nil) {
		fe["lat"] = "sonar64.err.location"
	} else if p.Lat != nil {
		if !finiteIn(*p.Lat, -90, 90) {
			fe["lat"] = "sonar64.err.lat"
		}
		if !finiteIn(*p.Lon, -180, 180) {
			fe["lon"] = "sonar64.err.lon"
		}
	}
	if p.Access != "" && !inList(p.Access, Accesses) {
		fe["access"] = "sonar64.err.access"
	}
	if p.Device != "" && !inList(p.Device, Devices) {
		fe["device"] = "sonar64.err.device"
	}
	return fe
}

// SaveProfile setzt Name, Standort, Anschlussart und Geraet bei ipv64 (PUT /sonar/me ueber den Kern). Rolle und
// Budget kommen immer aus der lokalen Einstellung.
func (m *Module) SaveProfile(ctx context.Context, p Profile) (*sonar.Me, error) {
	if fe := p.validate(); len(fe) > 0 {
		return nil, fe
	}
	if !m.LoadSettings(ctx).Participate {
		return nil, ErrNotJoined
	}
	m.mu.Lock()
	rs := m.run
	m.mu.Unlock()
	r := m.runner()
	if r == nil || rs == nil || !r.Status().Registered {
		return nil, ErrNotReady
	}
	cctx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	cur, err := r.Me(cctx)
	if err != nil {
		return nil, err
	}
	want := *cur
	if p.Name != "" {
		want.Name = p.Name
	}
	if p.ClearLoc {
		want.Lat, want.Lon = nil, nil
	} else if p.Lat != nil {
		lat, lon := round5(*p.Lat), round5(*p.Lon)
		want.Lat, want.Lon = &lat, &lon
	}
	if p.Access != "" {
		want.Access = p.Access
	}
	if p.Device != "" {
		want.Device = p.Device
	}
	want.Measured, want.Budget = rs.cfg.Measured, rs.cfg.Budget
	me, err := r.UpdateMe(cctx, want)
	if err != nil {
		return nil, err
	}
	m.setMe(me, nil)
	return me, nil
}

// inboundRows holt die Pings gegen mich aus den Ergebnissen bei ipv64 (seit since, hoechstens 24 h), eine Minute
// zwischengespeichert.
func (m *Module) inboundRows(ctx context.Context, since time.Time) ([]sonar.InboundRow, error) {
	r := m.runner()
	if r == nil || !r.Status().Registered {
		return nil, ErrNotReady
	}
	now := time.Now().UTC()
	if since.IsZero() || since.After(now) {
		since = now.Add(-inboundBack)
	}
	if since.Before(now.Add(-24 * time.Hour)) {
		since = now.Add(-24 * time.Hour)
	}
	key := since.Truncate(time.Minute).Format(time.RFC3339)
	m.mu.Lock()
	if m.inKey == key && time.Since(m.inAt) < inboundTTL {
		rows := m.inRows
		m.mu.Unlock()
		return rows, nil
	}
	m.mu.Unlock()
	cctx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	rows, err := r.Inbound(cctx, since.Truncate(time.Minute))
	if err != nil {
		return nil, err
	}
	if len(rows) > 500 {
		rows = rows[:500]
	}
	m.mu.Lock()
	m.inRows, m.inKey, m.inAt = rows, key, time.Now()
	m.mu.Unlock()
	return rows, nil
}

// parseQuiet liest "23-6" (Stunden lokal, von bis ausschliesslich); leer = keine Ruhezeit.
func parseQuiet(s string) (from, to int, ok bool) {
	if s == "" {
		return 0, 0, true
	}
	mm := quietRe.FindStringSubmatch(s)
	if mm == nil {
		return 0, 0, false
	}
	from, _ = strconv.Atoi(mm[1])
	to, _ = strconv.Atoi(mm[2])
	if from == to {
		return 0, 0, false
	}
	return from, to, true
}

// nameChar: erlaubtes Zeichen eines Namens bei ipv64 ([A-Za-z0-9 ._-]).
func nameChar(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune(" ._-", c)
}

func validBudget(b string) bool { return inList(b, Budgets) }

func inList(v string, list []string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func finiteIn(f, lo, hi float64) bool { return f == f && f >= lo && f <= hi }

// round5 rundet auf 5 Nachkommastellen (etwa 1 m), mehr Genauigkeit braucht niemand.
func round5(f float64) float64 {
	v, _ := strconv.ParseFloat(strconv.FormatFloat(f, 'f', 5, 64), 64)
	return v
}

// publicURL ist die oeffentliche Knotenseite bei ipv64 ("" = noch kein Slug).
func publicURL(slug string) string {
	if !slugRe.MatchString(slug) {
		return ""
	}
	return publicNodeURL + slug
}
