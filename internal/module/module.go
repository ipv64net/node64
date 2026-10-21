// Package module definiert das Modulsystem des Nodes.
//
// Der Kern (Web-UI, Datenbank, Benachrichtigungen, Sync, Audit) laeuft immer.
// Alles andere sind Module mit einheitlichem Lebenszyklus: Ein deaktiviertes
// Modul ist nicht gestartet, hat keine Goroutines, keine Ports, keine
// Hintergrundjobs und keinen Menuepunkt. Nur seine Konfiguration in der
// Datenbank bleibt erhalten.
package module

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/store"
)

// Info beschreibt ein Modul fuer Navigation und Einstellungen.
type Info struct {
	// Name ist der technische Schluessel (healthchecks, dyndns, ...).
	Name string
	// TitleKey ist der i18n-Schluessel des Menuetitels.
	TitleKey string
	// Icon ist eine Bootstrap-Icon-Klasse, z. B. "bi-heart-pulse".
	Icon string
	// Image ist optional ein Logo (Pfad unter /static/img), das statt des Icons gezeigt wird.
	Image string
	// Path ist der Einstiegspfad in der Oberflaeche.
	Path string
	// Available false = Platzhalter ("demnaechst"), kann nicht aktiviert werden.
	Available bool
	// Order bestimmt die Reihenfolge im Menue.
	Order int
	// Version des Moduls (SemVer, eigene Zaehlung je Modul, siehe docs/MODUL-VERSIONEN.md).
	Version string
	// Changelog ist der Inhalt der CHANGELOG.md des Moduls (per go:embed), leer = keiner.
	Changelog string
	// ChangelogEN ist die englische Fassung (CHANGELOG.en.md), leer = nur deutsch.
	ChangelogEN string
}

// Module ist das Interface, das jedes Modul erfuellt.
type Module interface {
	Info() Info
	// Migrations liefert die Datenbankaenderungen des Moduls (eigener Scope).
	Migrations() []store.Migration
	// Routes registriert die HTTP-Handler. g.Enabled umhuellt jeden Handler und
	// antwortet mit 404, solange das Modul deaktiviert ist; g.Auth verlangt
	// eine Anmeldung (Sitzung oder API-Key).
	Routes(mux *http.ServeMux, g Guards)
	// Start startet Hintergrundarbeit; ctx wird bei Stop abgebrochen.
	Start(ctx context.Context) error
	// Stop beendet alles sauber. Nach Stop laufen keine Goroutines mehr.
	Stop(ctx context.Context) error
}

// Guards sind Middleware und Hilfen, die der Kern den Modulen gibt.
type Guards struct {
	// Enabled antwortet mit 404, solange das Modul deaktiviert ist.
	Enabled func(http.Handler) http.Handler
	// Auth verlangt eine Anmeldung.
	Auth func(http.Handler) http.Handler
	// Render zeigt eine Seite des Moduls im Layout des Kerns. page ist
	// "<modul>/<name>" (Datei pages/<name>.html im Templates-FS des Moduls).
	Render func(w http.ResponseWriter, r *http.Request, status int, page, titleKey string, data any)
	// T uebersetzt in der Sprache des Aufrufers.
	T func(r *http.Request, key string, args ...any) string
	// Flash merkt eine Meldung fuer die naechste Seite.
	Flash func(w http.ResponseWriter, r *http.Request, kind, text string)
	// Actor ist der angemeldete Benutzername (fuer Audit).
	Actor func(r *http.Request) string
	// ClientIP ist die Adresse des Aufrufers wie im Audit des Kerns (X-Forwarded-For nur mit NODE64_TRUST_PROXY).
	ClientIP func(r *http.Request) string
	// Audit schreibt einen Eintrag ins Audit-Log wie der Kern (Benutzer aus Sitzung bzw. API-Key, IP, Fehler
	// werden geloggt). target: was (Name/Kennung), details: Zusatz ohne Geheimnisse.
	Audit func(r *http.Request, action, target, details string)
	// CSRF liefert den Token fuer Formulare.
	CSRF func(r *http.Request) string
	// Lang liefert die Sprache des Aufrufers.
	Lang func(r *http.Request) string
	// Timezone liefert die Zeitzone des Benutzers.
	Timezone func(r *http.Request) *time.Location
	// Translate uebersetzt fuer eine feste Sprache (z. B. fuer Tooltips, Hintergrundjobs).
	Translate func(lang, key string, args ...any) string
}

// Templater liefert die Seiten-Templates eines Moduls (pages/*.html).
type Templater interface {
	Templates() fs.FS
}

// Exporter exportiert und importiert die Konfiguration eines Moduls (JSON).
type Exporter interface {
	Export(ctx context.Context) (any, error)
	Import(ctx context.Context, raw json.RawMessage) (int, error)
}

// Resetter raeumt vor "Node zuruecksetzen" auf, was das Modul ausserhalb der Node angelegt hat (z. B. Namen
// und Tunnel bei ipv64). Fehler halten den Reset nicht auf.
type Resetter interface {
	BeforeReset(ctx context.Context) error
}

type channelMapKey struct{}

type certMapKey struct{}

// WithCertMap: beim Import die Zuordnung Zertifikat-ID der Datei -> Zertifikat-ID dieser Node.
func WithCertMap(ctx context.Context, m map[int64]int64) context.Context {
	return context.WithValue(ctx, certMapKey{}, m)
}

// MapCert setzt eine Zertifikat-ID aus einer importierten Datei auf diese Node um; ok = false, wenn die Datei keine
// Zertifikate enthielt oder die ID unbekannt ist (dann z. B. automatisch waehlen).
func MapCert(ctx context.Context, id int64) (int64, bool) {
	m, _ := ctx.Value(certMapKey{}).(map[int64]int64)
	n, ok := m[id]
	return n, ok && id != 0
}

// WithChannelMap: beim Import die Zuordnung Kanal-ID der Datei -> Kanal-ID dieser Node (fuer Import).
func WithChannelMap(ctx context.Context, m map[int64]int64) context.Context {
	return context.WithValue(ctx, channelMapKey{}, m)
}

type sealerKey struct{}

// SecretSealer verschluesselt Geheimnisse eines Moduls im Export mit dem Export-Passwort (Export „mit Passwort“).
type SecretSealer interface {
	Encrypt(plain string) string
	Decrypt(value string) (string, error)
}

// WithSecretSealer: Export bzw. Import mit Passwort – Module duerfen Geheimnisse damit verschluesselt mitgeben.
func WithSecretSealer(ctx context.Context, s SecretSealer) context.Context {
	return context.WithValue(ctx, sealerKey{}, s)
}

// SecretSealerOf liefert den Verschluesseler des Exports bzw. Imports (nil = ohne Passwort, Geheimnisse fehlen).
func SecretSealerOf(ctx context.Context) SecretSealer {
	s, _ := ctx.Value(sealerKey{}).(SecretSealer)
	return s
}

// MapChannels setzt Kanal-IDs aus einer importierten Datei auf die dieser Node um; unbekannte entfallen.
// Ohne Zuordnung (aeltere Exporte ohne Kanal-IDs) bleiben die IDs unveraendert.
func MapChannels(ctx context.Context, ids []int64) []int64 {
	m, _ := ctx.Value(channelMapKey{}).(map[int64]int64)
	if m == nil || ids == nil {
		return ids
	}
	out := []int64{}
	for _, id := range ids {
		if n, ok := m[id]; ok {
			out = append(out, n)
		}
	}
	return out
}

// DashboardProvider liefert Kacheln fuer das Dashboard des Kerns.
type DashboardProvider interface {
	Dashboard(ctx context.Context) (*DashboardInfo, error)
}

// CardProvider liefert eine kleine Karte mit Kennzahlen fuer das Dashboard (fuer Module ohne Checks).
type CardProvider interface {
	Card(ctx context.Context) (*Card, error)
}

// Card ist die Dashboard-Karte eines Moduls.
type Card struct {
	TitleKey string
	Image    string // Logo unter /static/img (sonst Icon)
	Icon     string
	Path     string
	Stats    []CardStat
	Err      string // Hinweis bei Stoerung (rot)
}

// CardStat ist eine Zeile der Karte: Value wird als Zahl formatiert, ausser Text ist gesetzt.
type CardStat struct {
	LabelKey string
	Value    int64
	Text     string
	Pct      float64 // > 0: Anteil in Prozent hinter der Zahl
	Class    string  // z. B. "text-danger"
	Bytes    bool    // Value ist eine Datenmenge (lesbar formatiert)

	TextKey   string    // statt Value/Text: i18n-Schluessel (uebersetzt)
	Ago       time.Time // nicht null: "vor …" hinter dem Wert
	Note      string    // kurzer Zusatz hinter dem Wert (z. B. Trend "▲ 12 %"), klein
	NoteClass string    // Klasse des Zusatzes (z. B. "text-danger")
	Title     string    // Tooltip des Werts (z. B. Fehlertext)

	// optional: Verbrauch mit Grenze als „Wert / Max“ und Balken unter der Zeile (z. B. Kontingent)
	Max       int64     // > 0: hinter dem Wert „/ Max“ (wie Value formatiert, auch Bytes)
	Bar       bool      // Balken zeigen
	BarPct    float64   // Breite in Prozent (0-100; mit BarWidth bei Verbrauch > 0 mindestens 1)
	BarClass  string    // bg-success (Standard), bg-warning, bg-danger
	HintKey   string    // i18n-Schluessel unter dem Balken, Argumente {date} = HintDate, {n} = HintBytes
	HintDate  time.Time // fuer {date}
	HintBytes int64     // fuer {n} (als Datenmenge)
	HintClass string    // Klasse des Hinweises (z. B. "text-warning-emphasis")
}

// BarWidth: Breite eines Balkens aus dem Fuellstand in Prozent – hoechstens 100 und bei Verbrauch > 0 mindestens 1,
// damit kleiner Verbrauch sichtbar bleibt.
func BarWidth(pct float64, used bool) float64 {
	pct = min(max(pct, 0), 100)
	if used && pct < 1 {
		pct = 1
	}
	return pct
}

// BarClassOf: Farbe wie bei den Limits des Accounts – gruen, ab 80 % (oder bei warn) gelb, voll rot.
func BarClassOf(pct float64, warn bool) string {
	switch {
	case pct >= 100:
		return "bg-danger"
	case warn || pct >= 80:
		return "bg-warning"
	}
	return "bg-success"
}

// DashboardInfo sind die Zahlen eines Moduls fuer das Dashboard.
type DashboardInfo struct {
	Module    string
	TitleKey  string
	Path      string
	OK        int
	Down      int
	Paused    int
	Other     int
	Unchecked int // nicht ueberwacht (seit 3 Intervallen keine Messung)
	Incidents []IncidentInfo
}

// IncidentInfo ist eine Stoerung in Kurzform.
type IncidentInfo struct {
	Name      string
	Path      string
	StartedAt time.Time
	EndedAt   time.Time
	Open      bool
	Message   string
}

// Status ist der Zustand eines Moduls fuer die Anzeige.
type Status struct {
	Info      Info
	Enabled   bool
	Running   bool
	StartedAt time.Time
	LastError string
}

var (
	ErrUnknown      = errors.New("unknown module")
	ErrNotAvailable = errors.New("module not available yet")
)

type entry struct {
	life      sync.Mutex // serialisiert Start und Stop (zwei gleichzeitige Enable starteten sonst doppelt)
	mod       Module
	cancel    context.CancelFunc
	running   bool
	startedAt time.Time
	lastErr   string
}

// Registry verwaltet Module, ihren Zustand und das Starten/Stoppen zur Laufzeit.
type Registry struct {
	mu      sync.Mutex
	st      *store.Store
	log     *slog.Logger
	entries map[string]*entry
	order   []string
	stopTO  time.Duration
}

func NewRegistry(st *store.Store, log *slog.Logger) *Registry {
	return &Registry{st: st, log: log.With("module", "core"), entries: map[string]*entry{}, stopTO: 10 * time.Second}
}

// Register meldet ein Modul an. Muss vor Routes und StartEnabled passieren.
func (r *Registry) Register(m Module) {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := m.Info().Name
	if _, dup := r.entries[name]; dup {
		panic("module registered twice: " + name)
	}
	r.entries[name] = &entry{mod: m}
	r.order = append(r.order, name)
	sort.SliceStable(r.order, func(i, j int) bool {
		return r.entries[r.order[i]].mod.Info().Order < r.entries[r.order[j]].mod.Info().Order
	})
}

// Routes registriert die Handler aller Module. Der Guard liefert 404, solange
// ein Modul deaktiviert ist; so bleiben die Pfade stabil.
func (r *Registry) Routes(mux *http.ServeMux, notFound http.Handler, base Guards) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, name := range r.order {
		e := r.entries[name]
		g := base
		g.Enabled = func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if !r.IsRunning(name) {
					notFound.ServeHTTP(w, req)
					return
				}
				next.ServeHTTP(w, req)
			})
		}
		e.mod.Routes(mux, g)
	}
}

// IsRunning sagt, ob das Modul gerade laeuft.
func (r *Registry) IsRunning(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[name]
	return ok && e.running
}

// StartEnabled startet beim Programmstart alle in der DB aktivierten Module.
func (r *Registry) StartEnabled(ctx context.Context) {
	for _, name := range r.names() {
		enabled, err := r.st.ModuleEnabled(ctx, name)
		if err != nil {
			r.log.Error("module state could not be read", "name", name, "err", err)
			continue
		}
		if !enabled {
			continue
		}
		if err := r.start(ctx, name); err != nil {
			r.log.Error("module failed to start", "name", name, "err", err)
		}
	}
}

// Enable aktiviert ein Modul dauerhaft und startet es sofort.
func (r *Registry) Enable(ctx context.Context, name string) error {
	e, err := r.get(name)
	if err != nil {
		return err
	}
	if !e.mod.Info().Available {
		return ErrNotAvailable
	}
	if err := r.st.SetModuleEnabled(ctx, name, true); err != nil {
		return err
	}
	return r.start(ctx, name)
}

// Disable stoppt ein Modul und merkt sich den Zustand dauerhaft.
func (r *Registry) Disable(ctx context.Context, name string) error {
	if _, err := r.get(name); err != nil {
		return err
	}
	if err := r.st.SetModuleEnabled(ctx, name, false); err != nil {
		return err
	}
	return r.stop(name)
}

// StopAll stoppt alle laufenden Module (beim Herunterfahren).
func (r *Registry) StopAll() {
	for _, name := range r.names() {
		if err := r.stop(name); err != nil {
			r.log.Error("module failed to stop", "name", name, "err", err)
		}
	}
}

// List liefert alle Module in Menuereihenfolge mit Zustand.
func (r *Registry) List(ctx context.Context) []Status {
	var out []Status
	for _, name := range r.names() {
		r.mu.Lock()
		e := r.entries[name]
		s := Status{Info: e.mod.Info(), Running: e.running, StartedAt: e.startedAt, LastError: e.lastErr}
		r.mu.Unlock()
		s.Enabled, _ = r.st.ModuleEnabled(ctx, name)
		out = append(out, s)
	}
	return out
}

// Modules liefert alle Module in Menuereihenfolge.
func (r *Registry) Modules() []Module {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Module, 0, len(r.order))
	for _, name := range r.order {
		out = append(out, r.entries[name].mod)
	}
	return out
}

// Get liefert das Modul selbst (fuer Dashboard-Daten u. ae.).
func (r *Registry) Get(name string) (Module, bool) {
	e, err := r.get(name)
	if err != nil {
		return nil, false
	}
	return e.mod, true
}

func (r *Registry) names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.order...)
}

func (r *Registry) get(name string) (*entry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknown, name)
	}
	return e, nil
}

func (r *Registry) start(ctx context.Context, name string) error {
	e, err := r.get(name)
	if err != nil {
		return err
	}
	e.life.Lock()
	defer e.life.Unlock()
	r.mu.Lock()
	if e.running {
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()

	// Migrationen des Moduls erst beim ersten Aktivieren anwenden
	if err := r.st.Migrate(ctx, name, e.mod.Migrations()); err != nil {
		r.setErr(e, err)
		return fmt.Errorf("migrate %s: %w", name, err)
	}
	mctx, cancel := context.WithCancel(context.Background())
	if err := e.mod.Start(mctx); err != nil {
		cancel()
		r.setErr(e, err)
		return fmt.Errorf("start %s: %w", name, err)
	}
	r.mu.Lock()
	e.cancel = cancel
	e.running = true
	e.startedAt = time.Now()
	e.lastErr = ""
	r.mu.Unlock()
	r.log.Info("module started", "name", name)
	return nil
}

func (r *Registry) stop(name string) error {
	e, err := r.get(name)
	if err != nil {
		return err
	}
	e.life.Lock()
	defer e.life.Unlock()
	r.mu.Lock()
	if !e.running {
		r.mu.Unlock()
		return nil
	}
	e.running = false
	cancel := e.cancel
	e.cancel = nil
	r.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	ctx, done := context.WithTimeout(context.Background(), r.stopTO)
	defer done()
	err = e.mod.Stop(ctx)
	if err != nil {
		r.setErr(e, err)
		return fmt.Errorf("stop %s: %w", name, err)
	}
	r.log.Info("module stopped", "name", name)
	return nil
}

func (r *Registry) setErr(e *entry, err error) {
	r.mu.Lock()
	e.lastErr = err.Error()
	r.mu.Unlock()
}

// Placeholder ist ein noch nicht verfuegbares Modul, das nur im Menue als
// "demnaechst" erscheint.
type Placeholder struct{ I Info }

func (p Placeholder) Info() Info                  { i := p.I; i.Available = false; return i }
func (Placeholder) Migrations() []store.Migration { return nil }
func (Placeholder) Routes(*http.ServeMux, Guards) {}
func (Placeholder) Start(context.Context) error   { return ErrNotAvailable }
func (Placeholder) Stop(context.Context) error    { return nil }
