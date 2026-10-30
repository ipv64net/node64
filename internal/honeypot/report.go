package honeypot

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/store"
)

// Meldung an ipv64 (Phase H2, Plan Abschnitt 5): nach Opt-in alle 10 Minuten der Zeitraum seit der letzten
// erfolgreichen Meldung (hoechstens 7 Tage), in Stuecken zu hoechstens einer Stunde, gzip, Format report_types.go.
//
// Leerer Zeitraum: es wird trotzdem eine kurze Meldung ohne Quellen geschickt (Lebenszeichen). So kann ipv64 aktive
// Sensoren und Accounts zaehlen (Plan Abschnitt 6: dynamische Schwelle; Abschnitt 8/10: Beitragende, Sensor
// online/offline), auch wenn gerade niemand angreift.

// Einstellungen bzw. Dateien des Zustands.
const (
	setSensorID    = "honeypot.sensor_id"    // Modul: Sensor-Kennung (UUID)
	setReportState = "honeypot.report_state" // Modul: ReportState als JSON
	fileSensorID   = "sensor_id"             // Modus ohne Oberflaeche: <data>/honeypot/sensor_id
	fileReport     = "report_state.json"     // Modus ohne Oberflaeche: <data>/honeypot/report_state.json
)

// Takt und Grenzen des Senders.
const (
	reportChunk     = time.Hour                     // hoechstens so lang ist ein Stueck
	reportChunkBig  = 6 * time.Hour                 // beim Nachholen von mehr als einem Tag (weniger Meldungen)
	reportMinGap    = 2*time.Minute + 5*time.Second // ipv64 nimmt hoechstens eine Meldung je Sensor in 2 Minuten an
	reportJitter    = 30 * time.Second              // Zufallsversatz je Durchlauf (+/-)
	reportFirst     = reportMinGap                  // erster Durchlauf nach dem Start (plus Versatz; Neustart kurz nach einer Meldung)
	reportGrace     = 5 * time.Second               // Ende des Zeitraums so weit vor jetzt (Puffer der Sink)
	reportBackoff   = time.Minute                   // erste Wartezeit nach einem Fehler, verdoppelt bis reportBackoffMax
	reportBackoffMx = time.Hour
	reportMaxBody   = 2<<20 - 64<<10 // entpackt hoechstens 2 MiB (Vertrag), mit Reserve
)

// ReportState ist der gespeicherte Stand der Meldung.
type ReportState struct {
	LastEnd     time.Time `json:"last_end,omitzero"`     // Ende des zuletzt gemeldeten (oder verworfenen) Zeitraums
	LastSuccess time.Time `json:"last_success,omitzero"` // letzte von ipv64 angenommene Meldung
}

// ReportStateStore speichert ReportState (Modul: Einstellung, Modus ohne Oberflaeche: Datei).
type ReportStateStore interface {
	Load(ctx context.Context) (ReportState, error)
	Save(ctx context.Context, s ReportState) error
}

type settingState struct{ core *store.Store }

// SettingsReportState legt den Stand in der Einstellung honeypot.report_state ab.
func SettingsReportState(core *store.Store) ReportStateStore { return settingState{core} }

func (s settingState) Load(ctx context.Context) (ReportState, error) {
	var st ReportState
	raw := s.core.SettingOr(ctx, setReportState, "")
	if raw == "" {
		return st, nil
	}
	return st, json.Unmarshal([]byte(raw), &st)
}

func (s settingState) Save(ctx context.Context, st ReportState) error {
	raw, _ := json.Marshal(st)
	return s.core.SetSetting(ctx, setReportState, string(raw))
}

type fileState struct{ path string }

// FileReportState legt den Stand in <dir>/report_state.json ab (dir: Datenverzeichnis des Honeypots).
func FileReportState(dir string) ReportStateStore { return fileState{filepath.Join(dir, fileReport)} }

func (f fileState) Load(context.Context) (ReportState, error) {
	var st ReportState
	b, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(b, &st)
}

func (f fileState) Save(_ context.Context, st ReportState) error {
	b, _ := json.Marshal(st)
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}

// newUUID liefert eine zufaellige UUID (Version 4).
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// validSensorID: UUID in Kleinbuchstaben (8-4-4-4-12 Hex-Zeichen), wie ipv64 sie verlangt.
func validSensorID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if r != '-' {
				return false
			}
		} else if !(r >= 'a' && r <= 'f' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

var sensorIDMu sync.Mutex

// SensorIDFromSettings liefert die feste Sensor-Kennung des Moduls (Einstellung honeypot.sensor_id), legt sie beim
// ersten Aufruf an.
func SensorIDFromSettings(ctx context.Context, core *store.Store) (string, error) {
	sensorIDMu.Lock()
	defer sensorIDMu.Unlock()
	if id := core.SettingOr(ctx, setSensorID, ""); validSensorID(id) {
		return id, nil
	}
	id := newUUID()
	return id, core.SetSetting(ctx, setSensorID, id)
}

// SensorIDFromFile liefert die feste Sensor-Kennung des Modus ohne Oberflaeche (<dir>/sensor_id), legt sie beim
// ersten Aufruf an.
func SensorIDFromFile(dir string) (string, error) {
	sensorIDMu.Lock()
	defer sensorIDMu.Unlock()
	p := filepath.Join(dir, fileSensorID)
	if b, err := os.ReadFile(p); err == nil {
		if id := strings.TrimSpace(string(b)); validSensorID(id) {
			return id, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	id := newUUID()
	return id, os.WriteFile(p, []byte(id+"\n"), 0o640)
}

// ReporterConfig verbindet den Sender mit Modul bzw. Modus ohne Oberflaeche.
type ReporterConfig struct {
	Store    *Store
	API      func(ctx context.Context) (*ipv64api.Client, string) // Client und Key ("" = kein Key)
	Enabled  func(ctx context.Context) bool                       // Opt-in
	Profile  func(ctx context.Context) string
	SensorID func(ctx context.Context) (string, error)
	Country  func(ctx context.Context) string       // Standort des Sensors ("" = automatisch; nil = keiner)
	OwnAddrs func(ctx context.Context) []netip.Addr // eigene oeffentliche Adressen, nicht melden (nil = keine)
	State    ReportStateStore
	Mode     string // module | headless
	Version  string // Version der Node
	Log      *slog.Logger
}

// Reporter schickt die Meldungen (eine gleichzeitig) und haelt den Zustand fuer Anzeige und Prometheus.
type Reporter struct {
	cfg   ReporterConfig
	now   func() time.Time
	every time.Duration
	first time.Duration

	run sync.Mutex // eine Meldung gleichzeitig

	mu          sync.Mutex // die Felder darunter
	gen         int64      // erhoeht bei ResetWindow: ein laufender Durchlauf speichert dann nicht mehr
	pending     ReportPeriod
	fails       int
	next        time.Time
	lastErr     string
	lastErrAt   time.Time
	errors      int64
	rejected    int            // von ipv64 einzeln abgelehnte Quellen der letzten angenommenen Meldung
	rejectedWhy map[string]int // Gruende dazu (z. B. not_public)
	day         string         // Datum (lokal) fuer srcToday
	srcToday    int64
	srcTotal    int64
	state       ReportState // letzter gelesener bzw. gespeicherter Stand (Anzeige)
	sensorID    string
}

// NewReporter erzeugt den Sender (Log nil = Standard).
func NewReporter(cfg ReporterConfig) *Reporter {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Profile == nil {
		cfg.Profile = func(context.Context) string { return "" }
	}
	return &Reporter{cfg: cfg, now: time.Now, every: ReportEvery, first: reportFirst}
}

// ReportStatus ist der Zustand der Meldung (Oberflaeche, API, Info-Seite).
type ReportStatus struct {
	Enabled      bool      `json:"enabled"` // Opt-in an
	KeySet       bool      `json:"key_set"` // API-Key vorhanden
	Active       bool      `json:"active"`  // beides: es wird gemeldet
	SensorID     string    `json:"sensor_id,omitempty"`
	LastSuccess  time.Time `json:"last_success,omitzero"`  // letzte angenommene Meldung
	LastEnd      time.Time `json:"last_end,omitzero"`      // gemeldet bis
	LastError    string    `json:"last_error,omitempty"`   // letzter Fehler seit dem Start (bleibt nach Erfolg stehen, siehe LastErrorAt)
	LastErrorAt  time.Time `json:"last_error_at,omitzero"` //
	NextAttempt  time.Time `json:"next_attempt,omitzero"`  // naechster Durchlauf (nur aktiv)
	Errors       int64     `json:"errors"`                 // fehlgeschlagene bzw. verworfene Meldungen seit dem Start
	SourcesToday int64     `json:"sources_today"`          // gemeldete Quell-IPs heute (je Meldung gezaehlt)
	SourcesTotal int64     `json:"sources_total"`          // seit dem Start
	// von ipv64 in der letzten angenommenen Meldung einzeln abgelehnte Quellen (private/eigene IP, ausserhalb des
	// Zeitraums, unbekannte Art …) mit Gruenden; die Meldung selbst war gueltig
	LastRejected        int            `json:"last_rejected"`
	LastRejectedReasons map[string]int `json:"last_rejected_reasons,omitempty"`
}

// Status liefert den Zustand (fragt Opt-in und Key ab, liest den gespeicherten Stand einmal nach).
func (r *Reporter) Status(ctx context.Context) ReportStatus {
	_, key := r.cfg.API(ctx)
	st := ReportStatus{Enabled: r.cfg.Enabled(ctx), KeySet: key != ""}
	st.Active = st.Enabled && st.KeySet
	state := r.loadedState(ctx)
	r.mu.Lock()
	id := r.sensorID
	r.mu.Unlock()
	if id == "" && st.Enabled {
		id, _ = r.cfg.SensorID(ctx)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rollDay()
	st.SensorID, st.LastSuccess, st.LastEnd = id, state.LastSuccess, state.LastEnd
	st.LastError, st.LastErrorAt, st.Errors = r.lastErr, r.lastErrAt, r.errors
	st.SourcesToday, st.SourcesTotal = r.srcToday, r.srcTotal
	st.LastRejected, st.LastRejectedReasons = r.rejected, r.rejectedWhy
	if st.Active {
		st.NextAttempt = r.next
	}
	return st
}

// RejectedText fasst die Gruende der abgelehnten Quellen zusammen ("not_public 2, out_of_period 1", haeufigste zuerst).
func (s ReportStatus) RejectedText() string {
	keys := make([]string, 0, len(s.LastRejectedReasons))
	for k := range s.LastRejectedReasons {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := s.LastRejectedReasons[keys[i]], s.LastRejectedReasons[keys[j]]
		return a > b || a == b && keys[i] < keys[j]
	})
	for i, k := range keys {
		keys[i] = k + " " + strconv.Itoa(s.LastRejectedReasons[k])
	}
	return strings.Join(keys, ", ")
}

// loadedState liefert den Stand aus dem Speicher des Senders, beim ersten Mal (nach dem Start) aus State.
func (r *Reporter) loadedState(ctx context.Context) ReportState {
	r.mu.Lock()
	state := r.state
	r.mu.Unlock()
	if !state.LastEnd.IsZero() || !state.LastSuccess.IsZero() {
		return state
	}
	s, err := r.cfg.State.Load(ctx)
	if err != nil {
		return state
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state.LastEnd.IsZero() && r.state.LastSuccess.IsZero() {
		r.state = s
	}
	return r.state
}

// rollDay setzt den Tageszaehler zurueck, wenn ein neuer Tag begonnen hat (mit r.mu).
func (r *Reporter) rollDay() {
	if d := r.now().Format("2006-01-02"); d != r.day {
		r.day, r.srcToday = d, 0
	}
}

// ResetWindow laesst den naechsten Zeitraum jetzt beginnen (beim Einschalten der Meldung: nichts von vorher melden).
func (r *Reporter) ResetWindow(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gen++
	r.pending, r.fails = ReportPeriod{}, 0
	st, _ := r.cfg.State.Load(ctx)
	st.LastEnd = r.now().UTC().Truncate(time.Second)
	r.state = st
	return r.cfg.State.Save(ctx, st)
}

// jitter liefert einen Zufallsversatz in [-reportJitter, +reportJitter].
func jitter() time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(2*reportJitter)))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64()) - reportJitter
}

// Run meldet bis ctx endet: erster Durchlauf kurz nach dem Start, dann alle ReportEvery (mit Zufallsversatz), nach
// Fehlern mit Backoff.
func (r *Reporter) Run(ctx context.Context) {
	delay := r.first + jitter() + reportJitter
	for {
		r.mu.Lock()
		r.next = r.now().Add(delay)
		r.mu.Unlock()
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		delay = r.RunOnce(ctx)
	}
}

// RunOnce ist ein Durchlauf (Opt-in aus oder kein Key: nichts). Liefert die Wartezeit bis zum naechsten.
func (r *Reporter) RunOnce(ctx context.Context) time.Duration {
	regular := r.every + jitter()
	if !r.run.TryLock() {
		return regular
	}
	defer r.run.Unlock()
	if !r.cfg.Enabled(ctx) {
		return regular
	}
	client, key := r.cfg.API(ctx)
	if key == "" || client == nil {
		return regular
	}
	id, err := r.cfg.SensorID(ctx)
	if err != nil {
		return r.failed(fmt.Errorf("sensor id: %w", err), 0, false)
	}
	r.mu.Lock()
	gen := r.gen
	r.sensorID = id
	r.mu.Unlock()
	st, err := r.cfg.State.Load(ctx)
	if err != nil {
		r.cfg.Log.Warn("honeypot report: state unreadable, starting new", "err", err)
		st = ReportState{}
	}
	_ = r.cfg.Store.Flush(ctx)
	end := r.now().Add(-reportGrace).UTC().Truncate(time.Second)
	if st.LastEnd.IsZero() || st.LastEnd.After(end.Add(time.Minute)) { // erster Durchlauf oder Uhr zurueckgestellt
		st.LastEnd = end
		r.save(ctx, gen, st)
		return regular
	}
	start := st.LastEnd.UTC()
	if end.Sub(start) > ReportMaxBack {
		r.cfg.Log.Warn("honeypot report: backlog older than 7 days is not reported", "from", start, "to", end.Add(-ReportMaxBack))
		start = end.Add(-ReportMaxBack)
	}
	if !start.Before(end) {
		return regular
	}
	hasAny, err := r.cfg.Store.hasEvents(ctx, start, end)
	if err != nil {
		return r.failed(fmt.Errorf("read events: %w", err), 0, false)
	}
	var own []netip.Addr
	if r.cfg.OwnAddrs != nil {
		own = r.cfg.OwnAddrs(ctx)
	}
	// je Durchlauf hoechstens eine angenommene Meldung (Rate-Limit bei ipv64); verworfene bzw. schon bekannte
	// Stuecke zaehlen dort nicht, danach geht es gleich weiter
	for start.Before(end) {
		if ctx.Err() != nil || !r.cfg.Enabled(ctx) {
			return regular
		}
		ce := end
		if chunk := reportChunk; hasAny && end.Sub(start) > chunk { // ohne Ereignisse: ein Lebenszeichen fuer den ganzen Zeitraum
			if end.Sub(start) > 24*time.Hour {
				chunk = reportChunkBig
			}
			ce = start.Add(chunk)
		}
		r.mu.Lock()
		if p := r.pending; p.Start.Equal(start) && p.End.After(start) && !p.End.After(end) {
			ce = p.End // Wiederholung: genau derselbe Zeitraum (gleiche report_id)
		}
		r.mu.Unlock()
		rep, err := r.cfg.Store.BuildReport(ctx, start, ce, own...)
		if err != nil {
			return r.failed(fmt.Errorf("build report: %w", err), 0, false)
		}
		rep.ReportID = id + "-" + strconv.FormatInt(start.Unix(), 10)
		rep.Sensor = ReportSensor{ID: id, Version: r.cfg.Version, Profile: r.cfg.Profile(ctx), Mode: r.cfg.Mode}
		if r.cfg.Country != nil {
			rep.Sensor.Country = r.cfg.Country(ctx)
		}
		body, err := encodeReport(rep)
		if err != nil {
			return r.failed(fmt.Errorf("encode report: %w", err), 0, false)
		}
		res, err := client.HoneypotReport(ctx, key, body)
		if err != nil {
			if ctx.Err() != nil {
				return regular
			}
			var ae *ipv64api.APIError
			if errors.As(err, &ae) && (ae.Status == http.StatusBadRequest || ae.Status == http.StatusRequestEntityTooLarge || ae.Status == http.StatusUnprocessableEntity) {
				// ungueltig: nicht wiederholen, verwerfen und weiter
				r.failed(err, 0, true)
				r.cfg.Log.Warn("honeypot report rejected by ipv64, discarded", "report_id", rep.ReportID, "status", ae.Status, "err", err)
				if !r.advance(ctx, gen, ce, false) {
					return regular
				}
				start = ce
				continue
			}
			var after time.Duration
			if ae != nil {
				after = ae.RetryAfter
				if (ae.Status == http.StatusUnauthorized || ae.Status == http.StatusForbidden) && after < r.every {
					after = r.every // Key ungueltig bzw. Klasse gesperrt: nicht oefter als im Takt
				}
			}
			r.mu.Lock()
			r.pending = ReportPeriod{Start: start, End: ce}
			r.mu.Unlock()
			return r.failed(err, after, false)
		}
		n := reportIPs(rep)
		r.mu.Lock()
		r.rollDay()
		r.srcToday += n
		r.srcTotal += n
		r.fails, r.pending = 0, ReportPeriod{}
		if !res.Duplicate {
			r.rejected, r.rejectedWhy = res.Rejected, res.RejectedReasons
		}
		r.mu.Unlock()
		r.cfg.Log.Debug("honeypot report sent", "report_id", rep.ReportID, "status", res.Status, "sources", len(rep.Sources), "ips", n,
			"duplicate", res.Duplicate, "dropped", rep.Dropped, "rejected", res.Rejected)
		if res.Rejected > 0 {
			r.cfg.Log.Info("honeypot report: ipv64 rejected some sources", "report_id", rep.ReportID, "rejected", res.Rejected, "reasons", res.RejectedReasons)
		}
		// schon bekannt, aber ipv64 hat einen kuerzeren Zeitraum (Stand ging hier verloren): nur bis dorthin
		// vorruecken, der Rest geht gleich als neue Meldung hinterher (sonst fehlten diese Ereignisse bei ipv64)
		if res.Duplicate && res.PeriodEnd > start.Unix() && res.PeriodEnd < ce.Unix() {
			ce = time.Unix(res.PeriodEnd, 0).UTC()
			res.Duplicate = false
		}
		if !r.advance(ctx, gen, ce, true) {
			return regular
		}
		start = ce
		if !res.Duplicate && start.Before(end) {
			return reportMinGap // Rest nach der Sperrzeit von ipv64 nachholen
		}
	}
	return regular
}

// advance speichert den neuen Stand (ok = von ipv64 angenommen). false = inzwischen ResetWindow: abbrechen.
func (r *Reporter) advance(ctx context.Context, gen int64, end time.Time, ok bool) bool {
	st, _ := r.cfg.State.Load(ctx)
	st.LastEnd = end
	if ok {
		st.LastSuccess = r.now().UTC()
	}
	return r.save(ctx, gen, st)
}

func (r *Reporter) save(ctx context.Context, gen int64, st ReportState) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if gen != r.gen {
		return false
	}
	r.state = st
	if err := r.cfg.State.Save(ctx, st); err != nil {
		r.cfg.Log.Warn("honeypot report: state not saved", "err", err)
	}
	return true
}

// failed zaehlt und merkt sich einen Fehler. discard = Meldung verworfen (kein Backoff). Liefert die Wartezeit:
// Backoff ab 1 Minute, verdoppelt bis 1 Stunde, mindestens Retry-After.
func (r *Reporter) failed(err error, retryAfter time.Duration, discard bool) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errors++
	r.lastErr, r.lastErrAt = err.Error(), r.now()
	if discard {
		return 0
	}
	r.fails++
	d := reportBackoff << min(r.fails-1, 10)
	if d > reportBackoffMx {
		d = reportBackoffMx
	}
	if retryAfter > d {
		d = retryAfter
	}
	if r.fails == 1 || r.fails%10 == 0 {
		r.cfg.Log.Warn("honeypot report failed, will retry", "err", err, "retry_in", d.String(), "attempt", r.fails)
	}
	return d
}

// metricsValues liefert letzte erfolgreiche Meldung, Fehler und gemeldete Quellen seit dem Start (Prometheus).
func (r *Reporter) metricsValues(ctx context.Context) (lastSuccess time.Time, errs, sources int64) {
	r.loadedState(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state.LastSuccess, r.errors, r.srcTotal
}

// encodeReport packt den Bericht als gzip-JSON. Ist er entpackt groesser als erlaubt, werden Quellen und Proben
// halbiert (Rest in Dropped), bis er passt.
func encodeReport(rep *Report) ([]byte, error) {
	raw, err := json.Marshal(rep)
	for i := 0; err == nil && len(raw) > reportMaxBody && i < 16; i++ {
		rep.Dropped += halve(&rep.Sources) + halve(&rep.Samples.Credentials) + halve(&rep.Samples.Paths) +
			halve(&rep.Samples.UserAgents) + halve(&rep.Samples.Payloads)
		raw, err = json.Marshal(rep)
	}
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if _, err := zw.Write(raw); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func halve[T any](s *[]T) int64 {
	n := len(*s) / 2
	cut := int64(len(*s) - n)
	*s = (*s)[:n]
	return cut
}
