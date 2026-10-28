package sonar

// Oeffentliche Go-Schnittstelle des Kerns (Vertrag docs/SONAR64-VERTRAG.md, Abschnitt Go). cmd/sonar64 und das
// Node64-Modul internal/sonar64 nutzen nur, was hier steht. Die Ablaeufe stehen in runner.go, Grenzen in
// limits.go, Plan in plan.go, HTTP in client.go, Ablage in state.go.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ErrNotImplemented markiert Teile des Geruests, die noch fehlen (der Kern nutzt es nicht mehr; bleibt fuer das
// Geruest von probe.go, bis der Teil Messung es ersetzt).
var ErrNotImplemented = errors.New("sonar: not implemented")

// Config ist die Einstellung eines Knotens.
type Config struct {
	APIBase    string       // leer = https://ipv64.net/api/v2 (nur Tests aendern das)
	Token      string       // Sonar-Token (s64_… oder Anker s64a_…)
	DataDir    string       // Ablage fuer Schluessel, Node-ID, Seq, Puffer (ein paar KB); leer = nur im Speicher (Tests)
	Mode       string       // module | headless | anchor
	Version    string       // Programmversion (Health, Register)
	Measured   bool         // UDP 6464 beantworten und gemessen werden
	Budget     string       // sparsam | normal | grosszuegig (lokale Obergrenze, Abschnitt Grenzen)
	Quiet      [2]int       // Ruhezeit Stunden [von, bis) in lokaler Zeit; {0,0} = keine
	Log        *slog.Logger // nil = slog.Default()
	Prober     Prober       // nil = NewProber(ProbeConfig{})
	PlanKeys   []string     // nil = PlanKeys aus keys.go (Tests setzen eigene)
	HTTPClient HTTPDoer     // nil = eigener Client mit Timeout
}

// Status ist der Zustand fuer Oberflaeche, Mini-Status und Log.
type Status struct {
	NodeID      string    `json:"node_id"`
	Registered  bool      `json:"registered"`
	Mode        string    `json:"mode"`
	Measured    bool      `json:"measured"`
	Budget      string    `json:"budget"`
	Responder   bool      `json:"responder"` // UDP 6464 offen
	PlanIssued  time.Time `json:"plan_issued,omitzero"`
	PlanExpires time.Time `json:"plan_expires,omitzero"`
	AnchorsOnly bool      `json:"anchors_only"` // kein gueltiger Plan, nur Anker
	Paused      string    `json:"paused,omitempty"`
	SentToday   int       `json:"sent_today"`
	LastReport  time.Time `json:"last_report,omitzero"`
	Buffered    int       `json:"buffered"` // noch nicht gemeldete Ergebnisse
	LastError   string    `json:"last_error,omitempty"`
}

// Modi des Programms.
const (
	ModeModule   = "module"
	ModeHeadless = "headless"
	ModeAnchor   = "anchor"
)

// DefaultAPIBase ist die API v2 von ipv64.net.
const DefaultAPIBase = "https://ipv64.net/api/v2"

var (
	nodeTokenRe   = regexp.MustCompile(`^s64_[A-Za-z0-9]{40}$`)
	anchorTokenRe = regexp.MustCompile(`^s64a_[A-Za-z0-9]{40}$`)
	apiKeyRe      = regexp.MustCompile(`^[A-Za-z0-9]{16,64}$`)
	tokenNameRe   = regexp.MustCompile(`^[A-Za-z0-9 ._-]{1,32}$`)
	nameRe        = regexp.MustCompile(`^[A-Za-z0-9 ._-]{3,32}$`)
	deviceRe      = regexp.MustCompile(`^[a-z0-9-]{0,16}$`)
)

var accessKinds = map[string]bool{"": true, "fiber": true, "dsl": true, "cable": true, "mobile": true,
	"satellite": true, "datacenter": true, "other": true}

// Runner fuehrt einen Knoten aus.
type Runner struct {
	cfg     Config
	log     *slog.Logger
	key     ed25519.PrivateKey
	pubB64  string
	keys    []ed25519.PublicKey
	anchor  bool
	api     *client
	tokenID string

	// Zeiten (Konstanten aus wire.go; Tests verkuerzen sie)
	now         func() time.Time
	roundLen    time.Duration
	planEvery   time.Duration
	reportEvery time.Duration
	reportGap   time.Duration // Mindestabstand zweier Meldungen (Server: hoechstens 1 je 60 s)
	retryMin    time.Duration
	tick        time.Duration

	running atomic.Bool
	bucket  *bucket
	wake    chan struct{} // Measured geaendert -> Antworter pruefen

	mu          sync.Mutex
	st          persisted
	registered  bool
	measured    bool
	budget      string
	prober      Prober
	plan        *activePlan
	doneRounds  map[int64]bool
	pauseNext   bool
	uplink      bool
	paused      string
	buf         []Result  // Puffer, aelteste zuerst
	bufOff      uint64    // absolute Position von buf[0]
	inbuf       []Inbound //
	inOff       uint64
	recent      []Result
	recentIn    []Inbound
	lastReport  time.Time
	lastErr     string
	icmpDenied  bool
	responder   responderIface
	responderOn bool
	traces      []time.Time
}

// New prueft die Einstellung und laedt bzw. erzeugt Schluessel und Node-ID im DataDir.
func New(cfg Config) (*Runner, error) {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Mode == "" {
		cfg.Mode = ModeHeadless
	}
	if cfg.Version == "" {
		cfg.Version = "dev"
	}
	if len(cfg.Version) > 32 {
		cfg.Version = cfg.Version[:32]
	}
	switch cfg.Mode {
	case ModeModule, ModeHeadless:
		if !nodeTokenRe.MatchString(cfg.Token) {
			return nil, errors.New("sonar: token must be s64_ followed by 40 letters/digits")
		}
	case ModeAnchor:
		if !anchorTokenRe.MatchString(cfg.Token) {
			return nil, errors.New("sonar: anchor mode needs an anchor token (s64a_…)")
		}
	default:
		return nil, fmt.Errorf("sonar: unknown mode %q", cfg.Mode)
	}
	if cfg.Budget == "" {
		cfg.Budget = BudgetLow
	}
	if !validBudget(cfg.Budget) {
		return nil, fmt.Errorf("sonar: unknown budget %q", cfg.Budget)
	}
	for _, h := range cfg.Quiet {
		if h < 0 || h > 23 {
			return nil, errors.New("sonar: quiet hours must be 0..23")
		}
	}
	base, err := checkBase(cfg.APIBase)
	if err != nil {
		return nil, err
	}
	keys := cfg.PlanKeys
	if keys == nil {
		keys = PlanKeys
		if len(keys) == 0 {
			if v := os.Getenv("SONAR64_PLAN_KEY"); v != "" {
				cfg.Log.Warn("sonar64: plan key from SONAR64_PLAN_KEY (only for tests/development)")
				keys = []string{v}
			}
		}
	}
	pks, err := parsePlanKeys(keys)
	if err != nil {
		return nil, err
	}
	if len(pks) == 0 {
		cfg.Log.Warn("sonar64: no plan key - plans cannot be verified, nothing will be measured")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = defaultHTTPClient()
	}
	r := &Runner{
		cfg: cfg, log: cfg.Log, keys: pks, anchor: cfg.Mode == ModeAnchor,
		api:     &client{base: base, http: hc, ua: "sonar64/" + cfg.Version},
		tokenID: tokenID(cfg.Token),
		now:     time.Now, roundLen: RoundInterval, planEvery: 15 * time.Minute, reportEvery: 5 * time.Minute,
		reportGap: 61 * time.Second, retryMin: time.Minute, tick: 2 * time.Second,
		wake:       make(chan struct{}, 1),
		measured:   cfg.Measured || cfg.Mode == ModeAnchor,
		budget:     cfg.Budget,
		doneRounds: map[int64]bool{},
		uplink:     true,
	}
	if cfg.DataDir != "" {
		if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
			return nil, fmt.Errorf("sonar: data dir: %w", err)
		}
		if r.key, err = loadOrCreateKey(cfg.DataDir); err != nil {
			return nil, err
		}
		st, err := loadState(cfg.DataDir)
		if err != nil {
			r.log.Warn("sonar64: state file unreadable, starting fresh (key kept)", "err", err)
		}
		r.st = st
	} else {
		_, r.key, err = ed25519.GenerateKey(nil)
		if err != nil {
			return nil, err
		}
	}
	r.pubB64 = base64.StdEncoding.EncodeToString(r.key.Public().(ed25519.PublicKey))
	if r.st.NodeID != "" && r.st.TokenID == r.tokenID && validNodeID(r.st.NodeID) {
		r.registered = true
	}
	r.bucket = newBucket(r.limits().pps, r.now)
	if r.registered {
		r.restorePlan()
	}
	return r, nil
}

// Run laeuft bis ctx endet: anmelden (Register, einmal), Plan holen (alle 15 min, ETag), Runden messen, alle 5 min
// melden, Antworter auf UDP 6464 (wenn Measured).
func (r *Runner) Run(ctx context.Context) error {
	if !r.running.CompareAndSwap(false, true) {
		return errors.New("sonar: runner already running")
	}
	defer r.running.Store(false)
	if err := r.ensureRegistered(ctx); err != nil {
		return nil // nur bei Ende von ctx
	}
	r.initProber()
	var wg sync.WaitGroup
	for _, loop := range []func(context.Context){r.planLoop, r.measureLoop, r.reportLoop, r.responderLoop} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			loop(ctx)
		}()
	}
	wg.Wait()
	// Zum Schluss noch einmal melden (kurz), damit nichts verloren geht.
	r.mu.Lock()
	last := r.lastReport
	r.mu.Unlock()
	if r.now().Sub(last) >= r.reportGap {
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		r.safe("final report", func() { r.report(fctx) })
	}
	r.saveState()
	return nil
}

// Status liefert den aktuellen Zustand.
func (r *Runner) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	s := Status{
		NodeID: r.st.NodeID, Registered: r.registered, Mode: r.cfg.Mode, Measured: r.measured, Budget: r.budget,
		Responder: r.responderOn, Paused: r.paused, SentToday: r.sentTodayLocked(now), LastReport: r.lastReport,
		Buffered: len(r.buf), LastError: r.lastErr,
	}
	if p := r.plan; p != nil {
		s.PlanIssued, s.PlanExpires = p.plan.Issued.UTC(), p.validUntil.UTC()
		s.AnchorsOnly = !now.Before(p.validUntil) && now.Before(p.anchorsUntil)
	}
	return s
}

// Recent liefert die letzten n eigenen Messungen (neueste zuerst) und die letzten n auf UDP 6464 beantworteten Proben.
// Ziel-Adressen sind darin nicht enthalten (nur Target-ID).
func (r *Runner) Recent(n int) ([]Result, []Inbound) {
	n = max(0, min(n, recentMax))
	r.mu.Lock()
	defer r.mu.Unlock()
	res := make([]Result, 0, min(n, len(r.recent)))
	for i := len(r.recent) - 1; i >= 0 && len(res) < n; i-- {
		x := r.recent[i]
		x.Hops = append([]Hop(nil), x.Hops...)
		res = append(res, x)
	}
	in := make([]Inbound, 0, min(n, len(r.recentIn)))
	for i := len(r.recentIn) - 1; i >= 0 && len(in) < n; i-- {
		in = append(in, r.recentIn[i])
	}
	return res, in
}

// Me holt den eigenen Knoten von ipv64.
func (r *Runner) Me(ctx context.Context) (*Me, error) {
	var m Me
	if err := r.api.call(ctx, http.MethodGet, "/sonar/me", r.cfg.Token, nil, smallLimit, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// meWrite sind die schreibbaren Felder von PUT /sonar/me.
type meWrite struct {
	Name     string   `json:"name,omitempty"`
	Lat      *float64 `json:"lat,omitempty"`
	Lon      *float64 `json:"lon,omitempty"`
	Access   string   `json:"access,omitempty"`
	Device   string   `json:"device,omitempty"`
	Measured bool     `json:"measured"`
	Budget   string   `json:"budget"`
}

// UpdateMe setzt Name, Standort, Anschlussart, Geraet, Measured, Budget (PUT /sonar/me) und uebernimmt Measured
// und Budget sofort lokal.
func (r *Runner) UpdateMe(ctx context.Context, m Me) (*Me, error) {
	w, err := r.checkMe(m)
	if err != nil {
		return nil, err
	}
	var out Me
	if err := r.api.call(ctx, http.MethodPut, "/sonar/me", r.cfg.Token, w, smallLimit, &out); err != nil {
		return nil, err
	}
	r.mu.Lock()
	if !r.anchor {
		r.measured = w.Measured
	}
	r.budget = w.Budget
	r.mu.Unlock()
	r.signalWake()
	return &out, nil
}

// checkMe prueft die schreibbaren Felder.
func (r *Runner) checkMe(m Me) (meWrite, error) {
	w := meWrite{Name: m.Name, Access: m.Access, Device: m.Device, Measured: m.Measured, Budget: m.Budget}
	if w.Name != "" && (!nameRe.MatchString(w.Name) || strings.TrimSpace(w.Name) != w.Name || strings.Contains(w.Name, "  ")) {
		return w, errors.New("sonar: name must be 3..32 of A-Z a-z 0-9 space . _ - (no leading, trailing or double spaces)")
	}
	if !accessKinds[w.Access] {
		return w, errors.New("sonar: unknown access kind")
	}
	if !deviceRe.MatchString(w.Device) {
		return w, errors.New("sonar: device must be up to 16 of a-z 0-9 -")
	}
	if (m.Lat == nil) != (m.Lon == nil) {
		return w, errors.New("sonar: lat and lon only together")
	}
	if m.Lat != nil {
		la, lo := *m.Lat, *m.Lon
		if math.IsNaN(la) || math.IsNaN(lo) || la < -90 || la > 90 || lo < -180 || lo > 180 {
			return w, errors.New("sonar: location out of range")
		}
		w.Lat, w.Lon = &la, &lo
	}
	if w.Budget == "" {
		r.mu.Lock()
		w.Budget = r.budget
		r.mu.Unlock()
	}
	if !validBudget(w.Budget) {
		return w, errors.New("sonar: unknown budget")
	}
	if r.anchor {
		w.Measured = true
	}
	return w, nil
}

// Inbound holt, wer mich seit since gemessen hat (GET /sonar/inbound, aus den Ergebnissen bei ipv64).
func (r *Runner) Inbound(ctx context.Context, since time.Time) ([]InboundRow, error) {
	now := r.now().UTC()
	if since.IsZero() || since.Before(now.Add(-24*time.Hour)) {
		since = now.Add(-24 * time.Hour)
	}
	if since.After(now) {
		since = now
	}
	var rows []InboundRow
	path := "/sonar/inbound?since=" + url.QueryEscape(since.UTC().Format(time.RFC3339))
	if err := r.api.call(ctx, http.MethodGet, path, r.cfg.Token, nil, listLimit, &rows); err != nil {
		return nil, err
	}
	if len(rows) > maxInboundRows {
		rows = rows[:maxInboundRows]
	}
	return rows, nil
}

// CreateToken legt mit dem API-Key des Accounts ein Sonar-Token an (POST /sonar/tokens). Node64 nutzt das beim Opt-in.
func CreateToken(ctx context.Context, apiBase, apiKey, name string) (string, error) {
	base, err := checkBase(apiBase)
	if err != nil {
		return "", err
	}
	if !apiKeyRe.MatchString(apiKey) {
		return "", errors.New("sonar: invalid API key format")
	}
	if !tokenNameRe.MatchString(name) {
		return "", errors.New("sonar: token name must be 1..32 of A-Z a-z 0-9 space . _ -")
	}
	c := &client{base: base, http: defaultHTTPClient(), ua: "sonar64"}
	var out struct {
		ID    any    `json:"id"`
		Token string `json:"token"`
	}
	if err := c.call(ctx, http.MethodPost, "/sonar/tokens", apiKey, map[string]string{"name": name}, smallLimit, &out); err != nil {
		return "", err
	}
	if !nodeTokenRe.MatchString(out.Token) {
		return "", errors.New("sonar: unexpected token format from ipv64")
	}
	return out.Token, nil
}
