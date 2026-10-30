package proxmox

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

// Speicher der Proxmox-Ueberwachung: Systeme, Einstellungen und Regeln je Ebene (Tabellen pve_* aus der Migration
// internal/healthchecks/migrations/0015_proxmox.sql, Scope healthchecks). Der Verlauf steht in history.go.

var (
	ErrNotFound = errors.New("proxmox system not found")
	ErrNoBox    = errors.New("no secret key loaded (token secret cannot be stored encrypted)")
)

// FieldError ist ein Fehler in einem Eingabefeld; Key ist der i18n-Schluessel.
type FieldError struct{ Field, Key string }

func (e *FieldError) Error() string { return e.Field + ": " + e.Key }

func pveFerr(field, key string) error { return &FieldError{Field: field, Key: key} }

// Store ist die Datenhaltung auf Basis des Kern-Stores.
type Store struct {
	w, r *sql.DB
	box  *secrets.Box
	now  func() time.Time // Uhr (Tests)

	mu         sync.Mutex
	seen       map[int64]map[string]bool // Gaeste, die schon laufend gesehen wurden (je System)
	rawDays    int                       // Aufbewahrung 5-min-Werte (Tage, wie hc.raw_days)
	hourlyDays int                       // Aufbewahrung Stundenwerte (Tage, 0 = unbegrenzt, wie hc.hourly_days)
	compacted  map[string]int64          // je Aufloesung: Beginn des zuletzt verdichteten Intervalls (Unix)
	lastPrune  int64
}

// NewStore erzeugt den Speicher. box verschluesselt das Token-Secret (ohne Box kann kein System gespeichert werden).
func NewStore(core *store.Store, box *secrets.Box) *Store {
	return &Store{w: core.Writer(), r: core.Reader(), box: box, now: time.Now, seen: map[int64]map[string]bool{},
		rawDays: DefaultRawDays, hourlyDays: DefaultHourlyDays, compacted: map[string]int64{}}
}

const (
	DefaultInterval = 30
	MinInterval     = 15
	MaxInterval     = 300
	DefaultPort     = "8006"
	DefaultPortPBS  = "8007"
	maxAddresses    = 16
	maxChannels     = 100 // Kanaele je Ebene
)

var (
	pveReTokenID = regexp.MustCompile(`^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+![A-Za-z][A-Za-z0-9._-]*$`)
	pveRePin     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// NormalizeAddress prueft eine Adresse und liefert sie als https://host:port (ohne Pfad). Ohne Port gilt 8006.
func NormalizeAddress(s string) (string, bool) { return normalizeAddress(s, DefaultPort) }

// NormalizeAddressFor: wie NormalizeAddress, ohne Port gilt der der Art (PBS 8007).
func NormalizeAddressFor(kind, s string) (string, bool) {
	if kind == KindPBS {
		return normalizeAddress(s, DefaultPortPBS)
	}
	return normalizeAddress(s, DefaultPort)
}

func normalizeAddress(s, defPort string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" || u.User != nil {
		return "", false
	}
	port := u.Port()
	if port == "" {
		port = defPort
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return "", false
	}
	return "https://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port), true
}

// NormalizePin entfernt Doppelpunkte/Leerzeichen und prueft den Fingerabdruck (64 hex, leer = System-CA).
func NormalizePin(s string) (string, bool) {
	s = strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(s)))
	return s, s == "" || pveRePin.MatchString(s)
}

// SameEndpoint sagt, ob b dieselben Adressen (Reihenfolge egal) und denselben Pin hat wie a, beides normalisiert.
// Nur dann darf ein gespeichertes Secret fuer einen Test wiederverwendet werden (sonst ginge es an ein anderes Ziel).
func SameEndpoint(a, b *System) bool {
	norm := func(l []string) []string {
		var out []string
		for _, x := range l {
			if n, ok := NormalizeAddressFor(a.Kind, x); ok && !slices.Contains(out, n) {
				out = append(out, n)
			}
		}
		slices.Sort(out)
		return out
	}
	pa, okA := NormalizePin(a.PinSHA256)
	pb, okB := NormalizePin(b.PinSHA256)
	return okA && okB && pa == pb && slices.Equal(norm(a.Addresses), norm(b.Addresses))
}

// ValidateSystem prueft und normalisiert ein System. isNew verlangt ein Secret (beim Aendern: leer = behalten).
// Docker-Hosts haben eine Adresse (unix://, tcp://, http(s)://, ssh://) und kein Token; Secret (Zugangsdaten als JSON) und
// Pin nur bei https:// und ssh:// (docker_remote.go).
func ValidateSystem(sys *System, isNew bool) error {
	sys.Name = strings.TrimSpace(sys.Name)
	if len(sys.Name) > 100 {
		return pveFerr("name", "pve.err.name")
	}
	switch sys.Kind {
	case "":
		sys.Kind = KindPVE
	case KindPVE, KindPBS:
	case KindDocker:
		return validateDocker(sys, isNew)
	default:
		return pveFerr("kind", "pve.err.kind")
	}
	var addrs []string
	have := map[string]bool{}
	for _, a := range sys.Addresses {
		if strings.TrimSpace(a) == "" {
			continue
		}
		n, ok := NormalizeAddressFor(sys.Kind, a)
		if !ok {
			return pveFerr("addresses", "pve.err.address")
		}
		if !have[n] {
			have[n] = true
			addrs = append(addrs, n)
		}
	}
	if len(addrs) == 0 || len(addrs) > maxAddresses {
		return pveFerr("addresses", "pve.err.address")
	}
	sys.Addresses = addrs
	sys.TokenID = strings.TrimSpace(sys.TokenID)
	if len(sys.TokenID) > 200 || !pveReTokenID.MatchString(sys.TokenID) {
		return pveFerr("token_id", "pve.err.token_id")
	}
	sys.Secret = strings.TrimSpace(sys.Secret)
	if (isNew && sys.Secret == "") || len(sys.Secret) > 256 || strings.ContainsAny(sys.Secret, " \t\r\n") {
		return pveFerr("secret", "pve.err.secret")
	}
	pin, ok := NormalizePin(sys.PinSHA256)
	if !ok {
		return pveFerr("pin_sha256", "pve.err.pin")
	}
	sys.PinSHA256 = pin
	if sys.Interval == 0 {
		sys.Interval = DefaultInterval
	}
	if sys.Interval < MinInterval || sys.Interval > MaxInterval {
		return pveFerr("interval", "pve.err.interval")
	}
	return nil
}

// validateDocker prueft einen Docker-Host (leere Adresse = Standard, NODE64_DOCKER_HOST bzw. der Socket). isNew verlangt
// bei ssh:// einen Schluessel (beim Aendern: leeres Secret = behalten).
func validateDocker(sys *System, isNew bool) error {
	var addrs []string
	for _, a := range sys.Addresses {
		if a = strings.TrimSpace(a); a != "" {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) == 0 {
		addrs = []string{DefaultDockerHost()}
	}
	if len(addrs) != 1 || len(addrs[0]) > 300 || !ValidDockerHost(addrs[0]) {
		return pveFerr("addresses", "pve.err.docker_host")
	}
	sys.Addresses = addrs
	sys.TokenID = ""
	if !DockerUsesSecret(addrs[0]) {
		sys.Secret, sys.PinSHA256 = "", ""
	} else {
		pin, ok := NormalizeDockerPin(sys.PinSHA256)
		if !ok {
			return pveFerr("pin_sha256", "pve.err.pin")
		}
		sys.PinSHA256 = pin
		if DockerScheme(addrs[0]) == "ssh" && pin == "" {
			return pveFerr("pin_sha256", "docker.err.hostkey")
		}
		if len(sys.Secret) > dockerMaxSecret {
			return pveFerr("key", "docker.err.key")
		}
		if sys.Secret != "" || (isNew && DockerScheme(addrs[0]) == "ssh") {
			if err := validateDockerCreds(addrs[0], ParseDockerCreds(sys.Secret)); err != nil {
				return err
			}
		}
	}
	if sys.Interval == 0 {
		sys.Interval = DefaultInterval
	}
	if sys.Interval < MinInterval || sys.Interval > MaxInterval {
		return pveFerr("interval", "pve.err.interval")
	}
	return nil
}

const systemCols = `id, kind, name, addresses, token_id, secret, pin_sha256, interval_sec, enabled, created_at, uid, home`

func (s *Store) scanSystem(row interface{ Scan(...any) error }) (*System, error) {
	var sys System
	var addrs, secret, created string
	if err := row.Scan(&sys.ID, &sys.Kind, &sys.Name, &addrs, &sys.TokenID, &secret, &sys.PinSHA256, &sys.Interval, &sys.Enabled, &created, &sys.UID, &sys.Home); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(addrs), &sys.Addresses)
	sys.Created = store.ParseTime(created)
	// Fehlt der Schluessel (secret.key verloren), bleibt das Secret leer: die Abfrage meldet dann 401.
	if plain, err := s.box.Decrypt(secret); err == nil {
		sys.Secret = plain
	}
	return &sys, nil
}

// Systems liefert alle Systeme (Secret entschluesselt, per JSON nie ausgegeben).
func (s *Store) Systems(ctx context.Context) ([]*System, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT `+systemCols+` FROM pve_systems ORDER BY name, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*System
	for rows.Next() {
		sys, err := s.scanSystem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sys)
	}
	return out, rows.Err()
}

// System liefert ein System.
func (s *Store) System(ctx context.Context, id int64) (*System, error) {
	sys, err := s.scanSystem(s.r.QueryRowContext(ctx, `SELECT `+systemCols+` FROM pve_systems WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return sys, err
}

// SystemByUID liefert ein System nach seiner Kennung im Cluster.
func (s *Store) SystemByUID(ctx context.Context, uid string) (*System, error) {
	if uid == "" {
		return nil, ErrNotFound
	}
	sys, err := s.scanSystem(s.r.QueryRowContext(ctx, `SELECT `+systemCols+` FROM pve_systems WHERE uid = ?`, uid))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return sys, err
}

var reUID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ValidUID: Kennung eines Systems (32 hex).
func ValidUID(uid string) bool { return reUID.MatchString(uid) }

func newUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// SaveSystem legt ein System an (ID 0) oder aendert es. Beim Aendern behaelt ein leeres Secret das gespeicherte.
// Das Secret wird nur verschluesselt gespeichert.
func (s *Store) SaveSystem(ctx context.Context, sys *System) error {
	if err := ValidateSystem(sys, sys.ID == 0); err != nil {
		return err
	}
	if s.box == nil && (!sys.IsDocker() || (sys.Secret != "" && sys.Secret != DockerNoCreds)) { // Docker-Hosts meist ohne Secret
		return ErrNoBox
	}
	addrs, _ := json.Marshal(sys.Addresses)
	now := store.Now()
	if sys.ID == 0 {
		if sys.Secret == DockerNoCreds {
			sys.Secret = ""
		}
		if !ValidUID(sys.UID) { // neu hier: eigene Kennung (aus dem Cluster: die der anderen Node)
			sys.UID = newUID()
		}
		res, err := s.w.ExecContext(ctx, `INSERT INTO pve_systems (kind, name, addresses, token_id, secret, pin_sha256, interval_sec, enabled,
			created_at, updated_at, uid, home) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
			sys.Kind, sys.Name, string(addrs), sys.TokenID, s.box.Encrypt(sys.Secret), sys.PinSHA256, sys.Interval, sys.Enabled, now, now, sys.UID, sys.Home)
		if err != nil {
			return err
		}
		sys.ID, _ = res.LastInsertId()
		sys.Created = store.ParseTime(now)
		return nil
	}
	q := `UPDATE pve_systems SET name=?, addresses=?, token_id=?, pin_sha256=?, interval_sec=?, enabled=?, updated_at=?`
	args := []any{sys.Name, string(addrs), sys.TokenID, sys.PinSHA256, sys.Interval, sys.Enabled, now}
	keepSecret := !sys.IsDocker() || DockerUsesSecret(sys.Addresses[0])
	if sys.IsDocker() && sys.Secret == DockerNoCreds { // ausdruecklich ohne Zugangsdaten
		sys.Secret, keepSecret = "", false
	}
	if !keepSecret {
		q += `, secret=''`
	}
	if sys.Secret != "" {
		q += `, secret=?`
		args = append(args, s.box.Encrypt(sys.Secret))
	}
	res, err := s.w.ExecContext(ctx, q+` WHERE id=?`, append(args, sys.ID)...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if sys.Secret == "" && keepSecret {
		if old, err := s.System(ctx, sys.ID); err == nil {
			sys.Secret = old.Secret
		}
	}
	return nil
}

// ResetHistory verwirft Verlauf und „laufend gesehen“ eines Systems (Docker-Host auf eine andere Maschine umgestellt:
// Container gleichen Namens sind andere). Regeln, Stummschaltung und „als Check“ bleiben.
func (s *Store) ResetHistory(ctx context.Context, id int64) error {
	for _, q := range []string{`UPDATE pve_settings SET seen_running = 0 WHERE system_id = ?`, `DELETE FROM pve_hist_1m WHERE system_id = ?`,
		`DELETE FROM pve_hist_5m WHERE system_id = ?`, `DELETE FROM pve_hist_1h WHERE system_id = ?`} {
		if _, err := s.w.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}
	s.mu.Lock()
	delete(s.seen, id)
	s.mu.Unlock()
	return nil
}

// DeleteSystem loescht ein System mit Einstellungen und Verlauf.
func (s *Store) DeleteSystem(ctx context.Context, id int64) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	res, err := tx.ExecContext(ctx, `DELETE FROM pve_systems WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	for _, q := range []string{`DELETE FROM pve_settings WHERE system_id = ?`, `DELETE FROM pve_hist_1m WHERE system_id = ?`,
		`DELETE FROM pve_hist_5m WHERE system_id = ?`, `DELETE FROM pve_hist_1h WHERE system_id = ?`} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.seen, id)
	s.mu.Unlock()
	return nil
}

// --- Regeln ---

// Threshold ist eine Schwelle: Percent 0 = aus; Minutes = so lange mindestens ueber der Grenze.
type Threshold struct {
	Percent float64 `json:"percent"`
	Minutes int     `json:"minutes"`
}

// RuleSet sind die Regeln einer Ebene (System, Node, Gast); nil = von oben erben.
type RuleSet struct {
	Crashed     *bool      `json:"crashed,omitempty"` // Absturz (StateError), ohne Verzoegerung
	Stopped     *bool      `json:"stopped,omitempty"`
	Paused      *bool      `json:"paused,omitempty"`
	Suspended   *bool      `json:"suspended,omitempty"`
	Offline     *bool      `json:"offline,omitempty"`
	Unreachable *bool      `json:"unreachable,omitempty"`
	Restarted   *bool      `json:"restarted,omitempty"`
	CPU         *Threshold `json:"cpu,omitempty"`
	Mem         *Threshold `json:"mem,omitempty"`
	Disk        *Threshold `json:"disk,omitempty"`
	Delay       *int       `json:"delay,omitempty"` // erst nach N Abfragen melden (1 = sofort)
	// nur Proxmox Backup Server (Systemebene, alle Datastores): belegt ab Prozent bzw. voll in weniger als N Tagen
	Datastore     *Threshold `json:"datastore,omitempty"`
	DatastoreDays *int       `json:"datastore_days,omitempty"` // 0 = aus
	// Channels: Kanaele der Meldungen wie bei Checks; nil = erben, leere Liste = Standardkanaele, sonst diese Kanaele
	Channels *[]int64 `json:"channels,omitempty"`
}

// Rule ist die wirksame Regel nach der Vererbung.
type Rule struct {
	Crashed     bool      `json:"crashed"`
	Stopped     bool      `json:"stopped"`
	Paused      bool      `json:"paused"`
	Suspended   bool      `json:"suspended"`
	Offline     bool      `json:"offline"`
	Unreachable bool      `json:"unreachable"`
	Restarted   bool      `json:"restarted"`
	CPU         Threshold `json:"cpu"`
	Mem         Threshold `json:"mem"`
	Disk        Threshold `json:"disk"`
	Delay       int       `json:"delay"`
	Channels    []int64   `json:"channels"` // wirksame Kanaele; leer = Standardkanaele
	// PBS: Datastore belegt ab (Prozent 0 = aus) bzw. voll in weniger als DatastoreDays Tagen (0 = aus)
	Datastore     Threshold `json:"datastore"`
	DatastoreDays int       `json:"datastore_days"`
}

// DefaultRule sind die Standardwerte der Systemebene.
func DefaultRule() Rule {
	return Rule{Crashed: true, Stopped: true, Paused: true, Suspended: true, Offline: true, Unreachable: true, Restarted: true,
		CPU: Threshold{90, 10}, Mem: Threshold{95, 10}, Disk: Threshold{90, 0}, Delay: 2, Channels: []int64{}, Datastore: Threshold{90, 0}}
}

// Apply ueberschreibt r mit den gesetzten Werten von rs.
func (r Rule) Apply(rs RuleSet) Rule {
	set := func(dst *bool, v *bool) {
		if v != nil {
			*dst = *v
		}
	}
	set(&r.Crashed, rs.Crashed)
	set(&r.Stopped, rs.Stopped)
	set(&r.Paused, rs.Paused)
	set(&r.Suspended, rs.Suspended)
	set(&r.Offline, rs.Offline)
	set(&r.Unreachable, rs.Unreachable)
	set(&r.Restarted, rs.Restarted)
	if rs.CPU != nil {
		r.CPU = *rs.CPU
	}
	if rs.Mem != nil {
		r.Mem = *rs.Mem
	}
	if rs.Disk != nil {
		r.Disk = *rs.Disk
	}
	if rs.Delay != nil {
		r.Delay = *rs.Delay
	}
	if rs.Datastore != nil {
		r.Datastore = *rs.Datastore
	}
	if rs.DatastoreDays != nil {
		r.DatastoreDays = *rs.DatastoreDays
	}
	if rs.Channels != nil {
		r.Channels = append([]int64{}, (*rs.Channels)...)
	}
	return r
}

// Validate prueft die Werte einer Ebene.
func (rs *RuleSet) Validate() error {
	for _, t := range []struct {
		f string
		v *Threshold
	}{{"cpu", rs.CPU}, {"mem", rs.Mem}, {"disk", rs.Disk}, {"datastore", rs.Datastore}} {
		if t.v != nil && (t.v.Percent < 0 || t.v.Percent > 100 || t.v.Minutes < 0 || t.v.Minutes > 1440) {
			return pveFerr(t.f, "pve.err.threshold")
		}
	}
	if rs.Delay != nil && (*rs.Delay < 1 || *rs.Delay > 60) {
		return pveFerr("delay", "pve.err.delay")
	}
	if rs.DatastoreDays != nil && (*rs.DatastoreDays < 0 || *rs.DatastoreDays > 3650) {
		return pveFerr("datastore_days", "pve.err.datastore_days")
	}
	if rs.Channels != nil { // doppelte entfernen, sortieren
		ids := []int64{}
		have := map[int64]bool{}
		for _, id := range *rs.Channels {
			if id <= 0 {
				return pveFerr("channels", "pve.err.channels")
			}
			if !have[id] {
				have[id] = true
				ids = append(ids, id)
			}
		}
		if len(ids) > maxChannels {
			return pveFerr("channels", "pve.err.channels")
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		rs.Channels = &ids
	}
	return nil
}

// --- Einstellungen je Ressource ---

// Settings sind die Einstellungen einer Ebene: Key "" = System, sonst wie Resource.Key().
type Settings struct {
	SystemID      int64   `json:"system_id"`
	Key           string  `json:"key"`
	Muted         bool    `json:"muted"`                 // keine Meldungen (System: fuer alles)
	AsCheck       bool    `json:"as_check"`              // als Healthchecks-Check fuehren (Zustand kommt dann ueber den Check)
	CheckToken    string  `json:"check_token,omitempty"` // zugehoeriger Check ('' = keiner)
	ExpectRunning *bool   `json:"expect_running"`        // nil = automatisch (lief schon einmal)
	SeenRunning   bool    `json:"seen_running"`          // wurde laufend gesehen (nur lesen, setzt Record)
	Rules         RuleSet `json:"rules"`
}

// SystemSettings sind alle Einstellungen eines Systems (fuer Effective und die Regeln).
type SystemSettings struct {
	SystemID int64                `json:"system_id"`
	Name     string               `json:"name"`
	Kind     string               `json:"kind,omitempty"` // pve bzw. docker
	Items    map[string]*Settings `json:"items"`          // Key → Einstellungen; "" = Systemebene
}

// Item liefert die Einstellungen eines Keys oder nil.
func (ss *SystemSettings) Item(key string) *Settings {
	if ss == nil || ss.Items == nil {
		return nil
	}
	return ss.Items[key]
}

// Effective liefert die wirksame Regel: Standard → System → Node → Gast. key "" = System, nodeName = Node des Gasts.
func (ss *SystemSettings) Effective(key, nodeName string) Rule {
	r := DefaultRule()
	if it := ss.Item(""); it != nil {
		r = r.Apply(it.Rules)
	}
	if key == "" {
		return r
	}
	nk := "node/" + nodeName
	if nodeName != "" && nk != key {
		if it := ss.Item(nk); it != nil {
			r = r.Apply(it.Rules)
		}
	}
	if it := ss.Item(key); it != nil {
		r = r.Apply(it.Rules)
	}
	return r
}

var pveReKey = regexp.MustCompile(`^(node/[A-Za-z0-9._-]{1,64}|(qemu|lxc)/[1-9][0-9]{0,9}|docker/[A-Za-z0-9][A-Za-z0-9_.-]{0,127})$`)

// ValidKey sagt, ob key eine Ebene bezeichnet ("" = System).
func ValidKey(key string) bool { return key == "" || pveReKey.MatchString(key) }

// Settings liefert alle Einstellungen eines Systems.
func (s *Store) Settings(ctx context.Context, systemID int64) (*SystemSettings, error) {
	ss := &SystemSettings{SystemID: systemID, Items: map[string]*Settings{}}
	if err := s.r.QueryRowContext(ctx, `SELECT name, kind FROM pve_systems WHERE id = ?`, systemID).Scan(&ss.Name, &ss.Kind); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	rows, err := s.r.QueryContext(ctx, `SELECT key, muted, as_check, check_token, expect_running, seen_running, rules
		FROM pve_settings WHERE system_id = ?`, systemID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		st := &Settings{SystemID: systemID}
		var exp sql.NullBool
		var rules string
		if err := rows.Scan(&st.Key, &st.Muted, &st.AsCheck, &st.CheckToken, &exp, &st.SeenRunning, &rules); err != nil {
			return nil, err
		}
		if exp.Valid {
			v := exp.Bool
			st.ExpectRunning = &v
		}
		if rules != "" {
			_ = json.Unmarshal([]byte(rules), &st.Rules)
		}
		ss.Items[st.Key] = st
	}
	return ss, rows.Err()
}

// SaveSettings legt die Einstellungen einer Ebene an oder ersetzt sie (SeenRunning bleibt erhalten).
func (s *Store) SaveSettings(ctx context.Context, st *Settings) error {
	if !ValidKey(st.Key) {
		return pveFerr("key", "pve.err.key")
	}
	if err := st.Rules.Validate(); err != nil {
		return err
	}
	st.CheckToken = strings.TrimSpace(st.CheckToken)
	if !st.AsCheck {
		st.CheckToken = ""
	}
	if st.Key == "" { // nur Regeln und Stummschaltung auf Systemebene
		st.AsCheck, st.CheckToken, st.ExpectRunning = false, "", nil
	}
	var exists int
	if err := s.r.QueryRowContext(ctx, `SELECT count(*) FROM pve_systems WHERE id = ?`, st.SystemID).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return ErrNotFound
	}
	rules := ""
	if st.Rules != (RuleSet{}) {
		b, _ := json.Marshal(st.Rules)
		rules = string(b)
	}
	var exp any
	if st.ExpectRunning != nil {
		exp = *st.ExpectRunning
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO pve_settings (system_id, key, muted, as_check, check_token, expect_running, rules, updated_at)
		VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(system_id, key) DO UPDATE SET muted=excluded.muted, as_check=excluded.as_check,
		check_token=excluded.check_token, expect_running=excluded.expect_running, rules=excluded.rules, updated_at=excluded.updated_at`,
		st.SystemID, st.Key, st.Muted, st.AsCheck, st.CheckToken, exp, rules, store.Now())
	return err
}

// ResetSettings setzt eine Ebene auf „alles erben“ zurueck: Regeln, Stummschaltung und „erwartet laeuft“;
// „als Check“ und SeenRunning bleiben erhalten (Oberflaeche und API).
func (s *Store) ResetSettings(ctx context.Context, systemID int64, key string) error {
	if !ValidKey(key) {
		return pveFerr("key", "pve.err.key")
	}
	_, err := s.w.ExecContext(ctx, `UPDATE pve_settings SET muted=0, expect_running=NULL, rules='', updated_at=?
		WHERE system_id = ? AND key = ?`, store.Now(), systemID, key)
	return err
}
