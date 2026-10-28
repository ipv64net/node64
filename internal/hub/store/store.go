// Package store ist die MySQL-Datenhaltung des hub (Tabellen hc2_* in der
// Datenbank ipv64_hc, Accounts lesend aus ipv64.hc2_users_v).
//
// Jede hub-Instanz schreibt Messpunkte und Zustaende unter ihrer Messstelle
// (source "loc:<location>"). Der Gesamtzustand eines Checks wird aus allen
// Messstellen nach der Regel des Checks berechnet (verdict.go).
package store

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql" // Treiber

	"github.com/ipv64net/node64/internal/secrets"
)

// TimeFormat ist das Format fuer DATETIME(3) in UTC.
const TimeFormat = "2006-01-02 15:04:05.000"

// Aufbewahrung. Rohdaten braucht nur die Ansicht bis 24 h (und die Pillen), laengere Zeitraeume kommen
// aus hc2_hourly (bis 30 Tage) und hc2_daily (1 Jahr). Bei 100.000 Checks sind das sonst Milliarden Zeilen.
const (
	RawKeepDays    = 2  // hc2_measurements (Tagespartitionen)
	HourlyKeepDays = 90 // hc2_hourly
)

// Store ist die Verbindung einer Instanz zur Datenbank.
type Store struct {
	db       *sql.DB
	log      *slog.Logger
	source   string // "loc:nbg"
	location string
	node     string

	mu         sync.RWMutex
	users      map[string]int64 // token -> userid (fuer Events, Wartung)
	intervl    map[string]int   // token -> interval_sec (Frische im Verdict)
	states     map[string]string
	maint      []Maintenance
	nodeOnline map[string]onlineState
	box        *secrets.Box // Kanal-Geheimnisse (Server-Schluessel), nil = nicht konfiguriert
	owners     tokenOwners  // token -> userid fuer eingehende Messpunkte (sync.go)

	meas   chan measurementRow
	ingest chan ingestJob // Messpunkte der Nodes (ingest.go)
	stopCh chan struct{}
	wg     sync.WaitGroup

	Metrics *Metrics
	// OnOverall wird nach jedem benachrichtigungswuerdigen Wechsel des Gesamtzustands gerufen.
	OnOverall func(OverallEvent)
	// OnUsageFlip: Tageskontingent eines Accounts erschoepft (true) bzw. wieder frei (false), usage.go.
	OnUsageFlip func(userID int64, blocked bool)
	// OnQuotaReached: Tageskontingent erreicht (zur Benachrichtigung, checker.go)
	OnQuotaReached func(userID int64, today, limit int)

	use usage
}

// Open verbindet sich und prueft die Verbindung.
func Open(dsn, location, node string, log *slog.Logger) (*Store, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	// Verbindungen offen halten: ein kleiner Leerlauf-Vorrat fuehrte unter Last zu tausenden
	// Verbindungsaufbauten pro Minute (Anmeldung am DB-Server, TIME_WAIT-Ports)
	db.SetMaxOpenConns(40)
	db.SetMaxIdleConns(40)
	db.SetConnMaxLifetime(30 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("mysql: %w", err)
	}
	s := &Store{db: db, log: log.With("module", "store"), source: "loc:" + location, location: location, node: node,
		users: map[string]int64{}, intervl: map[string]int{}, states: map[string]string{},
		meas: make(chan measurementRow, 10000), stopCh: make(chan struct{}), Metrics: NewMetrics()}
	s.wg.Add(1)
	go s.measurementWriter()
	s.startIngestWriter()
	return s, nil
}

// Close leert den Schreibpuffer und schliesst die Verbindung.
func (s *Store) Close() error {
	close(s.stopCh)
	s.wg.Wait()
	return s.db.Close()
}

// SetBox setzt den Schluessel fuer Kanal-Geheimnisse (Node-Kanaele im Sync).
func (s *Store) SetBox(b *secrets.Box) { s.box = b }

// Source ist die Messstelle dieser Instanz.
func (s *Store) Source() string { return s.source }

// DB gibt die rohe Verbindung frei (Housekeeping, Tests).
func (s *Store) DB() *sql.DB { return s.db }

func ft(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(TimeFormat)
}

func pt(v sql.NullString) time.Time {
	if !v.Valid || v.String == "" {
		return time.Time{}
	}
	for _, f := range []string{TimeFormat, "2006-01-02 15:04:05", time.RFC3339Nano} {
		if t, err := time.ParseInLocation(f, v.String, time.UTC); err == nil {
			return t
		}
	}
	return time.Time{}
}

func nowStr() string { return time.Now().UTC().Format(TimeFormat) }

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (s *Store) userOf(token string) int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.users[token]
}

// ---------------------------------------------------------------- Metriken

// Metrics sind einfache Zaehler fuer /metrics.
type Metrics struct {
	mu                sync.Mutex
	Measurements      int64
	MeasurementErrors int64
	DBErrors          int64
	Verdicts          int64
	OverallChanges    int64
	Checks            int
	Nodes             int
	SlotIndex, Slots  int
}

func NewMetrics() *Metrics { return &Metrics{} }

// DBErrorCount liefert die Zahl der Datenbankfehler seit dem Start.
func (m *Metrics) DBErrorCount() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.DBErrors
}

func (m *Metrics) add(field *int64, n int64) {
	m.mu.Lock()
	*field += n
	m.mu.Unlock()
}

// Snapshot liefert eine Kopie.
func (m *Metrics) Snapshot() Metrics {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Metrics{Measurements: m.Measurements, MeasurementErrors: m.MeasurementErrors, DBErrors: m.DBErrors, Verdicts: m.Verdicts,
		OverallChanges: m.OverallChanges, Checks: m.Checks, Nodes: m.Nodes, SlotIndex: m.SlotIndex, Slots: m.Slots}
}

// Set setzt die Gauge-Werte.
func (m *Metrics) Set(checks, nodes, slotIndex, slots int) {
	m.mu.Lock()
	m.Checks, m.Nodes, m.SlotIndex, m.Slots = checks, nodes, slotIndex, slots
	m.mu.Unlock()
}
