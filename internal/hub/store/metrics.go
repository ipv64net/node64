package store

import (
	"database/sql"
	"time"
)

// Prometheus-Werte je Check-Typ und zur Datenbank (docs/HUB-PROMETHEUS.md). Labels nur mit wenigen festen Werten
// (Typ, Ergebnis, Art des Schreibens), nie je Check, Nutzer oder Ziel.

// TypeRuns sind die Laeufe eines Check-Typs auf diesem hub seit dem Start.
type TypeRuns struct {
	OK, Fail int64
	Seconds  float64 // Summe der Laufzeiten
}

// DBWrite sind die Schreibvorgaenge einer Art seit dem Start.
type DBWrite struct {
	Count   int64
	Seconds float64 // Summe der Dauer
}

// Detail ist die Kopie fuer /metrics.
type Detail struct {
	Checks             map[string]int // geladene Checks je Typ
	Runs               map[string]TypeRuns
	PingSent, PingLost int64
	Writes             map[string]DBWrite
	CleanupAt          time.Time // letzte fehlerfreie taegliche Aufraeumrunde (nur der Housekeeper)
	Pool               *sql.DBStats
	Buffer, BufferCap  int // Schreibpuffer der eigenen Messungen
}

type metricsExtra struct {
	types     map[string]int
	runs      map[string]*TypeRuns
	pingSent  int64
	pingLost  int64
	writes    map[string]*DBWrite
	cleanupAt time.Time
	pool      func() sql.DBStats
	buffer    func() (int, int)
}

// SetTypes setzt die Anzahl geladener Checks je Typ.
func (m *Metrics) SetTypes(counts map[string]int) {
	m.mu.Lock()
	m.x.types = counts
	m.mu.Unlock()
}

// ObserveRun zaehlt einen Lauf; sent/lost nur bei Ping (Pakete, v4 und v6 zusammen).
func (m *Metrics) ObserveRun(typ string, ok bool, took time.Duration, sent, lost int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.x.runs == nil {
		m.x.runs = map[string]*TypeRuns{}
	}
	r := m.x.runs[typ]
	if r == nil {
		r = &TypeRuns{}
		m.x.runs[typ] = r
	}
	if ok {
		r.OK++
	} else {
		r.Fail++
	}
	r.Seconds += took.Seconds()
	m.x.pingSent += sent
	m.x.pingLost += lost
}

// observeWrite zaehlt einen Schreibvorgang der Art op mit seiner Dauer.
func (m *Metrics) observeWrite(op string, start time.Time) {
	d := time.Since(start).Seconds()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.x.writes == nil {
		m.x.writes = map[string]*DBWrite{}
	}
	w := m.x.writes[op]
	if w == nil {
		w = &DBWrite{}
		m.x.writes[op] = w
	}
	w.Count++
	w.Seconds += d
}

func (m *Metrics) cleanupDone(t time.Time) {
	m.mu.Lock()
	m.x.cleanupAt = t
	m.mu.Unlock()
}

// Detail liefert eine Kopie der Werte je Typ und zur Datenbank.
func (m *Metrics) Detail() Detail {
	m.mu.Lock()
	d := Detail{Checks: map[string]int{}, Runs: map[string]TypeRuns{}, Writes: map[string]DBWrite{}, PingSent: m.x.pingSent, PingLost: m.x.pingLost,
		CleanupAt: m.x.cleanupAt}
	for k, v := range m.x.types {
		d.Checks[k] = v
	}
	for k, v := range m.x.runs {
		d.Runs[k] = *v
	}
	for k, v := range m.x.writes {
		d.Writes[k] = *v
	}
	pool, buffer := m.x.pool, m.x.buffer
	m.mu.Unlock()
	if pool != nil {
		st := pool()
		d.Pool = &st
	}
	if buffer != nil {
		d.Buffer, d.BufferCap = buffer()
	}
	return d
}
