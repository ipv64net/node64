package proxmox

import (
	"context"
	"database/sql"
	"maps"
	"math"
	"strconv"
	"time"

	"github.com/ipv64net/node64/internal/store"
)

// Verlauf (nur lokal): je Node und Gast 1-Minuten-Werte fuer 48 h, 5-Minuten-Werte so lange wie hc.raw_days und
// Stundenwerte so lange wie hc.hourly_days (0 = unbegrenzt). Die Tage setzt die Einbindung mit SetRetention.
// Werte als Ganzzahlen: Anteile in 1/10000 (CPU bezogen auf MaxCPU, RAM und Disk bezogen auf das Maximum), Raten in
// Byte/s. Mehrere Abfragen je Intervall werden gemittelt (CPU zusaetzlich als Maximum).

const (
	Step1m            = time.Minute
	Step5m            = 5 * time.Minute
	Step1h            = time.Hour
	Retention1m       = 48 * time.Hour
	DefaultRawDays    = 30
	DefaultHourlyDays = 365
)

// Point ist ein Wert im Verlauf. CPU, Mem und Disk in Prozent, Raten in Byte/s.
type Point struct {
	T         time.Time `json:"t"` // Beginn des Intervalls
	CPU       float64   `json:"cpu"`
	CPUMax    float64   `json:"cpu_max"`
	Mem       float64   `json:"mem"`
	Disk      *float64  `json:"disk"` // nil = unbekannt (QEMU ohne Gast-Agent)
	NetIn     float64   `json:"net_in"`
	NetOut    float64   `json:"net_out"`
	DiskRead  float64   `json:"disk_read"`
	DiskWrite float64   `json:"disk_write"`
}

// SetRetention setzt die Aufbewahrung: rawDays fuer 5-Minuten-Werte (mindestens 2), hourlyDays fuer Stundenwerte
// (0 = unbegrenzt). Ungueltige Werte ergeben den Standard (30 bzw. 365).
func (s *Store) SetRetention(rawDays, hourlyDays int) {
	if rawDays < 2 {
		rawDays = DefaultRawDays
	}
	if hourlyDays < 0 {
		hourlyDays = DefaultHourlyDays
	}
	s.mu.Lock()
	s.rawDays, s.hourlyDays = rawDays, hourlyDays
	s.mu.Unlock()
}

// pveGuestRan sagt, ob ein Gast von sich aus laeuft (laeuft, angehalten, abgestuerzt) – dann gilt er als „lief schon
// einmal“ (ExpectRunning automatisch). Mit Lock bzw. direkt nach einem Lock nicht: Proxmox startet einen gestoppten
// Gast fuers Backup kurz (lock=backup), danach waere er sonst „gestoppt, obwohl erwartet“.
func pveGuestRan(r *Resource) bool {
	if r.Type == TypeDocker { // beendet mit Fehler ist kein Lauf (alte Container wuerden sonst sofort erwartet)
		return r.Status == "running" || r.Status == "paused" || r.Status == "restarting"
	}
	if r.AfterLock {
		return false
	}
	switch r.State {
	case StateRunning, StatePaused, StateSuspended, StateError:
		return true
	}
	return false
}

// pveRecordable: Templates nie, Nodes nur online, Gaeste nur gestartet (gestoppte haben keine Werte).
func pveRecordable(r *Resource) bool {
	if r.Template {
		return false
	}
	if r.Type == TypeNode {
		return r.State == StateOnline
	}
	if r.Type == TypeDocker {
		return r.Status == "running" // Werte (stats) nur von laufenden Containern
	}
	switch r.State {
	case StateRunning, StatePaused, StateSuspended, StateError:
		return true
	case StateBackup, StateLocked: // Lock auch bei gestoppten Gaesten (Backup im Stopp-Modus, Offline-Migration)
		return r.Status != "stopped"
	}
	return false
}

func pveRatio(v, max int64) int64 {
	if max <= 0 {
		return 0
	}
	return pveClamp(float64(v) * 10000 / float64(max))
}

func pveClamp(f float64) int64 {
	if math.IsNaN(f) || f < 0 {
		return 0
	}
	if f > 10000 {
		return 10000
	}
	return int64(math.Round(f))
}

func pveRateInt(f float64) int64 {
	if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
		return 0
	}
	return int64(math.Round(f))
}

const pveUpsert1m = `INSERT INTO pve_hist_1m (system_id, key, t, n, cpu, cpu_max, mem, disk, net_in, net_out, disk_read, disk_write)
	VALUES (?,?,?,1,?,?,?,?,?,?,?,?) ON CONFLICT(system_id, key, t) DO UPDATE SET n = n + 1,
	cpu = CAST(round((cpu * n + excluded.cpu) * 1.0 / (n + 1)) AS INTEGER),
	cpu_max = max(cpu_max, excluded.cpu_max),
	mem = CAST(round((mem * n + excluded.mem) * 1.0 / (n + 1)) AS INTEGER),
	disk = CASE WHEN excluded.disk IS NULL THEN disk WHEN disk IS NULL THEN excluded.disk
		ELSE CAST(round((disk * n + excluded.disk) * 1.0 / (n + 1)) AS INTEGER) END,
	net_in = CAST(round((net_in * n + excluded.net_in) * 1.0 / (n + 1)) AS INTEGER),
	net_out = CAST(round((net_out * n + excluded.net_out) * 1.0 / (n + 1)) AS INTEGER),
	disk_read = CAST(round((disk_read * n + excluded.disk_read) * 1.0 / (n + 1)) AS INTEGER),
	disk_write = CAST(round((disk_write * n + excluded.disk_write) * 1.0 / (n + 1)) AS INTEGER)`

// Record speichert einen Snapshot im Verlauf (eine Transaktion je Snapshot), merkt sich laufend gesehene Gaeste
// (ExpectRunning automatisch) und verdichtet bzw. raeumt auf, wenn ein Intervall abgeschlossen ist. Nicht
// erreichbare Systeme (snap.OK = false) schreiben nichts.
func (s *Store) Record(ctx context.Context, snap *Snapshot) error {
	if snap == nil || !snap.OK {
		return nil
	}
	now := snap.Time
	if now.IsZero() {
		now = s.now()
	}
	seen, err := s.seenRunning(ctx, snap.SystemID)
	if err != nil {
		return err
	}
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	ins, err := tx.PrepareContext(ctx, pveUpsert1m)
	if err != nil {
		return err
	}
	defer ins.Close()
	bucket := now.Unix() / 60 * 60
	var newSeen []string
	for i := range snap.Resources {
		r := &snap.Resources[i]
		if !pveRecordable(r) {
			continue
		}
		key := r.Key()
		var disk any
		if _, ok := r.DiskPercent(); ok {
			disk = pveRatio(r.Disk, r.MaxDisk)
		}
		cpu := pveClamp(r.CPU * 10000)
		if _, err := ins.ExecContext(ctx, snap.SystemID, key, bucket, cpu, cpu, pveRatio(r.Mem, r.MaxMem), disk,
			pveRateInt(r.NetIn), pveRateInt(r.NetOut), pveRateInt(r.DiskRead), pveRateInt(r.DiskWrite)); err != nil {
			return err
		}
		if r.Type != TypeNode && !seen[key] && pveGuestRan(r) {
			if _, err := tx.ExecContext(ctx, `INSERT INTO pve_settings (system_id, key, seen_running, updated_at) VALUES (?,?,1,?)
				ON CONFLICT(system_id, key) DO UPDATE SET seen_running = 1`, snap.SystemID, key, store.Now()); err != nil {
				return err
			}
			newSeen = append(newSeen, key)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if len(newSeen) > 0 {
		s.mu.Lock()
		if m := s.seen[snap.SystemID]; m != nil {
			for _, k := range newSeen {
				m[k] = true
			}
		}
		s.mu.Unlock()
	}
	return s.maintain(ctx, now)
}

// seenRunning liefert (zwischengespeichert) die Gaeste eines Systems, die schon laufend gesehen wurden.
func (s *Store) seenRunning(ctx context.Context, systemID int64) (map[string]bool, error) {
	s.mu.Lock()
	m := s.seen[systemID]
	s.mu.Unlock()
	if m != nil {
		return maps.Clone(m), nil
	}
	rows, err := s.r.QueryContext(ctx, `SELECT key FROM pve_settings WHERE system_id = ? AND seen_running = 1`, systemID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m = map[string]bool{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		m[k] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.seen[systemID] == nil {
		s.seen[systemID] = m
	}
	m = s.seen[systemID]
	s.mu.Unlock()
	return maps.Clone(m), nil
}

// pveCompactSQL fasst src in Intervalle von step Sekunden in dst zusammen (gewichtet mit n). Bereits vorhandene
// Intervalle werden ersetzt, damit ein erneuter Lauf (z. B. nach spaeten Werten) dasselbe Ergebnis liefert.
func pveCompactSQL(src, dst string, step int64) string {
	return `INSERT INTO ` + dst + ` (system_id, key, t, n, cpu, cpu_max, mem, disk, net_in, net_out, disk_read, disk_write)
	SELECT system_id, key, ` + pveAggCols(step, true) + `
	FROM ` + src + ` WHERE t >= ? AND t < ? GROUP BY system_id, key, b
	ON CONFLICT(system_id, key, t) DO UPDATE SET n = excluded.n, cpu = excluded.cpu, cpu_max = excluded.cpu_max,
		mem = excluded.mem, disk = excluded.disk, net_in = excluded.net_in, net_out = excluded.net_out,
		disk_read = excluded.disk_read, disk_write = excluded.disk_write`
}

// pveAggCols sind die Spalten eines Intervalls von step Sekunden (b = Beginn, gewichtet mit n gemittelt, CPU auch
// als Maximum, Disk nur ueber Werte ungleich NULL) – gemeinsam fuer Verdichtung und Series. withN: mit sum(n).
func pveAggCols(step int64, withN bool) string {
	st := strconv.FormatInt(step, 10)
	avg := func(c string) string { return "CAST(round(sum(" + c + " * n) * 1.0 / sum(n)) AS INTEGER)" }
	n := ""
	if withN {
		n = "sum(n), "
	}
	return `(t / ` + st + `) * ` + st + ` AS b, ` + n + avg("cpu") + `, max(cpu_max), ` + avg("mem") + `,
		CAST(round(sum(disk * n) * 1.0 / sum(CASE WHEN disk IS NULL THEN 0 ELSE n END)) AS INTEGER),
		` + avg("net_in") + `, ` + avg("net_out") + `, ` + avg("disk_read") + `, ` + avg("disk_write")
}

// maintain verdichtet abgeschlossene Intervalle (1 min → 5 min → 1 h) und raeumt alle 15 Minuten auf.
func (s *Store) maintain(ctx context.Context, now time.Time) error {
	if err := s.compact(ctx, "pve_hist_1m", "pve_hist_5m", int64(Step5m/time.Second), now); err != nil {
		return err
	}
	if err := s.compact(ctx, "pve_hist_5m", "pve_hist_1h", int64(Step1h/time.Second), now); err != nil {
		return err
	}
	s.mu.Lock()
	due := now.Unix()-s.lastPrune >= 15*60
	if due {
		s.lastPrune = now.Unix()
	}
	rawDays, hourlyDays := s.rawDays, s.hourlyDays
	s.mu.Unlock()
	if !due {
		return nil
	}
	return s.prune(ctx, now, rawDays, hourlyDays)
}

// compact verdichtet alle abgeschlossenen Intervalle seit dem letzten Lauf; das letzte Intervall des vorigen Laufs
// wird noch einmal gerechnet (Werte anderer Systeme koennen leicht verspaetet kommen).
func (s *Store) compact(ctx context.Context, src, dst string, step int64, now time.Time) error {
	to := now.Unix() / step * step
	s.mu.Lock()
	last := s.compacted[dst]
	s.mu.Unlock()
	if last != 0 && to <= last {
		return nil
	}
	from := last - step
	if last == 0 { // erster Lauf: ab dem letzten vorhandenen Intervall bzw. so weit die Quelle reicht
		var max sql.NullInt64
		if err := s.r.QueryRowContext(ctx, `SELECT max(t) FROM `+dst).Scan(&max); err != nil {
			return err
		}
		if max.Valid {
			from = max.Int64
		} else {
			from = 0
		}
	}
	if _, err := s.w.ExecContext(ctx, pveCompactSQL(src, dst, step), from, to); err != nil {
		return err
	}
	s.mu.Lock()
	s.compacted[dst] = to
	s.mu.Unlock()
	return nil
}

// prune loescht abgelaufene Werte.
func (s *Store) prune(ctx context.Context, now time.Time, rawDays, hourlyDays int) error {
	day := int64(24 * 3600)
	if _, err := s.w.ExecContext(ctx, `DELETE FROM pve_hist_1m WHERE t < ?`, now.Add(-Retention1m).Unix()); err != nil {
		return err
	}
	if _, err := s.w.ExecContext(ctx, `DELETE FROM pve_hist_5m WHERE t < ?`, now.Unix()-int64(rawDays)*day); err != nil {
		return err
	}
	if hourlyDays > 0 {
		if _, err := s.w.ExecContext(ctx, `DELETE FROM pve_hist_1h WHERE t < ?`, now.Unix()-int64(hourlyDays)*day); err != nil {
			return err
		}
	}
	return nil
}

// Resolution liefert die Aufloesung fuer einen Zeitraum ab from: bis 48 h zurueck 1 min, bis raw_days 5 min,
// sonst 1 h.
func (s *Store) Resolution(from time.Time) time.Duration {
	now := s.now()
	s.mu.Lock()
	rawDays := s.rawDays
	s.mu.Unlock()
	switch {
	case !from.Before(now.Add(-Retention1m)):
		return Step1m
	case !from.Before(now.Add(-time.Duration(rawDays) * 24 * time.Hour)):
		return Step5m
	}
	return Step1h
}

// Series liefert den Verlauf einer Ressource (key wie Resource.Key()) in der passenden Aufloesung (Resolution),
// zeitlich aufsteigend. Intervalle ohne Werte (gestoppt, nicht erreichbar) fehlen. Bei 5-Minuten- und Stundenwerten
// wird das noch nicht verdichtete Ende (laufendes Intervall) aus den 1-Minuten-Werten angehaengt, damit der Graph
// bis jetzt reicht.
func (s *Store) Series(ctx context.Context, systemID int64, key string, from, to time.Time) ([]Point, error) {
	table, step := "pve_hist_1h", int64(Step1h/time.Second)
	switch s.Resolution(from) {
	case Step1m:
		table, step = "pve_hist_1m", 0
	case Step5m:
		table, step = "pve_hist_5m", int64(Step5m/time.Second)
	}
	out, err := s.seriesQuery(ctx, `SELECT t, cpu, cpu_max, mem, disk, net_in, net_out, disk_read, disk_write FROM `+table+`
		WHERE system_id = ? AND key = ? AND t >= ? AND t <= ? ORDER BY t`, systemID, key, from.Unix(), to.Unix())
	if err != nil || step == 0 {
		return out, err
	}
	// Ende aus den 1-Minuten-Werten, je Intervall gewichtet gemittelt wie bei der Verdichtung
	tail := from.Unix() / step * step
	if n := len(out); n > 0 {
		tail = out[n-1].T.Unix() + step
	}
	if tail > to.Unix() {
		return out, nil
	}
	more, err := s.seriesQuery(ctx, `SELECT `+pveAggCols(step, false)+`
		FROM pve_hist_1m WHERE system_id = ? AND key = ? AND t >= ? AND t <= ? GROUP BY b ORDER BY b`, systemID, key, tail, to.Unix())
	if err != nil {
		return nil, err
	}
	return append(out, more...), nil
}

func (s *Store) seriesQuery(ctx context.Context, q string, args ...any) ([]Point, error) {
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Point
	for rows.Next() {
		var t, cpu, cpuMax, mem, nin, nout, dr, dw int64
		var disk sql.NullInt64
		if err := rows.Scan(&t, &cpu, &cpuMax, &mem, &disk, &nin, &nout, &dr, &dw); err != nil {
			return nil, err
		}
		p := Point{T: time.Unix(t, 0).UTC(), CPU: float64(cpu) / 100, CPUMax: float64(cpuMax) / 100, Mem: float64(mem) / 100,
			NetIn: float64(nin), NetOut: float64(nout), DiskRead: float64(dr), DiskWrite: float64(dw)}
		if disk.Valid {
			d := float64(disk.Int64) / 100
			p.Disk = &d
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
