package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/scheduler"
)

// Flags in hc2_measurements.flags und hc2_events.flags
const (
	FlagMaintenance = 1
	FlagDependent   = 2
	FlagSilent      = 2 // bei Events
)

func fmtSscan(s string, v *int64) (int, error) { return fmt.Sscan(s, v) }

// ---------------------------------------------------------------- scheduler.Store

type measurementRow struct {
	token, reason, message, family, details string
	status                                  int
	latency                                 float64
	time                                    time.Time
	flags                                   int
}

// SaveMeasurement puffert den Messpunkt; der Writer schreibt gebuendelt.
// Heartbeats, die ueber die Datenbank hereinkamen (details.via = "db"), sind
// dort schon gespeichert und werden nicht doppelt abgelegt.
func (s *Store) SaveMeasurement(_ context.Context, m scheduler.Measurement) error {
	if via, ok := m.Details["via"]; ok && via == "db" {
		return nil
	}
	details := ""
	if len(m.Details) > 0 {
		if b, err := json.Marshal(m.Details); err == nil {
			details = string(b)
		}
	}
	flags := 0
	if m.Maintenance {
		flags |= FlagMaintenance
	}
	if m.Dependent {
		flags |= FlagDependent
	}
	row := measurementRow{token: m.Token, time: m.Time, status: b2i(m.Status == checks.Up), latency: msf(m.Latency),
		reason: string(m.Reason), message: truncate(m.Message, 500), family: m.Family, details: details, flags: flags}
	select {
	case s.meas <- row:
	default:
		s.Metrics.add(&s.Metrics.MeasurementErrors, 1)
		return fmt.Errorf("measurement buffer full")
	}
	return nil
}

func (s *Store) measurementWriter() {
	defer s.wg.Done()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	batch := make([]measurementRow, 0, 500)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := s.insertMeasurements(batch); err != nil {
			s.log.Error("measurements insert failed", "rows", len(batch), "err", err)
			s.Metrics.add(&s.Metrics.MeasurementErrors, int64(len(batch)))
			s.Metrics.add(&s.Metrics.DBErrors, 1)
		} else {
			s.Metrics.add(&s.Metrics.Measurements, int64(len(batch)))
		}
		batch = batch[:0]
	}
	for {
		select {
		case r := <-s.meas:
			batch = append(batch, r)
			if len(batch) >= 500 {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-s.stopCh:
			for {
				select {
				case r := <-s.meas:
					batch = append(batch, r)
				default:
					flush()
					return
				}
			}
		}
	}
}

func (s *Store) insertMeasurements(rows []measurementRow) error {
	var sb strings.Builder
	sb.WriteString(`INSERT IGNORE INTO hc2_measurements (token, source, node_seq, time, status, latency_ms, reason, message, family, details, flags, received_at) VALUES `)
	args := make([]any, 0, len(rows)*12)
	now := nowStr()
	for i, r := range rows {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("(?,?,0,?,?,?,?,?,?,?,?,?)")
		var details any
		if r.details != "" {
			details = r.details
		}
		args = append(args, r.token, s.source, r.time.UTC().Format(TimeFormat), r.status, r.latency, r.reason, r.message, r.family, details, r.flags, now)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := s.db.ExecContext(ctx, sb.String(), args...)
	return err
}

// SaveRuntime schreibt den Zustand dieser Messstelle und stoesst bei einem
// Zustandswechsel die Neubewertung des Gesamtzustands an.
func (s *Store) SaveRuntime(ctx context.Context, token string, rt scheduler.Runtime) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO hc2_check_states (token, source, state, since, last_check_at, next_check_at, last_status, last_latency_ms,
			last_reason, last_message, consecutive_fail, consecutive_ok, down_since, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON DUPLICATE KEY UPDATE state=VALUES(state), since=VALUES(since), last_check_at=VALUES(last_check_at), next_check_at=VALUES(next_check_at),
			last_status=VALUES(last_status), last_latency_ms=VALUES(last_latency_ms), last_reason=VALUES(last_reason), last_message=VALUES(last_message),
			consecutive_fail=VALUES(consecutive_fail), consecutive_ok=VALUES(consecutive_ok), down_since=VALUES(down_since), updated_at=VALUES(updated_at)`,
		token, s.source, string(rt.State), ft(rt.Since), ft(rt.LastCheck), ft(rt.NextCheck), nullStr(string(rt.LastStatus)), msf(rt.LastLatency),
		nullStr(string(rt.LastReason)), truncate(rt.LastMessage, 500), rt.ConsecutiveFail, rt.ConsecutiveOK, ft(rt.DownSince), nowStr())
	if err != nil {
		s.Metrics.add(&s.Metrics.DBErrors, 1)
		return err
	}
	s.mu.Lock()
	prev, seen := s.states[token]
	s.states[token] = string(rt.State)
	s.mu.Unlock()
	if !seen || prev != string(rt.State) || s.overallPending(ctx, token) {
		if err := s.Reverdict(ctx, token); err != nil {
			s.log.Error("verdict failed", "token", token, "err", err)
		}
	}
	return nil
}

// overallPending: der Gesamtzustand steht auf "pending", z. B. nachdem die Standorte wegen des Tageskontingents nicht
// gemessen haben. Dann bewertet schon eine Messung ohne Zustandswechsel neu; sonst bliebe ein Online-Check nach
// Mitternacht auf "Wartet", bis sich an einem Standort der Zustand aendert.
func (s *Store) overallPending(ctx context.Context, token string) bool {
	var st string
	err := s.db.QueryRowContext(ctx, `SELECT state FROM hc2_checks WHERE token = ? AND deleted_at IS NULL`, token).Scan(&st)
	return err == nil && st == string(scheduler.StatePending)
}

// OpenIncident/CloseIncident je Messstelle: Stoerungen gibt es nur fuer den
// Gesamtzustand (verdict.go), daher hier bewusst nichts.
func (s *Store) OpenIncident(context.Context, string, time.Time, checks.Reason, string) (int64, error) {
	return 0, nil
}
func (s *Store) CloseIncident(context.Context, int64, time.Time) error { return nil }

// SaveEvent speichert den Statuswechsel dieser Messstelle (immer still; Alarme
// entstehen nur aus dem Gesamtzustand).
func (s *Store) SaveEvent(ctx context.Context, e scheduler.Event) error {
	flags := FlagSilent
	if e.Maintenance {
		flags |= FlagMaintenance
	}
	_, err := s.db.ExecContext(ctx, `INSERT IGNORE INTO hc2_events (event_id, token, userid, source, kind, time, from_state, to_state, reason, message, duration_sec, flaps, flags, incident_id)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)`,
		e.ID, e.Token, s.userOf(e.Token), s.source, string(e.Kind), ft(e.Time), string(e.From), string(e.To), nullStr(string(e.Reason)), truncate(e.Message, 500),
		int64(e.Duration.Seconds()), e.Flaps, flags)
	if err != nil {
		s.Metrics.add(&s.Metrics.DBErrors, 1)
	}
	return err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func msf(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
