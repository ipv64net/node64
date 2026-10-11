package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// AggregateHourly verdichtet die Messpunkte dieser Messstelle der letzten
// Stunden (laufende und zwei davor) in hc2_hourly. Idempotent.
func (s *Store) AggregateHourly(ctx context.Context, now time.Time) error {
	from := now.UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	to := now.UTC().Truncate(time.Hour).Add(time.Hour)
	_, err := s.db.ExecContext(ctx, `INSERT INTO hc2_hourly (token, source, hour, count, up_count, min_ms, avg_ms, max_ms)
		SELECT token, source, DATE_FORMAT(time, '%Y-%m-%d %H:00:00'), COUNT(*), SUM(status = 1), MIN(NULLIF(latency_ms, 0)), AVG(NULLIF(latency_ms, 0)), MAX(latency_ms)
		FROM hc2_measurements WHERE source = ? AND time >= ? AND time < ? GROUP BY token, source, DATE_FORMAT(time, '%Y-%m-%d %H:00:00')
		ON DUPLICATE KEY UPDATE count = VALUES(count), up_count = VALUES(up_count), min_ms = VALUES(min_ms), avg_ms = VALUES(avg_ms), max_ms = VALUES(max_ms)`,
		s.source, from.Format(TimeFormat), to.Format(TimeFormat))
	if err != nil {
		s.Metrics.add(&s.Metrics.DBErrors, 1)
	}
	return err
}

// AggregateHourlyShared verdichtet Messstellen ohne festen Standort (Nodes, Push) der laufenden
// und der vorigen Stunde. Nur der Housekeeper ruft es (sonst doppelte Arbeit).
func (s *Store) AggregateHourlyShared(ctx context.Context, now time.Time) error {
	from := now.UTC().Truncate(time.Hour).Add(-time.Hour)
	to := now.UTC().Truncate(time.Hour).Add(time.Hour)
	_, err := s.db.ExecContext(ctx, `INSERT INTO hc2_hourly (token, source, hour, count, up_count, min_ms, avg_ms, max_ms)
		SELECT token, source, DATE_FORMAT(time, '%Y-%m-%d %H:00:00'), COUNT(*), SUM(status = 1), MIN(NULLIF(latency_ms, 0)), AVG(NULLIF(latency_ms, 0)), MAX(latency_ms)
		FROM hc2_measurements WHERE time >= ? AND time < ? AND (source LIKE 'node:%' OR source = 'push') GROUP BY token, source, DATE_FORMAT(time, '%Y-%m-%d %H:00:00')
		ON DUPLICATE KEY UPDATE count = VALUES(count), up_count = VALUES(up_count), min_ms = VALUES(min_ms), avg_ms = VALUES(avg_ms), max_ms = VALUES(max_ms)`,
		from.Format(TimeFormat), to.Format(TimeFormat))
	if err != nil {
		s.Metrics.add(&s.Metrics.DBErrors, 1)
	}
	return err
}

// AggregateDaily rechnet Tageswerte fuer alle Messstellen aus hc2_hourly
// (gestern und heute). Idempotent; nur der Housekeeper ruft es.
func (s *Store) AggregateDaily(ctx context.Context, now time.Time) error {
	day := now.UTC().Truncate(24 * time.Hour)
	from := day.AddDate(0, 0, -1)
	_, err := s.db.ExecContext(ctx, `INSERT INTO hc2_daily (token, source, day, count, up_count, min_ms, avg_ms, max_ms)
		SELECT token, source, DATE(hour), SUM(count), SUM(up_count), MIN(min_ms), SUM(avg_ms * count) / NULLIF(SUM(count), 0), MAX(max_ms)
		FROM hc2_hourly WHERE hour >= ? GROUP BY token, source, DATE(hour)
		ON DUPLICATE KEY UPDATE count = VALUES(count), up_count = VALUES(up_count), min_ms = VALUES(min_ms), avg_ms = VALUES(avg_ms), max_ms = VALUES(max_ms)`,
		from.Format("2006-01-02 15:04:05"))
	if err != nil {
		s.Metrics.add(&s.Metrics.DBErrors, 1)
	}
	return err
}

// RotatePartitions legt Tagespartitionen fuer heute bis uebermorgen an und
// loescht Partitionen, die aelter als keepDays sind. Nur der Housekeeper.
func (s *Store) RotatePartitions(ctx context.Context, now time.Time, keepDays int) error {
	rows, err := s.db.QueryContext(ctx, `SELECT partition_name FROM information_schema.partitions WHERE table_schema = DATABASE() AND table_name = 'hc2_measurements' AND partition_name IS NOT NULL ORDER BY partition_ordinal_position`)
	if err != nil {
		return err
	}
	existing := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		existing[n] = true
	}
	rows.Close()
	if !existing["pMAX"] {
		return fmt.Errorf("partition pMAX missing, table not partitioned as expected")
	}
	day := now.UTC().Truncate(24 * time.Hour)
	// anlegen: heute, morgen, uebermorgen
	for i := 0; i <= 2; i++ {
		d := day.AddDate(0, 0, i)
		name := "p" + d.Format("20060102")
		if existing[name] {
			continue
		}
		next := d.AddDate(0, 0, 1).Format("2006-01-02")
		stmt := fmt.Sprintf("ALTER TABLE hc2_measurements REORGANIZE PARTITION pMAX INTO (PARTITION %s VALUES LESS THAN (TO_DAYS('%s')), PARTITION pMAX VALUES LESS THAN MAXVALUE)", name, next)
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("add partition %s: %w", name, err)
		}
		s.log.Info("partition added", "name", name)
		existing[name] = true
	}
	// loeschen: aelter als keepDays
	cut := day.AddDate(0, 0, -keepDays)
	var drop []string
	for n := range existing {
		if !strings.HasPrefix(n, "p") || n == "pMAX" || len(n) != 9 {
			continue
		}
		d, err := time.Parse("20060102", n[1:])
		if err == nil && d.Before(cut) {
			drop = append(drop, n)
		}
	}
	if len(drop) > 0 {
		if _, err := s.db.ExecContext(ctx, "ALTER TABLE hc2_measurements DROP PARTITION "+strings.Join(drop, ", ")); err != nil {
			return fmt.Errorf("drop partitions: %w", err)
		}
		s.log.Info("partitions dropped", "names", drop)
	}
	return nil
}

// Cleanup raeumt Log, erledigte Auftraege, abgelaufene Codes und alte Tombstones auf.
func (s *Store) Cleanup(ctx context.Context, now time.Time) {
	exec := func(q string, args ...any) {
		if _, err := s.db.ExecContext(ctx, q, args...); err != nil {
			s.log.Warn("cleanup failed", "sql", q[:40], "err", err)
			s.Metrics.add(&s.Metrics.DBErrors, 1)
		}
	}
	exec(`DELETE FROM hc2_config_log WHERE time < ?`, now.UTC().AddDate(0, 0, -30).Format(TimeFormat))
	exec(`DELETE FROM hc2_send_orders WHERE (done_at IS NOT NULL AND done_at < ?) OR created_at < ?`, now.UTC().Add(-time.Hour).Format(TimeFormat), now.UTC().AddDate(0, 0, -7).Format(TimeFormat))
	exec(`DELETE FROM hc2_commands WHERE created_at < ?`, now.UTC().AddDate(0, 0, -1).Format(TimeFormat))
	exec(`DELETE FROM hc2_link_codes WHERE expires_at < ?`, now.UTC().AddDate(0, 0, -1).Format(TimeFormat))
	exec(`DELETE FROM hc2_testruns WHERE created_at < ?`, now.UTC().AddDate(0, 0, -7).Format(TimeFormat))
	exec(`DELETE FROM hc2_hubs WHERE heartbeat < ?`, now.UTC().Add(-24*time.Hour).Format(TimeFormat))
	old := now.UTC().AddDate(0, 0, -90).Format(TimeFormat)
	exec(`DELETE st FROM hc2_check_states st JOIN hc2_checks c ON c.token = st.token WHERE c.deleted_at IS NOT NULL AND c.deleted_at < ?`, old)
	exec(`DELETE FROM hc2_checks WHERE deleted_at IS NOT NULL AND deleted_at < ?`, old)
	exec(`DELETE FROM hc2_channels WHERE deleted_at IS NOT NULL AND deleted_at < ?`, old)
	exec(`DELETE FROM hc2_maintenance WHERE deleted_at IS NOT NULL AND deleted_at < ?`, old)
	exec(`DELETE FROM hc2_hourly WHERE hour < ?`, now.UTC().AddDate(-1, 0, 0).Format("2006-01-02 15:04:05"))
	exec(`DELETE FROM hc2_events WHERE time < ?`, now.UTC().AddDate(-1, 0, 0).Format(TimeFormat))
}
