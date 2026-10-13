package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Die Verdichtungen lesen mit einer normalen (sperrfreien) Abfrage und schreiben das Ergebnis in Paketen.
// Ein INSERT ... SELECT setzt in MariaDB Lesesperren auf alle gelesenen Messpunkte; im Lasttest
// (100.000 Checks) blockierte das die Annahme neuer Messpunkte fuer ueber eine Minute.

const hourlySelect = `SELECT token, source, DATE_FORMAT(time, '%Y-%m-%d %H:00:00'), COUNT(*), SUM(status = 1), MIN(NULLIF(latency_ms, 0)), AVG(NULLIF(latency_ms, 0)), MAX(latency_ms)
	FROM hc2_measurements WHERE `

// AggregateHourly verdichtet die Messpunkte dieser Messstelle der letzten
// Stunden (laufende und zwei davor) in hc2_hourly. Idempotent.
func (s *Store) AggregateHourly(ctx context.Context, now time.Time) error {
	from := now.UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	to := now.UTC().Truncate(time.Hour).Add(time.Hour)
	return s.aggregate(ctx, "hc2_hourly", "hour", hourlySelect+`source = ? AND time >= ? AND time < ? GROUP BY token, source, DATE_FORMAT(time, '%Y-%m-%d %H:00:00')`,
		s.source, from.Format(TimeFormat), to.Format(TimeFormat))
}

// AggregateHourlyShared verdichtet die Messpunkte der Nodes und Pushes (gemeinsam fuer alle hubs).
// Laufende Stunde; die vorige nur in den ersten 10 Minuten (spaet eintreffende Messpunkte). Rechnet
// gerade ein anderer hub, wird uebersprungen (Datenbank-Sperre statt doppelter Arbeit).
func (s *Store) AggregateHourlyShared(ctx context.Context, now time.Time) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	var got sql.NullInt64
	if err := conn.QueryRowContext(ctx, `SELECT GET_LOCK('hc2_aggregate_shared', 0)`).Scan(&got); err != nil {
		return err
	}
	if got.Int64 != 1 {
		return nil // ein anderer hub verdichtet gerade
	}
	defer conn.ExecContext(context.Background(), `SELECT RELEASE_LOCK('hc2_aggregate_shared')`) //nolint:errcheck
	from := now.UTC().Truncate(time.Hour)
	if now.UTC().Minute() < 10 {
		from = from.Add(-time.Hour)
	}
	to := now.UTC().Truncate(time.Hour).Add(time.Hour)
	return s.aggregate(ctx, "hc2_hourly", "hour", hourlySelect+`time >= ? AND time < ? AND (source LIKE 'node:%' OR source = 'push') GROUP BY token, source, DATE_FORMAT(time, '%Y-%m-%d %H:00:00')`,
		from.Format(TimeFormat), to.Format(TimeFormat))
}

// AggregateDaily verdichtet hc2_hourly des Vortags und des laufenden Tags in hc2_daily.
func (s *Store) AggregateDaily(ctx context.Context, now time.Time) error {
	day := now.UTC().Truncate(24 * time.Hour)
	from := day.AddDate(0, 0, -1)
	return s.aggregate(ctx, "hc2_daily", "day", `SELECT token, source, DATE(hour), SUM(count), SUM(up_count), MIN(min_ms), SUM(avg_ms * count) / NULLIF(SUM(count), 0), MAX(max_ms)
		FROM hc2_hourly WHERE hour >= ? GROUP BY token, source, DATE(hour)`, from.Format("2006-01-02 15:04:05"))
}

// aggregateLate verdichtet nachgelieferte Messpunkte einer Node (war offline): deren Stunden und Tage,
// die die laufende Verdichtung (nur aktuelle Stunde) nicht mehr erfasst.
func (s *Store) aggregateLate(source string, earliest, now time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	from := earliest.Truncate(time.Hour)
	if err := s.aggregate(ctx, "hc2_hourly", "hour", hourlySelect+`source = ? AND time >= ? AND time < ? GROUP BY token, source, DATE_FORMAT(time, '%Y-%m-%d %H:00:00')`,
		source, from.Format(TimeFormat), now.Truncate(time.Hour).Add(time.Hour).Format(TimeFormat)); err != nil {
		s.log.Warn("late aggregation failed", "source", source, "err", err)
		return
	}
	day := from.Truncate(24 * time.Hour)
	if err := s.aggregate(ctx, "hc2_daily", "day", `SELECT token, source, DATE(hour), SUM(count), SUM(up_count), MIN(min_ms), SUM(avg_ms * count) / NULLIF(SUM(count), 0), MAX(max_ms)
		FROM hc2_hourly WHERE source = ? AND hour >= ? GROUP BY token, source, DATE(hour)`, source, day.Format("2006-01-02 15:04:05")); err != nil {
		s.log.Warn("late daily aggregation failed", "source", source, "err", err)
	}
}

// aggregate liest die Verdichtung sperrfrei und schreibt sie in Paketen zu 500 Zeilen (Upsert).
func (s *Store) aggregate(ctx context.Context, table, col, query string, args ...any) error {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		s.Metrics.add(&s.Metrics.DBErrors, 1)
		return err
	}
	defer rows.Close()
	var vals []string
	var batch []any
	flush := func() error {
		if len(vals) == 0 {
			return nil
		}
		_, err := s.db.ExecContext(ctx, `INSERT INTO `+table+` (token, source, `+col+`, count, up_count, min_ms, avg_ms, max_ms) VALUES `+strings.Join(vals, ",")+`
			ON DUPLICATE KEY UPDATE count = VALUES(count), up_count = VALUES(up_count), min_ms = VALUES(min_ms), avg_ms = VALUES(avg_ms), max_ms = VALUES(max_ms)`, batch...)
		vals, batch = vals[:0], batch[:0]
		if err != nil {
			s.Metrics.add(&s.Metrics.DBErrors, 1)
		}
		return err
	}
	for rows.Next() {
		var token, source, bucket string
		var count, up int64
		var minMS, avgMS, maxMS sql.NullFloat64
		if err := rows.Scan(&token, &source, &bucket, &count, &up, &minMS, &avgMS, &maxMS); err != nil {
			return err
		}
		vals = append(vals, "(?,?,?,?,?,?,?,?)")
		batch = append(batch, token, source, bucket, count, up, minMS, avgMS, maxMS)
		if len(vals) == 500 {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return flush()
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
	exec(`DELETE FROM hc2_hourly WHERE hour < ?`, now.UTC().AddDate(0, 0, -HourlyKeepDays).Format("2006-01-02 15:04:05"))
	exec(`DELETE FROM hc2_events WHERE time < ?`, now.UTC().AddDate(-1, 0, 0).Format(TimeFormat))
}

// CloseDeletedIncidents schliesst offene Stoerungen geloeschter Checks (Ende = Loeschzeitpunkt).
// Faengt alle Loeschwege ab (Portal, API v2, Node) und raeumt Altfaelle auf.
func (s *Store) CloseDeletedIncidents(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE hc2_incidents i JOIN hc2_checks c ON c.token = i.token
		SET i.ended_at = GREATEST(c.deleted_at, i.started_at)
		WHERE i.ended_at IS NULL AND c.deleted_at IS NOT NULL`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		_, _ = s.db.ExecContext(ctx, `UPDATE hc2_checks SET incident_id = NULL WHERE deleted_at IS NOT NULL AND incident_id IS NOT NULL`)
	}
	return n, nil
}

// CleanupStaleSources loescht Zustaende von Messstellen, die nach einem Umhaengen nicht mehr
// zum Check gehoeren (gleiche Regeln wie die Bewertung). 10 Minuten Karenz fuer laufende Wechsel.
func (s *Store) CleanupStaleSources(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE st FROM hc2_check_states st JOIN hc2_checks c ON c.token = st.token
		WHERE st.updated_at < ? AND c.deleted_at IS NULL AND (
			(c.execution = 'online' AND st.source LIKE 'node:%')
			OR (c.execution = 'local' AND st.source NOT LIKE 'node:%')
			OR (st.source LIKE 'node:%' AND FIND_IN_SET(SUBSTRING(st.source, 6), IF(c.nodes = '', COALESCE(c.node_id, ''), c.nodes)) = 0)
			OR (st.source LIKE 'loc:%%' AND FIND_IN_SET(SUBSTRING(st.source, 5), c.locations) = 0))`,
		now.UTC().Add(-10*time.Minute).Format(TimeFormat))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
