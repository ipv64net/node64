package monitor64

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Laufzeit des Moduls (fuer die Statusseiten, statusfeed.go): solange Monitor64 laeuft, schreibt es jede Minute einen
// Herzschlag (Einstellung monitor64.heartbeat, nur lokal). Liegt der letzte Herzschlag beim Start - oder im Lauf, z. B.
// nach einem angehaltenen System - laenger als uptimeGapMin zurueck, lief das Modul dazwischen nicht: die Zeit steht
// als Luecke in m64_gaps (je Node). Kuerzere Unterbrechungen (Neustart, Update) zaehlen nicht. Im Cluster gehen die
// Luecken als Eintraege "gap:<node>:<beginn in ms>" ueber den Bereich status an die anderen Nodes (gehoeren der Node,
// kein Konflikt); aufbewahrt werden sie wie die Problem-Historie (keepProblems).

const setHeartbeat = "monitor64.heartbeat" // letzter Herzschlag (Zeit), nur lokal

var (
	uptimeBeatEvery = time.Minute
	uptimeGapMin    = 5 * time.Minute // kuerzere Unterbrechungen zaehlen nicht als Luecke
)

// uptimeMark schreibt den Herzschlag; liegt der letzte mindestens uptimeGapMin zurueck, merkt es die Zeit dazwischen
// als Luecke dieser Node (Start nach einer Pause des Moduls bzw. der Node).
func (m *Module) uptimeMark(ctx context.Context, now time.Time) {
	now = now.UTC().Round(0)
	if last := parseTS(m.st.SettingOr(ctx, setHeartbeat, "")); !last.IsZero() && now.Sub(last) >= uptimeGapMin {
		m.addGap(ctx, last, now)
	}
	if err := m.st.SetSetting(ctx, setHeartbeat, ts(now)); err != nil {
		m.log.Warn("monitor64: heartbeat", "err", err)
	}
}

// uptimeLoop schreibt den Herzschlag, solange das Modul laeuft, und zum Schluss noch einmal (die Luecke beginnt dann
// genau beim Stopp).
func (m *Module) uptimeLoop(ctx context.Context) {
	t := time.NewTicker(uptimeBeatEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			m.uptimeMark(sctx, time.Now())
			cancel()
			return
		case <-t.C:
			m.uptimeMark(ctx, time.Now())
		}
	}
}

// addGap merkt eine Luecke dieser Node und meldet sie an den Cluster.
func (m *Module) addGap(ctx context.Context, from, to time.Time) {
	self := m.clusterSelf()
	from = from.UTC().Truncate(time.Millisecond)
	if _, err := m.st.Writer().ExecContext(ctx, `INSERT INTO m64_gaps (node_id, from_at, to_at) VALUES (?, ?, ?)
		ON CONFLICT (node_id, from_at) DO UPDATE SET to_at = excluded.to_at`, self, ts(from), ts(to)); err != nil {
		m.log.Warn("monitor64: runtime gap", "err", err)
		return
	}
	m.log.Info("monitor64: module was not running", "from", ts(from), "to", ts(to))
	m.clusterChange(ctx, ClusterItemStatus, gapID(self, from), false)
}

func gapID(node string, from time.Time) string {
	return "gap:" + node + ":" + strconv.FormatInt(from.UnixMilli(), 10)
}

// splitGapID zerlegt "<node>:<beginn in ms>" (Kennung ohne "gap:").
func splitGapID(id string) (node string, from time.Time, ok bool) {
	i := strings.LastIndexByte(id, ':')
	if i <= 0 {
		return "", time.Time{}, false
	}
	ms, err := strconv.ParseInt(id[i+1:], 10, 64)
	if err != nil || ms <= 0 || !reNodeID.MatchString(id[:i]) {
		return "", time.Time{}, false
	}
	return id[:i], time.UnixMilli(ms).UTC(), true
}

// gapEntry ist eine Luecke im Cluster.
type gapEntry struct {
	To string `json:"to"`
}

func (m *Module) gapGet(ctx context.Context, id string) (json.RawMessage, bool, error) {
	node, from, ok := splitGapID(id)
	if !ok {
		return nil, false, errClItem
	}
	var e gapEntry
	err := m.st.Reader().QueryRowContext(ctx, `SELECT to_at FROM m64_gaps WHERE node_id = ? AND from_at = ?`, node, ts(from)).Scan(&e.To)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	b, err := json.Marshal(e)
	return b, err == nil, err
}

// gapApply uebernimmt die Luecke einer anderen Node (eigene kommen nie von anderen).
func (m *Module) gapApply(ctx context.Context, id string, data json.RawMessage, deleted bool) error {
	node, from, ok := splitGapID(id)
	if !ok {
		return errClItem
	}
	if node == m.clusterSelf() {
		return nil
	}
	if deleted {
		_, err := m.st.Writer().ExecContext(ctx, `DELETE FROM m64_gaps WHERE node_id = ? AND from_at = ?`, node, ts(from))
		return err
	}
	var e gapEntry
	if err := json.Unmarshal(data, &e); err != nil {
		return err
	}
	to := parseTS(e.To)
	if !to.After(from) || to.After(time.Now().Add(time.Hour)) {
		return errClItem
	}
	_, err := m.st.Writer().ExecContext(ctx, `INSERT INTO m64_gaps (node_id, from_at, to_at) VALUES (?, ?, ?)
		ON CONFLICT (node_id, from_at) DO UPDATE SET to_at = excluded.to_at`, node, ts(from), ts(to))
	return err
}

// purgeGaps entfernt Luecken nach der Aufbewahrung (cut); die eigenen gehen als Vermerk an den Cluster (haelt das
// Protokoll klein, die anderen Nodes raeumen ebenso auf).
func (m *Module) purgeGaps(ctx context.Context, cut string) {
	self := m.clusterSelf()
	var own []string
	if rows, err := m.st.Reader().QueryContext(ctx, `SELECT from_at FROM m64_gaps WHERE node_id = ? AND to_at < ?`, self, cut); err == nil {
		for rows.Next() {
			var at string
			if rows.Scan(&at) == nil {
				own = append(own, at)
			}
		}
		rows.Close()
	}
	if _, err := m.st.Writer().ExecContext(ctx, `DELETE FROM m64_gaps WHERE to_at < ?`, cut); err != nil {
		m.log.Warn("monitor64: purge runtime gaps", "err", err)
		return
	}
	for _, at := range own {
		m.clusterChange(ctx, ClusterItemStatus, gapID(self, parseTS(at)), true)
	}
}
