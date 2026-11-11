package monitor64

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/eval"
)

// Zusaetzliche Datenzugriffe fuer Oberflaeche und API (Dienste aendern, Schwellen der Stufe "dieser Host",
// Abweichungen, Wartung, Probleme lesen, Kanaele der Node).

// svcPatch sind die aenderbaren Felder eines Dienstes (nil = unveraendert).
type svcPatch struct {
	Name     *string
	Soll     *string
	Report   *string
	HostRule *string
}

// UpdateService aendert Anzeigename, Soll-Zustand, Melden/Nur anzeigen bzw. die Schwellen "nur dieser Dienst"
// (host_rule: JSON Regel-Art -> Regel).
func (s *Store) UpdateService(ctx context.Context, hostUID, key string, p svcPatch, by Actor) error {
	var sets []string
	var args []any
	add := func(col string, v *string) {
		if v != nil {
			sets = append(sets, col+" = ?")
			args = append(args, *v)
		}
	}
	add("name", p.Name)
	add("soll", p.Soll)
	add("report", p.Report)
	add("host_rule", p.HostRule)
	if len(sets) == 0 {
		return nil
	}
	sets = append(sets, "updated_at = ?", "updated_by = ?")
	args = append(args, tsNow(), by.json(), hostUID, key)
	res, err := s.st.Writer().ExecContext(ctx, `UPDATE m64_services SET `+strings.Join(sets, ", ")+` WHERE host_uid = ? AND key = ? AND deleted = 0`, args...)
	return affected(res, err)
}

// encodeHostRules schreibt die Schwellen "nur dieser Dienst" (Regel-Art -> Regel) fuer m64_services.host_rule;
// leere Regeln entfallen, ohne Regel "" (Gegenstueck: parseHostRules im Kern).
func encodeHostRules(rules map[string]eval.Rule) string {
	out := map[string]eval.Rule{}
	for k, r := range rules {
		if !r.Empty() {
			out[k] = r
		}
	}
	if len(out) == 0 {
		return ""
	}
	b, err := json.Marshal(out) // Schluessel sortiert
	if err != nil {
		return ""
	}
	return string(b)
}

// hostRuleRow ist eine Schwelle der Stufe "dieser Host" fuer alle Dienste einer Regel-Art (z. B. fs.used).
type hostRuleRow struct {
	HostUID string    `json:"host_uid"`
	Kind    string    `json:"kind"`
	Rule    eval.Rule `json:"rule"`
	By      Actor     `json:"by"`
	At      time.Time `json:"at"`
}

// HostRules liefert die Schwellen "alle Dienste dieses Hosts mit dieser Regel-Art" (leer = alle Hosts).
func (s *Store) HostRules(ctx context.Context, hostUID string) ([]hostRuleRow, error) {
	q := `SELECT host_uid, kind, rule, updated_by, updated_at FROM m64_host_rules WHERE deleted = 0`
	var args []any
	if hostUID != "" {
		q += ` AND host_uid = ?`
		args = append(args, hostUID)
	}
	rows, err := s.st.Reader().QueryContext(ctx, q+` ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []hostRuleRow
	for rows.Next() {
		var r hostRuleRow
		var rule, by, at string
		if err := rows.Scan(&r.HostUID, &r.Kind, &rule, &by, &at); err != nil {
			return nil, err
		}
		if json.Unmarshal([]byte(rule), &r.Rule) != nil {
			continue
		}
		r.By, r.At = parseActor(by), parseTS(at)
		out = append(out, r)
	}
	return out, rows.Err()
}

// SaveHostRule setzt (rule != nil) oder entfernt (nil) die Schwelle fuer alle Dienste eines Hosts mit der
// Regel-Art kind.
func (s *Store) SaveHostRule(ctx context.Context, hostUID, kind string, rule *eval.Rule, by Actor) error {
	now := tsNow()
	if rule == nil || rule.Empty() {
		_, err := s.st.Writer().ExecContext(ctx, `UPDATE m64_host_rules SET deleted = 1, updated_at = ?, updated_by = ? WHERE host_uid = ? AND kind = ? AND deleted = 0`,
			now, by.json(), hostUID, kind)
		return err
	}
	b, err := json.Marshal(rule)
	if err != nil {
		return err
	}
	_, err = s.st.Writer().ExecContext(ctx, `INSERT INTO m64_host_rules (uid, host_uid, kind, rule, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (host_uid, kind) DO UPDATE SET rule = excluded.rule, deleted = 0, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
		newUID(), hostUID, kind, string(b), now, by.json())
	return err
}

// overrideRow ist eine Abweichung fuer Gruppe oder Tag (Schwelle oder Benachrichtigung).
type overrideRow struct {
	UID        string          `json:"uid"`
	Scope      string          `json:"-"`
	Position   int             `json:"position"`
	TargetType string          `json:"target_type"` // group, tag
	Target     string          `json:"target"`
	Kind       string          `json:"kind,omitempty"`
	Data       json.RawMessage `json:"data"`
	By         Actor           `json:"by"`
	At         time.Time       `json:"at"`
}

// Overrides liefert die Abweichungen einer Art (rule, notify) in ihrer Reihenfolge (oben gewinnt).
func (s *Store) Overrides(ctx context.Context, scope string) ([]overrideRow, error) {
	rows, err := s.st.Reader().QueryContext(ctx, `SELECT uid, scope, position, target_type, target, kind, data, updated_by, updated_at FROM m64_overrides
		WHERE deleted = 0 AND scope = ? ORDER BY position, id`, scope)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []overrideRow
	for rows.Next() {
		var o overrideRow
		var data, by, at string
		if err := rows.Scan(&o.UID, &o.Scope, &o.Position, &o.TargetType, &o.Target, &o.Kind, &data, &by, &at); err != nil {
			return nil, err
		}
		o.Data, o.By, o.At = json.RawMessage(data), parseActor(by), parseTS(at)
		out = append(out, o)
	}
	return out, rows.Err()
}

// SaveOverride legt eine Abweichung unten an (UID leer) oder aendert sie (Position bleibt).
func (s *Store) SaveOverride(ctx context.Context, o *overrideRow, by Actor) error {
	now := tsNow()
	if o.UID == "" {
		o.UID = newUID()
		var pos sql.NullInt64
		_ = s.st.Reader().QueryRowContext(ctx, `SELECT MAX(position) FROM m64_overrides WHERE deleted = 0 AND scope = ?`, o.Scope).Scan(&pos)
		o.Position = int(pos.Int64) + 1
		_, err := s.st.Writer().ExecContext(ctx, `INSERT INTO m64_overrides (uid, scope, position, target_type, target, kind, data, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			o.UID, o.Scope, o.Position, o.TargetType, o.Target, o.Kind, string(o.Data), now, by.json())
		return err
	}
	res, err := s.st.Writer().ExecContext(ctx, `UPDATE m64_overrides SET target_type = ?, target = ?, kind = ?, data = ?, updated_at = ?, updated_by = ? WHERE uid = ? AND scope = ? AND deleted = 0`,
		o.TargetType, o.Target, o.Kind, string(o.Data), now, by.json(), o.UID, o.Scope)
	return affected(res, err)
}

// DeleteOverride setzt den Loeschvermerk einer Abweichung.
func (s *Store) DeleteOverride(ctx context.Context, scope, uid string, by Actor) error {
	res, err := s.st.Writer().ExecContext(ctx, `UPDATE m64_overrides SET deleted = 1, updated_at = ?, updated_by = ? WHERE uid = ? AND scope = ? AND deleted = 0`,
		tsNow(), by.json(), uid, scope)
	return affected(res, err)
}

// MoveOverride verschiebt eine Abweichung um eine Stelle nach oben (dir < 0) oder unten; die Liste wird dabei
// lueckenlos neu nummeriert.
func (s *Store) MoveOverride(ctx context.Context, scope, uid string, dir int, by Actor) error {
	list, err := s.Overrides(ctx, scope)
	if err != nil {
		return err
	}
	i := -1
	for k, o := range list {
		if o.UID == uid {
			i = k
		}
	}
	if i < 0 {
		return ErrNotFound
	}
	j := i + 1
	if dir < 0 {
		j = i - 1
	}
	if j < 0 || j >= len(list) {
		return nil
	}
	list[i], list[j] = list[j], list[i]
	tx, err := s.st.Writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := tsNow()
	for k, o := range list {
		if o.Position == k+1 && o.UID != uid {
			continue
		}
		// jede Zeile mit neuer Position bekommt eine neue Aenderungszeit (der Abgleich im Cluster findet Aenderungen
		// nur darueber)
		if _, err := tx.ExecContext(ctx, `UPDATE m64_overrides SET position = ?, updated_at = ?, updated_by = ? WHERE uid = ?`, k+1, now, by.json(), o.UID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// maintRow ist ein Wartungsfenster.
type maintRow struct {
	UID     string           `json:"uid"`
	Title   string           `json:"title"`
	Hosts   []string         `json:"hosts"`
	Groups  []string         `json:"groups"`
	Tags    []string         `json:"tags"`
	Start   time.Time        `json:"start,omitzero"`
	End     time.Time        `json:"end,omitzero"`
	Recur   *eval.Recurrence `json:"recur,omitempty"`
	Ended   time.Time        `json:"ended,omitzero"`
	By      Actor            `json:"by"`
	At      time.Time        `json:"at"`
	Changed Actor            `json:"changed_by"`
}

type maintTargets struct {
	Hosts  []string `json:"hosts"`
	Groups []string `json:"groups"`
	Tags   []string `json:"tags"`
}

// Maintenances liefert alle Wartungsfenster (neueste zuerst).
func (s *Store) Maintenances(ctx context.Context) ([]maintRow, error) {
	rows, err := s.st.Reader().QueryContext(ctx, `SELECT uid, title, targets, start_at, end_at, recur, ended_at, created_by, updated_at, updated_by FROM m64_maint WHERE deleted = 0 ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []maintRow
	for rows.Next() {
		var m maintRow
		var targets, start, end, recur, ended, by, at, chg string
		if err := rows.Scan(&m.UID, &m.Title, &targets, &start, &end, &recur, &ended, &by, &at, &chg); err != nil {
			return nil, err
		}
		var t maintTargets
		_ = json.Unmarshal([]byte(targets), &t)
		m.Hosts, m.Groups, m.Tags = t.Hosts, t.Groups, t.Tags
		m.Start, m.End, m.Ended, m.At = parseTS(start), parseTS(end), parseTS(ended), parseTS(at)
		m.By, m.Changed = parseActor(by), parseActor(chg)
		if recur != "" {
			var r eval.Recurrence
			if json.Unmarshal([]byte(recur), &r) == nil {
				m.Recur = &r
			}
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func tsOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return ts(t)
}

// SaveMaint legt ein Wartungsfenster an (UID leer) oder aendert es.
func (s *Store) SaveMaint(ctx context.Context, m *maintRow, by Actor) error {
	tb, _ := json.Marshal(maintTargets{Hosts: nonNil(m.Hosts), Groups: nonNil(m.Groups), Tags: nonNil(m.Tags)})
	recur := ""
	if m.Recur != nil {
		b, err := json.Marshal(m.Recur)
		if err != nil {
			return err
		}
		recur = string(b)
	}
	now := tsNow()
	if m.UID == "" {
		m.UID = newUID()
		_, err := s.st.Writer().ExecContext(ctx, `INSERT INTO m64_maint (uid, title, targets, start_at, end_at, recur, created_by, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			m.UID, m.Title, string(tb), tsOrEmpty(m.Start), tsOrEmpty(m.End), recur, by.json(), now, by.json())
		return err
	}
	res, err := s.st.Writer().ExecContext(ctx, `UPDATE m64_maint SET title = ?, targets = ?, start_at = ?, end_at = ?, recur = ?, updated_at = ?, updated_by = ? WHERE uid = ? AND deleted = 0`,
		m.Title, string(tb), tsOrEmpty(m.Start), tsOrEmpty(m.End), recur, now, by.json(), m.UID)
	return affected(res, err)
}

// EndMaint beendet ein Wartungsfenster jetzt (wiederkehrend: endgueltig).
func (s *Store) EndMaint(ctx context.Context, uid string, at time.Time, by Actor) error {
	res, err := s.st.Writer().ExecContext(ctx, `UPDATE m64_maint SET ended_at = ?, updated_at = ?, updated_by = ? WHERE uid = ? AND deleted = 0 AND ended_at = ''`,
		ts(at), tsNow(), by.json(), uid)
	return affected(res, err)
}

// DeleteMaint setzt den Loeschvermerk eines Wartungsfensters.
func (s *Store) DeleteMaint(ctx context.Context, uid string, by Actor) error {
	res, err := s.st.Writer().ExecContext(ctx, `UPDATE m64_maint SET deleted = 1, updated_at = ?, updated_by = ? WHERE uid = ? AND deleted = 0`, tsNow(), by.json(), uid)
	return affected(res, err)
}

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

// ackInfo ist eine Quittierung (wer, wann, Kommentar).
type ackInfo struct {
	By      Actor     `json:"by"`
	At      time.Time `json:"at"`
	Comment string    `json:"comment,omitempty"`
}

func parseAck(s string) *ackInfo {
	if s == "" {
		return nil
	}
	var raw struct {
		By      Actor  `json:"by"`
		At      string `json:"at"`
		Comment string `json:"comment"`
	}
	if json.Unmarshal([]byte(s), &raw) != nil {
		return nil
	}
	return &ackInfo{By: raw.By, At: parseTS(raw.At), Comment: raw.Comment}
}

// problemRow ist ein Problem (offen oder geloest) fuer die Seite Probleme.
type problemRow struct {
	UID      string    `json:"uid"`
	HostUID  string    `json:"host_uid"`
	Key      string    `json:"key"`
	State    string    `json:"state"`
	Worst    string    `json:"worst"`
	Opened   time.Time `json:"opened"`
	Closed   time.Time `json:"closed,omitzero"`
	How      string    `json:"how,omitempty"`
	ClosedBy Actor     `json:"closed_by"`
	Ack      *ackInfo  `json:"ack,omitempty"`
	Notified []string  `json:"notified"`
}

// problemFilter waehlt Probleme aus.
type problemFilter struct {
	Status  string    // open, closed, all
	Since   time.Time // geoeffnet oder geschlossen ab (leer = alle)
	HostUID string
	Limit   int
}

// Problems liefert Probleme (neueste zuerst).
func (s *Store) Problems(ctx context.Context, f problemFilter) ([]problemRow, error) {
	q := `SELECT uid, host_uid, service_key, state, worst, opened_at, closed_at, closed_how, closed_by, ack, notified FROM m64_problems WHERE deleted = 0`
	var args []any
	switch f.Status {
	case "open":
		q += ` AND closed_at = ''`
	case "closed":
		q += ` AND closed_at != ''`
	}
	if !f.Since.IsZero() {
		q += ` AND (closed_at = '' OR closed_at >= ?)`
		args = append(args, ts(f.Since))
	}
	if f.HostUID != "" {
		q += ` AND host_uid = ?`
		args = append(args, f.HostUID)
	}
	if f.Limit <= 0 || f.Limit > 5000 {
		f.Limit = 5000
	}
	if f.Status == "open" || f.Status == "closed" { // nur eine Art: Sortierung ueber den Index (opened_at)
		q += ` ORDER BY opened_at DESC LIMIT ?`
	} else {
		q += ` ORDER BY (closed_at = '') DESC, opened_at DESC LIMIT ?`
	}
	args = append(args, f.Limit)
	rows, err := s.st.Reader().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []problemRow
	for rows.Next() {
		var p problemRow
		var opened, closed, by, ack, notified string
		if err := rows.Scan(&p.UID, &p.HostUID, &p.Key, &p.State, &p.Worst, &opened, &closed, &p.How, &by, &ack, &notified); err != nil {
			return nil, err
		}
		p.Opened, p.Closed, p.ClosedBy, p.Ack = parseTS(opened), parseTS(closed), parseActor(by), parseAck(ack)
		p.Notified = nonNil(parseList(notified))
		out = append(out, p)
	}
	return out, rows.Err()
}

// Problem liefert ein Problem.
func (s *Store) Problem(ctx context.Context, uid string) (*problemRow, error) {
	var p problemRow
	var opened, closed, by, ack, notified string
	err := s.st.Reader().QueryRowContext(ctx, `SELECT uid, host_uid, service_key, state, worst, opened_at, closed_at, closed_how, closed_by, ack, notified FROM m64_problems WHERE uid = ? AND deleted = 0`, uid).
		Scan(&p.UID, &p.HostUID, &p.Key, &p.State, &p.Worst, &opened, &closed, &p.How, &by, &ack, &notified)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.Opened, p.Closed, p.ClosedBy, p.Ack = parseTS(opened), parseTS(closed), parseActor(by), parseAck(ack)
	p.Notified = nonNil(parseList(notified))
	return &p, nil
}

// eventRow ist ein Eintrag im Ablauf eines Problems (bzw. allgemein, z. B. Wartung).
type eventRow struct {
	At      time.Time `json:"at"`
	Kind    string    `json:"kind"`
	Text    string    `json:"text,omitempty"`
	Actor   Actor     `json:"actor"`
	HostUID string    `json:"host_uid,omitempty"`
	Key     string    `json:"key,omitempty"`
	Problem string    `json:"problem,omitempty"`
}

// Events liefert den Ablauf eines Problems (aelteste zuerst).
func (s *Store) Events(ctx context.Context, problemUID string) ([]eventRow, error) {
	return s.queryEvents(ctx, `SELECT ts, kind, text, actor, host_uid, service_key, problem_uid FROM m64_events WHERE problem_uid = ? ORDER BY ts, id LIMIT 500`, problemUID)
}

// RecentEvents liefert die juengsten Ereignisse der Arten kinds (neueste zuerst).
func (s *Store) RecentEvents(ctx context.Context, kinds []string, limit int) ([]eventRow, error) {
	if len(kinds) == 0 {
		return nil, nil
	}
	args := make([]any, 0, len(kinds)+1)
	for _, k := range kinds {
		args = append(args, k)
	}
	args = append(args, limit)
	return s.queryEvents(ctx, `SELECT ts, kind, text, actor, host_uid, service_key, problem_uid FROM m64_events WHERE kind IN (?`+strings.Repeat(", ?", len(kinds)-1)+`) ORDER BY ts DESC, id DESC LIMIT ?`, args...)
}

func (s *Store) queryEvents(ctx context.Context, q string, args ...any) ([]eventRow, error) {
	rows, err := s.st.Reader().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []eventRow
	for rows.Next() {
		var e eventRow
		var at, actor string
		if err := rows.Scan(&at, &e.Kind, &e.Text, &actor, &e.HostUID, &e.Key, &e.Problem); err != nil {
			return nil, err
		}
		e.At, e.Actor = parseTS(at), parseActor(actor)
		out = append(out, e)
	}
	return out, rows.Err()
}

// openProblemInfo ist ein offenes Problem fuer Uebersicht und Host (seit wann, quittiert).
type openProblemInfo struct {
	UID    string
	Opened time.Time
	Ack    *ackInfo
}

// OpenProblems liefert alle offenen Probleme (Schluessel: host_uid|service_key).
func (s *Store) OpenProblems(ctx context.Context) (map[string]openProblemInfo, error) {
	rows, err := s.st.Reader().QueryContext(ctx, `SELECT uid, host_uid, service_key, opened_at, ack FROM m64_problems WHERE closed_at = '' AND deleted = 0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]openProblemInfo{}
	for rows.Next() {
		var uid, host, key, opened, ack string
		if err := rows.Scan(&uid, &host, &key, &opened, &ack); err != nil {
			return nil, err
		}
		out[host+"|"+key] = openProblemInfo{UID: uid, Opened: parseTS(opened), Ack: parseAck(ack)}
	}
	return out, rows.Err()
}

// Unack hebt eine Quittierung von Hand auf (mit Akteur im Ablauf).
func (m *Module) Unack(ctx context.Context, hostUID, svcKey string, by Actor) error {
	p := m.loadOpen(ctx, hostUID)[svcKey]
	if p == nil || !p.Acked {
		return ErrNotFound
	}
	if _, err := m.st.Writer().ExecContext(ctx, `UPDATE m64_problems SET ack = '', updated_at = ? WHERE uid = ?`, tsNow(), p.UID); err != nil {
		return err
	}
	m.event(ctx, p.UID, hostUID, svcKey, "unack", "", by, time.Now())
	return nil
}

// Comment schreibt einen Kommentar in den Ablauf eines offenen Problems.
func (m *Module) Comment(ctx context.Context, hostUID, svcKey, text string, by Actor) error {
	p := m.loadOpen(ctx, hostUID)[svcKey]
	if p == nil {
		return ErrNotFound
	}
	m.event(ctx, p.UID, hostUID, svcKey, "comment", text, by, time.Now())
	return nil
}

// channelInfo ist ein Benachrichtigungskanal der Node (ohne Konfiguration und Geheimnisse).
type channelInfo struct {
	ID      int64  `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Default bool   `json:"default"`
}

// Channels liefert die Kanaele der Node (Tabelle des Kerns nf_channels; nur Name, Art, Schalter).
func (s *Store) Channels(ctx context.Context) ([]channelInfo, error) {
	rows, err := s.st.Reader().QueryContext(ctx, `SELECT id, type, name, enabled, is_default FROM nf_channels ORDER BY name COLLATE NOCASE, id`)
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var out []channelInfo
	for rows.Next() {
		var c channelInfo
		var en, def int
		if err := rows.Scan(&c.ID, &c.Type, &c.Name, &en, &def); err != nil {
			return nil, err
		}
		c.Enabled, c.Default = en == 1, def == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

// ServiceCount zaehlt die uebernommenen Dienste aller Hosts.
func (s *Store) ServiceCount(ctx context.Context) int {
	var n int
	_ = s.st.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM m64_services WHERE deleted = 0 AND adopted = 1`).Scan(&n)
	return n
}

// openUnackedCount zaehlt offene, nicht quittierte Probleme (Zaehler am Reiter Probleme).
func (s *Store) openUnackedCount(ctx context.Context) int {
	var n int
	_ = s.st.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM m64_problems WHERE closed_at = '' AND ack = '' AND deleted = 0`).Scan(&n)
	return n
}
