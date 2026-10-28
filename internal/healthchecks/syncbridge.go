package healthchecks

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/scheduler"
	"github.com/ipv64net/node64/internal/wire"
)

// Bruecke zwischen dem Modul und dem Sync-Client (internal/sync): Wire-Form der
// Checks, Anwenden von Server-Aenderungen, Outbox und Konflikte, Messdaten-Export.

// ChannelMap bildet Kanal-IDs ab (lokal <-> Server); nil = unveraendert.
type ChannelMap func(id int64) int64

// WireCheck liefert die Wire-Form eines Checks (Kanaele ueber chanMap abgebildet).
func (m *Module) WireCheck(c *Check, chanMap ChannelMap) wire.Check {
	w := wire.Check{Token: c.Token, Name: c.Name, Type: string(c.Type), Target: c.Target, Params: c.Params,
		IntervalSeconds: int(c.Interval.Seconds()), RetryIntervalSeconds: int(c.RetryInterval.Seconds()), Retries: c.Retries,
		ConnectTimeoutSeconds: c.ConnectTimeout.Seconds(), TimeoutSeconds: c.TotalTimeout.Seconds(), Invert: c.Invert, Stabilize: c.Stabilize,
		IPMode: string(c.IPMode), Tags: c.Tags, Group: c.Group, Description: c.Description, Paused: c.Paused, Parent: c.Parent, Critical: c.Critical,
		Execution: c.Execution, Policy: c.Policy, Locations: c.Locations, NotifyDegraded: c.NotifyDegraded, NotifyDown: c.NotifyDown, NotifyUp: c.NotifyUp,
		RepeatMinutes: c.RepeatMinutes, Revision: c.Revision, Channels: []int64{}}
	if c.Execution != "online" && len(c.Nodes) > 0 {
		w.Nodes = append([]string{}, c.Nodes...)
	}
	if w.Tags == nil {
		w.Tags = []string{}
	}
	if w.Locations == nil {
		w.Locations = []string{}
	}
	for _, id := range c.Channels {
		if chanMap != nil {
			if r := chanMap(id); r > 0 {
				w.Channels = append(w.Channels, r)
			}
			continue
		}
		w.Channels = append(w.Channels, id)
	}
	return w
}

// ApplyWireCheck uebernimmt einen Check vom Server (ohne Outbox-Eintrag).
// Eigene Checks (owner self) laufen im Scheduler, fremde und reine Online-Checks nur zur Anzeige.
func (m *Module) ApplyWireCheck(ctx context.Context, w wire.Check, chanMap ChannelMap) error {
	ctx = WithRemote(ctx)
	if !tokenRe.MatchString(w.Token) && len(w.Token) < 20 {
		return errors.New("invalid token")
	}
	existing, err := m.st.Check(ctx, w.Token)
	if err != nil {
		return err
	}
	c := existing
	create := c == nil
	if create {
		c = &Check{Token: w.Token}
	}
	oldType := c.Type
	grp := w.Group
	// Felder neuerer Versionen (z. B. params.system) weglassen statt den ganzen Check abzulehnen
	params := checks.WithoutUnknownParams(checks.Definition{Type: checks.Type(strings.ToLower(strings.TrimSpace(w.Type))), Target: strings.TrimSpace(w.Target), Params: w.Params})
	params = keepSystemUID(existing, params)
	in := checkJSON{Name: w.Name, Type: w.Type, Target: w.Target, Params: params, IPMode: w.IPMode, Tags: w.Tags, Group: &grp, Description: w.Description,
		Execution: "local", Policy: w.Policy, Locations: w.Locations}
	iv, riv, re, st, rp := w.IntervalSeconds, w.RetryIntervalSeconds, w.Retries, w.Stabilize, w.RepeatMinutes
	ct, tt := w.ConnectTimeoutSeconds, w.TimeoutSeconds
	inv, pa, cr, nd, nu, ndeg, parent := w.Invert, w.Paused, w.Critical, w.NotifyDown, w.NotifyUp, w.NotifyDegraded, w.Parent
	in.IntervalSeconds, in.RetryIntervalSeconds, in.Retries, in.Stabilize, in.RepeatMinutes = &iv, &riv, &re, &st, &rp
	in.ConnectTimeoutSeconds, in.TimeoutSeconds = &ct, &tt
	in.Invert, in.Paused, in.Critical, in.NotifyDown, in.NotifyUp, in.NotifyDegraded, in.Parent = &inv, &pa, &cr, &nd, &nu, &ndeg, &parent
	in.Channels = []int64{}
	for _, id := range w.Channels {
		if chanMap != nil {
			if l := chanMap(id); l > 0 {
				in.Channels = append(in.Channels, l)
			}
			continue
		}
		in.Channels = append(in.Channels, id)
	}
	c.UpdatedBy = "ipv64"
	if err := m.apply(c, in, create); err != nil {
		return err
	}
	// Felder, die apply nicht setzt
	c.Execution = w.Execution
	if c.Execution == "" {
		c.Execution = "local"
	}
	c.Owner = w.Owner
	if c.Owner == "" {
		c.Owner = "self"
	}
	c.Nodes = nil
	if c.Execution != "online" {
		c.Nodes = w.Nodes
	}
	if c.Parent != "" {
		if p, _ := m.st.Check(ctx, c.Parent); p == nil {
			c.Parent = ""
		}
	}
	if create {
		c.Revision = w.Revision
		err = m.st.Insert(ctx, c)
	} else {
		err = m.st.Update(ctx, c)
		if err == nil && w.Revision > 0 {
			err = m.st.SetRevision(ctx, c.Token, w.Revision)
		}
	}
	if err != nil {
		return err
	}
	nc, _ := m.st.Check(ctx, c.Token)
	if nc != nil {
		m.pveLinkCheck(ctx, nc) // Check eines Systems aus dem Cluster: beim System vermerken
	}
	if s := m.scheduler(); s != nil && nc != nil {
		if nc.MeasuredHere() {
			var rt *scheduler.Runtime
			if !create && oldType == nc.Type {
				if live, ok := s.Runtime(nc.Token); ok {
					rt = &live
				}
			}
			if rt == nil {
				rt = m.adoptIncident(ctx, s, nc.Token)
			}
			s.Upsert(nc.SchedulerCheck(), rt)
		} else {
			s.Remove(nc.Token)
		}
	}
	return nil
}

// adoptIncident: misst diese Node einen Check ab jetzt selbst (Besitzerwechsel), uebernimmt der Scheduler eine
// offene Stoerung, die bisher ipv64 bzw. die andere Node gefuehrt hat (beendet sie beim naechsten up), statt sie
// offen stehen zu lassen. nil = Check laeuft schon im Scheduler oder keine offene Stoerung.
func (m *Module) adoptIncident(ctx context.Context, s *scheduler.Scheduler, token string) *scheduler.Runtime {
	if _, live := s.Runtime(token); live {
		return nil
	}
	if id := m.st.openIncidentID(ctx, token); id != 0 {
		return &scheduler.Runtime{Incident: id}
	}
	return nil
}

// MeasuredHere: eigener Check, der lokal gemessen wird.
func (c *Check) MeasuredHere() bool {
	return c.Execution != "online" && c.measures()
}

// RemoveRemoteCheck loescht einen Check auf Anweisung des Servers (ohne Outbox).
func (m *Module) RemoveRemoteCheck(ctx context.Context, token string) error {
	ctx = WithRemote(ctx)
	if s := m.scheduler(); s != nil {
		s.Remove(token)
	}
	if c, _ := m.st.Check(ctx, token); c == nil {
		return nil
	}
	return m.st.Delete(ctx, token)
}

// WireMaintenance liefert die Wire-Form (ID = Server-ID, lokale ID separat).
func (m *Module) WireMaintenance(mw Maintenance) wire.Maintenance {
	return wire.Maintenance{ID: mw.RemoteID, Name: mw.Name, StartAt: mw.StartAt, EndAt: mw.EndAt, Repeat: mw.Repeat, RepeatUntil: mw.RepeatUntil,
		Tokens: append([]string{}, mw.Tokens...), Active: mw.Active, Revision: mw.Revision}
}

// ApplyWireMaintenance uebernimmt ein Wartungsfenster vom Server.
func (m *Module) ApplyWireMaintenance(ctx context.Context, w wire.Maintenance) error {
	ctx = WithRemote(ctx)
	existing, err := m.st.MaintenanceByRemote(ctx, w.ID)
	if err != nil {
		return err
	}
	mw := Maintenance{RemoteID: w.ID, Revision: w.Revision, Name: w.Name, StartAt: w.StartAt, EndAt: w.EndAt, Repeat: w.Repeat, RepeatUntil: w.RepeatUntil, Tokens: w.Tokens, Active: w.Active}
	if mw.Repeat == "" {
		mw.Repeat = "none"
	}
	if existing != nil {
		mw.ID = existing.ID
		return m.st.MaintenanceUpdate(ctx, &mw)
	}
	mw.CreatedAt = time.Now()
	return m.st.MaintenanceInsert(ctx, &mw)
}

// RemoveRemoteMaintenance loescht ein Wartungsfenster ueber seine Server-ID.
func (m *Module) RemoveRemoteMaintenance(ctx context.Context, remoteID int64) error {
	ctx = WithRemote(ctx)
	mw, err := m.st.MaintenanceByRemote(ctx, remoteID)
	if err != nil || mw == nil {
		return err
	}
	return m.st.MaintenanceDelete(ctx, mw.ID)
}

// SetMaintenanceRemote traegt nach einem ack die Server-ID und Revision ein.
func (m *Module) SetMaintenanceRemote(ctx context.Context, localID, remoteID, revision int64) error {
	var old int64
	_ = m.st.r.QueryRowContext(ctx, `SELECT remote_id FROM hc_maintenance WHERE id = ?`, localID).Scan(&old)
	_, err := m.st.w.ExecContext(ctx, `UPDATE hc_maintenance SET remote_id=?, revision=? WHERE id=?`, remoteID, revision, localID)
	m.st.reloadMaintenance(ctx)
	if err == nil && old == 0 && remoteID > 0 {
		m.LogMaintenanceRemote(ctx, localID) // die Gruppe ordnet das Fenster dem vom hub zu
	}
	return err
}

// SetCheckRevision setzt die Server-Revision eines Checks.
func (m *Module) SetCheckRevision(ctx context.Context, token string, rev int64) error {
	return m.st.SetRevision(ctx, token, rev)
}

// CheckByToken, MaintenanceByID: Lesezugriffe fuer den Client.
func (m *Module) CheckByToken(ctx context.Context, token string) (*Check, error) {
	return m.st.Check(ctx, token)
}
func (m *Module) MaintenanceByID(ctx context.Context, id int64) (*Maintenance, error) {
	list, err := m.st.MaintenanceList(ctx)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].ID == id {
			return &list[i], nil
		}
	}
	return nil, nil
}
func (m *Module) AllChecks(ctx context.Context) ([]*Check, error) { return m.st.Checks(ctx) }
func (m *Module) AllMaintenance(ctx context.Context) ([]Maintenance, error) {
	return m.st.MaintenanceList(ctx)
}

// StateOf liefert den Zustand eines Checks in Wire-Form.
func (m *Module) StateOf(token string, rt scheduler.Runtime) wire.State {
	return wire.State{Token: token, State: string(rt.State), LastStatus: string(rt.LastStatus), LatencyMS: msf(rt.LastLatency),
		Reason: string(rt.LastReason), Message: rt.LastMessage, Since: rt.Since, LastCheckAt: rt.LastCheck, NextCheckAt: rt.NextCheck,
		DownSince: rt.DownSince, ConsecutiveFail: rt.ConsecutiveFail, ConsecutiveOK: rt.ConsecutiveOK}
}

// Snapshot liefert die Zustaende aller eigenen Checks.
func (m *Module) Snapshot(ctx context.Context) []wire.State {
	list, err := m.st.Checks(ctx)
	if err != nil {
		return nil
	}
	var out []wire.State
	for _, c := range list {
		if !c.MeasuredHere() {
			continue
		}
		out = append(out, m.StateOf(c.Token, m.liveRuntime(c)))
	}
	return out
}

// PushState meldet den aktuellen Zustand eines Checks an den Sync (nach pausieren/fortsetzen).
func (m *Module) PushState(token string) {
	if m.st.OnRuntime == nil {
		return
	}
	if s := m.scheduler(); s != nil {
		if rt, ok := s.Runtime(token); ok {
			m.st.OnRuntime(token, rt)
			return
		}
	}
	if c, _ := m.st.Check(context.Background(), token); c != nil {
		m.st.OnRuntime(token, c.Runtime)
	}
}

// RunNow stoesst einen Check an.
// OnlinePushURL ist die Push-Adresse bei ipv64 (health.php); fuer lokale Checks reicht ipv64 sie an die Node weiter.
const OnlinePushURL = "https://ipv64.net/health.php?token="

// PushRemote nimmt einen ueber ipv64 eingegangenen Push an (Kommando "push" vom hub).
// Zu alte Pushes (Node war offline) werden verworfen, damit sie keinen Ausfall verdecken.
func (m *Module) PushRemote(ctx context.Context, token string, down bool, msg, from string, at time.Time) bool {
	if !at.IsZero() && time.Since(at) > 2*time.Minute {
		return false
	}
	s := m.scheduler()
	if s == nil {
		return false
	}
	status := checks.Up
	if down {
		status = checks.Down
	}
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return s.Push(ctx, token, status, msg, map[string]any{"via": "ipv64", "from": from})
}

func (m *Module) RunNow(token string) bool {
	if s := m.scheduler(); s != nil {
		return s.RunNow(token)
	}
	return false
}

// SetPausedRemote pausiert/setzt fort auf Anweisung des Servers (Kommando pause/resume).
// Bewusst als lokale Aenderung, damit der neue Wert ueber den Postausgang zum Server zurueckgeht.
func (m *Module) SetPausedRemote(ctx context.Context, token string, paused bool) error {
	if err := m.st.SetPaused(ctx, token, paused, "ipv64"); err != nil {
		return err
	}
	if c, _ := m.st.Check(ctx, token); c != nil {
		if s := m.scheduler(); s != nil && c.MeasuredHere() {
			s.Upsert(c.SchedulerCheck(), nil)
		}
	}
	m.PushState(token)
	return nil
}

// TestDefinition fuehrt eine Definition einmal aus (Testlauf beim Umhaengen).
func (m *Module) TestDefinition(ctx context.Context, w wire.Check) []checks.Result {
	def := checks.Definition{Token: w.Token, Type: checks.Type(w.Type), Target: w.Target, Params: w.Params, IPMode: checks.IPMode(w.IPMode),
		Timeouts: checks.Timeouts{Connect: time.Duration(w.ConnectTimeoutSeconds * float64(time.Second)), Total: time.Duration(w.TimeoutSeconds * float64(time.Second))}}
	if err := checks.Validate(def); err != nil {
		return []checks.Result{{Status: checks.Down, Reason: checks.ReasonInvalid, Message: err.Error(), Time: time.Now()}}
	}
	r := checks.NewRunner()
	r.PublicIP = m.publicIP
	return r.Run(ctx, def)
}

// ---------------------------------------------------------------- Messdaten-Export

// MeasurementsAfter liefert Messpunkte eigener Checks mit node_seq > seq (aelteste zuerst),
// ohne uebernommene Punkte anderer Messstellen (flags 8).
func (m *Module) MeasurementsAfter(ctx context.Context, seq int64, limit int) ([]wire.Measurement, error) {
	rows, err := m.st.r.QueryContext(ctx, `SELECT m.node_seq, m.token, m.time, m.status, m.latency_ms, m.reason, m.message, m.family, m.details, m.flags
		FROM hc_measurements m JOIN hc_checks c ON c.token = m.token WHERE m.node_seq > ? AND (m.flags & 8) = 0 AND (c.owner IN ('', 'self') OR (',' || c.nodes || ',') LIKE ?) ORDER BY m.node_seq LIMIT ?`, seq, "%,"+selfNodeID()+",%", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []wire.Measurement
	for rows.Next() {
		var w wire.Measurement
		var t, details string
		var status int
		if err := rows.Scan(&w.Seq, &w.Token, &t, &status, &w.LatencyMS, &w.Reason, &w.Message, &w.Family, &details, &w.Flags); err != nil {
			return nil, err
		}
		w.Time = pt(t)
		w.Status = "down"
		if status == 1 {
			w.Status = "up"
		}
		if details != "" {
			_ = json.Unmarshal([]byte(details), &w.Details)
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// MaxMeasurementSeq liefert die hoechste node_seq (fuer den Startwert).
func (m *Module) MaxMeasurementSeq(ctx context.Context) int64 {
	var v sql.NullInt64
	_ = m.st.r.QueryRowContext(ctx, `SELECT MAX(node_seq) FROM hc_measurements`).Scan(&v)
	return v.Int64
}

// EventsAfter liefert Ereignisse eigener Checks mit id > after.
func (m *Module) EventsAfter(ctx context.Context, after int64, limit int) ([]wire.Event, int64, error) {
	rows, err := m.st.r.QueryContext(ctx, `SELECT e.id, e.event_id, e.token, e.kind, e.time, e.from_state, e.to_state, e.reason, e.message, e.duration_sec, e.flaps, e.flags
		FROM hc_events e JOIN hc_checks c ON c.token = e.token WHERE e.id > ? AND (c.owner IN ('', 'self') OR (',' || c.nodes || ',') LIKE ?) ORDER BY e.id LIMIT ?`, after, "%,"+selfNodeID()+",%", limit)
	if err != nil {
		return nil, after, err
	}
	defer rows.Close()
	var out []wire.Event
	last := after
	for rows.Next() {
		var w wire.Event
		var id int64
		var t string
		if err := rows.Scan(&id, &w.EventID, &w.Token, &w.Kind, &t, &w.From, &w.To, &w.Reason, &w.Message, &w.DurationSec, &w.Flaps, &w.Flags); err != nil {
			return nil, after, err
		}
		w.Time = pt(t)
		out = append(out, w)
		last = id
	}
	return out, last, rows.Err()
}

// MaxEventID liefert die hoechste Ereignis-ID.
func (m *Module) MaxEventID(ctx context.Context) int64 {
	var v sql.NullInt64
	_ = m.st.r.QueryRowContext(ctx, `SELECT MAX(id) FROM hc_events`).Scan(&v)
	return v.Int64
}

// ---------------------------------------------------------------- Outbox / Konflikte

// Outbox ist eine ausstehende lokale Aenderung.
type Outbox struct {
	ID           int64
	Entity       string
	EntityID     string
	Op           string
	BaseRevision int64
	Payload      string
	CreatedAt    time.Time
	Status       string
	Error        string
}

// Conflict stellt lokale und Server-Version gegenueber.
type Conflict struct {
	ID             int64
	Entity         string
	EntityID       string
	LocalOp        string
	LocalPayload   string
	ServerPayload  string
	ServerRevision int64
	CreatedAt      time.Time
	// Error: Grund, mit dem der hub die Aenderung abgelehnt hat ("" = alter Eintrag, Server-Stand unbekannt).
	// Mit Grund und leerer ServerPayload hat der hub den Eintrag nicht.
	Error string
}

func (m *Module) OutboxAdd(ctx context.Context, entity, id, op string, base int64, payload string) error {
	// eine Zeile je Entitaet: die neueste Aenderung ersetzt aeltere (gleiche Basis bleibt)
	var oldBase sql.NullInt64
	_ = m.st.r.QueryRowContext(ctx, `SELECT base_revision FROM hc_outbox WHERE entity = ? AND entity_id = ? AND status = 'pending'`, entity, id).Scan(&oldBase)
	if oldBase.Valid {
		base = oldBase.Int64
		if _, err := m.st.w.ExecContext(ctx, `DELETE FROM hc_outbox WHERE entity = ? AND entity_id = ? AND status = 'pending'`, entity, id); err != nil {
			return err
		}
	}
	_, err := m.st.w.ExecContext(ctx, `INSERT INTO hc_outbox (entity, entity_id, op, base_revision, payload, created_at) VALUES (?,?,?,?,?,?)`, entity, id, op, base, payload, ft(time.Now()))
	return err
}

func (m *Module) OutboxPending(ctx context.Context) ([]Outbox, error) {
	rows, err := m.st.r.QueryContext(ctx, `SELECT id, entity, entity_id, op, base_revision, payload, created_at, status, error FROM hc_outbox WHERE status = 'pending' ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Outbox
	for rows.Next() {
		var o Outbox
		var t string
		if err := rows.Scan(&o.ID, &o.Entity, &o.EntityID, &o.Op, &o.BaseRevision, &o.Payload, &t, &o.Status, &o.Error); err != nil {
			return nil, err
		}
		o.CreatedAt = pt(t)
		out = append(out, o)
	}
	return out, rows.Err()
}

// OutboxErrors: Checks, deren Aenderung ipv64 abgelehnt hat (z. B. Online-Limit), Token -> Grund.
func (m *Module) OutboxErrors(ctx context.Context) map[string]string {
	out := map[string]string{}
	rows, err := m.st.r.QueryContext(ctx, `SELECT entity_id, error FROM hc_outbox WHERE entity = 'check' AND status = 'pending' AND error IS NOT NULL AND error != ''`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id, e string
		if rows.Scan(&id, &e) == nil {
			out[id] = e
		}
	}
	return out
}

func (m *Module) OutboxCount(ctx context.Context) int {
	var n int
	_ = m.st.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM hc_outbox WHERE status = 'pending'`).Scan(&n)
	return n
}

func (m *Module) OutboxHas(ctx context.Context, entity, id string) bool {
	var n int
	_ = m.st.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM hc_outbox WHERE entity = ? AND entity_id = ? AND status = 'pending'`, entity, id).Scan(&n)
	return n > 0
}

func (m *Module) OutboxDelete(ctx context.Context, id int64) error {
	_, err := m.st.w.ExecContext(ctx, `DELETE FROM hc_outbox WHERE id = ?`, id)
	return err
}

func (m *Module) OutboxDeleteEntity(ctx context.Context, entity, id string) error {
	_, err := m.st.w.ExecContext(ctx, `DELETE FROM hc_outbox WHERE entity = ? AND entity_id = ?`, entity, id)
	return err
}

func (m *Module) OutboxSetError(ctx context.Context, id int64, status, errText string) error {
	_, err := m.st.w.ExecContext(ctx, `UPDATE hc_outbox SET status = ?, error = ? WHERE id = ?`, status, errText, id)
	return err
}

func (m *Module) ConflictAdd(ctx context.Context, c Conflict) error {
	_, err := m.st.w.ExecContext(ctx, `INSERT OR REPLACE INTO hc_conflicts (entity, entity_id, local_op, local_payload, server_payload, server_revision, created_at, error) VALUES (?,?,?,?,?,?,?,?)`,
		c.Entity, c.EntityID, c.LocalOp, c.LocalPayload, c.ServerPayload, c.ServerRevision, ft(time.Now()), c.Error)
	return err
}

func (m *Module) Conflicts(ctx context.Context) ([]Conflict, error) {
	rows, err := m.st.r.QueryContext(ctx, `SELECT id, entity, entity_id, local_op, local_payload, server_payload, server_revision, created_at, error FROM hc_conflicts ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Conflict
	for rows.Next() {
		var c Conflict
		var t string
		if err := rows.Scan(&c.ID, &c.Entity, &c.EntityID, &c.LocalOp, &c.LocalPayload, &c.ServerPayload, &c.ServerRevision, &t, &c.Error); err != nil {
			return nil, err
		}
		c.CreatedAt = pt(t)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (m *Module) ConflictByID(ctx context.Context, id int64) (*Conflict, error) {
	list, err := m.Conflicts(ctx)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].ID == id {
			return &list[i], nil
		}
	}
	return nil, nil
}

func (m *Module) ConflictDelete(ctx context.Context, id int64) error {
	_, err := m.st.w.ExecContext(ctx, `DELETE FROM hc_conflicts WHERE id = ?`, id)
	return err
}

func (m *Module) ConflictCount(ctx context.Context) int {
	var n int
	_ = m.st.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM hc_conflicts`).Scan(&n)
	return n
}

// ConflictName liefert einen Anzeigenamen fuer die Konfliktliste.
func ConflictName(c Conflict) string {
	for _, p := range []string{c.LocalPayload, c.ServerPayload} {
		var x struct {
			Name string `json:"name"`
		}
		if p != "" && json.Unmarshal([]byte(p), &x) == nil && x.Name != "" {
			return x.Name
		}
	}
	return c.Entity + " " + c.EntityID
}

// SetOwnerAll setzt beim Trennen alle Checks wieder auf "self" (die Node misst, was sie hat).
func (m *Module) SetOwnerAllSelf(ctx context.Context) error {
	ctx = WithRemote(ctx)
	if _, err := m.st.w.ExecContext(ctx, `DELETE FROM hc_checks WHERE owner IN ('other', 'online')`); err != nil {
		return err
	}
	_, err := m.st.w.ExecContext(ctx, `UPDATE hc_checks SET owner = 'self', execution = 'local', nodes = ''`)
	if err != nil {
		return err
	}
	_, _ = m.st.w.ExecContext(ctx, `DELETE FROM hc_outbox`)
	_, _ = m.st.w.ExecContext(ctx, `DELETE FROM hc_conflicts`)
	_, _ = m.st.w.ExecContext(ctx, `UPDATE hc_maintenance SET remote_id = 0`)
	if s := m.scheduler(); s != nil {
		if list, err := m.st.Checks(ctx); err == nil {
			for _, c := range list {
				s.Upsert(c.SchedulerCheck(), m.adoptIncident(ctx, s, c.Token))
			}
		}
	}
	return nil
}

var _ = strconv.Itoa
var _ = strings.TrimSpace

// RemoteState ist der Zustand eines Checks, den diese Node nicht selbst misst (vom hub).
type RemoteState struct {
	Token     string    `json:"token"`
	State     string    `json:"state"`
	Since     time.Time `json:"since"`
	Source    string    `json:"source"`
	Time      time.Time `json:"time"`
	Status    string    `json:"status"`
	LatencyMS float64   `json:"latency_ms"`
	Reason    string    `json:"reason"`
	Message   string    `json:"message"`
	// je Messstelle (ab Hub 0.10.4; aeltere Hubs schicken nur den Gesamtzustand)
	SourceState string    `json:"source_state,omitempty"`
	SourceSince time.Time `json:"source_since,omitempty"`
	SourceLabel string    `json:"source_label,omitempty"`
}

// ApplyRemoteState uebernimmt Zustand und letzten Messpunkt eines fremden Checks (nur Anzeige):
// Gesamtzustand in hc_checks, Messpunkt in hc_measurements (flags 8 = von ipv64, wird nicht hochgeladen).
func (m *Module) ApplyRemoteState(ctx context.Context, r RemoteState) {
	c, _ := m.st.Check(ctx, r.Token)
	if c == nil {
		return
	}
	if r.Source != "" && r.SourceState != "" {
		m.applySource(ctx, c, r)
	}
	if c.MeasuredHere() {
		return
	}
	// misst eine nicht verknuepfte Node der Gruppe mit, bewertet die Gruppe (der hub zeigt den Check nur an)
	group := m.groupDecides != nil && c.Execution != "online" && m.groupDecides(ctx, c.Nodes)
	if r.State != "" && !group {
		_, _ = m.st.w.ExecContext(ctx, `UPDATE hc_checks SET state=?, state_since=?, last_check_at=?, last_status=?, last_latency_ms=?, last_reason=?, last_message=? WHERE token=?`,
			r.State, ft(r.Since), ft(r.Time), r.Status, r.LatencyMS, r.Reason, r.Message, r.Token)
		m.remoteIncident(ctx, r)
	}
	if r.Time.IsZero() || (r.Status != "up" && r.Status != "down") {
		return
	}
	var last string
	_ = m.st.r.QueryRowContext(ctx, `SELECT COALESCE(MAX(time), '') FROM hc_measurements WHERE token = ? AND details = ?`, r.Token, r.Source).Scan(&last)
	if last != "" && !r.Time.After(pt(last)) {
		return // schon bekannt
	}
	st := 0
	if r.Status == "up" {
		st = 1
	}
	_, _ = m.st.w.ExecContext(ctx, `INSERT INTO hc_measurements (token, time, status, latency_ms, reason, message, family, details, flags) VALUES (?,?,?,?,?,?,?,?,8)`,
		r.Token, ft(r.Time), st, r.LatencyMS, r.Reason, r.Message, "", r.Source)
}

// remoteIncident fuehrt Stoerungen fuer Checks, die ipv64 bewertet (Online-Checks, Checks anderer
// Nodes), nach denselben Regeln wie der Hub: "down" oeffnet, degraded/flapping halten offen,
// alles andere beendet. Beginn und Ende kommen aus dem Zeitpunkt des Zustandswechsels.
func (m *Module) remoteIncident(ctx context.Context, r RemoteState) {
	var id int64
	_ = m.st.r.QueryRowContext(ctx, `SELECT id FROM hc_incidents WHERE token = ? AND ended_at = '' ORDER BY id DESC LIMIT 1`, r.Token).Scan(&id)
	at := r.Since
	if at.IsZero() {
		at = time.Now().UTC()
	}
	switch r.State {
	case "down":
		if id == 0 {
			_, _ = m.st.OpenIncident(ctx, r.Token, at, checks.Reason(r.Reason), r.Message)
		}
	case "degraded", "flapping":
		// offen lassen bzw. nicht neu oeffnen (wie im Hub)
	default:
		if id != 0 {
			_ = m.st.CloseIncident(ctx, id, at)
		}
	}
}
