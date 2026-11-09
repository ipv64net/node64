package monitor64

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/store"
)

// Datenhaltung der Konfiguration und der Problem-Historie in node64.db (Tabellen m64_*, Migrationen des Moduls).

const dbTime = "2006-01-02T15:04:05.000Z"

func tsNow() string         { return time.Now().UTC().Format(dbTime) }
func ts(t time.Time) string { return t.UTC().Format(dbTime) }
func parseTS(s string) time.Time {
	t, _ := time.Parse(dbTime, s)
	return t
}

// newUID: clusterweite Kennung eines Eintrags.
func newUID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Actor ist, wer etwas getan hat (Plan "Wer war es"): Benutzer (UID, Name, Anmeldeart), API-Key oder System.
type Actor struct {
	Kind   string `json:"kind"`             // user, api, system
	UID    string `json:"uid,omitempty"`    // clusterweite Benutzer-UID
	Name   string `json:"name,omitempty"`   // Name zum Zeitpunkt der Aktion
	Method string `json:"method,omitempty"` // local, sso, ldap
	IP     string `json:"ip,omitempty"`
}

// SystemActor: automatisch (z. B. Wert wieder unter der Schwelle).
var SystemActor = Actor{Kind: "system"}

func (a Actor) json() string {
	b, _ := json.Marshal(a)
	return string(b)
}

func parseActor(s string) Actor {
	var a Actor
	_ = json.Unmarshal([]byte(s), &a)
	return a
}

// ErrNotFound: Eintrag gibt es nicht (oder geloescht).
var ErrNotFound = errors.New("monitor64: not found")

// Host ist ein ueberwachtes System.
type Host struct {
	UID           string    `json:"uid"`
	Name          string    `json:"name"`
	Address       string    `json:"address"`
	Kind          string    `json:"kind"`
	Group         string    `json:"group"`
	Tags          []string  `json:"tags"`
	IntervalSec   int       `json:"interval_sec"`
	OwnerNode     string    `json:"owner_node,omitempty"`
	PreferredNode string    `json:"preferred_node,omitempty"`
	BackupNodes   []string  `json:"backup_nodes,omitempty"`
	AgentAutoUpd  bool      `json:"agent_autoupdate"`
	Paused        bool      `json:"paused"`
	Notes         string    `json:"notes,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Access ist ein Zugang eines Hosts (Geheimnis verschluesselt, nie in JSON-Antworten).
type Access struct {
	UID     string          `json:"uid"`
	HostUID string          `json:"host_uid"`
	Type    string          `json:"type"` // agent, ssh, snmp, pve, pbs, docker, prom
	Config  json.RawMessage `json:"config"`
	Secret  string          `json:"-"` // verschluesselt (internal/secrets)
	HostKey string          `json:"hostkey,omitempty"`
	Enabled bool            `json:"enabled"`
}

// ServiceRow ist ein Dienst eines Hosts in der Konfiguration.
type ServiceRow struct {
	UID        string    `json:"uid"`
	HostUID    string    `json:"host_uid"`
	Key        string    `json:"key"`
	Name       string    `json:"name"`
	Kind       string    `json:"kind"`
	Adopted    int       `json:"adopted"` // 1 uebernommen, 0 neu (Hinweis), -1 ignoriert
	VanishedAt time.Time `json:"vanished_at,omitzero"`
	Via        string    `json:"via,omitempty"`
	HostRule   string    `json:"host_rule,omitempty"`
	Soll       string    `json:"soll,omitempty"`
	Report     string    `json:"report,omitempty"`
}

// Store ist die Datenhaltung des Moduls.
type Store struct{ st *store.Store }

func newStore(st *store.Store) *Store { return &Store{st: st} }

func jsonList(l []string) string {
	if l == nil {
		l = []string{}
	}
	b, _ := json.Marshal(l)
	return string(b)
}

func parseList(s string) []string {
	var l []string
	_ = json.Unmarshal([]byte(s), &l)
	return l
}

// normTags: klein, ohne Leerzeichen, ohne Doppelte.
func normTags(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" || seen[t] || len(t) > 64 {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

const hostCols = `uid, name, address, kind, group_name, tags, interval_sec, owner_node, preferred_node, backup_nodes, agent_autoupd, paused, notes, created_at, updated_at`

func scanHost(row interface{ Scan(...any) error }) (*Host, error) {
	var h Host
	var tags, backups, created, updated string
	var auto, paused int
	if err := row.Scan(&h.UID, &h.Name, &h.Address, &h.Kind, &h.Group, &tags, &h.IntervalSec, &h.OwnerNode, &h.PreferredNode, &backups, &auto, &paused, &h.Notes, &created, &updated); err != nil {
		return nil, err
	}
	h.Tags, h.BackupNodes = parseList(tags), parseList(backups)
	h.AgentAutoUpd, h.Paused = auto == 1, paused == 1
	h.CreatedAt, h.UpdatedAt = parseTS(created), parseTS(updated)
	return &h, nil
}

// Hosts liefert alle (nicht geloeschten) Hosts, nach Gruppe und Name.
func (s *Store) Hosts(ctx context.Context) ([]*Host, error) {
	rows, err := s.st.Reader().QueryContext(ctx, `SELECT `+hostCols+` FROM m64_hosts WHERE deleted = 0 ORDER BY group_name, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// Host liefert einen Host.
func (s *Store) Host(ctx context.Context, uid string) (*Host, error) {
	h, err := scanHost(s.st.Reader().QueryRowContext(ctx, `SELECT `+hostCols+` FROM m64_hosts WHERE uid = ? AND deleted = 0`, uid))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return h, err
}

// SaveHost legt einen Host an (UID leer) oder aendert ihn.
func (s *Store) SaveHost(ctx context.Context, h *Host, by Actor) error {
	h.Tags = normTags(h.Tags)
	h.IntervalSec = int(clampInterval(time.Duration(h.IntervalSec)*time.Second) / time.Second)
	now := tsNow()
	auto := 0
	if h.AgentAutoUpd {
		auto = 1
	}
	paused := 0
	if h.Paused {
		paused = 1
	}
	if h.UID == "" {
		h.UID = newUID()
		_, err := s.st.Writer().ExecContext(ctx, `INSERT INTO m64_hosts (uid, name, address, kind, group_name, tags, interval_sec, owner_node, preferred_node, backup_nodes, agent_autoupd, paused, notes, created_at, created_by, updated_at, updated_by)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			h.UID, h.Name, h.Address, h.Kind, h.Group, jsonList(h.Tags), h.IntervalSec, h.OwnerNode, h.PreferredNode, jsonList(h.BackupNodes), auto, paused, h.Notes, now, by.json(), now, by.json())
		return err
	}
	// owner_node fuehrt der Cluster (cluster_owner.go), eine Aenderung am Host laesst sie stehen
	res, err := s.st.Writer().ExecContext(ctx, `UPDATE m64_hosts SET name = ?, address = ?, kind = ?, group_name = ?, tags = ?, interval_sec = ?, preferred_node = ?, backup_nodes = ?, agent_autoupd = ?, paused = ?, notes = ?, updated_at = ?, updated_by = ?
		WHERE uid = ? AND deleted = 0`,
		h.Name, h.Address, h.Kind, h.Group, jsonList(h.Tags), h.IntervalSec, h.PreferredNode, jsonList(h.BackupNodes), auto, paused, h.Notes, now, by.json(), h.UID)
	return affected(res, err)
}

// DeleteHost setzt den Loeschvermerk (Host, Zugaenge, Dienste); Problem-Historie bleibt.
func (s *Store) DeleteHost(ctx context.Context, uid string, by Actor) error {
	tx, err := s.st.Writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := tsNow()
	res, err := tx.ExecContext(ctx, `UPDATE m64_hosts SET deleted = 1, updated_at = ?, updated_by = ? WHERE uid = ? AND deleted = 0`, now, by.json(), uid)
	if err := affected(res, err); err != nil {
		return err
	}
	for _, t := range []string{"m64_access", "m64_services", "m64_host_rules"} {
		if _, err := tx.ExecContext(ctx, `UPDATE `+t+` SET deleted = 1, updated_at = ?, updated_by = ? WHERE host_uid = ? AND deleted = 0`, now, by.json(), uid); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func affected(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Accesses liefert die Zugaenge eines Hosts (leer = alle Hosts).
func (s *Store) Accesses(ctx context.Context, hostUID string) ([]*Access, error) {
	q := `SELECT uid, host_uid, type, config, secret, hostkey, enabled FROM m64_access WHERE deleted = 0`
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
	var out []*Access
	for rows.Next() {
		var a Access
		var cfg string
		var en int
		if err := rows.Scan(&a.UID, &a.HostUID, &a.Type, &cfg, &a.Secret, &a.HostKey, &en); err != nil {
			return nil, err
		}
		a.Config, a.Enabled = json.RawMessage(cfg), en == 1
		out = append(out, &a)
	}
	return out, rows.Err()
}

// SaveAccess legt einen Zugang an oder aendert ihn (Secret bereits verschluesselt; leer bei Aenderung = unveraendert).
func (s *Store) SaveAccess(ctx context.Context, a *Access, keepSecret bool, by Actor) error {
	if len(a.Config) == 0 {
		a.Config = json.RawMessage(`{}`)
	}
	en := 0
	if a.Enabled {
		en = 1
	}
	now := tsNow()
	if a.UID == "" {
		a.UID = newUID()
		_, err := s.st.Writer().ExecContext(ctx, `INSERT INTO m64_access (uid, host_uid, type, config, secret, hostkey, enabled, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			a.UID, a.HostUID, a.Type, string(a.Config), a.Secret, a.HostKey, en, now, by.json())
		return err
	}
	if keepSecret {
		res, err := s.st.Writer().ExecContext(ctx, `UPDATE m64_access SET type = ?, config = ?, hostkey = ?, enabled = ?, updated_at = ?, updated_by = ? WHERE uid = ? AND deleted = 0`,
			a.Type, string(a.Config), a.HostKey, en, now, by.json(), a.UID)
		return affected(res, err)
	}
	res, err := s.st.Writer().ExecContext(ctx, `UPDATE m64_access SET type = ?, config = ?, secret = ?, hostkey = ?, enabled = ?, updated_at = ?, updated_by = ? WHERE uid = ? AND deleted = 0`,
		a.Type, string(a.Config), a.Secret, a.HostKey, en, now, by.json(), a.UID)
	return affected(res, err)
}

// SetHostKey merkt den Hostschluessel eines Zugangs (TOFU; System).
func (s *Store) SetHostKey(ctx context.Context, accessUID, fp string) error {
	_, err := s.st.Writer().ExecContext(ctx, `UPDATE m64_access SET hostkey = ?, updated_at = ? WHERE uid = ? AND deleted = 0`, fp, tsNow(), accessUID)
	return err
}

// SetAccessNode traegt die erkannte Proxmox-Node in die Konfiguration ein, falls dort noch keine steht (System).
func (s *Store) SetAccessNode(ctx context.Context, accessUID, node string) error {
	_, err := s.st.Writer().ExecContext(ctx, `UPDATE m64_access SET config = json_set(CASE WHEN json_valid(config) THEN config ELSE '{}' END, '$.node', ?), updated_at = ?
		WHERE uid = ? AND deleted = 0 AND COALESCE(json_extract(CASE WHEN json_valid(config) THEN config ELSE '{}' END, '$.node'), '') = ''`, node, tsNow(), accessUID)
	return err
}

// DeleteAccess setzt den Loeschvermerk eines Zugangs.
func (s *Store) DeleteAccess(ctx context.Context, uid string, by Actor) error {
	res, err := s.st.Writer().ExecContext(ctx, `UPDATE m64_access SET deleted = 1, updated_at = ?, updated_by = ? WHERE uid = ? AND deleted = 0`, tsNow(), by.json(), uid)
	return affected(res, err)
}

// Services liefert die Dienste eines Hosts (leer = alle).
func (s *Store) Services(ctx context.Context, hostUID string) ([]*ServiceRow, error) {
	q := `SELECT uid, host_uid, key, name, kind, adopted, vanished_at, via, host_rule, soll, report FROM m64_services WHERE deleted = 0`
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
	var out []*ServiceRow
	for rows.Next() {
		var r ServiceRow
		var van string
		if err := rows.Scan(&r.UID, &r.HostUID, &r.Key, &r.Name, &r.Kind, &r.Adopted, &van, &r.Via, &r.HostRule, &r.Soll, &r.Report); err != nil {
			return nil, err
		}
		r.VanishedAt = parseTS(van)
		out = append(out, &r)
	}
	return out, rows.Err()
}

// UpsertDiscovered traegt erkannte Dienste ein: neue als Hinweis (adopted 0) bzw. sofort uebernommen
// (adopt = true, beim Anlegen im Assistenten bestaetigt); vorhandene behalten ihren Zustand, "verschwunden" endet.
// Nicht vorgeschlagene Dienste (Default false, z. B. einzelne Windows-Dienste, gestoppte Gaeste) kommen als
// "ignoriert" (adopted -1, Akteur System) dazu: so lassen sie sich spaeter uebernehmen, ohne die Liste der neuen Dienste
// zu fuellen; werden sie spaeter vorgeschlagen (z. B. Port mit Link), rutschen sie zu den neuen. Vom Benutzer
// ignorierte bleiben ignoriert. Nie automatisch uebernehmen (Plan "Dienste erkennen").
func (s *Store) UpsertDiscovered(ctx context.Context, hostUID string, found []Service, adopt map[string]bool, by Actor) (added int, err error) {
	tx, err := s.st.Writer().BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	type cur struct {
		deleted  bool
		adopted  int
		systemBy bool // zuletzt vom System gesetzt (nicht vorgeschlagen), nicht vom Benutzer ignoriert
	}
	sys := SystemActor.json()
	known := map[string]cur{}
	rows, err := tx.QueryContext(ctx, `SELECT key, deleted, adopted, updated_by FROM m64_services WHERE host_uid = ?`, hostUID)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var k, upBy string
		var del, ad int
		if err := rows.Scan(&k, &del, &ad, &upBy); err != nil {
			rows.Close()
			return 0, err
		}
		known[k] = cur{deleted: del == 1, adopted: ad, systemBy: upBy == sys}
	}
	rows.Close()
	now := tsNow()
	for _, f := range found {
		state := 0
		if adopt[f.Key] {
			state = 1
		}
		offered := f.Default || state == 1
		c, ok := known[f.Key]
		switch {
		case !ok && !offered: // nicht vorgeschlagen: uebernehmbar, aber nicht als neu gezaehlt
			if _, err := tx.ExecContext(ctx, `INSERT INTO m64_services (uid, host_uid, key, name, kind, adopted, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, -1, ?, ?)`,
				newUID(), hostUID, f.Key, f.Name, f.Kind, now, sys); err != nil {
				return 0, err
			}
		case !ok:
			if _, err := tx.ExecContext(ctx, `INSERT INTO m64_services (uid, host_uid, key, name, kind, adopted, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				newUID(), hostUID, f.Key, f.Name, f.Kind, state, now, by.json()); err != nil {
				return 0, err
			}
			added++
		case c.deleted && !offered: // vom Benutzer entfernt und nicht vorgeschlagen: bleibt weg
		case c.deleted: // frueher entfernt: wieder als neu anbieten
			if _, err := tx.ExecContext(ctx, `UPDATE m64_services SET deleted = 0, adopted = ?, vanished_at = '', updated_at = ?, updated_by = ? WHERE host_uid = ? AND key = ?`,
				state, now, by.json(), hostUID, f.Key); err != nil {
				return 0, err
			}
			added++
		default: // vorhanden: "verschwunden" endet
			if _, err := tx.ExecContext(ctx, `UPDATE m64_services SET vanished_at = '', updated_at = ? WHERE host_uid = ? AND key = ? AND vanished_at != ''`,
				now, hostUID, f.Key); err != nil {
				return 0, err
			}
			switch {
			case state == 1:
				if _, err := tx.ExecContext(ctx, `UPDATE m64_services SET adopted = 1, updated_at = ?, updated_by = ? WHERE host_uid = ? AND key = ? AND (adopted = 0 OR adopted = -1 AND updated_by = ?)`,
					now, by.json(), hostUID, f.Key, sys); err != nil {
					return 0, err
				}
			case f.Default && c.adopted == -1 && c.systemBy: // bisher nicht vorgeschlagen, jetzt schon: zu den neuen
				if _, err := tx.ExecContext(ctx, `UPDATE m64_services SET adopted = 0, updated_at = ?, updated_by = ? WHERE host_uid = ? AND key = ? AND adopted = -1 AND updated_by = ?`,
					now, sys, hostUID, f.Key, sys); err != nil {
					return 0, err
				}
				added++
			}
		}
	}
	return added, tx.Commit()
}

// MarkVanished merkt uebernommene Dienste, die nicht mehr geliefert werden (bleiben bis "Entfernen").
func (s *Store) MarkVanished(ctx context.Context, hostUID string, keys []string, at time.Time) error {
	for _, k := range keys {
		if _, err := s.st.Writer().ExecContext(ctx, `UPDATE m64_services SET vanished_at = ?, updated_at = ? WHERE host_uid = ? AND key = ? AND adopted = 1 AND vanished_at = '' AND deleted = 0`,
			ts(at), tsNow(), hostUID, k); err != nil {
			return err
		}
	}
	return nil
}

// ClearVanished: Dienst wird wieder geliefert ("verschwunden" endet sofort).
func (s *Store) ClearVanished(ctx context.Context, hostUID, key string) error {
	_, err := s.st.Writer().ExecContext(ctx, `UPDATE m64_services SET vanished_at = '', updated_at = ? WHERE host_uid = ? AND key = ? AND vanished_at != '' AND deleted = 0`,
		tsNow(), hostUID, key)
	return err
}

// SetAdopted uebernimmt (1), ignoriert (-1) oder entfernt (deleted) einen Dienst.
func (s *Store) SetAdopted(ctx context.Context, hostUID, key string, state int, by Actor) error {
	res, err := s.st.Writer().ExecContext(ctx, `UPDATE m64_services SET adopted = ?, updated_at = ?, updated_by = ? WHERE host_uid = ? AND key = ? AND deleted = 0`,
		state, tsNow(), by.json(), hostUID, key)
	return affected(res, err)
}

// RemoveService entfernt einen Dienst (aktiver Klick "Entfernen", z. B. nach "verschwunden").
func (s *Store) RemoveService(ctx context.Context, hostUID, key string, by Actor) error {
	res, err := s.st.Writer().ExecContext(ctx, `UPDATE m64_services SET deleted = 1, updated_at = ?, updated_by = ? WHERE host_uid = ? AND key = ? AND deleted = 0`,
		tsNow(), by.json(), hostUID, key)
	return affected(res, err)
}

// Runtime liest den gespeicherten Laufzeitstand eines Hosts (nicht abgeglichen).
func (s *Store) Runtime(ctx context.Context, hostUID string) ([]byte, error) {
	var st string
	err := s.st.Reader().QueryRowContext(ctx, `SELECT state FROM m64_runtime WHERE host_uid = ?`, hostUID).Scan(&st)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return []byte(st), err
}

// SaveRuntime speichert den Laufzeitstand eines Hosts.
func (s *Store) SaveRuntime(ctx context.Context, hostUID string, state []byte) error {
	_, err := s.st.Writer().ExecContext(ctx, `INSERT INTO m64_runtime (host_uid, state, updated_at) VALUES (?, ?, ?)
		ON CONFLICT (host_uid) DO UPDATE SET state = excluded.state, updated_at = excluded.updated_at`, hostUID, string(state), tsNow())
	return err
}
