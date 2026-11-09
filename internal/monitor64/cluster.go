package monitor64

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/eval"
)

// Monitor64 im Cluster (Plan "Cluster (Konzept fuer Phase 4)", docs/CLUSTER.md Abschnitt "Monitor64"). Verbunden ueber
// monitor64/m64cluster, damit das Modul nicht vom Cluster abhaengt. Zwei Bereiche:
//
//   - config (gemeinsam, juengere Aenderung gewinnt): Hosts mit bevorzugter und Ersatz-Nodes, Zugaenge (Geheimnisse im
//     Klartext ueber die Cluster-Verbindung, auf der Empfaengerin mit ihrem Schluessel gespeichert; Hostschluessel mit),
//     Dienste (uebernommen/ignoriert, Namen, Schwellen am Dienst), Einstellungen am Host, Abweichungen, Wartung,
//     Standard-Schwellen, Benachrichtigung, gemeinsame Einstellungen, die zustaendige Node je Host und der gemeinsame
//     Cluster-Schluessel.
//   - status (gehoert einer Node, kein Konflikt): Probleme samt Ablauf (Quittierungen, Kommentare, "gemeldet an"),
//     Zustand und letzter Wert der Hosts je Node.
//
// Nur lokal: Verlauf (monitor64.db; Diagramme fragen live bei der Node, cluster_series.go), Arbeiter-Zahl, Trap- und
// Push-Port, Agent-Download-Zwischenspeicher.
//
// Eigene Aenderungen erkennt die Node an allen Schreibstellen ueber Aenderungszeit und Loeschvermerk der Zeilen
// (clusterScan, alle paar Sekunden): was sich gegenueber dem zuletzt gemeldeten bzw. uebernommenen Stand (m64_csync)
// geaendert hat, geht an den Cluster. Uebernommene Staende behalten die Aenderungszeit der Urheberin.

// Bereiche im Cluster (Modul monitor64).
const (
	ClusterModuleID   = "monitor64"
	ClusterTitleKey   = "cluster.mod.monitor64"
	ClusterItemConfig = "config"
	ClusterItemStatus = "status"
)

// ClusterCalls sind die Anfragen, die andere Nodes stellen duerfen (HandleClusterCall).
var ClusterCalls = []string{callSeries, callRepoll, callReach}

var (
	clusterScanEvery = 2 * time.Second  // eigene Aenderungen suchen
	clusterTick      = 30 * time.Second // Blick auf die Mitglieder (Uebernahme, Rueckgabe, Probleme, Schluessel)
	clusterReloadLag = 300 * time.Millisecond

	reNodeID  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	reUID     = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	errClItem = errors.New("monitor64 cluster: unknown area or entry")
)

// ClusterPeer ist eine andere Node, mit der ein Bereich abgeglichen wird.
type ClusterPeer struct {
	ID     string
	Name   string
	Online bool
}

// ClusterHooks verbinden das Modul mit dem Cluster (main.go ueber monitor64/m64cluster); leer = kein Cluster.
type ClusterHooks struct {
	// Change meldet eine Aenderung eines Eintrags (ctx traegt bei Uebernahmen die Herkunft).
	Change func(ctx context.Context, item, id string, deleted bool)
	// Members: Nodes, mit denen der Bereich abgeglichen wird (hier und dort an, nicht ausgesetzt); leer = allein bzw.
	// Bereich hier aus.
	Members func(ctx context.Context, item string) []ClusterPeer
	// Self: Kennung dieser Node.
	Self func() string
	// Call fragt eine andere Node (HandleClusterCall dort).
	Call func(ctx context.Context, node, name string, in, out any) error
}

// SetCluster haengt den Cluster an (vor Start).
func (m *Module) SetCluster(h ClusterHooks) { m.cl.hooks.Store(&h) }

// hooks liefert die Anbindung (leer ohne Cluster; das Modul kann vor dem Cluster starten).
func (m *Module) hooks() ClusterHooks {
	if h := m.cl.hooks.Load(); h != nil {
		return *h
	}
	return ClusterHooks{}
}

// ClusterRunning: das Modul laeuft (sonst sind die Bereiche auf dieser Node aus und sie wird nie zustaendig).
func (m *Module) ClusterRunning() bool { return m.scheduler() != nil }

// clusterRT ist der Stand des Clusters im Modul (nur im Speicher, ausser m64_csync/m64_cstate).
type clusterRT struct {
	hooks atomic.Pointer[ClusterHooks]
	now   func() time.Time // Tests

	csMu      sync.Mutex // Suche eigener Aenderungen und Uebernahmen nacheinander
	scanFrom  string     // Aenderungszeit, ab der gesucht wird ("" = alles)
	eventMax  int64      // hoechste gesehene Ereignis-Nummer
	snap      atomic.Pointer[clusterSnap]
	mu        sync.Mutex
	since     map[string]time.Time // erreichbar seit (Nullzeit: schon beim ersten Blick erreichbar)
	known     map[string]bool
	roles     map[string]int // Host -> letzte Rolle dieser Node (Wechsel erkennen)
	views     map[string]map[string]*stateEntry
	viewsInit bool
	started   time.Time
	dirtyCfg  bool
	dirtyHost map[string]bool
	timer     *time.Timer
	bg        sync.WaitGroup // Hosts neu laden nach einem Schluesselwechsel (Tests warten darauf)
}

func (c *clusterRT) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (m *Module) clusterSelf() string {
	if m.hooks().Self != nil {
		if s := m.hooks().Self(); s != "" {
			return s
		}
	}
	return m.nodeID()
}

// clusterChange meldet eine Aenderung an den Cluster (ohne Cluster: nichts).
func (m *Module) clusterChange(ctx context.Context, item, id string, deleted bool) {
	if m.hooks().Change != nil && id != "" {
		m.hooks().Change(ctx, item, id, deleted)
	}
}

// supersededErr: die Aenderung wurde bewusst nicht (ganz) uebernommen, der eigene Stand ist neu gemeldet.
type supersededErr struct{ what string }

func (e supersededErr) Error() string    { return "monitor64 cluster: own state kept (" + e.what + ")" }
func (e supersededErr) Superseded() bool { return true }

// ---------------------------------------------------------------------------------------------------------
// Eintraege

// clTable: abgeglichene Tabelle mit ihren Spalten (ohne id; Hosts ohne owner_node, die laeuft als eigener Eintrag).
type clTable struct {
	kind, table string
	cols        []string
}

var clTables = func() []clTable {
	kinds := map[string]string{"m64_hosts": "host", "m64_access": "access", "m64_services": "service", "m64_host_rules": "hostrule",
		"m64_overrides": "override", "m64_maint": "maint"}
	var out []clTable
	for _, t := range exportTables {
		cols := make([]string, 0, len(t.cols))
		for _, c := range t.cols {
			if c != "owner_node" {
				cols = append(cols, c)
			}
		}
		out = append(out, clTable{kind: kinds[t.name], table: t.name, cols: cols})
	}
	return out
}()

func clTableOf(kind string) *clTable {
	for i := range clTables {
		if clTables[i].kind == kind {
			return &clTables[i]
		}
	}
	return nil
}

// clSettings: gemeinsame Einstellungen (Arbeiter-Zahl, Trap-/Push-Port und Engine-ID bleiben je Node).
var clSettings = []string{setStd, setNotify, setInterval, setProm, setPromTags}

func sharedSetting(k string) bool {
	for _, s := range clSettings {
		if s == k {
			return true
		}
	}
	return false
}

// ClusterIDs: alle vorhandenen Eintraege eines Bereichs (erster Abgleich).
func (m *Module) ClusterIDs(ctx context.Context, item string) ([]string, error) {
	var out []string
	add := func(q, prefix string, args ...any) error {
		rows, err := m.st.Reader().QueryContext(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if rows.Scan(&id) == nil && id != "" {
				out = append(out, prefix+id)
			}
		}
		return rows.Err()
	}
	switch item {
	case ClusterItemConfig:
		for _, t := range clTables {
			if err := add(`SELECT uid FROM `+t.table+` WHERE deleted = 0 ORDER BY id`, t.kind+":"); err != nil {
				return nil, err
			}
		}
		if err := add(`SELECT uid FROM m64_hosts WHERE deleted = 0 AND owner_node != '' ORDER BY id`, "owner:"); err != nil {
			return nil, err
		}
		for _, k := range clSettings {
			if _, ok, _ := m.st.Setting(ctx, k); ok {
				out = append(out, "setting:"+k)
			}
		}
		if m.st.SettingOr(ctx, setKeyCluster, "") != "" {
			out = append(out, "key:cluster")
		}
	case ClusterItemStatus:
		if err := add(`SELECT uid FROM m64_problems WHERE deleted = 0 ORDER BY id`, "problem:"); err != nil {
			return nil, err
		}
		self := m.clusterSelf()
		if err := add(`SELECT host_uid FROM m64_cstate WHERE node_id = ?`, "state:", self); err != nil {
			return nil, err
		}
		for i, id := range out {
			if strings.HasPrefix(id, "state:") {
				out[i] = id + ":" + self
			}
		}
	default:
		return nil, errClItem
	}
	return out, nil
}

// ClusterGet liefert einen Eintrag (found=false: gibt es nicht bzw. geloescht).
func (m *Module) ClusterGet(ctx context.Context, item, id string) (json.RawMessage, bool, error) {
	kind, uid, ok := strings.Cut(id, ":")
	if !ok {
		return nil, false, errClItem
	}
	switch {
	case item == ClusterItemConfig && kind == "setting":
		if !sharedSetting(uid) {
			return nil, false, errClItem
		}
		v, found, err := m.st.Setting(ctx, uid)
		if err != nil || !found {
			return nil, false, err
		}
		if uid == setNotify {
			v = m.notifyToCluster(ctx, v)
		}
		b, err := json.Marshal(map[string]string{"value": v})
		return b, err == nil, err
	case item == ClusterItemConfig && kind == "owner":
		return m.ownerGet(ctx, uid)
	case item == ClusterItemConfig && kind == "key":
		return m.keyGet(ctx)
	case item == ClusterItemConfig:
		t := clTableOf(kind)
		if t == nil {
			return nil, false, errClItem
		}
		row, err := m.clRow(ctx, t, uid)
		if err != nil || row == nil {
			return nil, false, err
		}
		if fmt.Sprint(row["deleted"]) == "1" {
			return nil, false, nil
		}
		switch t.kind {
		case "host":
			if fmt.Sprint(row["preferred_node"]) == "" { // ohne Wahl: die Node, auf der der Host angelegt wurde
				row["preferred_node"] = m.clusterSelf()
			}
		case "access":
			if enc := fmt.Sprint(row["secret"]); enc != "" {
				plain, err := m.box.Decrypt(enc)
				if err != nil {
					return json.RawMessage(`{"incomplete":true}`), true, nil
				}
				row["secret"] = plain
			}
		case "override":
			if fmt.Sprint(row["scope"]) == "notify" {
				row["data"] = m.notifyOverrideToCluster(ctx, fmt.Sprint(row["data"]))
			}
		}
		b, err := json.Marshal(row)
		return b, err == nil, err
	case item == ClusterItemStatus && kind == "problem":
		return m.problemGet(ctx, uid)
	case item == ClusterItemStatus && kind == "state":
		return m.stateGet(ctx, uid)
	}
	return nil, false, errClItem
}

// ClusterApply uebernimmt einen Eintrag einer anderen Node (anlegen, aendern, loeschen).
func (m *Module) ClusterApply(ctx context.Context, item, id string, data json.RawMessage, deleted bool) error {
	kind, uid, ok := strings.Cut(id, ":")
	if !ok {
		return errClItem
	}
	m.cl.csMu.Lock()
	defer m.cl.csMu.Unlock()
	switch {
	case item == ClusterItemConfig && kind == "setting":
		return m.settingApply(ctx, uid, data, deleted)
	case item == ClusterItemConfig && kind == "owner":
		return m.ownerApply(ctx, uid, data, deleted)
	case item == ClusterItemConfig && kind == "key":
		return m.keyApply(ctx, data, deleted)
	case item == ClusterItemConfig:
		t := clTableOf(kind)
		if t == nil || !reUID.MatchString(uid) {
			return errClItem
		}
		return m.rowApply(ctx, t, uid, data, deleted)
	case item == ClusterItemStatus && kind == "problem":
		if !reUID.MatchString(uid) {
			return errClItem
		}
		return m.problemApply(ctx, uid, data, deleted)
	case item == ClusterItemStatus && kind == "state":
		return m.stateApply(ctx, uid, data, deleted)
	}
	return errClItem
}

// clRow liest eine Zeile als Spalten-Map (nil = gibt es nicht).
func (m *Module) clRow(ctx context.Context, t *clTable, uid string) (map[string]any, error) {
	vals := make([]any, len(t.cols))
	ptrs := make([]any, len(t.cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	err := m.st.Reader().QueryRowContext(ctx, `SELECT `+strings.Join(t.cols, ", ")+` FROM `+t.table+` WHERE uid = ?`, uid).Scan(ptrs...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	row := map[string]any{}
	for i, c := range t.cols {
		if b, ok := vals[i].([]byte); ok {
			vals[i] = string(b)
		}
		row[c] = vals[i]
	}
	return row, nil
}

// clUpsert schreibt eine Zeile (alle Spalten wie geliefert, Konflikt ueber uid).
func clUpsert(ctx context.Context, tx *sql.Tx, table string, cols []string, row map[string]any) error {
	args := make([]any, len(cols))
	sets := make([]string, 0, len(cols))
	for i, c := range cols {
		v := row[c]
		switch x := v.(type) {
		case float64:
			v = int64(x)
		case nil:
			v = ""
		case string, int64, bool:
		default:
			b, _ := json.Marshal(x) // verschachteltes JSON (z. B. eine Liste) als Text
			v = string(b)
		}
		args[i] = v
		if c != "uid" {
			sets = append(sets, c+" = excluded."+c)
		}
	}
	q := `INSERT INTO ` + table + ` (` + strings.Join(cols, ", ") + `) VALUES (` + strings.TrimSuffix(strings.Repeat("?, ", len(cols)), ", ") +
		`) ON CONFLICT (uid) DO UPDATE SET ` + strings.Join(sets, ", ")
	_, err := tx.ExecContext(ctx, q, args...)
	return err
}

// rowApply uebernimmt Host, Zugang, Dienst, Einstellung am Host, Abweichung oder Wartungsfenster.
func (m *Module) rowApply(ctx context.Context, t *clTable, uid string, data json.RawMessage, deleted bool) error {
	db := m.st.Writer()
	if deleted {
		cur, err := m.clRow(ctx, t, uid)
		if err != nil || cur == nil || fmt.Sprint(cur["deleted"]) == "1" {
			return err
		}
		upd := fmt.Sprint(cur["updated_at"])
		if _, at, ok := clusterOriginOf(ctx); ok {
			upd = ts(at)
		}
		if _, err := db.ExecContext(ctx, `UPDATE `+t.table+` SET deleted = 1, updated_at = ? WHERE uid = ?`, upd, uid); err != nil {
			return err
		}
		m.csyncMark(ctx, t, uid)
		if t.kind == "host" { // Zugaenge, Dienste und Einstellungen des Hosts mit (wie DeleteHost)
			for _, sub := range []string{"access", "service", "hostrule"} {
				st := clTableOf(sub)
				var uids []string
				if rows, err := db.QueryContext(ctx, `SELECT uid FROM `+st.table+` WHERE host_uid = ? AND deleted = 0`, uid); err == nil {
					for rows.Next() {
						var u string
						if rows.Scan(&u) == nil {
							uids = append(uids, u)
						}
					}
					rows.Close()
				}
				for _, u := range uids {
					_, _ = db.ExecContext(ctx, `UPDATE `+st.table+` SET deleted = 1, updated_at = ? WHERE uid = ?`, upd, u)
					m.csyncMark(ctx, st, u)
				}
			}
		}
		m.clusterDirty(t.kind, fmt.Sprint(cur["host_uid"]), uid)
		return nil
	}
	var row map[string]any
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	if err := dec.Decode(&row); err != nil {
		return err
	}
	if inc, _ := row["incomplete"].(bool); inc {
		return nil // dort nicht lesbar: hier bleibt der Stand
	}
	for k, v := range row {
		if n, ok := v.(json.Number); ok {
			i, err := n.Int64()
			if err != nil {
				return fmt.Errorf("monitor64 cluster: %s: %w", k, err)
			}
			row[k] = i
		}
	}
	row["uid"] = uid
	for _, c := range t.cols {
		if _, ok := row[c]; !ok {
			return fmt.Errorf("monitor64 cluster: %s: field %s missing", t.kind, c)
		}
	}
	switch t.kind {
	case "host":
		if p := fmt.Sprint(row["preferred_node"]); p != "" && !reNodeID.MatchString(p) {
			return errClItem
		}
	case "access":
		if s := fmt.Sprint(row["secret"]); s != "" {
			row["secret"] = m.box.Encrypt(s)
		}
	case "override":
		if fmt.Sprint(row["scope"]) == "notify" {
			row["data"] = m.notifyOverrideFromCluster(ctx, fmt.Sprint(row["data"]))
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var renamed string
	if t.kind == "host" { // zustaendige Node folgt nicht sofort einer neuen bevorzugten Node (Eintrag "owner" folgt)
		var owner, pref string
		if err := tx.QueryRowContext(ctx, `SELECT owner_node, preferred_node FROM m64_hosts WHERE uid = ?`, uid).Scan(&owner, &pref); err == nil && owner == "" {
			if pref == "" {
				pref = m.clusterSelf()
			}
			if pref != fmt.Sprint(row["preferred_node"]) {
				if _, err := tx.ExecContext(ctx, `UPDATE m64_hosts SET owner_node = ? WHERE uid = ?`, pref, uid); err != nil {
					return err
				}
			}
		}
	}
	if t.kind == "service" || t.kind == "hostrule" { // eindeutig je Host und Schluessel: Doppel zusammenfuehren
		col := "key"
		if t.kind == "hostrule" {
			col = "kind"
		}
		var other string
		err := tx.QueryRowContext(ctx, `SELECT uid FROM `+t.table+` WHERE host_uid = ? AND `+col+` = ? AND uid != ?`, row["host_uid"], row[col], uid).Scan(&other)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return err
		case other < uid:
			return nil // hier gilt die kleinere Kennung, die andere Node uebernimmt sie
		default: // die eingehende Kennung ist kleiner: der Eintrag hier uebernimmt sie
			if _, err := tx.ExecContext(ctx, `UPDATE `+t.table+` SET uid = ? WHERE uid = ?`, uid, other); err != nil {
				return err
			}
			renamed = other
		}
	}
	if err := clUpsert(ctx, tx, t.table, t.cols, row); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	m.csyncMark(ctx, t, uid)
	if renamed != "" {
		_, _ = db.ExecContext(ctx, `DELETE FROM m64_csync WHERE kind = ? AND uid = ?`, t.kind, renamed)
		m.clusterChange(context.Background(), ClusterItemConfig, t.kind+":"+renamed, true) // alte Kennung: von hier geloescht
	}
	hostUID := fmt.Sprint(row["host_uid"])
	m.clusterDirty(t.kind, hostUID, uid)
	return nil
}

// clusterDirty merkt, was nach Uebernahmen neu zu laden ist (gebuendelt, clusterFlush).
func (m *Module) clusterDirty(kind, hostUID, uid string) {
	m.cl.mu.Lock()
	defer m.cl.mu.Unlock()
	switch kind {
	case "host":
		m.cl.dirtyCfg = true // Gruppe/Tags aendern Abweichungen und Wartung
		hostUID = uid
	case "access":
	case "service":
		return // jede Runde liest die Dienste neu
	default:
		m.cl.dirtyCfg = true
		hostUID = ""
	}
	if hostUID != "" {
		if m.cl.dirtyHost == nil {
			m.cl.dirtyHost = map[string]bool{}
		}
		m.cl.dirtyHost[hostUID] = true
	}
	if m.cl.timer == nil {
		m.cl.timer = time.AfterFunc(clusterReloadLag, func() { m.clusterFlush(context.Background()) })
	}
}

// clusterFlush laedt nach Uebernahmen Konfiguration und betroffene Hosts neu.
func (m *Module) clusterFlush(ctx context.Context) {
	m.cl.mu.Lock()
	cfg, hosts := m.cl.dirtyCfg, m.cl.dirtyHost
	m.cl.dirtyCfg, m.cl.dirtyHost, m.cl.timer = false, nil, nil
	m.cl.mu.Unlock()
	if cfg {
		m.reloadConfig(ctx)
	}
	for uid := range hosts {
		m.ReloadHost(ctx, uid)
	}
	if cfg {
		m.repollAll() // Neubewertung sofort (Schwellen, Benachrichtigung, Wartung)
	}
}

// clusterOriginOf liest die Herkunft aus ctx (gesetzt vom Cluster bzw. von Tests); das Modul kennt den Cluster nicht,
// daher ueber die Schnittstelle des Hooks.
var originFn atomic.Pointer[func(ctx context.Context) (string, time.Time, bool)]

func clusterOriginOf(ctx context.Context) (string, time.Time, bool) {
	if f := originFn.Load(); f != nil {
		return (*f)(ctx)
	}
	return "", time.Time{}, false
}

// SetClusterOrigin verbindet die Herkunft einer uebernommenen Aenderung (m64cluster: peer.ClusterOrigin).
func SetClusterOrigin(fn func(ctx context.Context) (string, time.Time, bool)) {
	if fn != nil {
		originFn.Store(&fn)
	}
}

// ---------------------------------------------------------------------------------------------------------
// Einstellungen

func (m *Module) settingApply(ctx context.Context, key string, data json.RawMessage, deleted bool) error {
	if !sharedSetting(key) {
		return errClItem
	}
	if deleted {
		return nil // Einstellungen werden nicht geloescht
	}
	var in struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	v := in.Value
	switch key {
	case setNotify:
		v = m.notifyFromCluster(ctx, v)
	case setStd:
		var x map[string]json.RawMessage
		if v != "" && json.Unmarshal([]byte(v), &x) != nil {
			return errClItem
		}
	case setInterval:
		if n, err := strconv.Atoi(v); err != nil || n < 0 || n > 86400 {
			return errClItem
		}
	}
	if err := m.st.SetSetting(ctx, key, v); err != nil {
		return err
	}
	m.csyncSet(ctx, "setting", key, settingStamp(v))
	m.clusterDirty("setting", "", key)
	return nil
}

func settingStamp(v string) string {
	h := sha256.Sum256([]byte(v))
	return hex.EncodeToString(h[:12])
}

// Kanaele: lokal ueber ihre Nummer (je Node verschieden), im Cluster ueber ihre Kennung (nf_channels.uid, gleich auf
// allen Nodes mit abgeglichenen Kanaelen). Unbekannte Kanaele entfallen beim Uebernehmen; "default" bleibt.

func (m *Module) channelUIDs(ctx context.Context) (byID map[string]string, byUID map[string]string) {
	byID, byUID = map[string]string{}, map[string]string{}
	rows, err := m.st.Reader().QueryContext(ctx, `SELECT id, uid FROM nf_channels WHERE uid != ''`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var uid string
		if rows.Scan(&id, &uid) == nil {
			byID[strconv.FormatInt(id, 10)], byUID[uid] = uid, strconv.FormatInt(id, 10)
		}
	}
	return
}

func mapRoutes(routes []eval.ChannelRoute, m map[string]string, prefixIn, prefixOut string) []eval.ChannelRoute {
	var out []eval.ChannelRoute
	for _, r := range routes {
		if r.ID == defaultChannels {
			out = append(out, r)
			continue
		}
		id, ok := strings.CutPrefix(r.ID, prefixIn)
		if !ok {
			continue
		}
		if to, ok := m[id]; ok {
			r.ID = prefixOut + to
			out = append(out, r)
		}
	}
	return out
}

func (m *Module) notifyToCluster(ctx context.Context, raw string) string {
	byID, _ := m.channelUIDs(ctx)
	return remapNotify(raw, func(r []eval.ChannelRoute) []eval.ChannelRoute { return mapRoutes(r, byID, "", "uid:") })
}

func (m *Module) notifyFromCluster(ctx context.Context, raw string) string {
	_, byUID := m.channelUIDs(ctx)
	return remapNotify(raw, func(r []eval.ChannelRoute) []eval.ChannelRoute { return mapRoutes(r, byUID, "uid:", "") })
}

func (m *Module) notifyOverrideToCluster(ctx context.Context, raw string) string {
	byID, _ := m.channelUIDs(ctx)
	return remapOverride(raw, func(r []eval.ChannelRoute) []eval.ChannelRoute { return mapRoutes(r, byID, "", "uid:") })
}

func (m *Module) notifyOverrideFromCluster(ctx context.Context, raw string) string {
	_, byUID := m.channelUIDs(ctx)
	return remapOverride(raw, func(r []eval.ChannelRoute) []eval.ChannelRoute { return mapRoutes(r, byUID, "uid:", "") })
}

func remapNotify(raw string, f func([]eval.ChannelRoute) []eval.ChannelRoute) string {
	var c eval.NotifyConfig
	if json.Unmarshal([]byte(raw), &c) != nil {
		return raw
	}
	c.Channels = f(c.Channels)
	b, _ := json.Marshal(c)
	return string(b)
}

func remapOverride(raw string, f func([]eval.ChannelRoute) []eval.ChannelRoute) string {
	var o eval.NotifyOverride
	if json.Unmarshal([]byte(raw), &o) != nil {
		return raw
	}
	o.Channels = f(o.Channels)
	b, _ := json.Marshal(o)
	return string(b)
}

// channelListToCluster/FromCluster: Kanal-Nummern eines Problems ("gemeldet an").
func (m *Module) channelListToCluster(ctx context.Context, ids []string) []string {
	byID, _ := m.channelUIDs(ctx)
	out := []string{}
	for _, id := range ids {
		if id == defaultChannels {
			out = append(out, id)
		} else if u, ok := byID[id]; ok {
			out = append(out, "uid:"+u)
		}
	}
	return out
}

func (m *Module) channelListFromCluster(ctx context.Context, ids []string) []string {
	_, byUID := m.channelUIDs(ctx)
	out := []string{}
	for _, id := range ids {
		if id == defaultChannels {
			out = append(out, id)
		} else if u, ok := strings.CutPrefix(id, "uid:"); ok {
			if n, ok := byUID[u]; ok {
				out = append(out, n)
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------------------------------------
// Eigene Aenderungen finden

func (m *Module) csyncGet(ctx context.Context, kind, uid string) string {
	var s string
	_ = m.st.Reader().QueryRowContext(ctx, `SELECT stamp FROM m64_csync WHERE kind = ? AND uid = ?`, kind, uid).Scan(&s)
	return s
}

func (m *Module) csyncSet(ctx context.Context, kind, uid, stamp string) {
	if _, err := m.st.Writer().ExecContext(ctx, `INSERT INTO m64_csync (kind, uid, stamp) VALUES (?, ?, ?)
		ON CONFLICT (kind, uid) DO UPDATE SET stamp = excluded.stamp`, kind, uid, stamp); err != nil {
		m.log.Warn("monitor64: cluster stamp", "err", err)
	}
}

// csyncMark merkt den aktuellen Stand einer Zeile als bekannt (nach einer Uebernahme).
func (m *Module) csyncMark(ctx context.Context, t *clTable, uid string) {
	var upd string
	var del int
	if err := m.st.Reader().QueryRowContext(ctx, `SELECT updated_at, deleted FROM `+t.table+` WHERE uid = ?`, uid).Scan(&upd, &del); err == nil {
		m.csyncSet(ctx, t.kind, uid, upd+"|"+strconv.Itoa(del))
	}
}

func (m *Module) problemStamp(ctx context.Context, uid string) string {
	var upd string
	var del, n int
	if err := m.st.Reader().QueryRowContext(ctx, `SELECT updated_at, deleted, (SELECT COUNT(*) FROM m64_events e WHERE e.problem_uid = p.uid)
		FROM m64_problems p WHERE uid = ?`, uid).Scan(&upd, &del, &n); err != nil {
		return ""
	}
	return upd + "|" + strconv.Itoa(del) + "|" + strconv.Itoa(n)
}

type scanRow struct {
	uid, stamp string
	deleted    bool
}

// clusterScan sucht eigene Aenderungen (Aenderungszeit bzw. neue Ereignisse) und meldet, was vom zuletzt gemeldeten
// bzw. uebernommenen Stand abweicht.
func (m *Module) clusterScan(ctx context.Context) {
	if m.hooks().Change == nil {
		return
	}
	m.cl.csMu.Lock()
	defer m.cl.csMu.Unlock()
	start := time.Now()
	from := m.cl.scanFrom
	report := func(item, kind string, rows []scanRow) {
		if len(rows) == 0 {
			return
		}
		known := map[string]string{}
		if len(rows) > 20 { // viele (erster Lauf): alle Staende auf einmal lesen
			if r, err := m.st.Reader().QueryContext(ctx, `SELECT uid, stamp FROM m64_csync WHERE kind = ?`, kind); err == nil {
				for r.Next() {
					var u, s string
					if r.Scan(&u, &s) == nil {
						known[u] = s
					}
				}
				r.Close()
			}
		}
		for _, x := range rows {
			old, ok := known[x.uid]
			if !ok && len(rows) <= 20 {
				old = m.csyncGet(ctx, kind, x.uid)
			}
			if old == x.stamp {
				continue
			}
			m.clusterChange(ctx, item, kind+":"+x.uid, x.deleted)
			m.csyncSet(ctx, kind, x.uid, x.stamp)
		}
	}
	for _, t := range clTables {
		var list []scanRow
		rows, err := m.st.Reader().QueryContext(ctx, `SELECT uid, updated_at, deleted FROM `+t.table+` WHERE updated_at >= ?`, from)
		if err != nil {
			m.log.Warn("monitor64: cluster scan", "table", t.table, "err", err)
			return
		}
		for rows.Next() {
			var uid, upd string
			var del int
			if rows.Scan(&uid, &upd, &del) == nil {
				list = append(list, scanRow{uid: uid, stamp: upd + "|" + strconv.Itoa(del), deleted: del == 1})
			}
		}
		rows.Close()
		report(ClusterItemConfig, t.kind, list)
	}
	// Probleme: geaendert oder neue Ereignisse (Kommentar aendert die Zeile nicht)
	var evMax int64
	_ = m.st.Reader().QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM m64_events`).Scan(&evMax)
	var plist []scanRow
	rows, err := m.st.Reader().QueryContext(ctx, `SELECT uid, updated_at, deleted, (SELECT COUNT(*) FROM m64_events e WHERE e.problem_uid = p.uid)
		FROM m64_problems p WHERE updated_at >= ? OR uid IN (SELECT problem_uid FROM m64_events WHERE id > ? AND id <= ?)`, from, m.cl.eventMax, evMax)
	if err == nil {
		for rows.Next() {
			var uid, upd string
			var del, n int
			if rows.Scan(&uid, &upd, &del, &n) == nil {
				plist = append(plist, scanRow{uid: uid, stamp: upd + "|" + strconv.Itoa(del) + "|" + strconv.Itoa(n), deleted: del == 1})
			}
		}
		rows.Close()
	}
	report(ClusterItemStatus, "problem", plist)
	m.cl.eventMax = evMax
	// gemeinsame Einstellungen (nur gesetzte; eine frische Node schickt keine Vorgaben hinaus)
	var slist []scanRow
	for _, k := range clSettings {
		if v, ok, err := m.st.Setting(ctx, k); err == nil && ok {
			slist = append(slist, scanRow{uid: k, stamp: settingStamp(v)})
		}
	}
	for _, x := range slist { // wenige: einzeln vergleichen (report liest bei bis zu 20 einzeln)
		if m.csyncGet(ctx, "setting", x.uid) != x.stamp {
			m.clusterChange(ctx, ClusterItemConfig, "setting:"+x.uid, false)
			m.csyncSet(ctx, "setting", x.uid, x.stamp)
		}
	}
	m.cl.scanFrom = ts(start.Add(-10 * time.Second)) // Schreibstellen mit etwas aelterer Zeit nicht verpassen
}
