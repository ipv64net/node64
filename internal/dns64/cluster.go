package dns64

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/dns64/groups"
)

// Cluster: DNS64 gleicht ueber den Cluster (internal/peer, verbunden ueber dns64/dns64cluster, damit dns64 nicht von
// peer abhaengt) seine Bereiche ab, jeden einzeln schaltbar und ohne Einstellung aus. Nie abgeglichen werden Ports,
// Schnittstellen, Router, DoH/DoT/DoQ, Namen und Zertifikat, Client-Netze, Pause, Abfrage-Log sowie Eintraege und
// Weiterleitungen mit "nur diese Node".
//
// Aenderungen erkennt DNS64 am Vergleich mit dem zuletzt gemeldeten Stand je Bereich (nach jedem Neuladen der
// Eintraege, Weiterleitungen, Zonen, Gruppen, Einstellungen und Freigaben) - so meldet jede Aenderung, egal ueber
// welchen Weg (Seite, API, Import, Cluster). Uebernahmen tragen die Herkunft in ctx; der Cluster behaelt sie.

// Kennungen fuer den Cluster.
const (
	ClusterModuleID = "dns64"
	ClusterTitleKey = "cluster.mod.dns64"

	ItemSettings = "settings"      // Upstreams, Modus, Blockier-Art, Cache, Anonymisierung, Aufbewahrung, Firefox, Meldungen
	ItemLists    = "lists"         // Blocklisten-Auswahl, eigene Listen, Aktualisierung
	ItemAllow    = "allowlist"     // Freigaben
	ItemDeny     = "denylist"      // eigene Sperrliste
	ItemRecords  = "records"       // eigene Eintraege (r:<hash>) und lokale Zonen (z:<name>)
	ItemForwards = "forwards"      // Weiterleitungen (f:<domain>) und Umschreiben (w:<name>)
	ItemGroups   = "groups"        // Gruppen mit Regeln, Domains, Zeitplaenen, Sperren/Frei (<uid>)
	ItemMembers  = "group_members" // Mitglieder je Gruppe (<uid>)
)

// ClusterItem ist ein abgleichbarer Bereich.
type ClusterItem struct{ ID, TitleKey string }

// ClusterItems: Bereiche von DNS64 (alle ohne Einstellung aus).
func ClusterItems() []ClusterItem {
	out := []ClusterItem{}
	for _, id := range []string{ItemSettings, ItemLists, ItemAllow, ItemDeny, ItemRecords, ItemForwards, ItemGroups, ItemMembers} {
		out = append(out, ClusterItem{id, "cluster.item.dns64_" + id})
	}
	return out
}

// ClusterHook meldet eine Aenderung an den Cluster.
type ClusterHook func(ctx context.Context, item, id string, deleted bool)

var clusterKeys = map[string][]string{
	ItemSettings: {setUpstreams, setUpMode, setUpCount, setBlockMode, setCacheSize, setAnonymize, setRetention, setCanary, setNotifyUpstream, setNotifyLists},
	ItemLists:    {setLists, setListHours},
}

// SetCluster verbindet DNS64 mit dem Cluster und merkt sich den Ausgangsstand (ohne Meldung; vorhandene Eintraege
// legt der Cluster beim Start selbst ins Protokoll). Die Tabellen legt es dabei an, damit eine Node die Eintraege
// auch uebernimmt, solange DNS64 bei ihr (noch) aus ist.
func (m *Module) SetCluster(hook ClusterHook) {
	ctx := context.Background()
	if err := m.core.Migrate(ctx, Name, m.Migrations()); err != nil {
		m.log.Warn("dns64 tables for the cluster", "err", err)
	}
	snap := map[string]map[string]string{}
	for _, it := range ClusterItems() {
		cur, err := m.clCurrent(ctx, it.ID)
		if err != nil {
			cur = map[string]string{}
		}
		snap[it.ID] = cur
	}
	m.clMu.Lock()
	m.clHook, m.clSnap = hook, snap
	m.clMu.Unlock()
}

// clChanged vergleicht einen Bereich mit dem zuletzt gemeldeten Stand und meldet die Unterschiede. Der Stand wird
// ausserhalb von clMu gelesen; hat inzwischen ein anderer Aufruf getauscht (Zaehler clGen), wird neu gelesen, damit
// ein aelterer Stand nie einen neueren ueberschreibt (sonst Meldungen geloeschter Eintraege, die es noch gibt).
func (m *Module) clChanged(ctx context.Context, item string) {
	var hook ClusterHook
	var prev, cur map[string]string
	for try := 0; ; try++ {
		m.clMu.Lock()
		hook = m.clHook
		gen := m.clGen[item]
		m.clMu.Unlock()
		if hook == nil {
			return
		}
		var err error
		if cur, err = m.clCurrent(ctx, item); err != nil {
			return
		}
		m.clMu.Lock()
		if m.clGen[item] != gen && try < 8 {
			m.clMu.Unlock()
			continue
		}
		prev = m.clSnap[item]
		m.clSnap[item] = cur
		m.clBump(item)
		m.clMu.Unlock()
		break
	}
	for id, v := range cur {
		if old, ok := prev[id]; !ok || old != v {
			hook(ctx, item, id, false)
		}
	}
	for id := range prev {
		if _, ok := cur[id]; !ok {
			hook(ctx, item, id, true)
		}
	}
}

// ---- Stand je Bereich: Kennung -> Daten (JSON) ----

type clRecord struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Value   string `json:"value"`
	TTL     int    `json:"ttl"`
	Comment string `json:"comment,omitempty"`
	NoPTR   bool   `json:"no_ptr,omitempty"`
	Enabled bool   `json:"enabled"`
}

type clZone struct {
	Name          string `json:"name"`
	Authoritative bool   `json:"authoritative"`
	Devices       bool   `json:"devices"`
	Comment       string `json:"comment,omitempty"`
	Enabled       bool   `json:"enabled"`
	TTL           int    `json:"ttl,omitempty"`
	Refresh       int    `json:"refresh,omitempty"`
	Retry         int    `json:"retry,omitempty"`
	Expire        int    `json:"expire,omitempty"`
	Minimum       int    `json:"minimum,omitempty"`
	Hostmaster    string `json:"hostmaster,omitempty"`
}

type clForward struct {
	Domain  string   `json:"domain"`
	Servers []string `json:"servers"`
	Comment string   `json:"comment,omitempty"`
	Enabled bool     `json:"enabled"`
}

type clRewrite struct {
	Name    string `json:"name"`
	Target  string `json:"target"`
	Comment string `json:"comment,omitempty"`
	Enabled bool   `json:"enabled"`
}

type clDomain struct {
	Domain string `json:"domain"`
	Action string `json:"action"`
}

type clSchedule struct {
	Label   string   `json:"label,omitempty"`
	Days    []int    `json:"days"`
	Start   string   `json:"start"`
	End     string   `json:"end"`
	Action  string   `json:"action"`
	Cats    []string `json:"categories,omitempty"`
	Enabled bool     `json:"enabled"`
}

type clGroup struct {
	Name       string       `json:"name"`
	Position   int          `json:"position"`
	ListsMode  string       `json:"lists_mode"`
	Lists      []string     `json:"lists"`
	Cats       []string     `json:"categories"`
	SafeSearch bool         `json:"safesearch"`
	YouTube    string       `json:"youtube"`
	Bypass     bool         `json:"bypass"`
	Hold       string       `json:"hold"`
	HoldUntil  string       `json:"hold_until"`
	Domains    []clDomain   `json:"domains"`
	Schedules  []clSchedule `json:"schedules"`
}

type clMember struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
	Label string `json:"label,omitempty"`
}

func recordKey(name, typ, value string) string {
	h := sha256.Sum256([]byte(name + "\x00" + typ + "\x00" + value))
	return "r:" + hex.EncodeToString(h[:12])
}

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func (m *Module) clCurrent(ctx context.Context, item string) (map[string]string, error) {
	out := map[string]string{}
	switch item {
	case ItemSettings, ItemLists:
		for _, k := range clusterKeys[item] {
			if v, ok, err := m.core.Setting(ctx, k); err != nil {
				return nil, err
			} else if ok {
				out[k] = jsonString(v)
			}
		}
	case ItemAllow, ItemDeny:
		a, err := m.allowlist()
		if item == ItemDeny {
			a, err = m.denylist()
		}
		if err != nil {
			return nil, err
		}
		for _, e := range a.List() {
			out[e.Domain] = "true"
		}
	case ItemRecords:
		recs, err := m.Records(ctx)
		if err != nil && !m.noTable(err) {
			return nil, err
		}
		for _, r := range recs {
			if !r.LocalOnly {
				out[recordKey(r.Name, r.Type, r.Value)] = jsonString(clRecord{r.Name, r.Type, r.Value, r.TTL, r.Comment, r.NoPTR, r.Enabled})
			}
		}
		zones, err := m.Zones(ctx)
		if err != nil && !m.noTable(err) {
			return nil, err
		}
		for _, z := range zones {
			out["z:"+z.Name] = jsonString(clZone{z.Name, z.Authoritative, z.Devices, z.Comment, z.Enabled, z.TTL, z.Refresh, z.Retry, z.Expire, z.Minimum, z.Hostmaster})
		}
	case ItemForwards:
		fl, err := m.Forwards(ctx)
		if err != nil && !m.noTable(err) {
			return nil, err
		}
		for _, f := range fl {
			if !f.LocalOnly {
				out["f:"+f.Domain] = jsonString(clForward{f.Domain, f.Servers, f.Comment, f.Enabled})
			}
		}
		rl, err := m.Rewrites(ctx)
		if err != nil && !m.noTable(err) {
			return nil, err
		}
		for _, r := range rl {
			out["w:"+r.Name] = jsonString(clRewrite{r.Name, r.Target, r.Comment, r.Enabled})
		}
	case ItemGroups, ItemMembers:
		list, err := m.Groups(ctx)
		if err != nil && !m.noTable(err) {
			return nil, err
		}
		for _, g := range list {
			if g.UID == "" {
				continue
			}
			if item == ItemMembers {
				mem := []clMember{}
				for _, x := range g.Members {
					mem = append(mem, clMember{x.Kind, x.Value, x.Label})
				}
				slices.SortFunc(mem, func(a, b clMember) int { return strings.Compare(a.Kind+a.Value, b.Kind+b.Value) })
				out[g.UID] = jsonString(mem)
				continue
			}
			out[g.UID] = jsonString(clGroupOf(g))
		}
	default:
		return nil, errUnknownItem
	}
	return out, nil
}

func clGroupOf(g groups.Group) clGroup {
	c := clGroup{Name: g.Name, Position: g.Position, ListsMode: g.ListsMode, Lists: g.Lists, Cats: g.Cats, SafeSearch: g.SafeSearch,
		YouTube: g.YouTube, Bypass: g.Bypass, Hold: g.Hold, HoldUntil: g.HoldUntil, Domains: []clDomain{}, Schedules: []clSchedule{}}
	for _, d := range g.Domains {
		c.Domains = append(c.Domains, clDomain{d.Domain, d.Action})
	}
	slices.SortFunc(c.Domains, func(a, b clDomain) int { return strings.Compare(a.Domain, b.Domain) })
	for _, s := range g.Schedules {
		c.Schedules = append(c.Schedules, clSchedule{s.Label, s.Days, s.Start, s.End, s.Action, s.Cats, s.Enabled})
	}
	slices.SortFunc(c.Schedules, func(a, b clSchedule) int { return strings.Compare(jsonString(a), jsonString(b)) })
	return c
}

var errUnknownItem = errors.New("unknown cluster item")

// ClusterIDs: alle Eintraege eines Bereichs (fuer den ersten Abgleich).
func (m *Module) ClusterIDs(ctx context.Context, item string) ([]string, error) {
	cur, err := m.clCurrent(ctx, item)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(cur))
	for id := range cur {
		out = append(out, id)
	}
	slices.Sort(out)
	return out, nil
}

// ClusterGet: aktueller Stand eines Eintrags; found=false, wenn es ihn nicht (mehr) gibt. Kommt aus dem zuletzt
// gemeldeten Stand (jede Aenderung laeuft ueber clChanged bzw. eine Uebernahme), sonst muesste die Node fuer jeden
// abgeholten Eintrag den ganzen Bereich neu bauen.
func (m *Module) ClusterGet(ctx context.Context, item, id string) (json.RawMessage, bool, error) {
	m.clMu.Lock()
	snap, has := m.clSnap[item]
	v, ok := snap[id]
	m.clMu.Unlock()
	if has {
		if !ok {
			return nil, false, nil
		}
		return json.RawMessage(v), true, nil
	}
	cur, err := m.clCurrent(ctx, item)
	if err != nil {
		return nil, false, err
	}
	v, ok = cur[id]
	if !ok {
		return nil, false, nil
	}
	return json.RawMessage(v), true, nil
}

// ClusterApply uebernimmt einen Eintrag einer anderen Node (ctx traegt die Herkunft).
func (m *Module) ClusterApply(ctx context.Context, item, id string, data json.RawMessage, deleted bool) error {
	switch item {
	case ItemSettings, ItemLists:
		if !slices.Contains(clusterKeys[item], id) {
			return fmt.Errorf("dns64 cluster: setting %q not synced", id)
		}
		if deleted {
			return nil // Einstellungen verschwinden nicht
		}
		var v string
		if err := json.Unmarshal(data, &v); err != nil {
			return err
		}
		if err := m.core.SetSetting(ctx, id, v); err != nil {
			return err
		}
		m.clChanged(ctx, item)
		m.restartSoon()
		return nil
	case ItemAllow, ItemDeny:
		a, err := m.allowlist()
		if item == ItemDeny {
			a, err = m.denylist()
		}
		if err != nil {
			return err
		}
		if deleted {
			if err := a.Remove(id); err != nil && !strings.Contains(err.Error(), "not") {
				return err
			}
		} else if _, err := a.Add(id); err != nil {
			return err
		}
		m.clChanged(ctx, item)
		return nil
	case ItemRecords:
		if strings.HasPrefix(id, "z:") {
			return m.clApplyZone(ctx, strings.TrimPrefix(id, "z:"), data, deleted)
		}
		return m.clApplyRecord(ctx, id, data, deleted)
	case ItemForwards:
		if strings.HasPrefix(id, "w:") {
			return m.clApplyRewrite(ctx, strings.TrimPrefix(id, "w:"), data, deleted)
		}
		return m.clApplyForward(ctx, strings.TrimPrefix(id, "f:"), data, deleted)
	case ItemGroups:
		return m.clApplyGroup(ctx, id, data, deleted)
	case ItemMembers:
		return m.clApplyMembers(ctx, id, data, deleted)
	}
	return errUnknownItem
}

// restartSoon startet DNS64 nach uebernommenen Einstellungen neu (gebuendelt: mehrere kommen meist zusammen).
func (m *Module) restartSoon() {
	m.clMu.Lock()
	defer m.clMu.Unlock()
	if m.clRestart != nil {
		m.clRestart.Stop()
	}
	m.clRestart = time.AfterFunc(2*time.Second, func() {
		if err := m.restart(context.Background()); err != nil {
			m.log.Warn("dns64 restart after cluster change", "err", err)
		}
	})
}

// clApplyRecord uebernimmt einen Eintrag gezielt per SQL und setzt den gemeldeten Stand selbst (die Herkunft fuehrt
// der Cluster); die Momentaufnahme fuer den DNS-Dienst entsteht gebuendelt kurz danach (reloadRecordsSoon).
func (m *Module) clApplyRecord(ctx context.Context, id string, data json.RawMessage, deleted bool) error {
	w := m.core.Writer()
	if deleted {
		m.clMu.Lock()
		old, ok := m.clSnap[ItemRecords][id]
		m.clMu.Unlock()
		var in clRecord
		if !ok || json.Unmarshal([]byte(old), &in) != nil {
			return nil // hier nicht vorhanden
		}
		if _, err := w.ExecContext(ctx, `DELETE FROM dns64_records WHERE name = ? AND type = ? AND value = ? AND local_only = 0`, in.Name, in.Type, in.Value); err != nil {
			return err
		}
		m.clSetSnap(ItemRecords, id, "")
		m.reloadRecordsSoon()
		return nil
	}
	var in clRecord
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	r := Record{Name: in.Name, Type: in.Type, Value: in.Value, TTL: in.TTL, Comment: in.Comment, NoPTR: in.NoPTR}
	if err := normalizeRecord(&r); err != nil {
		return err
	}
	var rowID int64
	var local bool
	err := m.core.Reader().QueryRowContext(ctx, `SELECT id, local_only FROM dns64_records WHERE name = ? AND type = ? AND value = ?`, r.Name, r.Type, r.Value).Scan(&rowID, &local)
	switch {
	case err == nil && local:
		return nil // hier gilt der eigene Eintrag
	case err == nil:
		_, err = w.ExecContext(ctx, `UPDATE dns64_records SET ttl = ?, comment = ?, no_ptr = ?, enabled = ? WHERE id = ?`, r.TTL, r.Comment, r.NoPTR, in.Enabled, rowID)
	case errors.Is(err, sql.ErrNoRows):
		if err = m.checkRecord(ctx, &r, 0); err != nil {
			return err // z. B. CNAME neben anderen Typen hier
		}
		_, err = w.ExecContext(ctx, `INSERT INTO dns64_records (name, type, value, ttl, comment, no_ptr, enabled, created_at) VALUES (?,?,?,?,?,?,?,?)`,
			r.Name, r.Type, r.Value, r.TTL, r.Comment, r.NoPTR, in.Enabled, time.Now().UTC().Format(time.RFC3339))
	}
	if err != nil {
		return err
	}
	m.clSetSnap(ItemRecords, id, jsonString(clRecord{r.Name, r.Type, r.Value, r.TTL, r.Comment, r.NoPTR, in.Enabled}))
	m.reloadRecordsSoon()
	return nil
}

// clSetSnap setzt einen Eintrag im gemeldeten Stand ("" = entfernt).
func (m *Module) clSetSnap(item, id, v string) {
	m.clMu.Lock()
	defer m.clMu.Unlock()
	if m.clSnap == nil {
		return
	}
	if m.clSnap[item] == nil {
		m.clSnap[item] = map[string]string{}
	}
	if v == "" {
		delete(m.clSnap[item], id)
	} else {
		m.clSnap[item][id] = v
	}
	m.clBump(item)
}

// clBump zaehlt den Stand eines Bereichs weiter (clMu gehalten).
func (m *Module) clBump(item string) {
	if m.clGen == nil {
		m.clGen = map[string]uint64{}
	}
	m.clGen[item]++
}

func (m *Module) clApplyZone(ctx context.Context, name string, data json.RawMessage, deleted bool) error {
	zones, err := m.Zones(ctx)
	if err != nil {
		return err
	}
	var cur *Zone
	for i := range zones {
		if zones[i].Name == name {
			cur = &zones[i]
		}
	}
	if deleted {
		if cur != nil {
			return m.DeleteZone(ctx, cur.ID)
		}
		return nil
	}
	var in clZone
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	nz := Zone{Name: in.Name, Authoritative: in.Authoritative, Devices: in.Devices, Comment: in.Comment, TTL: in.TTL, Refresh: in.Refresh,
		Retry: in.Retry, Expire: in.Expire, Minimum: in.Minimum, Hostmaster: in.Hostmaster}
	if cur == nil {
		z, err := m.AddZone(ctx, nz)
		if err != nil {
			return err
		}
		cur = &z
	} else if _, err := m.UpdateZone(ctx, cur.ID, nz); err != nil {
		return err
	}
	return m.SetZoneEnabled(ctx, cur.ID, in.Enabled)
}

func (m *Module) clApplyForward(ctx context.Context, domain string, data json.RawMessage, deleted bool) error {
	fl, err := m.Forwards(ctx)
	if err != nil {
		return err
	}
	var cur *Forward
	for i := range fl {
		if fl[i].Domain == domain {
			cur = &fl[i]
		}
	}
	if cur != nil && cur.LocalOnly {
		return nil // hier gilt die eigene Weiterleitung
	}
	if deleted {
		if cur != nil {
			return m.DeleteForward(ctx, cur.ID)
		}
		return nil
	}
	var in clForward
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	f := Forward{Domain: in.Domain, Servers: in.Servers, Comment: in.Comment}
	if cur == nil {
		x, err := m.AddForward(ctx, f)
		if err != nil {
			return err
		}
		cur = &x
	} else if _, err := m.UpdateForward(ctx, cur.ID, f); err != nil {
		return err
	}
	return m.SetForwardEnabled(ctx, cur.ID, in.Enabled)
}

func (m *Module) clApplyRewrite(ctx context.Context, name string, data json.RawMessage, deleted bool) error {
	rl, err := m.Rewrites(ctx)
	if err != nil {
		return err
	}
	var cur *Rewrite
	for i := range rl {
		if rl[i].Name == name {
			cur = &rl[i]
		}
	}
	if deleted {
		if cur != nil {
			return m.DeleteRewrite(ctx, cur.ID)
		}
		return nil
	}
	var in clRewrite
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	x := Rewrite{Name: in.Name, Target: in.Target, Comment: in.Comment}
	if cur == nil {
		y, err := m.AddRewrite(ctx, x)
		if err != nil {
			return err
		}
		cur = &y
	} else if _, err := m.UpdateRewrite(ctx, cur.ID, x); err != nil {
		return err
	}
	return m.SetRewriteEnabled(ctx, cur.ID, in.Enabled)
}

// groupID: lokale Kennung einer Gruppe ueber ihre uid (0 = nicht vorhanden).
func (m *Module) groupID(ctx context.Context, uid string) (int64, error) {
	var id int64
	err := m.core.Reader().QueryRowContext(ctx, `SELECT id FROM dns64_groups WHERE uid = ?`, uid).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return id, err
}

// clApplyGroup uebernimmt eine Gruppe mit Regeln, Domains, Zeitplaenen und Knopf-Zustand. Gibt es sie hier unter
// anderer uid mit demselben Namen (beide Nodes hatten sie schon vor dem Cluster), uebernimmt sie die uid.
func (m *Module) clApplyGroup(ctx context.Context, uid string, data json.RawMessage, deleted bool) error {
	id, err := m.groupID(ctx, uid)
	if err != nil {
		return err
	}
	if deleted {
		if id > 0 {
			return m.DeleteGroup(ctx, id)
		}
		return nil
	}
	var in clGroup
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	w := m.core.Writer()
	if id == 0 {
		err := m.core.Reader().QueryRowContext(ctx, `SELECT id FROM dns64_groups WHERE name = ?`, in.Name).Scan(&id)
		switch {
		case err == nil:
			if _, err := w.ExecContext(ctx, `UPDATE dns64_groups SET uid = ? WHERE id = ?`, uid, id); err != nil {
				return err
			}
		case errors.Is(err, sql.ErrNoRows):
			res, err := w.ExecContext(ctx, `INSERT INTO dns64_groups (uid, name, position, created_at) VALUES (?,?,?,?)`, uid, in.Name, in.Position, time.Now().UTC().Format(time.RFC3339))
			if err != nil {
				return err
			}
			id, _ = res.LastInsertId()
		default:
			return err
		}
	}
	if _, err := w.ExecContext(ctx, `UPDATE dns64_groups SET name = ?, position = ?, lists_mode = ?, lists = ?, cats = ?, safesearch = ?, youtube = ?, bypass = ?, hold = ?, hold_until = ? WHERE id = ?`,
		in.Name, in.Position, in.ListsMode, strings.Join(in.Lists, "\n"), strings.Join(in.Cats, ","), in.SafeSearch, in.YouTube, in.Bypass, in.Hold, in.HoldUntil, id); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := w.ExecContext(ctx, `DELETE FROM dns64_group_domains WHERE group_id = ?`, id); err != nil {
		return err
	}
	for _, d := range in.Domains {
		if _, err := w.ExecContext(ctx, `INSERT INTO dns64_group_domains (group_id, domain, action, created_at) VALUES (?,?,?,?)`, id, d.Domain, d.Action, now); err != nil {
			return err
		}
	}
	if _, err := w.ExecContext(ctx, `DELETE FROM dns64_group_schedules WHERE group_id = ?`, id); err != nil {
		return err
	}
	for _, s := range in.Schedules {
		days := make([]string, 0, len(s.Days))
		for _, d := range s.Days {
			days = append(days, fmt.Sprint(d))
		}
		if _, err := w.ExecContext(ctx, `INSERT INTO dns64_group_schedules (group_id, label, days, start, end, action, cats, enabled, created_at) VALUES (?,?,?,?,?,?,?,?,?)`,
			id, s.Label, strings.Join(days, ","), s.Start, s.End, s.Action, strings.Join(s.Cats, ","), s.Enabled, now); err != nil {
			return err
		}
	}
	return m.groupsChanged(ctx)
}

// clApplyMembers ersetzt die Mitglieder einer Gruppe; ein Geraet, das hier in einer anderen Gruppe ist, wechselt.
func (m *Module) clApplyMembers(ctx context.Context, uid string, data json.RawMessage, deleted bool) error {
	id, err := m.groupID(ctx, uid)
	if err != nil || id == 0 {
		return err // Gruppe (noch) nicht hier: ihre Mitglieder kommen mit der naechsten Aenderung
	}
	var in []clMember
	if !deleted {
		if err := json.Unmarshal(data, &in); err != nil {
			return err
		}
	}
	w := m.core.Writer()
	if _, err := w.ExecContext(ctx, `DELETE FROM dns64_group_members WHERE group_id = ?`, id); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, x := range in {
		if _, err := w.ExecContext(ctx, `DELETE FROM dns64_group_members WHERE kind = ? AND value = ?`, x.Kind, x.Value); err != nil {
			return err
		}
		if _, err := w.ExecContext(ctx, `INSERT INTO dns64_group_members (group_id, kind, value, label, created_at) VALUES (?,?,?,?,?)`, id, x.Kind, x.Value, x.Label, now); err != nil {
			return err
		}
	}
	return m.loadGroups(ctx)
}

// newUID: Kennung einer Gruppe im Cluster.
func newUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
