package dyndns

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"
)

// DynDNS ueber den Cluster (Bereich dyndns/config, ohne Einstellung aus; verbunden ueber dyndns/ddcluster, damit
// dyndns nicht vom Cluster abhaengt). Abgeglichen werden die Namen (Domain, Host, Record, Token, Modi, feste Adressen,
// Interface-ID, Interface, an/aus), die Einstellungen (Pruefabstand, Pruef-URLs, Aufbewahrung, Benachrichtigungen,
// bevorzugte Node) und die zustaendige Node. Je Node bleiben die ermittelten Adressen, der Laufzeitstand der Namen
// (zuletzt gemeldet, Fehler, Pause, DNS-Stand) und der Verlauf. Tokens gehen im Klartext ueber die Cluster-Verbindung
// (HTTPS, an die Kopplung gebunden) und werden auf der empfangenden Node mit ihrem Schluessel verschluesselt.
//
// Nur eine Node aktualisiert die Namen: die zustaendige (Eintrag "leader"). Sie bleibt es, solange die anderen sie
// erreichen. Ist sie laenger als die Karenz des Clusters weg (2 min ohne Antwort), ausgesetzt, der Bereich oder das
// Modul dort aus, uebernimmt die gewuenschte Node: die bevorzugte, sonst die mit der kleinsten Kennung - jeweils nur
// unter den Nodes, die seit leaderStable ununterbrochen erreichbar sind (diese Node selbst zaehlt immer). Kommt eine
// Node zurueck, gibt die zustaendige erst ab, wenn sie so lange erreichbar ist (kein Hin und Her). Nur die zustaendige
// Node gibt ab und nur die gewuenschte uebernimmt, so schreibt immer nur eine den Eintrag (bei getrennten Teilen eine
// je Teil, danach gewinnt der juengere). Nach dem Start wartet eine Node leaderStartWait, bis sie den Stand der anderen
// hat. Stehen die Nodes in verschiedenen Netzen, zeigen die Namen nach einer Uebernahme auf den anderen Anschluss
// (gewollt: Ausfallsicherheit ueber Standorte).
//
// Exakte Doppel: Gibt es hier schon einen Namen mit gleicher Einstellung samt Token unter anderer Kennung, gilt die
// kleinere Kennung - ist sie die fremde, uebernimmt der Name hier sie (lokale Nummer und Verlauf bleiben, die alte
// Kennung geht als geloescht hinaus). Derselbe Name mit anderer Einstellung wird nicht uebernommen (jede Node behaelt
// ihren Stand, bis er auf einer Seite angeglichen oder geloescht wird).

// Bereich im Cluster (Modul dyndns).
const (
	ClusterModuleID   = "dyndns"
	ClusterItemConfig = "config"
	ClusterTitleKey   = "cluster.mod.dyndns"

	clusterSettingsID = "settings" // Einstellungen samt bevorzugter Node
	clusterLeaderID   = "leader"   // zustaendige Node

	SetLeader    = "dyndns.cluster_leader" // Kennung der zustaendigen Node im Cluster
	SetPreferred = "dyndns.preferred_node" // bevorzugte Node ("" = die mit der kleinsten Kennung)
)

var (
	leaderStable    = 5 * time.Minute  // so lange erreichbar, bevor eine Node (wieder) zustaendig wird
	leaderStartWait = time.Minute      // nach dem Start: erst den Stand der anderen abholen
	clusterTick     = 30 * time.Second // Blick auf die Mitglieder (schnelle Uebernahme)

	clusterUIDRe    = regexp.MustCompile(`^[0-9a-f]{16,64}$`)
	nodeIDRe        = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	errClusterItem  = errors.New("cluster: unknown area or entry")
	errNameConflict = errors.New("cluster: name exists here with other settings")
)

func newClusterUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ClusterPeer ist eine andere Node, mit der der Bereich abgeglichen wird.
type ClusterPeer struct {
	ID     string
	Name   string
	Online bool
}

// ClusterHooks verbinden das Modul mit dem Cluster (main.go ueber dyndns/ddcluster); leer = kein Cluster.
type ClusterHooks struct {
	// Change meldet eine Aenderung (id = Kennung eines Namens, "settings" oder "leader"); ctx traegt bei Uebernahmen
	// die Herkunft.
	Change func(ctx context.Context, id string, deleted bool)
	// Members: Nodes, mit denen der Bereich abgeglichen wird (hier und dort an, nicht ausgesetzt); leer = allein bzw.
	// Bereich hier aus.
	Members func(ctx context.Context) []ClusterPeer
	// Self: Kennung dieser Node.
	Self func() string
}

// SetCluster haengt den Cluster an (vor Start).
func (m *Module) SetCluster(h ClusterHooks) { m.cluster = h }

// ClusterRunning: das Modul laeuft (sonst ist der Bereich auf dieser Node aus und sie wird nie zustaendig).
func (m *Module) ClusterRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cancel != nil
}

func (m *Module) clusterChanged(ctx context.Context, id string, deleted bool) {
	if m.cluster.Change != nil && id != "" {
		m.cluster.Change(ctx, id, deleted)
	}
}

func (m *Module) uidOf(ctx context.Context, id int64) string {
	var uid string
	_ = m.core.Reader().QueryRowContext(ctx, `SELECT uid FROM dyn_targets WHERE id = ?`, id).Scan(&uid)
	return uid
}

// targetWhere liefert ein Ziel (nil, nil = gibt es nicht).
func (m *Module) targetWhere(ctx context.Context, where string, args ...any) (*Target, error) {
	t, err := m.scanTarget(m.core.Reader().QueryRowContext(ctx, `SELECT `+targetCols+` FROM dyn_targets WHERE `+where, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

// clusterTarget ist ein Name im Cluster (Token im Klartext).
type clusterTarget struct {
	Domain    string `json:"domain"`
	Host      string `json:"host"`
	RecordID  int64  `json:"record_id"`
	TokenKind string `json:"token_kind"`
	Token     string `json:"token"`
	Mode4     string `json:"mode4"`
	Fixed4    string `json:"fixed4"`
	Mode6     string `json:"mode6"`
	Fixed6    string `json:"fixed6"`
	Suffix6   string `json:"suffix6"`
	Iface     string `json:"iface"`
	Enabled   bool   `json:"enabled"`
	// Token hier nicht lesbar: die anderen behalten ihren Stand
	Incomplete bool `json:"incomplete,omitempty"`
}

func toClusterTarget(t *Target) clusterTarget {
	return clusterTarget{Domain: t.Domain, Host: t.Host, RecordID: t.RecordID, TokenKind: t.TokenKind, Token: t.Token, Mode4: t.Mode4, Fixed4: t.Fixed4,
		Mode6: t.Mode6, Fixed6: t.Fixed6, Suffix6: t.Suffix6, Iface: t.Iface, Enabled: t.Enabled}
}

// clusterSettings sind die Einstellungen im Cluster.
type clusterSettings struct {
	moduleSettings
	Preferred string `json:"preferred_node"`
}

// settingsSet: hier wurde mindestens eine Einstellung gespeichert (eine frische Node schickt keine Vorgaben hinaus).
func (m *Module) settingsSet(ctx context.Context) bool {
	for _, k := range exportSettings {
		if _, ok, _ := m.core.Setting(ctx, k); ok {
			return true
		}
	}
	_, ok, _ := m.core.Setting(ctx, SetPreferred)
	return ok
}

// ClusterIDs: Kennungen der Namen, dazu Einstellungen und zustaendige Node (erster Abgleich).
func (m *Module) ClusterIDs(ctx context.Context, item string) ([]string, error) {
	if item != ClusterItemConfig {
		return nil, errClusterItem
	}
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT uid FROM dyn_targets WHERE uid <> '' ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var uid string
		if rows.Scan(&uid) == nil {
			out = append(out, uid)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if m.settingsSet(ctx) {
		out = append(out, clusterSettingsID)
	}
	if m.core.SettingOr(ctx, SetLeader, "") != "" {
		out = append(out, clusterLeaderID)
	}
	return out, nil
}

// ClusterGet liefert einen Eintrag (found=false: gibt es nicht).
func (m *Module) ClusterGet(ctx context.Context, item, id string) (json.RawMessage, bool, error) {
	if item != ClusterItemConfig {
		return nil, false, errClusterItem
	}
	switch id {
	case clusterSettingsID:
		b, err := json.Marshal(clusterSettings{moduleSettings: m.getSettings(ctx), Preferred: m.core.SettingOr(ctx, SetPreferred, "")})
		return b, err == nil, err
	case clusterLeaderID:
		node := m.core.SettingOr(ctx, SetLeader, "")
		if node == "" {
			return nil, false, nil
		}
		b, err := json.Marshal(map[string]string{"node": node})
		return b, err == nil, err
	}
	t, err := m.targetWhere(ctx, `uid = ?`, id)
	if errors.Is(err, errToken) {
		return json.RawMessage(`{"incomplete":true}`), true, nil
	}
	if err != nil || t == nil {
		return nil, false, err
	}
	b, err := json.Marshal(toClusterTarget(t))
	return b, err == nil, err
}

// ClusterApply uebernimmt einen Eintrag einer anderen Node (anlegen, aendern, loeschen); die Aenderung geht mit ihrer
// Herkunft (ctx) ueber den Hook weiter an den Cluster.
func (m *Module) ClusterApply(ctx context.Context, item, id string, data json.RawMessage, deleted bool) error {
	if item != ClusterItemConfig {
		return errClusterItem
	}
	switch id {
	case clusterSettingsID:
		if deleted {
			return nil
		}
		var in clusterSettings
		if err := json.Unmarshal(data, &in); err != nil {
			return err
		}
		if !nodeIDRe.MatchString(in.Preferred) {
			in.Preferred = ""
		}
		if err := m.core.SetSetting(ctx, SetPreferred, in.Preferred); err != nil {
			return err
		}
		return m.saveSettings(ctx, in.moduleSettings)
	case clusterLeaderID:
		var in struct {
			Node string `json:"node"`
		}
		if !deleted {
			if err := json.Unmarshal(data, &in); err != nil {
				return err
			}
			if !nodeIDRe.MatchString(in.Node) {
				return errClusterItem
			}
		}
		return m.core.SetSetting(ctx, SetLeader, in.Node)
	}
	if !clusterUIDRe.MatchString(id) {
		return errClusterItem
	}
	cur, err := m.targetWhere(ctx, `uid = ?`, id)
	if err != nil {
		return err
	}
	if deleted {
		if cur == nil {
			return nil
		}
		return m.DeleteTarget(ctx, cur.ID)
	}
	var in clusterTarget
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	if in.Incomplete {
		return nil
	}
	t := &Target{Domain: in.Domain, Host: in.Host, RecordID: in.RecordID, TokenKind: in.TokenKind, Token: in.Token, Mode4: in.Mode4, Fixed4: in.Fixed4,
		Mode6: in.Mode6, Fixed6: in.Fixed6, Suffix6: in.Suffix6, Iface: in.Iface, Enabled: in.Enabled, UID: id}
	if err := t.Normalize(); err != nil {
		return err
	}
	if cur == nil { // neu hier: exaktes Doppel unter anderer Kennung zusammenfuehren (die kleinere gilt)
		dup, err := m.targetWhere(ctx, `domain = ? AND host = ?`, t.Domain, t.Host)
		if err != nil {
			return err
		}
		if dup != nil {
			if toClusterTarget(dup) != toClusterTarget(t) {
				return fmt.Errorf("%w: %s", errNameConflict, t.FQDN())
			}
			if dup.UID != "" && dup.UID < id {
				return nil // hier gilt die eigene Kennung, die andere Node uebernimmt sie
			}
			if _, err := m.core.Writer().ExecContext(ctx, `UPDATE dyn_targets SET uid = ? WHERE id = ?`, id, dup.ID); err != nil {
				return err
			}
			m.clusterChanged(context.Background(), dup.UID, true) // alte Kennung: von hier aus geloescht (neuer Zeitpunkt)
			dup.UID = id
			cur = dup
		}
	}
	if cur == nil {
		return m.InsertTarget(ctx, t)
	}
	t.ID, t.Paused = cur.ID, cur.Paused // Pause gehoert zum Laufzeitstand dieser Node
	if t.Enabled && (!cur.Enabled || cur.Paused == PauseBadAuth && t.Token != cur.Token) {
		t.Paused = "" // wieder eingeschaltet bzw. neues Token: wie beim Speichern in der Oberflaeche
	}
	return m.UpdateTarget(ctx, t)
}

// ---------------------------------------------------------------- zustaendige Node

// clusterState ist der Blick dieser Node auf die anderen (nur im Speicher).
type clusterState struct {
	mu      sync.Mutex
	since   map[string]time.Time // erreichbar seit (Nullzeit: schon beim ersten Blick erreichbar, gilt als stabil)
	known   map[string]bool      // schon einmal gesehen
	leading bool                 // letzte Entscheidung: diese Node aktualisiert
	now     func() time.Time     // Tests
}

func (c *clusterState) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// observe merkt, seit wann die Mitglieder ununterbrochen erreichbar sind.
func (c *clusterState) observe(list []ClusterPeer, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.since == nil {
		c.since, c.known = map[string]time.Time{}, map[string]bool{}
	}
	for _, p := range list {
		switch {
		case !p.Online:
			delete(c.since, p.ID)
		case !c.known[p.ID]:
			c.since[p.ID] = time.Time{}
		default:
			if _, ok := c.since[p.ID]; !ok {
				c.since[p.ID] = now
			}
		}
		c.known[p.ID] = true
	}
}

// stable: das Mitglied ist lange genug erreichbar, um zustaendig zu werden.
func (c *clusterState) stable(p ClusterPeer, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.since[p.ID]
	return p.Online && ok && (s.IsZero() || now.Sub(s) >= leaderStable)
}

// wantLeader: die Node, die zustaendig sein sollte (bevorzugte, sonst kleinste Kennung; nur stabile Mitglieder).
func (m *Module) wantLeader(self, pref string, list []ClusterPeer, now time.Time) string {
	if pref == self {
		return self
	}
	best := self
	for _, p := range list {
		if !m.cl.stable(p, now) {
			continue
		}
		if p.ID == pref {
			return p.ID
		}
		if p.ID < best {
			best = p.ID
		}
	}
	return best
}

func online(list []ClusterPeer, id string) bool {
	for _, p := range list {
		if p.ID == id {
			return p.Online
		}
	}
	return false
}

// decideLead: aktualisiert diese Node die Namen? Schreibt bei Uebernahme bzw. Abgabe die zustaendige Node.
// clustered: es gibt weitere Nodes mit dem Bereich.
func (m *Module) decideLead(ctx context.Context) (lead, clustered bool) {
	if m.cluster.Members == nil || m.cluster.Self == nil {
		return true, false
	}
	self, list, now := m.cluster.Self(), m.cluster.Members(ctx), m.cl.clock()
	m.cl.observe(list, now)
	if len(list) == 0 || self == "" {
		return true, false // allein bzw. Bereich hier aus: wie ohne Cluster
	}
	if now.Sub(m.startedAt) < leaderStartWait {
		return false, true
	}
	want := m.wantLeader(self, m.core.SettingOr(ctx, SetPreferred, ""), list, now)
	cur := m.core.SettingOr(ctx, SetLeader, "")
	switch {
	case cur == self:
		if want == self {
			return true, true
		}
		m.setLeader(ctx, want) // abgeben: die gewuenschte Node ist lange genug erreichbar
		return false, true
	case cur != "" && online(list, cur):
		return false, true
	case want == self: // keine zustaendige Node oder seit der Karenz nicht erreichbar: uebernehmen
		m.setLeader(ctx, self)
		return true, true
	}
	return false, true
}

func (m *Module) setLeader(ctx context.Context, id string) {
	if err := m.core.SetSetting(ctx, SetLeader, id); err != nil {
		m.log.Error("cluster leader", "err", err)
		return
	}
	m.clusterChanged(ctx, clusterLeaderID, false)
}

// clusterLead entscheidet vor den Updates (Pruefrunde, Blick auf die Mitglieder); became: gerade zustaendig geworden.
func (m *Module) clusterLead(ctx context.Context) (lead, became bool) {
	lead, clustered := m.decideLead(ctx)
	m.cl.mu.Lock()
	changed := lead != m.cl.leading
	became = lead && !m.cl.leading
	m.cl.leading = lead
	m.cl.mu.Unlock()
	if changed && clustered {
		if lead {
			m.log.Info("this node now updates the dyndns names of the cluster")
			// zuletzt gemeldete Adressen vergessen: die Namen zeigen evtl. noch auf eine andere Node (anderes Netz,
			// Wartezeit nach dem eigenen letzten Update gilt nicht), daher einmal alle melden
			if _, err := m.core.Writer().ExecContext(ctx, `UPDATE dyn_targets SET last_ip4 = '', last_ip6 = '', last_prefix = ''`); err != nil {
				m.log.Error("cluster takeover", "err", err)
			}
		} else {
			m.log.Info("another node updates the dyndns names of the cluster", "node", m.core.SettingOr(ctx, SetLeader, ""))
		}
	}
	return lead, became
}

// clusterView ist der Stand fuer die Oberflaeche.
type clusterView struct {
	On         bool // weitere Nodes mit dem Bereich
	Self       string
	Leader     string // Kennung der zustaendigen Node ("" = wird gerade bestimmt)
	LeaderName string
	Here       bool // diese Node aktualisiert
	Preferred  string
	Nodes      []ClusterPeer // die anderen Nodes des Bereichs
}

func (m *Module) clusterView(ctx context.Context) clusterView {
	var v clusterView
	if m.cluster.Members == nil || m.cluster.Self == nil {
		return v
	}
	if v.Nodes = m.cluster.Members(ctx); len(v.Nodes) == 0 {
		return v
	}
	v.On, v.Self, v.Preferred = true, m.cluster.Self(), m.core.SettingOr(ctx, SetPreferred, "")
	m.cl.mu.Lock()
	v.Here = m.cl.leading
	m.cl.mu.Unlock()
	if v.Here {
		v.Leader = v.Self
		return v
	}
	cur := m.core.SettingOr(ctx, SetLeader, "")
	for _, p := range v.Nodes {
		if p.ID == cur && p.Online {
			v.Leader, v.LeaderName = p.ID, p.Name
		}
	}
	return v
}

// errPreferred: keine Node des Bereichs.
var errPreferred = errors.New("preferred node is not a member of the dyndns cluster area")

// setPreferred waehlt die bevorzugte Node ("" = die mit der kleinsten Kennung).
func (m *Module) setPreferred(ctx context.Context, id string) error {
	if id != "" {
		v := m.clusterView(ctx)
		ok := v.On && id == v.Self
		for _, p := range v.Nodes {
			ok = ok || p.ID == id
		}
		if !ok {
			return errPreferred
		}
	}
	if err := m.core.SetSetting(ctx, SetPreferred, id); err != nil {
		return err
	}
	m.clusterChanged(ctx, clusterSettingsID, false)
	return nil
}
