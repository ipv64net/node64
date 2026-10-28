package notify

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"regexp"
	"slices"
)

// Kanaele ueber den Cluster (Bereich notifications/channels, ohne Einstellung aus; verbunden ueber notify/nfcluster,
// damit notify nicht vom Cluster abhaengt). Nur Kanaele dieser Node gehen hinaus: keine Kanaele des Portals (execution
// server, Platzhalter ohne Geheimnisse), keine ipv64-Typen (Mail, SMS, App), nicht der Browser-Kanal (gehoert zur
// Oberflaeche seiner Node) und keine mit „Geheimnis nur lokal“. Die Geheimnisse gehen im Klartext ueber die
// Cluster-Verbindung (HTTPS, an die Kopplung gebunden) und werden auf der empfangenden Node mit ihrem Schluessel
// verschluesselt. Je Node bleiben Server-ID, Revision, letzter Versand und Fehler. Kennung im Cluster ist Channel.UID;
// Checks verweisen im Cluster ueber sie auf ihre Kanaele (healthchecks/peersync.go).
//
// Exakte Doppel: Gibt es hier schon einen Kanal mit gleichem Typ, Namen, gleicher Konfiguration samt Geheimnissen und
// gleichen Schaltern unter anderer Kennung, gilt die kleinere Kennung - ist sie die fremde, uebernimmt der Kanal hier
// sie (lokale Nummer bleibt, die alte Kennung geht als geloescht hinaus), sonst bleibt alles und die andere Node
// uebernimmt unsere.

// ClusterItemChannels ist der Bereich der Kanaele im Cluster (Modul notifications).
const ClusterItemChannels = "channels"

var (
	errClusterItem = errors.New("cluster: unknown area")
	clusterUIDRe   = regexp.MustCompile(`^[0-9a-f]{16,64}$`)
)

func newClusterUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// clusterChannel ist ein Kanal im Cluster (Konfiguration im Klartext).
type clusterChannel struct {
	Type       Type              `json:"type"`
	Name       string            `json:"name"`
	Config     map[string]string `json:"config"`
	Enabled    bool              `json:"enabled"`
	Default    bool              `json:"default"`
	Lang       string            `json:"lang"`
	NotifyDown bool              `json:"notify_down"`
	NotifyUp   bool              `json:"notify_up"`
	// Konfiguration hier nicht lesbar: die anderen behalten ihren Stand (sonst gingen leere Geheimnisse hinaus)
	Incomplete bool `json:"incomplete,omitempty"`
}

// clusterShared: der Kanal geht ueber den Cluster.
func clusterShared(c *Channel) bool {
	if c == nil || c.UID == "" || c.SecretOnlyLocal || (c.Execution != "" && c.Execution != "node") {
		return false
	}
	return slices.Contains(Types, c.Type) && c.Type != TypeBrowser
}

// SetCluster haengt den Cluster an (vor Start; nil = ohne).
func (s *Store) SetCluster(f func(ctx context.Context, uid string, deleted bool)) { s.cluster = f }

// clusterChanged meldet eine Aenderung an den Cluster: geteilte Kanaele, und einen, der nicht mehr geteilt wird
// (z. B. „Geheimnis nur lokal“ eingeschaltet), als geloescht.
func (s *Store) clusterChanged(ctx context.Context, old, cur *Channel) {
	if s.cluster == nil {
		return
	}
	switch {
	case clusterShared(cur):
		s.cluster(ctx, cur.UID, false)
	case clusterShared(old):
		s.cluster(ctx, old.UID, true)
	}
}

// ClusterUIDOf liefert die Kennung eines Kanals im Cluster ("" = gibt es nicht oder geht nicht ueber den Cluster).
func (s *Store) ClusterUIDOf(ctx context.Context, id int64) string {
	if c, _ := s.Channel(ctx, id); clusterShared(c) {
		return c.UID
	}
	return ""
}

// ClusterIDOf liefert die lokale Nummer zu einer Kennung im Cluster (0 = gibt es hier nicht).
func (s *Store) ClusterIDOf(ctx context.Context, uid string) int64 {
	if c, _ := s.byUID(ctx, uid); clusterShared(c) {
		return c.ID
	}
	return 0
}

func (s *Store) byUID(ctx context.Context, uid string) (*Channel, error) {
	if uid == "" {
		return nil, nil
	}
	c, err := s.scan(s.r.QueryRowContext(ctx, `SELECT `+channelCols+` FROM nf_channels WHERE uid = ?`, uid))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return c, err
}

// ClusterIDs: Kennungen der geteilten Kanaele (erster Abgleich).
func (s *Store) ClusterIDs(ctx context.Context, item string) ([]string, error) {
	if item != ClusterItemChannels {
		return nil, errClusterItem
	}
	list, err := s.Channels(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, c := range list {
		if clusterShared(c) {
			out = append(out, c.UID)
		}
	}
	return out, nil
}

func toCluster(c *Channel) clusterChannel {
	return clusterChannel{Type: c.Type, Name: c.Name, Config: c.Config, Enabled: c.Enabled, Default: c.Default, Lang: c.Lang,
		NotifyDown: c.NotifyDown, NotifyUp: c.NotifyUp, Incomplete: c.cfgErr}
}

// ClusterGet liefert einen geteilten Kanal samt Geheimnissen (found=false: gibt es nicht oder nicht mehr geteilt).
func (s *Store) ClusterGet(ctx context.Context, item, uid string) (json.RawMessage, bool, error) {
	if item != ClusterItemChannels {
		return nil, false, errClusterItem
	}
	c, err := s.byUID(ctx, uid)
	if err != nil || !clusterShared(c) {
		return nil, false, err
	}
	b, err := json.Marshal(toCluster(c))
	return b, err == nil, err
}

// ClusterApply uebernimmt einen Kanal einer anderen Node (anlegen, aendern, loeschen); die Aenderung geht mit ihrer
// Herkunft (ctx) ueber den Hook weiter an den Cluster.
func (s *Store) ClusterApply(ctx context.Context, item, uid string, data json.RawMessage, deleted bool) error {
	if item != ClusterItemChannels || !clusterUIDRe.MatchString(uid) {
		return errClusterItem
	}
	cur, err := s.byUID(ctx, uid)
	if err != nil {
		return err
	}
	if cur != nil && !clusterShared(cur) {
		return nil // hier nicht geteilt (z. B. „Geheimnis nur lokal“): bleibt, wie er ist
	}
	if deleted {
		if cur == nil {
			return nil
		}
		return s.Delete(ctx, cur.ID)
	}
	var in clusterChannel
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	if in.Incomplete {
		return nil
	}
	ch := &Channel{Type: in.Type, Name: in.Name, Config: in.Config, Enabled: in.Enabled, Default: in.Default, Lang: in.Lang,
		NotifyDown: in.NotifyDown, NotifyUp: in.NotifyUp, Execution: "node", UID: uid}
	if ch.Config == nil {
		ch.Config = map[string]string{}
	}
	if !clusterShared(ch) {
		return errClusterItem
	}
	if err := ch.Validate(); err != nil {
		return err
	}
	if cur == nil { // neu hier: exaktes Doppel unter anderer Kennung zusammenfuehren (die kleinere gilt)
		dup, err := s.clusterDup(ctx, ch)
		if err != nil {
			return err
		}
		if dup != nil {
			if dup.UID < uid {
				return nil // hier gilt die eigene Kennung, die andere Node uebernimmt sie
			}
			if _, err := s.w.ExecContext(ctx, `UPDATE nf_channels SET uid = ? WHERE id = ?`, uid, dup.ID); err != nil {
				return err
			}
			if s.cluster != nil {
				s.cluster(context.Background(), dup.UID, true) // alte Kennung: von hier aus geloescht (neuer Zeitpunkt)
			}
			dup.UID = uid
			cur = dup
		}
	}
	if cur == nil {
		return s.Insert(ctx, ch)
	}
	ch.ID, ch.RemoteID, ch.Revision, ch.SecretOnlyLocal = cur.ID, cur.RemoteID, cur.Revision, cur.SecretOnlyLocal
	return s.Update(ctx, ch)
}

// clusterDup sucht einen geteilten Kanal, der exakt gleich ist (Typ, Name, Konfiguration samt Geheimnissen, Schalter,
// Sprache), aber eine andere Kennung hat - z. B. derselbe Kanal auf beiden Nodes vor dem Cluster angelegt.
func (s *Store) clusterDup(ctx context.Context, ch *Channel) (*Channel, error) {
	list, err := s.Channels(ctx)
	if err != nil {
		return nil, err
	}
	want := toCluster(ch)
	for _, c := range list {
		if !clusterShared(c) || c.cfgErr || c.UID == ch.UID {
			continue
		}
		got := toCluster(c)
		if got.Type == want.Type && got.Name == want.Name && maps.Equal(setValues(got.Config), setValues(want.Config)) && got.Enabled == want.Enabled &&
			got.Default == want.Default && got.Lang == want.Lang && got.NotifyDown == want.NotifyDown && got.NotifyUp == want.NotifyUp {
			return c, nil
		}
	}
	return nil, nil
}

// setValues: Konfiguration ohne leere Werte (leer und nicht gesetzt sind gleich).
func setValues(cfg map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range cfg {
		if v != "" {
			out[k] = v
		}
	}
	return out
}
