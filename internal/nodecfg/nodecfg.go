// Package nodecfg gleicht Einstellungen der Node selbst ueber den Cluster ab (Modul "node", Weg /peer/v2/sync;
// verbunden ueber nodecfg/nodecluster, damit nodecfg nicht vom Cluster abhaengt). Beide Bereiche sind ohne
// Einstellung aus:
//
//   - apikey: der zentrale ipv64-API-Key samt Konto. Er geht im Klartext ueber die Cluster-Verbindung (HTTPS, an die
//     Kopplung gebunden) und wird auf der empfangenden Node mit ihrem Schluessel verschluesselt. Uebernommen wird er
//     nur bei gleichem Account oder wenn die Node noch keinen hat (0) und der Key zum Account des Clusters passt
//     (Dennis: gleicher Account oder keiner, nie ein anderer). Eine auf ipv64.net entfernte Node nimmt keinen Key an.
//   - settings: eine feste Liste allgemeiner Einstellungen (settings), je Schluessel mit eigenem Zeitpunkt. Nie
//     dabei: Name und Kennung der Node, Ports, Adressen, Zertifikate, Cluster und alles, was am Netz haengt.
package nodecfg

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/selfupdate"
	"github.com/ipv64net/node64/internal/store"
)

// Modul und Bereiche im Cluster.
const (
	ModuleID     = "node"
	TitleKey     = "cluster.mod.node"
	ItemAPIKey   = "apikey"
	ItemSettings = "settings"

	keyID   = "key"          // einzige Kennung im Bereich apikey
	setSeen = "nodecfg.seen" // Pruefsummen der abgeglichenen Einstellungen (Aenderungen erkennen, nie abgeglichen)
)

var (
	errItem = errors.New("cluster: unknown node area or setting")
	// ErrAccount: der Key gehoert zu einem anderen Account als dem dieser Node bzw. des Clusters.
	ErrAccount = errors.New("cluster: api key of another ipv64 account")
)

// Item ist ein Bereich des Moduls (fuer die Anmeldung beim Cluster).
type Item struct{ ID, TitleKey, HintKey string }

// Items: die Bereiche des Moduls.
func Items() []Item {
	return []Item{
		{ID: ItemAPIKey, TitleKey: "cluster.item.apikey", HintKey: "cluster.apikey_hint"},
		{ID: ItemSettings, TitleKey: "cluster.item.node_settings", HintKey: "cluster.node_settings_hint"},
	}
}

// Setting ist eine abgeglichene Einstellung.
type Setting struct {
	Key    string
	Secret bool                // verschluesselt gespeichert: im Klartext uebertragen, hier neu verschluesselt
	Valid  func(v string) bool // nil = jeder Wert
	// Apply speichert wie die Einstellungsseite (nil = nur den Wert speichern)
	Apply func(set func(k, v string) error, v string) error
}

func oneOf(list ...string) func(string) bool {
	return func(v string) bool { return slices.Contains(list, v) }
}

// settings: was abgeglichen wird (Whitelist). Die Kennzahlen fuer Prometheus haben keine Einstellungen, die
// MCP-Schluessel gehoeren zu den Benutzern (nur als Hash gespeichert), die Sprache ist je Benutzer.
var settings = []Setting{
	{Key: notify.SetNodeTimezone, Valid: func(v string) bool { _, err := time.LoadLocation(v); return v != "" && err == nil }},
	{Key: selfupdate.SetMode, Valid: oneOf(selfupdate.Modes...), Apply: selfupdate.SaveMode},
	{Key: selfupdate.SetChannel, Valid: oneOf(selfupdate.Channels...)},
	{Key: selfupdate.SetWindow, Valid: selfupdate.ValidWindow},
	{Key: "mcp.enabled", Valid: oneOf("0", "1")}, // web/mcp.go setMCPEnabled
}

// SettingKeys: Schluessel der abgeglichenen Einstellungen.
func SettingKeys() []string {
	out := make([]string, 0, len(settings))
	for _, s := range settings {
		out = append(out, s.Key)
	}
	return out
}

func lookup(key string) *Setting {
	for i := range settings {
		if settings[i].Key == key {
			return &settings[i]
		}
	}
	return nil
}

// Deps sind die Abhaengigkeiten.
type Deps struct {
	Store   *store.Store
	Box     *secrets.Box  // nil = unverschluesselt (nur Tests)
	Key     *ipv64api.Key // zentraler API-Key (nil = Bereich apikey ohne Inhalt)
	Account func() int64  // ipv64-Account dieser Node (wie der Cluster ihn prueft), 0 = keiner
	// ClusterAccount: Account des Clusters (eigener, sonst der eines Mitglieds; 0 = keiner), nil = keiner
	ClusterAccount func(ctx context.Context) int64
	Log            *slog.Logger
}

// Cluster liefert und uebernimmt die Eintraege des Moduls.
type Cluster struct {
	d Deps

	mu     sync.Mutex
	seen   map[string]string                                                      // Schluessel -> Pruefsumme des Werts
	change func(ctx context.Context, item, id string, deleted bool, at time.Time) // an den Cluster (at Null = jetzt bzw. Herkunft)
	origin func(ctx context.Context) string                                       // Name der Urheberin einer Uebernahme
}

// New legt das Modul an.
func New(d Deps) *Cluster {
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	if d.Account == nil {
		d.Account = func() int64 { return 0 }
	}
	return &Cluster{d: d, seen: map[string]string{}}
}

// SetCluster haengt den Cluster an (vor dessen Start): Aenderungen am Key und an den Einstellungen gehen an change.
// Einstellungen, die seit dem letzten Lauf neu oder anders sind, meldet es sofort mit ihrem Zeitpunkt.
func (c *Cluster) SetCluster(change func(ctx context.Context, item, id string, deleted bool, at time.Time), origin func(ctx context.Context) string) {
	ctx := context.Background()
	c.mu.Lock()
	c.change, c.origin = change, origin
	_ = json.Unmarshal([]byte(c.d.Store.SettingOr(ctx, setSeen, "{}")), &c.seen)
	if c.seen == nil {
		c.seen = map[string]string{}
	}
	c.mu.Unlock()
	if c.d.Key != nil {
		c.d.Key.SetCluster(func(ctx context.Context, deleted bool) { change(ctx, ItemAPIKey, keyID, deleted, time.Time{}) })
	}
	c.d.Store.SetSettingHook(c.settingWritten)
	for i := range settings {
		c.note(ctx, &settings[i], true)
	}
}

// settingWritten: Hook des Stores nach jedem Schreiben einer Einstellung.
func (c *Cluster) settingWritten(ctx context.Context, key string) {
	if s := lookup(key); s != nil {
		c.note(ctx, s, false)
	}
}

// value liest eine Einstellung im Klartext (ok=false: nicht gesetzt; err: Geheimnis nicht lesbar) mit ihrem Zeitpunkt.
func (c *Cluster) value(ctx context.Context, s *Setting) (v string, at time.Time, ok bool, err error) {
	var raw, upd string
	err = c.d.Store.Reader().QueryRowContext(ctx, `SELECT value, updated_at FROM settings WHERE key = ?`, s.Key).Scan(&raw, &upd)
	if errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, false, nil
	}
	if err != nil {
		return "", time.Time{}, false, err
	}
	if s.Secret && raw != "" && c.d.Box != nil {
		if raw, err = c.d.Box.Decrypt(raw); err != nil {
			return "", time.Time{}, false, err
		}
	}
	return raw, store.ParseTime(upd), true, nil
}

func sum(v string) string {
	h := sha256.Sum256([]byte(v))
	return hex.EncodeToString(h[:])
}

// note meldet eine geaenderte Einstellung an den Cluster (Vergleich mit der zuletzt gesehenen Pruefsumme, daher
// zaehlt ein unveraendert gespeicherter Wert nicht). startup: Zeitpunkt aus der Datenbank statt jetzt.
func (c *Cluster) note(ctx context.Context, s *Setting, startup bool) {
	v, at, ok, err := c.value(context.WithoutCancel(ctx), s)
	if err != nil || !ok {
		return
	}
	h := sum(v)
	c.mu.Lock()
	if c.seen[s.Key] == h {
		c.mu.Unlock()
		return
	}
	c.seen[s.Key] = h
	c.saveSeen(ctx)
	change := c.change
	c.mu.Unlock()
	if !startup {
		at = time.Time{}
	}
	if change != nil {
		change(ctx, ItemSettings, s.Key, false, at)
	}
}

// saveSeen speichert die Pruefsummen (unter c.mu).
func (c *Cluster) saveSeen(ctx context.Context) {
	b, _ := json.Marshal(c.seen)
	if err := c.d.Store.SetSetting(context.WithoutCancel(ctx), setSeen, string(b)); err != nil {
		c.d.Log.Warn("cluster: node settings state not saved", "err", err)
	}
}

// ClusterIDs: vorhandene Eintraege eines Bereichs (erster Abgleich).
func (c *Cluster) ClusterIDs(ctx context.Context, item string) ([]string, error) {
	switch item {
	case ItemAPIKey:
		if c.d.Key != nil && c.d.Store.SettingOr(ctx, ipv64api.SetKey, "") != "" {
			return []string{keyID}, nil
		}
		return nil, nil
	case ItemSettings:
		var out []string
		for i := range settings {
			if _, ok, err := c.d.Store.Setting(ctx, settings[i].Key); err == nil && ok {
				out = append(out, settings[i].Key)
			}
		}
		return out, nil
	}
	return nil, errItem
}

// keyData ist der Key im Cluster (Klartext); Incomplete: hier nicht lesbar oder durch ipv64.net entfernt, die anderen
// behalten ihren Stand.
type keyData struct {
	Key        string               `json:"key,omitempty"`
	Account    ipv64api.AccountInfo `json:"account"`
	Incomplete bool                 `json:"incomplete,omitempty"`
}

// settingData ist eine Einstellung im Cluster (Geheimnisse im Klartext).
type settingData struct {
	Value      string `json:"value"`
	Incomplete bool   `json:"incomplete,omitempty"`
}

// ClusterGet liefert den aktuellen Stand eines Eintrags.
func (c *Cluster) ClusterGet(ctx context.Context, item, id string) (json.RawMessage, bool, error) {
	switch {
	case item == ItemAPIKey && id == keyID:
		if c.d.Key == nil {
			return nil, false, nil
		}
		out := keyData{Key: c.d.Key.Get(ctx), Account: c.d.Key.Info(ctx)}
		if out.Key == "" { // ohne Hook weg (auf ipv64.net entfernt) oder nicht lesbar: kein Loeschen fuer die anderen
			out = keyData{Incomplete: true}
		}
		b, err := json.Marshal(out)
		return b, err == nil, err
	case item == ItemSettings:
		s := lookup(id)
		if s == nil {
			return nil, false, errItem
		}
		v, _, ok, err := c.value(ctx, s)
		out := settingData{Value: v}
		if err != nil {
			c.d.Log.Warn("cluster: node setting not readable", "key", id, "err", err)
			out = settingData{Incomplete: true}
		} else if !ok {
			return nil, false, nil
		}
		b, err := json.Marshal(out)
		return b, err == nil, err
	}
	return nil, false, errItem
}

// ClusterApply uebernimmt einen Eintrag einer anderen Node.
func (c *Cluster) ClusterApply(ctx context.Context, item, id string, data json.RawMessage, deleted bool) error {
	switch {
	case item == ItemAPIKey && id == keyID:
		return c.applyKey(ctx, data, deleted)
	case item == ItemSettings:
		if s := lookup(id); s != nil {
			return c.applySetting(ctx, s, data, deleted)
		}
	}
	return errItem
}

func (c *Cluster) applyKey(ctx context.Context, data json.RawMessage, deleted bool) error {
	k := c.d.Key
	if k == nil {
		return errItem
	}
	if !k.Removed(ctx).IsZero() {
		return nil // auf ipv64.net entfernt: nur ein hier eingetragener Key gilt wieder
	}
	if deleted {
		if c.d.Store.SettingOr(ctx, ipv64api.SetKey, "") == "" {
			return nil
		}
		// entfernt, bevor diese Node mit der entfernenden Node verbunden war (im Cluster vor dem Beitritt): der Key
		// hier gilt weiter und geht an die Nodes ohne Key (Dennis: die Node ohne Key
		// uebernimmt ihn). Ein spaeter, bewusstes Entfernen im gemeinsamen Cluster wirkt wie bisher.
		if at, since := applyInfoOf(ctx); !at.IsZero() && !since.IsZero() && at.Before(since) {
			c.mu.Lock()
			change := c.change
			c.mu.Unlock()
			if change != nil {
				change(ctx, ItemAPIKey, keyID, false, time.Now())
			}
			return supersededError{}
		}
		if err := k.Clear(ctx); err != nil { // wie das Entfernen in den Einstellungen
			return err
		}
		c.audit(ctx, "peer.ipv64_key_removed", "", "")
		return nil
	}
	var in keyData
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	if in.Incomplete {
		return nil
	}
	// gleicher Account oder die Node hat noch keinen (dann muss der Key zum Cluster passen); nie ein anderer Account
	own, acc := c.d.Account(), int64(in.Account.ID)
	if acc <= 0 || own != acc && (own != 0 || !c.clusterFits(ctx, acc)) {
		return fmt.Errorf("%w (key: %d, this node: %d)", ErrAccount, in.Account.ID, own)
	}
	if in.Key == k.Get(ctx) {
		return nil
	}
	if err := k.SetFromCluster(ctx, in.Key, in.Account); err != nil { // wie eine Eingabe in den Einstellungen
		return err
	}
	c.audit(ctx, "peer.ipv64_key", in.Account.Account, "account="+in.Account.Account)
	c.d.Log.Info("ipv64 api key taken from the cluster", "account", in.Account.ID)
	return nil
}

// ClusterJoined (peer.Joiner, nur auf der beitretenden Node): ohne Key geht der Loeschvermerk des Keys nicht in den
// neuen Cluster - ein Entfernen in einem Cluster loescht nie den Key in einem anderen, und die Node uebernimmt den Key
// des neuen Clusters (ohne eigenen Eintrag gewinnt dessen Stand). Einen vorhandenen Key meldet sie nicht neu: ein
// neuerer Key im Cluster gewinnt wie immer nach Zeitpunkt; steht dort nur ein aelterer Loeschvermerk, gilt applyKey.
func (c *Cluster) ClusterJoined(ctx context.Context) []string {
	if c.d.Key == nil {
		return nil
	}
	if c.d.Key.Get(ctx) == "" || !c.d.Key.Removed(ctx).IsZero() {
		return []string{ItemAPIKey + "/" + keyID}
	}
	return nil
}

// supersededError: Loeschvermerk aelter als die Verbindung zum liefernden Mitglied, der eigene Key gilt weiter und ist
// neu gemeldet (peer behandelt das nicht als Fehler, Superseded).
type supersededError struct{}

func (supersededError) Error() string    { return "key removal predates the membership, own key kept" }
func (supersededError) Superseded() bool { return true }

type applyKeyT struct{}

type applyInfo struct{ at, since time.Time }

// WithApplyInfo: Zeitpunkt der uebernommenen Aenderung und seit wann diese Node mit dem liefernden Mitglied verbunden
// ist (setzt der Cluster-Adapter nodecluster aus peer.ClusterOrigin und peer.MemberSince).
func WithApplyInfo(ctx context.Context, at, since time.Time) context.Context {
	return context.WithValue(ctx, applyKeyT{}, applyInfo{at, since})
}

func applyInfoOf(ctx context.Context) (at, since time.Time) {
	i, _ := ctx.Value(applyKeyT{}).(applyInfo)
	return i.at, i.since
}

// clusterFits: der Account acc passt zum Cluster (dessen Account ist derselbe oder es hat noch keiner einen).
func (c *Cluster) clusterFits(ctx context.Context, acc int64) bool {
	if c.d.ClusterAccount == nil {
		return true
	}
	ref := c.d.ClusterAccount(ctx)
	return ref == 0 || ref == acc
}

func (c *Cluster) applySetting(ctx context.Context, s *Setting, data json.RawMessage, deleted bool) error {
	if deleted {
		return nil // Einstellungen werden nicht geloescht (ohne Wert gilt hier der eigene)
	}
	var in settingData
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	if in.Incomplete {
		return nil
	}
	if s.Valid != nil && !s.Valid(in.Value) {
		return fmt.Errorf("cluster: invalid value for %s", s.Key)
	}
	cur, _, ok, err := c.value(ctx, s)
	if err == nil && ok && cur == in.Value {
		return nil
	}
	c.mu.Lock() // vorher merken: der Hook des Stores meldet die Uebernahme nicht als eigene Aenderung
	c.seen[s.Key] = sum(in.Value)
	c.saveSeen(ctx)
	c.mu.Unlock()
	set := func(k, v string) error {
		if k == s.Key && s.Secret && c.d.Box != nil && v != "" {
			v = c.d.Box.Encrypt(v)
		}
		return c.d.Store.SetSetting(ctx, k, v)
	}
	if s.Apply != nil {
		err = s.Apply(set, in.Value)
	} else {
		err = set(s.Key, in.Value)
	}
	if err != nil {
		return err
	}
	details := s.Key + "=" + in.Value
	if s.Secret {
		details = s.Key
	}
	c.audit(ctx, "peer.node_setting", s.Key, details)
	return nil
}

func (c *Cluster) audit(ctx context.Context, action, target, details string) {
	by := ""
	if c.origin != nil {
		by = c.origin(ctx)
	}
	if err := c.d.Store.Audit(context.WithoutCancel(ctx), store.AuditEntry{Actor: "node:" + by, Action: action, Target: target, Details: details, Origin: "peer"}); err != nil {
		c.d.Log.Error("audit write failed", "err", err)
	}
}
