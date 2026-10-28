package ipv64api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

// Einstellungen (Tabelle settings)
const (
	SetKey     = "ipv64.apikey"  // verschluesselt (secrets.Box)
	SetAccount = "ipv64.account" // AccountInfo als JSON, nur zur Anzeige
	SetRemoved = "ipv64.removed" // Node auf ipv64.net entfernt (RFC 3339); leer = nein, ein neuer Key setzt zurueck
)

// AccountInfo ist das Konto hinter dem gespeicherten Key (zur Anzeige, ohne Key).
type AccountInfo struct {
	ID        int       `json:"id,omitempty"` // Account-ID (Vergleich mit der Healthchecks-Verknuepfung)
	Account   string    `json:"account"`
	Plan      string    `json:"plan"`
	CheckedAt time.Time `json:"checked_at"`
	KeyName   string    `json:"key_name,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"` // Null = laeuft nicht ab
}

// DaysLeft sind die ganzen Tage bis zum Ablauf (negativ = abgelaufen); nur sinnvoll mit ExpiresAt.
func (a AccountInfo) DaysLeft() int {
	return int(time.Until(a.ExpiresAt).Hours() / 24)
}

// Expired: der Key ist abgelaufen.
func (a AccountInfo) Expired() bool { return !a.ExpiresAt.IsZero() && time.Now().After(a.ExpiresAt) }

// Key ist der zentrale API-Key des Containers.
type Key struct {
	st     *store.Store
	box    *secrets.Box
	client *Client
	log    *slog.Logger
	ovc    overviewCache // Account-Uebersicht (overview.go)
	// cluster meldet einen eingetragenen, geaenderten oder entfernten Key an den Cluster (nil = ohne, nodecfg)
	cluster func(ctx context.Context, deleted bool)
}

// NewKey erzeugt die Ablage; box darf nil sein (dann unverschluesselt, nur Tests).
func NewKey(st *store.Store, box *secrets.Box, client *Client, log *slog.Logger) *Key {
	return &Key{st: st, box: box, client: client, log: log}
}

// SetCluster haengt den Cluster an (vor Start; nil = ohne). Die Entfernung durch ipv64.net (MarkRemoved) betrifft
// nur diese Node und geht nicht an den Cluster.
func (k *Key) SetCluster(f func(ctx context.Context, deleted bool)) { k.cluster = f }

// Client liefert den API-Client.
func (k *Key) Client() *Client { return k.client }

// Get liefert den Key im Klartext (leer = keiner eingetragen).
func (k *Key) Get(ctx context.Context) string {
	v := k.st.SettingOr(ctx, SetKey, "")
	if v == "" || k.box == nil {
		return v
	}
	plain, err := k.box.Decrypt(v)
	if err != nil {
		k.log.Error("ipv64 api key not readable", "err", err)
		return ""
	}
	return plain
}

// Info liefert das zuletzt geprueft Konto.
func (k *Key) Info(ctx context.Context) AccountInfo {
	var a AccountInfo
	_ = json.Unmarshal([]byte(k.st.SettingOr(ctx, SetAccount, "")), &a)
	return a
}

// ErrFormat: kein gueltiger Key.
var ErrFormat = errors.New("invalid api key format")

// Set prueft den Key bei ipv64 und speichert ihn verschluesselt. Leer = gespeicherten Key erneut pruefen.
func (k *Key) Set(ctx context.Context, key string) (*Me, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		key = k.Get(ctx)
	}
	if !KeyRe.MatchString(key) {
		return nil, ErrFormat
	}
	me, err := k.client.Me(ctx, key)
	if err != nil {
		return nil, err
	}
	info := AccountInfo{ID: me.ID, Account: me.Account(), Plan: me.Plan.Name, CheckedAt: time.Now().UTC(), KeyName: me.Auth.KeyName}
	if me.Auth.KeyID != nil { // Ablauf steht nur in der Liste der Keys
		if keys, err := k.client.APIKeys(ctx, key); err == nil {
			for _, ak := range keys {
				if ak.ID == *me.Auth.KeyID {
					info.KeyName = ak.Name
					if ak.ExpiresAt != nil {
						info.ExpiresAt = ak.ExpiresAt.UTC()
					}
				}
			}
		} else {
			k.log.Warn("api key list not readable", "err", err)
		}
	}
	if err := k.save(ctx, key, info); err != nil {
		return nil, err
	}
	return me, nil
}

// SetFromCluster speichert einen Key, den eine andere Node des Clusters geprueft hat, mit deren Konto - auf demselben
// Weg wie eine Eingabe (Set). Hier geprueft wird er mit der naechsten Abfrage bei ipv64 (RefreshPlan, RefreshIfStale).
func (k *Key) SetFromCluster(ctx context.Context, key string, info AccountInfo) error {
	if !KeyRe.MatchString(key) {
		return ErrFormat
	}
	return k.save(ctx, key, info)
}

// save speichert einen geprueften Key verschluesselt mit seinem Konto; ein neuer Key geht an den Cluster.
func (k *Key) save(ctx context.Context, key string, info AccountInfo) error {
	old := k.Get(ctx)
	stored := key
	if k.box != nil {
		stored = k.box.Encrypt(key)
	}
	if err := k.st.SetSetting(ctx, SetKey, stored); err != nil {
		return err
	}
	raw, _ := json.Marshal(info)
	_ = k.st.SetSetting(ctx, SetAccount, string(raw))
	_ = k.st.SetSetting(ctx, SetRemoved, "") // neuer bzw. erneut geprueft Key: wieder melden (hello)
	if k.cluster != nil && key != old {
		k.cluster(ctx, false)
	}
	return nil
}

// Removed liefert, wann ipv64 diese Node entfernt hat (Null = nicht entfernt).
func (k *Key) Removed(ctx context.Context) time.Time {
	t, _ := time.Parse(time.RFC3339, k.st.SettingOr(ctx, SetRemoved, ""))
	return t
}

// MarkRemoved merkt die Entfernung auf ipv64.net und loescht den Key (lokale Daten bleiben).
func (k *Key) MarkRemoved(ctx context.Context) error {
	if err := k.st.SetSetting(ctx, SetRemoved, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	return k.clear(ctx)
}

// RefreshIfStale prueft den gespeicherten Key erneut, wenn die letzte Pruefung aelter als maxAge ist
// oder Name/Ablauf noch fehlen (z. B. nach dem Umzug aus einem Modul).
func (k *Key) RefreshIfStale(ctx context.Context, maxAge time.Duration) {
	if k.Get(ctx) == "" {
		return
	}
	info := k.Info(ctx)
	if info.KeyName != "" && info.ID != 0 && time.Since(info.CheckedAt) < maxAge {
		return
	}
	if _, err := k.Set(ctx, ""); err != nil {
		k.log.Warn("ipv64 api key check failed", "err", err)
	}
}

// PlanEvery: so oft fragt die Node die Account-Klasse ab (ein Upgrade soll schnell ankommen).
const PlanEvery = 2 * time.Minute

// RefreshPlan fragt Klasse und Konto beim gespeicherten Key ab (nur /me). true = geaendert; dann ist auch die
// Account-Uebersicht verworfen.
func (k *Key) RefreshPlan(ctx context.Context) bool {
	key := k.Get(ctx)
	if key == "" {
		return false
	}
	me, err := k.client.Me(ctx, key)
	if err != nil {
		return false
	}
	info := k.Info(ctx)
	if info.Account == "" || (info.Plan == me.Plan.Name && info.ID == me.ID && info.Account == me.Account()) {
		return false // noch nie geprueft (das macht Set) oder unveraendert
	}
	k.log.Info("ipv64 account class changed", "old", info.Plan, "new", me.Plan.Name)
	info.ID, info.Account, info.Plan = me.ID, me.Account(), me.Plan.Name
	raw, _ := json.Marshal(info)
	if k.st.SetSetting(ctx, SetAccount, string(raw)) != nil {
		return false
	}
	k.ResetOverview()
	return true
}

// Clear entfernt den Key (auch auf den anderen Nodes des Clusters, wenn der Bereich dort an ist).
func (k *Key) Clear(ctx context.Context) error {
	had := k.st.SettingOr(ctx, SetKey, "") != ""
	if err := k.clear(ctx); err != nil {
		return err
	}
	if k.cluster != nil && had {
		k.cluster(ctx, true)
	}
	return nil
}

func (k *Key) clear(ctx context.Context) error {
	if err := k.st.SetSetting(ctx, SetKey, ""); err != nil {
		return err
	}
	return k.st.SetSetting(ctx, SetAccount, "")
}

// Adopt uebernimmt einen schon verschluesselt gespeicherten Key aus einem Modul (Umzug), wenn zentral noch keiner steht.
func (k *Key) Adopt(ctx context.Context, sealed, accountJSON string) bool {
	if sealed == "" || k.st.SettingOr(ctx, SetKey, "") != "" {
		return false
	}
	if k.st.SetSetting(ctx, SetKey, sealed) != nil {
		return false
	}
	_ = k.st.SetSetting(ctx, SetAccount, accountJSON)
	return true
}
