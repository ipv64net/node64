package peer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"github.com/ipv64net/node64/internal/healthchecks"
	"github.com/ipv64net/node64/internal/notify"
)

// Benachrichtigungs-Einstellungen des Accounts (Ruhezeiten, Grenzen, Sammelmeldung) in der Gruppe: als ein
// Paket, die juengere Aenderung gewinnt. Erkannt wird eine Aenderung am Inhalt (lokal oder vom hub), daher
// braucht es keinen Hook in der Oberflaeche. Eine Node ohne ipv64, die neu dazukommt, uebernimmt die
// Einstellungen der Gruppe (ihre eigenen zaehlen erst, wenn sie sie aendert); eine verknuepfte Node bringt die
// Einstellungen des Accounts mit.

const (
	setSettingsHash = "peer.settings_hash"
	setSettingsAt   = "peer.settings_at"
)

func (m *Manager) settingsBundle(ctx context.Context) map[string]string {
	out := map[string]string{}
	for _, k := range notify.SyncedSettings {
		if v, ok, _ := m.d.Core.Setting(ctx, k); ok {
			out[k] = v
		}
	}
	return out
}

func hashKV(kv map[string]string) string {
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	b, _ := json.Marshal(struct {
		K []string
		M map[string]string
	}{keys, kv})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (m *Manager) settingsAt(ctx context.Context) time.Time {
	return parseTime(m.d.Core.SettingOr(ctx, setSettingsAt, ""))
}

// checkSettings traegt eine Aenderung der Einstellungen ins Protokoll ein (laeuft mit jedem Abgleich).
func (m *Manager) checkSettings(ctx context.Context) {
	kv := m.settingsBundle(ctx)
	h := hashKV(kv)
	old := m.d.Core.SettingOr(ctx, setSettingsHash, "")
	if h == old {
		return
	}
	m.saveSetting(ctx, setSettingsHash, h)
	if old == "" && (!m.linkedSelf() || len(kv) == 0) {
		return // erster Lauf ohne ipv64: kein Zeitpunkt, die Einstellungen der Gruppe gehen vor
	}
	m.saveSetting(ctx, setSettingsAt, fmtTime(time.Now()))
	m.LogChange(ctx, "settings", "notify", "upsert")
}

// applySettings uebernimmt die Einstellungen einer anderen Node, wenn sie juenger sind, und reicht sie weiter
// (Gruppe; als weiterreichende Node auch an den hub, wenn sie von einer Node ohne Sync kommen).
func (m *Manager) applySettings(ctx context.Context, c change) int {
	if c.Settings == nil || c.ChangedAt.IsZero() || !c.ChangedAt.After(m.settingsAt(ctx)) {
		return 0
	}
	for _, k := range notify.SyncedSettings {
		if v, ok := c.Settings[k]; ok {
			m.saveSetting(ctx, k, v)
		}
	}
	m.saveSetting(ctx, setSettingsHash, hashKV(m.settingsBundle(ctx)))
	m.saveSetting(ctx, setSettingsAt, fmtTime(c.ChangedAt))
	m.LogChange(healthchecks.WithPeer(ctx, c.Origin, c.ChangedAt), "settings", "notify", "upsert")
	if m.d.SettingsToHub != nil && m.forwardFor(ctx, c.Origin) {
		m.d.SettingsToHub()
	}
	return 1
}

// Forwarder: Node, die Aenderungen von Nodes ohne Sync an ipv64 weiterreicht (Anzeige; self = diese Node,
// leer = keine Node der Gruppe ist verknuepft und erreichbar).
func (m *Manager) Forwarder(ctx context.Context) (id, name string, self bool) {
	if m.linkedSelf() && m.syncOn(ctx, "healthchecks", "checks") { // wie forwarder
		id, name, self = m.d.NodeID(), m.d.NodeName(), true
	}
	list := m.hcMembers(ctx)
	for _, x := range list {
		if x.Linked && x.Online() && (id == "" || x.NodeID < id) {
			id, name, self = x.NodeID, x.Name, false
		}
	}
	return id, name, self
}

// LinkedSelf: diese Node ist mit ipv64 verknuepft (Anzeige).
func (m *Manager) LinkedSelf() bool { return m.linkedSelf() }

// saveSetting speichert eine Einstellung der Gruppe und loggt einen Fehler (sonst blieben Nodes still verschieden).
func (m *Manager) saveSetting(ctx context.Context, key, value string) {
	if err := m.d.Core.SetSetting(ctx, key, value); err != nil {
		m.d.Log.Error("group setting not saved", "key", key, "err", err)
	}
}
