package monitor64

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/monitor64/eval"
)

// Konfig-Export und -Import (Plan "Export und Backup"): Hosts, Zugaenge, Dienste, Einstellungen am Host,
// Abweichungen, Wartung, Standard-Schwellen und Benachrichtigung. Geheimnisse (Zugangsdaten, Schluessel der Node)
// nur bei Export mit Passwort, verschluesselt mit dem Export-Passwort. Problem-Historie und Verlauf sind nicht im
// Konfig-Export (Historie im Backup, Verlauf im Backup "mit Statistik").

// exportTables: Tabellen mit ihren Spalten (ohne id); uid ist der Schluessel beim Import.
var exportTables = []struct {
	name string
	cols []string
}{
	{"m64_hosts", []string{"uid", "name", "address", "kind", "group_name", "tags", "interval_sec", "owner_node", "preferred_node", "backup_nodes", "agent_autoupd", "paused", "notes", "created_at", "created_by", "updated_at", "updated_by", "deleted"}},
	{"m64_access", []string{"uid", "host_uid", "type", "config", "secret", "hostkey", "enabled", "updated_at", "updated_by", "deleted"}},
	{"m64_services", []string{"uid", "host_uid", "key", "name", "kind", "adopted", "vanished_at", "via", "host_rule", "soll", "report", "updated_at", "updated_by", "deleted"}},
	{"m64_host_rules", []string{"uid", "host_uid", "kind", "rule", "updated_at", "updated_by", "deleted"}},
	{"m64_overrides", []string{"uid", "scope", "position", "target_type", "target", "kind", "data", "updated_at", "updated_by", "deleted"}},
	{"m64_maint", []string{"uid", "title", "targets", "start_at", "end_at", "recur", "ended_at", "created_by", "updated_at", "updated_by", "deleted"}},
}

type exportData struct {
	Version  int                         `json:"version"`
	Tables   map[string][]map[string]any `json:"tables"`
	Std      string                      `json:"std,omitempty"`
	Notify   string                      `json:"notify,omitempty"`
	NodeKey  string                      `json:"node_key,omitempty"` // mit Export-Passwort verschluesselt
	Settings map[string]string           `json:"settings,omitempty"`
}

var exportSettings = []string{setWorkers, setProm, setPromTags}

// Export liefert die Konfiguration (module.Exporter).
func (m *Module) Export(ctx context.Context) (any, error) {
	seal := module.SecretSealerOf(ctx)
	out := exportData{Version: 1, Tables: map[string][]map[string]any{}, Settings: map[string]string{},
		Std: m.st.SettingOr(ctx, setStd, ""), Notify: m.st.SettingOr(ctx, setNotify, "")}
	for _, k := range exportSettings {
		if v := m.st.SettingOr(ctx, k, ""); v != "" {
			out.Settings[k] = v
		}
	}
	for _, t := range exportTables {
		rows, err := m.st.Reader().QueryContext(ctx, `SELECT `+strings.Join(t.cols, ", ")+` FROM `+t.name+` WHERE deleted = 0 ORDER BY id`)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			vals := make([]any, len(t.cols))
			ptrs := make([]any, len(t.cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				rows.Close()
				return nil, err
			}
			row := map[string]any{}
			for i, c := range t.cols {
				if b, ok := vals[i].([]byte); ok {
					vals[i] = string(b)
				}
				row[c] = vals[i]
			}
			if t.name == "m64_access" {
				row["secret"] = m.sealSecret(seal, fmt.Sprint(row["secret"]))
			}
			out.Tables[t.name] = append(out.Tables[t.name], row)
		}
		rows.Close()
	}
	if seal != nil {
		if enc := m.st.SettingOr(ctx, setNodeKey, ""); enc != "" {
			if pem, err := m.box.Decrypt(enc); err == nil {
				out.NodeKey = seal.Encrypt(pem)
			}
		}
	}
	return out, nil
}

// sealSecret: Geheimnis der Node in das Export-Passwort umschluesseln (ohne Passwort: leer).
func (m *Module) sealSecret(seal module.SecretSealer, enc string) string {
	if enc == "" || seal == nil {
		return ""
	}
	plain, err := m.box.Decrypt(enc)
	if err != nil {
		return ""
	}
	return seal.Encrypt(plain)
}

// Import uebernimmt eine exportierte Konfiguration (vorhandene Eintraege mit gleicher uid werden ersetzt).
func (m *Module) Import(ctx context.Context, raw json.RawMessage) (int, error) {
	var in exportData
	if err := json.Unmarshal(raw, &in); err != nil {
		return 0, err
	}
	seal := module.SecretSealerOf(ctx)
	tx, err := m.st.Writer().BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	n := 0
	for _, t := range exportTables {
		for _, row := range in.Tables[t.name] {
			uid, _ := row["uid"].(string)
			if uid == "" {
				continue
			}
			if t.name == "m64_access" {
				row["secret"] = m.unsealSecret(seal, fmt.Sprint(row["secret"]))
			}
			if t.name == "m64_overrides" && fmt.Sprint(row["scope"]) == "notify" {
				row["data"] = remapNotifyOverride(ctx, fmt.Sprint(row["data"]))
			}
			if err := upsertRow(ctx, tx, t.name, t.cols, row); err != nil {
				return n, fmt.Errorf("%s %s: %w", t.name, uid, err)
			}
			n++
		}
	}
	if err := tx.Commit(); err != nil {
		return n, err
	}
	if in.Std != "" {
		_ = m.st.SetSetting(ctx, setStd, in.Std)
	}
	if in.Notify != "" {
		_ = m.st.SetSetting(ctx, setNotify, remapNotifyConfig(ctx, in.Notify))
	}
	for k, v := range in.Settings {
		for _, allowed := range exportSettings {
			if k == allowed {
				_ = m.st.SetSetting(ctx, k, v)
			}
		}
	}
	if in.NodeKey != "" && seal != nil {
		if pem, err := seal.Decrypt(in.NodeKey); err == nil {
			_ = m.st.SetSetting(ctx, setNodeKey, m.box.Encrypt(pem))
		}
	}
	if m.scheduler() != nil { // laeuft: neu laden
		m.reloadConfig(ctx)
		hosts, _ := m.store.Hosts(ctx)
		for _, h := range hosts {
			m.ReloadHost(ctx, h.UID)
		}
	}
	return n, nil
}

func (m *Module) unsealSecret(seal module.SecretSealer, v string) string {
	if v == "" || seal == nil {
		return ""
	}
	plain, err := seal.Decrypt(v)
	if err != nil {
		return ""
	}
	return m.box.Encrypt(plain)
}

func upsertRow(ctx context.Context, tx *sql.Tx, table string, cols []string, row map[string]any) error {
	args := make([]any, len(cols))
	var sets []string
	for i, c := range cols {
		v := row[c]
		if f, ok := v.(float64); ok { // JSON-Zahlen
			v = int64(f)
		}
		if v == nil {
			v = ""
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

// remapChannelIDs setzt Kanal-IDs (als Text) auf die dieser Node um; "default" bleibt.
func remapChannelIDs(ctx context.Context, routes []eval.ChannelRoute) []eval.ChannelRoute {
	var out []eval.ChannelRoute
	for _, r := range routes {
		if r.ID == defaultChannels {
			out = append(out, r)
			continue
		}
		id, err := strconv.ParseInt(r.ID, 10, 64)
		if err != nil {
			continue
		}
		if mapped := module.MapChannels(ctx, []int64{id}); len(mapped) == 1 {
			r.ID = strconv.FormatInt(mapped[0], 10)
			out = append(out, r)
		}
	}
	return out
}

func remapNotifyConfig(ctx context.Context, raw string) string {
	var c eval.NotifyConfig
	if json.Unmarshal([]byte(raw), &c) != nil {
		return raw
	}
	c.Channels = remapChannelIDs(ctx, c.Channels)
	b, _ := json.Marshal(c)
	return string(b)
}

func remapNotifyOverride(ctx context.Context, raw string) string {
	var o eval.NotifyOverride
	if json.Unmarshal([]byte(raw), &o) != nil {
		return raw
	}
	o.Channels = remapChannelIDs(ctx, o.Channels)
	b, _ := json.Marshal(o)
	return string(b)
}
