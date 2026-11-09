package monitor64

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/eval"
)

// Zwischenspeicher der Regeln, Abweichungen, Benachrichtigung und Wartung (neu geladen nach jeder Aenderung).

const (
	setStd    = "monitor64.std"    // JSON: Abweichungen von der Standard-Tabelle je Art (Felder ueberschreiben)
	setNotify = "monitor64.notify" // JSON: eval.NotifyConfig
)

type cfgCache struct {
	std             eval.Table
	overrides       []eval.Override
	notify          eval.NotifyConfig
	notifyOverrides []eval.NotifyOverride
	hostKind        map[string]*eval.Rule // host_uid|kind
	maint           []eval.Window
	loaded          time.Time
}

// config liefert den aktuellen Stand (laedt beim ersten Aufruf).
func (m *Module) config() *cfgCache {
	if c := m.cfg.Load(); c != nil {
		return c
	}
	m.reloadConfig(context.Background())
	return m.cfg.Load()
}

// reloadConfig liest Regeln, Abweichungen, Benachrichtigung und Wartung neu.
func (m *Module) reloadConfig(ctx context.Context) {
	c := &cfgCache{std: eval.Defaults(), hostKind: map[string]*eval.Rule{}, loaded: time.Now(),
		notify: eval.DefaultNotifyConfig([]string{defaultChannels})}
	// Standard-Tabelle: gespeicherte Felder ueber die eingebauten Werte legen
	if raw := m.st.SettingOr(ctx, setStd, ""); raw != "" {
		var saved map[string]json.RawMessage
		if json.Unmarshal([]byte(raw), &saved) == nil {
			for kind, r := range saved {
				base := c.std[kind]
				if json.Unmarshal(r, &base) == nil {
					c.std[kind] = base
				}
			}
		}
	}
	if raw := m.st.SettingOr(ctx, setNotify, ""); raw != "" {
		var n eval.NotifyConfig
		if json.Unmarshal([]byte(raw), &n) == nil {
			c.notify = n
		}
	}
	rows, err := m.st.Reader().QueryContext(ctx, `SELECT uid, scope, target_type, target, kind, data FROM m64_overrides WHERE deleted = 0 ORDER BY position, id`)
	if err == nil {
		for rows.Next() {
			var uid, scope, tt, target, kind, data string
			if rows.Scan(&uid, &scope, &tt, &target, &kind, &data) != nil {
				continue
			}
			group, tag := "", ""
			if tt == "group" {
				group = target
			} else {
				tag = target
			}
			switch scope {
			case "rule":
				var r eval.Rule
				if json.Unmarshal([]byte(data), &r) == nil {
					c.overrides = append(c.overrides, eval.Override{ID: uid, Group: group, Tag: tag, Kind: kind, Rule: r})
				}
			case "notify":
				var n eval.NotifyOverride
				if json.Unmarshal([]byte(data), &n) == nil {
					n.ID, n.Group, n.Tag = uid, group, tag
					c.notifyOverrides = append(c.notifyOverrides, n)
				}
			}
		}
		rows.Close()
	} else {
		m.log.Warn("monitor64: load overrides", "err", err)
	}
	if rows, err := m.st.Reader().QueryContext(ctx, `SELECT host_uid, kind, rule FROM m64_host_rules WHERE deleted = 0`); err == nil {
		for rows.Next() {
			var hu, kind, data string
			if rows.Scan(&hu, &kind, &data) != nil {
				continue
			}
			var r eval.Rule
			if json.Unmarshal([]byte(data), &r) == nil {
				c.hostKind[hu+"|"+kind] = &r
			}
		}
		rows.Close()
	}
	if rows, err := m.st.Reader().QueryContext(ctx, `SELECT uid, title, targets, start_at, end_at, recur, ended_at FROM m64_maint WHERE deleted = 0`); err == nil {
		for rows.Next() {
			var uid, title, targets, start, end, recur, ended string
			if rows.Scan(&uid, &title, &targets, &start, &end, &recur, &ended) != nil {
				continue
			}
			w := eval.Window{ID: uid, Reason: title, Start: parseTS(start), End: parseTS(end)}
			if e := parseTS(ended); !e.IsZero() && (w.End.IsZero() || e.Before(w.End)) {
				w.End = e // vorzeitig beendet
			}
			var t struct {
				Hosts  []string `json:"hosts"`
				Groups []string `json:"groups"`
				Tags   []string `json:"tags"`
			}
			_ = json.Unmarshal([]byte(targets), &t)
			w.Hosts, w.Groups, w.Tags = t.Hosts, t.Groups, t.Tags
			if recur != "" {
				var r eval.Recurrence
				if json.Unmarshal([]byte(recur), &r) == nil {
					w.Recurring = &r
				}
			}
			c.maint = append(c.maint, w)
		}
		rows.Close()
	}
	m.cfg.Store(c)
}

// inMaintenance: Host gerade in Wartung (Zeitzone der Node).
func (m *Module) inMaintenance(at time.Time, h eval.HostRef) (bool, *eval.Window) {
	return eval.InMaintenance(m.config().maint, at, h, m.location())
}

// location ist die Zeitzone der Node (Einstellung node.timezone, sonst lokal).
func (m *Module) location() *time.Location {
	if tz := m.st.SettingOr(context.Background(), "node.timezone", ""); tz != "" {
		if loc, err := time.LoadLocation(tz); err == nil {
			return loc
		}
	}
	return time.Local
}

// quietNow: Ruhezeit (nur fuer Erinnerungen; Zurueckhalten und Sammelmeldung macht der Dispatcher).
// Vorerst immer false: Erinnerungen in der Ruhezeit haelt der Dispatcher zurueck und sie erscheinen in der
// Sammelmeldung (offener Punkt: Ruhezeit-Pruefung des Dispatchers exportieren).
func (m *Module) quietNow(time.Time) bool { return false }
