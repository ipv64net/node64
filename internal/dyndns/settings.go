package dyndns

import (
	"context"
	"errors"
	"strconv"
	"strings"
)

// Einstellungen des Moduls und Auswahl aus dem Account: gemeinsam fuer Oberflaeche und lokale API.

// moduleSettings sind die Einstellungen des Moduls.
type moduleSettings struct {
	Interval    int    `json:"interval_minutes"`
	Source4     string `json:"source4"`
	Source6     string `json:"source6"`
	KeepChecks  int    `json:"keep_checks_days"`
	KeepUpdates int    `json:"keep_updates_days"` // 0 = unbegrenzt
	NotifyIP    bool   `json:"notify_ip"`
	NotifyFail  bool   `json:"notify_fail"`
	NotifyLimit bool   `json:"notify_limit"`
}

// errSettings: ungueltige Einstellung (Pruefabstand, Aufbewahrung oder URL).
var errSettings = errors.New("invalid setting: interval_minutes, keep_*_days or source URL (http/https)")

func (m *Module) getSettings(ctx context.Context) moduleSettings {
	return moduleSettings{Interval: int(m.interval().Minutes()), Source4: m.core.SettingOr(ctx, SetSource4, ""), Source6: m.core.SettingOr(ctx, SetSource6, ""),
		KeepChecks: m.keepDays(ctx, SetKeepChecks, 30), KeepUpdates: m.keepDays(ctx, SetKeepUpdates, 365),
		NotifyIP: m.notifyOn(ctx, SetNotifyIP), NotifyFail: m.notifyOn(ctx, SetNotifyFail), NotifyLimit: m.notifyOn(ctx, SetNotifyLimit)}
}

// saveSettings prueft und speichert die Einstellungen.
func (m *Module) saveSettings(ctx context.Context, s moduleSettings) error {
	s.Source4, s.Source6 = strings.TrimSpace(s.Source4), strings.TrimSpace(s.Source6)
	if !in(strconv.Itoa(s.Interval), itoaList(IntervalOptions)) || !in(strconv.Itoa(s.KeepChecks), itoaList(KeepChecksOptions)) ||
		!in(strconv.Itoa(s.KeepUpdates), itoaList(KeepUpdatesOptions)) || (s.Source4 != "" && !validSource(s.Source4)) ||
		(s.Source6 != "" && !validSource(s.Source6)) || len(s.Source4) > 300 || len(s.Source6) > 300 {
		return errSettings
	}
	b := func(v bool) string {
		if v {
			return "1"
		}
		return "0"
	}
	for k, v := range map[string]string{SetInterval: strconv.Itoa(s.Interval), SetSource4: s.Source4, SetSource6: s.Source6, SetKeepChecks: strconv.Itoa(s.KeepChecks),
		SetKeepUpdates: strconv.Itoa(s.KeepUpdates), SetNotifyIP: b(s.NotifyIP), SetNotifyFail: b(s.NotifyFail), SetNotifyLimit: b(s.NotifyLimit)} {
		if err := m.core.SetSetting(ctx, k, v); err != nil {
			return err
		}
	}
	m.clusterChanged(ctx, clusterSettingsID, false)
	return nil
}

// pickChoice ist die Auswahl eines Namens aus dem Account (leere Modi = Vorbelegung).
type pickChoice struct {
	Mode4 string
	Mode6 string
}

// addPicked legt die gewaehlten Namen als Ziele an; die Tokens kommen frisch von ipv64, nie vom Aufrufer.
func (m *Module) addPicked(ctx context.Context, key string, picks map[string]pickChoice) (added []*Target, failed []string, err error) {
	names, err := m.accountNames(ctx, key)
	if err != nil {
		return nil, nil, err
	}
	for _, p := range names {
		c, ok := picks[p.Key]
		if !ok || p.Exists || p.Blocked != "" {
			continue
		}
		t := m.defaultsFor(p)
		if in(c.Mode4, pickModes4) {
			t.Mode4 = c.Mode4
		}
		if in(c.Mode6, pickModes6) && (c.Mode6 != Mode6Suffix || p.SuffixOf != "") {
			t.Mode6 = c.Mode6
		}
		if t.Mode6 == Mode6Suffix {
			t.Suffix6 = p.SuffixOf
		}
		if t.Mode4 == Mode4Off && t.Mode6 == Mode6Off {
			failed = append(failed, p.FQDN)
			continue
		}
		if err := m.InsertTarget(ctx, t); err != nil {
			failed = append(failed, p.FQDN)
			continue
		}
		if p.CDN { // DNS zeigt aufs CDN: Abweichung von Anfang an gewollt
			t.DNSState = dnsRedirected
			m.saveRuntime(ctx, t)
		}
		added = append(added, t)
	}
	return added, failed, nil
}
