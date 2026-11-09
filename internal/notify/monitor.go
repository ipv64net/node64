package notify

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// Meldungen von Monitor64 (Plan docs/PLAN-NODE64-MONITOR64.md, "Benachrichtigung"): eine Meldung je Host und Runde
// mit mehreren Zeilen. Der Text entsteht hier in der Sprache des Kanals; Monitor64 liefert nur Daten:
//   Data["host"]      Name des Hosts
//   Data["path"]      Link-Pfad in der Node (/monitor64/...)
//   Data["key"]       Dienst bei genau einer Zeile (fuer die Sammelmeldung nach der Ruhezeit), sonst leer
//   Data["severity"]  ok, warn, crit, unknown
//   Data["lines"]     JSON-Liste von MonitorLine
//   Data["after_maint"] "1" = nach dem Ende einer Wartung

// MonitorLine ist eine Zeile einer Monitor64-Meldung.
type MonitorLine struct {
	Kind   string    `json:"kind"` // problem, better, ok, flapping, flap_end, reminder, open, unreachable, reachable
	Key    string    `json:"key,omitempty"`
	Name   string    `json:"name,omitempty"`
	State  string    `json:"state"` // ok, warn, crit, unknown
	Since  time.Time `json:"since,omitzero"`
	Detail string    `json:"detail,omitempty"`
}

func monitorLines(a Alert) []MonitorLine {
	var l []MonitorLine
	if a.Data != nil {
		_ = json.Unmarshal([]byte(a.Data["lines"]), &l)
	}
	return l
}

func monitorIcon(state string) string {
	switch state {
	case "crit":
		return "🔴"
	case "warn":
		return "🟡"
	case "unknown":
		return "⚪"
	}
	return "✅"
}

// monitorLineText formuliert eine Zeile in der Sprache des Kanals.
func (d *Dispatcher) monitorLineText(lang string, l MonitorLine, now time.Time) string {
	t := func(key string, args ...any) string { return d.i18n.T(lang, key, args...) }
	dur := ""
	if !l.Since.IsZero() && now.After(l.Since) {
		dur = d.i18n.FormatDuration(lang, now.Sub(l.Since).Truncate(time.Minute))
	}
	state := t("monitor64.state." + l.State)
	return t("notify.monitor.line."+l.Kind, "icon", monitorIcon(l.State), "name", l.Name, "state", state, "detail", l.Detail, "duration", dur)
}

// monitorTitle ist der Betreff ("🔴 nas01: 1 Kritisch, 2 Warnung").
func (d *Dispatcher) monitorTitle(lang string, a Alert, lines []MonitorLine) string {
	t := func(key string, args ...any) string { return d.i18n.T(lang, key, args...) }
	host := a.Data["host"]
	if host == "" {
		host = a.Check.Name
	}
	n := map[string]int{}
	for _, l := range lines {
		n[l.State]++
	}
	var parts []string
	for _, s := range []string{"crit", "warn", "unknown"} {
		if n[s] > 0 {
			parts = append(parts, t("notify.monitor.count."+s, "n", n[s]))
		}
	}
	summary := strings.Join(parts, ", ")
	if len(lines) == 1 {
		summary = lines[0].Name
	}
	return t("notify.subject."+string(a.Kind), "icon", monitorIcon(a.Data["severity"]), "name", host, "summary", summary)
}

func (d *Dispatcher) composeMonitor(lang string, a Alert, m Message) Message {
	uid := a.Check.UserID
	path := a.Data["path"]
	if !strings.HasPrefix(path, "/monitor64") {
		path = "/monitor64"
	}
	m.URL = d.baseURL(uid, path)
	lines := monitorLines(a)
	m.Title = d.monitorTitle(lang, a, lines)
	switch {
	case a.Kind == KindMonitorUnreachable || a.Data["severity"] == "crit":
		m.Priority = 5
	case a.Kind == KindMonitorOK || a.Kind == KindMonitorReachable:
		m.Priority = 2
	default:
		m.Priority = 4
	}
	var text []string
	if a.Data["after_maint"] == "1" {
		text = append(text, d.i18n.T(lang, "notify.monitor.after_maint"))
	}
	for _, l := range lines {
		text = append(text, d.monitorLineText(lang, l, m.Time))
	}
	text = append(text, d.i18n.T(lang, "notify.body.time", "time", d.i18n.FormatDateTime(lang, m.Time, d.location(uid))), d.nodeLine(uid, lang))
	m.Text = strings.Join(text, "\n")
	counts := map[string]int{}
	for _, l := range lines {
		counts[l.State]++
	}
	m.Payload = map[string]any{"event_id": a.EventID, "kind": string(a.Kind), "time": m.Time.UTC().Format(time.RFC3339), "name": a.Data["host"],
		"severity": a.Data["severity"], "lines": lines, "counts": counts, "url": m.URL, "title": m.Title, "text": m.Text,
		"node": map[string]any{"name": d.settings(uid)(SetNodeName, ""), "location": d.settings(uid)(SetNodeLocation, "")}}
	return m
}

// monitorSummary ist eine Zeile fuer die Sammelmeldung nach der Ruhezeit.
func (d *Dispatcher) monitorSummary(lang string, a Alert) string {
	lines := monitorLines(a)
	var parts []string
	for _, l := range lines {
		s := monitorIcon(l.State) + " " + l.Name
		if l.Name == "" {
			s = monitorIcon(l.State)
		}
		if l.Detail != "" {
			s += ": " + l.Detail
		}
		parts = append(parts, s)
		if len(parts) == 3 && len(lines) > 3 {
			parts = append(parts, "+"+strconv.Itoa(len(lines)-3))
			break
		}
	}
	return strings.Join(parts, "; ")
}
