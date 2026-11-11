package mcp

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// Monitor64: Hosts, Dienste, Probleme und Wartungen (nur lesen). Namen und Texte von Diensten liefern die Geraete
// selbst (SNMP-Beschreibungen, Container-Namen, Meldungen der Agents) - sie stehen unter "untrusted". Zugangsdaten
// gibt die API ohnehin nie aus.

func monitor64Tools() []Tool {
	return []Tool{
		{Name: "monitor64_overview", Area: AreaMonitor64, Title: "Monitor64 overview", Untrusted: true,
			Desc:   "Monitor64 overview: counts per state, all hosts (state, kind, group, CPU/RAM, maintenance, open problems) and the open problems with host, service, state and detail.",
			Schema: noArgs, Run: m64Overview},
		{Name: "monitor64_host", Area: AreaMonitor64, Title: "Monitor64 host", Untrusted: true,
			Desc:   "One Monitor64 host with all monitored services: state, values with thresholds, text, plus the state of its accesses (agent, SSH, API, SNMP) and services waiting to be adopted. Never includes credentials.",
			Schema: schema([]string{"host"}, pStr("host", "Host id (from monitor64_overview) or exact host name.", 120)),
			Run:    m64Host},
		{Name: "monitor64_problems", Area: AreaMonitor64, Title: "Monitor64 problems", Untrusted: true,
			Desc: "Monitor64 problems (open by default, or closed/all) with host, service, state, worst state, since, duration, acknowledgement and notified channels.",
			Schema: schema(nil, pEnum("status", "Which problems.", "open", "open", "closed", "all"), pEnum("range", "Period for closed problems.", "7d", "24h", "7d", "30d", "1y"),
				pStr("host", "Only this host (id or exact name).", 120), pInt("limit", "Maximum number of problems.", 50, 1, 200)),
			Run: m64Problems},
		{Name: "monitor64_maintenance", Area: AreaMonitor64, Title: "Monitor64 maintenance",
			Desc:   "Monitor64 maintenance windows: running, planned, recurring and ended, with affected hosts, groups and tags.",
			Schema: noArgs, Run: m64Maintenance},
	}
}

// m64Text: Texte von Monitor64 kommen als Schluessel mit Werten ("i18n:monitor64.txt...") - auf Englisch aufloesen.
func (c *call) m64Text(s string, max int) string {
	tr := func(key string, args ...any) string { return key }
	if c.o.T != nil {
		tr = func(key string, args ...any) string { return c.o.T("en", key, args...) }
	}
	return clean(model.Translate(s, tr), max)
}

// m64Hosts: Hosts aus der Uebersicht (id -> Name) fuer die Suche nach Namen.
func (c *call) m64FindHost(ref string, hosts []any) (obj, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, errors.New("parameter host is required")
	}
	var hits []obj
	for _, e := range hosts {
		if m := asObj(e); str(m, "uid") == ref {
			return m, nil
		}
	}
	for _, e := range hosts {
		if m := asObj(e); strings.EqualFold(str(m, "name"), ref) {
			hits = append(hits, m)
		}
	}
	switch len(hits) {
	case 0:
		return nil, fmt.Errorf("host %q not found (use monitor64_overview)", clean(ref, 60))
	case 1:
		return hits[0], nil
	}
	return nil, fmt.Errorf("host %q is ambiguous, use the id from monitor64_overview", clean(ref, 60))
}

func m64Overview(c *call, _ map[string]any) (map[string]any, error) {
	ov, err := c.getObj("/api/monitor64/overview", nil)
	if err != nil {
		return nil, err
	}
	hosts := []any{}
	for _, e := range asArr(ov["hosts"]) {
		m := asObj(e)
		h := obj{"id": str(m, "uid"), "name": clean(str(m, "name"), 120), "address": clean(str(m, "address"), 200), "kind": str(m, "kind"),
			"group": clean(str(m, "group"), 80), "tags": strs(m, "tags"), "state": str(m, "state"), "paused": boolean(m, "paused"),
			"services": i64(m, "services"), "problems": i64(m, "problems"), "vanished": i64(m, "vanished"), "new_services": boolean(m, "new")}
		if boolean(m, "has_cpu") {
			h["cpu_percent"] = round(num(m, "cpu"), 1)
		}
		if boolean(m, "has_ram") {
			h["ram_percent"] = round(num(m, "ram"), 1)
		}
		if mt := asObj(m["maint"]); len(mt) > 0 {
			h["maintenance"] = obj{"until": ts(mt["end"]), "reason": clean(str(mt, "reason"), 200)}
		}
		if u := str(m, "unreach"); u != "" {
			h["unreachable"] = c.m64Text(u, 300)
		}
		hosts = append(hosts, h)
	}
	probs := []any{}
	for _, e := range asArr(ov["problems"]) {
		m := asObj(e)
		p := obj{"host_id": str(m, "host_uid"), "host": clean(str(m, "host"), 120), "service_key": clean(str(m, "key"), 200), "state": str(m, "state"),
			"since": ts(m["since"]), "acknowledged": boolean(m, "acked"), "in_maintenance": boolean(m, "maint"), "unreachable": boolean(m, "unreach"),
			"untrusted": obj{"service": c.m64Text(str(m, "name"), 200), "detail": c.m64Text(str(m, "detail"), 400)}}
		probs = append(probs, p)
	}
	return obj{"counts": ov["counts"], "hosts_total": len(hosts), "services_total": i64(ov, "services"), "unreachable": i64(ov, "unreachable"),
		"open_unacknowledged": i64(ov, "open_unacked"), "monitoring_running": boolean(ov, "running"), "hosts": hosts, "problems": probs}, nil
}

func m64Host(c *call, a map[string]any) (map[string]any, error) {
	ov, err := c.getObj("/api/monitor64/overview", nil)
	if err != nil {
		return nil, err
	}
	hm, err := c.m64FindHost(argStr(a, "host"), asArr(ov["hosts"]))
	if err != nil {
		return nil, err
	}
	d, err := c.getObj("/api/monitor64/hosts/"+url.PathEscape(str(hm, "uid")), nil)
	if err != nil {
		return nil, err
	}
	h := asObj(d["host"])
	out := obj{"id": str(h, "uid"), "name": clean(str(h, "name"), 120), "address": clean(str(h, "address"), 200), "kind": str(h, "kind"),
		"group": clean(str(h, "group"), 80), "tags": strs(h, "tags"), "paused": boolean(h, "paused"), "interval_seconds": i64(h, "interval_sec"),
		"state": str(d, "state"), "checked_at": ts(d["checked"])}
	if u := str(d, "unreach"); u != "" {
		out["unreachable"] = c.m64Text(u, 300)
	}
	if mt := asObj(d["maint"]); len(mt) > 0 {
		out["maintenance"] = obj{"from": ts(mt["start"]), "until": ts(mt["end"]), "reason": clean(str(mt, "reason"), 200)}
	}
	svcs := []any{}
	for _, e := range asArr(d["services"]) {
		m := asObj(e)
		s := obj{"key": clean(str(m, "key"), 200), "kind": str(m, "kind"), "state": str(m, "state"), "since": ts(m["since"]),
			"vanished": boolean(m, "vanished"), "show_only": boolean(m, "show_only"), "acknowledged": boolean(m, "acked")}
		var metrics []any
		for _, x := range asArr(m["metrics"]) {
			mx := asObj(x)
			v := obj{"name": str(mx, "name"), "value": round(num(mx, "value"), 3), "unit": str(mx, "unit")}
			if st := asObj(mx["status"]); len(st) > 0 {
				v["state"] = str(st, "level")
				if th, ok := st["threshold"].(float64); ok && str(st, "level") != "ok" {
					v["threshold"] = th // Schwelle der aktiven Stufe
				}
			}
			metrics = append(metrics, v)
		}
		if len(metrics) > 0 {
			s["metrics"] = metrics
		}
		name := str(m, "custom_name")
		if name == "" {
			name = str(m, "name")
		}
		s["untrusted"] = obj{"name": c.m64Text(name, 200), "text": c.m64Text(str(m, "text"), 400), "cause": c.m64Text(str(m, "cause"), 400)}
		svcs = append(svcs, s)
	}
	out["services"] = svcs
	var acc []any
	for _, e := range asArr(d["accesses"]) {
		m := asObj(e)
		x := obj{"type": str(m, "type"), "name": clean(str(m, "name"), 120), "ok": boolean(m, "ok"), "failures": i64(m, "failures"), "enabled": boolean(m, "enabled")}
		if er := str(m, "error"); er != "" {
			x["untrusted"] = obj{"error": c.m64Text(er, 300)}
		}
		if ag := asObj(m["agent"]); len(ag) > 0 {
			x["agent_version"] = str(ag, "version")
		}
		acc = append(acc, x)
	}
	out["accesses"] = acc
	var waiting []any
	for _, e := range asArr(d["new"]) {
		m := asObj(e)
		waiting = append(waiting, obj{"key": clean(str(m, "key"), 200), "untrusted": obj{"name": c.m64Text(str(m, "name"), 200)}})
	}
	if len(waiting) > 0 {
		out["new_services"] = waiting
	}
	return out, nil
}

func m64Problems(c *call, a map[string]any) (map[string]any, error) {
	q := url.Values{"status": {argStr(a, "status")}, "range": {argStr(a, "range")}}
	if q.Get("status") == "" {
		q.Set("status", "open")
	}
	if q.Get("range") == "" {
		q.Set("range", "7d")
	}
	if ref := strings.TrimSpace(argStr(a, "host")); ref != "" {
		ov, err := c.getObj("/api/monitor64/overview", nil)
		if err != nil {
			return nil, err
		}
		hm, err := c.m64FindHost(ref, asArr(ov["hosts"]))
		if err != nil {
			return nil, err
		}
		q.Set("host", str(hm, "uid"))
	}
	limit := argInt(a, "limit", 50, 1, 200)
	p, err := c.getObj("/api/monitor64/problems", q)
	if err != nil {
		return nil, err
	}
	list := []any{}
	for _, e := range asArr(p["problems"]) {
		if len(list) >= limit {
			break
		}
		m := asObj(e)
		x := obj{"id": str(m, "uid"), "host_id": str(m, "host_uid"), "host": clean(str(m, "host"), 120), "service_key": clean(str(m, "key"), 200),
			"state": str(m, "state"), "worst": str(m, "worst"), "opened": ts(m["opened"]), "closed": ts(m["closed"]), "duration_seconds": i64(m, "duration"),
			"channels": strs(m, "channels"), "untrusted": obj{"service": c.m64Text(str(m, "name"), 200)}}
		if ack := asObj(m["ack"]); len(ack) > 0 {
			x["acknowledged"] = obj{"at": ts(ack["at"]), "comment": clean(str(ack, "comment"), 300)}
		}
		list = append(list, x)
	}
	return obj{"counts": p["counts"], "problems": list}, nil
}

func m64Maintenance(c *call, _ map[string]any) (map[string]any, error) {
	d, err := c.getObj("/api/monitor64/maintenance", nil)
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	for _, e := range asArr(d["hosts"]) {
		m := asObj(e)
		names[str(m, "uid")] = clean(str(m, "name"), 120)
	}
	out := []any{}
	for _, e := range asArr(d["items"]) {
		m := asObj(e)
		var hosts []string
		for _, uid := range strs(m, "hosts") {
			if n := names[uid]; n != "" {
				hosts = append(hosts, n)
			} else {
				hosts = append(hosts, uid)
			}
		}
		out = append(out, obj{"id": str(m, "uid"), "title": clean(str(m, "title"), 120), "status": str(m, "status"), "running": boolean(m, "running"),
			"start": ts(m["start"]), "end": ts(m["end"]), "ended": ts(m["ended"]), "recurring": len(asObj(m["recur"])) > 0,
			"hosts": hosts, "groups": strs(m, "groups"), "tags": strs(m, "tags")})
	}
	return obj{"timezone": str(d, "tz"), "maintenance": out}, nil
}
