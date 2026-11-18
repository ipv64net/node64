package mcp

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
)

// Werte von "part" je Werkzeug: eine Liste fuer Schema und Auswertung (vorher je dreifach gepflegt).
var (
	partsMonitor64Config  = partSet{def: "", list: []string{"rules", "notify", "settings", "traps", "agent", "cluster"}}        // monitor64_config
	partsMonitor64Details = partSet{def: "", list: []string{"problem", "accesses", "smart", "traps", "series", "cluster_host"}} // monitor64_details
)

// Monitor64: Regeln, Benachrichtigung, Einstellungen, Traps, Agent-Verteilung, Cluster sowie Einzelheiten zu
// Problemen, Zugaengen, SMART, Traps und Verlaeufen eines Hosts. Zugaenge ohne Geheimnisse (Positivliste der
// Konfiguration, nie Passwort, Community, Token oder Push-Token).

func monitor64MoreTools() []Tool {
	hostArg := pStr("host", "Host id (from monitor64_overview) or exact host name.", 120)
	return []Tool{
		{Name: "monitor64_config", Area: AreaMonitor64, Title: "Monitor64 configuration", Untrusted: true,
			Desc:   "Monitor64 configuration by part: rules (thresholds: defaults, standard rules, overrides for groups/tags/hosts, host-specific rules), notify (channel routing, reminders, quiet hours, overrides), settings (interval, workers, retention, ports, scheduler state), traps (SNMP trap receiver and unknown senders), agent (agent distribution: versions, files, hosts, events), cluster (members, responsible node per host, orphaned hosts, key state).",
			Schema: schema([]string{"part"}, partsMonitor64Config.prop()),
			Run:    m64Config},
		{Name: "monitor64_details", Area: AreaMonitor64, Title: "Monitor64 details", Untrusted: true,
			Desc: "Details by part: problem (one problem with its timeline, needs problem), accesses (accesses of a host with non-secret settings, agent state, and services found by discovery waiting to be adopted or ignored), smart (SMART values of a disk service, needs service), traps (received SNMP traps of a host), series (history of metrics, needs series), cluster_host (responsibility of a host in the cluster). Never includes credentials.",
			Schema: schema([]string{"part"}, partsMonitor64Details.prop(), hostArg,
				pStr("problem", "Problem id (from monitor64_problems), for part problem.", 80),
				pStr("service", "Service key (from monitor64_host), for part smart, e.g. disk:S4EWNX0M123456.", 200),
				pStr("series", "For part series: one or more 'service_key|metric' separated by commas (max 8), metric names from monitor64_host.", 1000),
				pEnum("range", "Period for part series.", "24h", "6h", "24h", "7d", "30d", "1y"), pInt("points", "Points per series (part series).", 60, 2, 300)),
			Run: m64Details},
	}
}

func m64Actor(v any) string { return clean(str(asObj(v), "name"), 80) }

func m64Config(c *call, a map[string]any) (map[string]any, error) {
	part, err := partsMonitor64Config.arg(a)
	if err != nil {
		return nil, err
	}
	switch part {
	case "rules":
		d, err := c.getObj("/api/monitor64/rules", nil)
		if err != nil {
			return nil, err
		}
		overrides := []any{}
		for _, e := range asArr(d["overrides"]) {
			m := asObj(e)
			x := pick(m, "uid", "position", "target_type", "target", "kind", "at")
			x["by"], x["rule"], x["effect"] = m64Actor(m["by"]), plain(m["rule"], 4), plain(m["effect"], 3)
			overrides = append(overrides, x)
		}
		own := []any{}
		for _, e := range asArr(d["own"]) {
			m := asObj(e)
			x := pick(m, "host_uid", "host", "key", "kind")
			x["rule"] = plain(m["rule"], 4)
			x["untrusted"] = obj{"name": c.m64Text(str(m, "name"), 200)}
			own = append(own, x)
		}
		return obj{"part": part, "kinds": pickList(d["kinds"], 0, "kind", "group", "unit", "factor", "state", "down", "nofor"),
			"defaults": plain(d["defaults"], 5), "standard_rules": plain(d["std"], 5), "overrides": overrides, "host_rules": own,
			"targets": plain(d["targets"], 3)}, nil
	case "notify":
		d, err := c.getObj("/api/monitor64/notify", nil)
		if err != nil {
			return nil, err
		}
		overrides := []any{}
		for _, e := range asArr(d["overrides"]) {
			m := asObj(e)
			x := pick(m, "uid", "position", "target_type", "target", "kind", "at")
			x["by"], x["notify"] = m64Actor(m["by"]), plain(m["notify"], 4)
			overrides = append(overrides, x)
		}
		return obj{"part": part, "config": plain(d["config"], 4), "channels": pickList(d["channels"], 0, "id", "type", "name", "enabled", "default"),
			"overrides": overrides, "quiet": plain(d["quiet"], 3), "targets": plain(d["targets"], 3)}, nil
	case "settings":
		d, err := c.getObj("/api/monitor64/settings", nil)
		if err != nil {
			return nil, err
		}
		out := pick(d, "interval", "workers", "retention_raw_hours", "retention_5m_days", "retention_1h_days", "hosts", "services", "port", "fingerprint",
			"trap_port", "push_port")
		out["part"], out["status"] = part, plain(d["status"], 4)
		push := asObj(d["push"])
		out["push"] = obj{"listening": strs(push, "listening"), "stats": plain(push["stats"], 2)}
		return out, nil
	case "traps":
		d, err := c.getObj("/api/monitor64/traps", nil)
		if err != nil {
			return nil, err
		}
		out := pick(d, "active", "running", "port", "engine_id", "error")
		out["part"], out["stats"] = part, plain(d["stats"], 2)
		unknown := []any{}
		for _, e := range asArr(d["unknown"]) { // Absender, die keinem Host zugeordnet sind: Inhalte schreibt der Absender
			m := asObj(e)
			x := pick(m, "addr", "first", "last", "count", "version")
			x["untrusted"] = obj{"trap_oid": clean(str(m, "trap_oid"), 120), "trap_name": clean(str(m, "trap_name"), 120), "user": clean(str(m, "user"), 64)}
			unknown = append(unknown, x)
			if len(unknown) >= 50 {
				break
			}
		}
		out["unknown_senders"] = unknown
		return out, nil
	case "agent":
		d, err := c.getObj("/api/monitor64/agent", nil)
		if err != nil {
			return nil, err
		}
		out := pick(d, "internet", "http_port", "port", "running", "version", "date", "due", "fingerprint")
		src := asObj(d["source"])
		out["part"] = part
		out["source"] = obj{"source": clean(str(src, "source"), 120), "checked": ts(src["checked"]), "ok": boolean(src, "ok"), "untrusted": obj{"error": clean(str(src, "error"), 200)}}
		out["files"] = pickList(d["files"], 50, "name", "os", "arch", "size", "cached")
		hosts := []any{}
		for _, e := range asArr(d["hosts"]) {
			m := asObj(e)
			x := pick(m, "uid", "name", "access", "push", "version", "platform", "auto", "state", "busy", "tried", "next", "node", "latest", "disabled")
			if er := str(m, "error"); er != "" {
				x["untrusted"] = obj{"error": c.m64Text(er, 200)}
			}
			hosts = append(hosts, x)
		}
		out["hosts"] = hosts
		events := []any{}
		for _, e := range asArr(d["events"]) {
			m := asObj(e)
			events = append(events, obj{"at": ts(m["at"]), "kind": str(m, "kind"), "host": clean(str(m, "host"), 120), "untrusted": obj{"text": c.m64Text(str(m, "text"), 300)}})
			if len(events) >= 20 {
				break
			}
		}
		out["events"] = events
		return out, nil
	}
	// cluster
	d, err := c.getObj("/api/monitor64/cluster", nil)
	if err != nil {
		return nil, err
	}
	out := pick(d, "active", "self", "majority", "total", "connected")
	out["part"] = part
	out["nodes"] = pickList(d["nodes"], 0, "id", "name", "self", "online", "stable")
	out["hosts"] = pickList(d["hosts"], 500, "uid", "name", "owner", "owner_name", "preferred", "backups", "role", "reachable")
	k := asObj(d["key"])
	key := pick(k, "fingerprint", "cluster", "at", "running")
	pending := []any{}
	for _, e := range asArr(k["pending"]) {
		m := asObj(e)
		x := pick(m, "access_uid", "host_uid", "host_name", "type", "tries", "last_try", "manual")
		if er := str(m, "error"); er != "" {
			x["untrusted"] = obj{"error": c.m64Text(er, 200)}
		}
		pending = append(pending, x)
	}
	key["pending_rollout"] = pending
	out["key"] = key
	if v, err := c.getObj("/api/monitor64/cluster/views", nil); err == nil {
		refs := obj{}
		for uid, r := range asObj(v["refs"]) {
			refs[uid] = pick(asObj(r), "node", "name", "here", "reporting", "reachable", "note", "at")
		}
		out["responsible_node_by_host"] = refs
	}
	if o, err := c.getObj("/api/monitor64/cluster/orphans", nil); err == nil {
		out["orphans"] = pickList(o["orphans"], 100, "uid", "name", "address", "reason", "node", "node_name")
	}
	return out, nil
}

// m64HostUID: Host per Id oder Name (Uebersicht).
func (c *call) m64HostUID(ref string) (string, error) {
	ov, err := c.getObj("/api/monitor64/overview", nil)
	if err != nil {
		return "", err
	}
	hm, err := c.m64FindHost(ref, asArr(ov["hosts"]))
	if err != nil {
		return "", err
	}
	return str(hm, "uid"), nil
}

// m64AccessConfig: Positivliste der Konfiguration eines Zugangs. Nie: Passwort/Geheimnis (gibt die API ohnehin
// nicht aus), Community, token (Wegweiser des Push-Agents), token_id, eigene OIDs.
var m64AccessConfigFields = []string{"port", "user", "smart", "no_smart", "url", "node", "pin", "backup_max_age_h", "site", "ups", "tls", "api", "session", "mode",
	"snmp_version", "level", "auth_proto", "priv_proto", "context", "profiles", "traps", "trap_engine_id"}

func m64Details(c *call, a map[string]any) (map[string]any, error) {
	part, err := partsMonitor64Details.arg(a)
	if err != nil {
		return nil, err
	}
	if part == "problem" {
		uid := argStr(a, "problem")
		if uid == "" {
			return nil, errors.New("parameter problem is required for part problem")
		}
		d, err := c.getObj("/api/monitor64/problems/"+url.PathEscape(uid), nil)
		if err != nil {
			return nil, err
		}
		p := asObj(d["problem"])
		out := pick(p, "uid", "host_uid", "key", "state", "worst", "opened", "closed", "how", "notified")
		out["part"] = part
		if cb := m64Actor(p["closed_by"]); cb != "" {
			out["closed_by"] = cb
		}
		if ack := asObj(p["ack"]); len(ack) > 0 {
			out["acknowledged"] = obj{"by": m64Actor(ack["by"]), "at": ts(ack["at"]), "comment": clean(str(ack, "comment"), 300)}
		}
		events := []any{}
		for _, e := range asArr(d["events"]) {
			m := asObj(e)
			events = append(events, obj{"at": ts(m["at"]), "kind": str(m, "kind"), "actor": m64Actor(m["actor"]), "untrusted": obj{"text": c.m64Text(str(m, "text"), 300)}})
			if len(events) >= 100 {
				break
			}
		}
		out["timeline"] = events
		out["channels"] = plain(d["channels"], 3)
		return out, nil
	}
	ref := argStr(a, "host")
	if ref == "" {
		return nil, errors.New("parameter host is required for part " + part)
	}
	uid, err := c.m64HostUID(ref)
	if err != nil {
		return nil, err
	}
	base := "/api/monitor64/hosts/" + url.PathEscape(uid)
	switch part {
	case "accesses":
		d, err := c.getObj(base, nil)
		if err != nil {
			return nil, err
		}
		acc := []any{}
		for _, e := range asArr(d["accesses"]) {
			m := asObj(e)
			x := pick(m, "uid", "type", "enabled", "hostkey", "name", "ok", "failures", "known")
			x["auth_configured"] = boolean(m, "secret_set") // ein Geheimnis ist gespeichert (Feldname ohne "secret", sonst filtert sanitize ihn)
			x["config"] = pick(asObj(m["config"]), m64AccessConfigFields...)
			if n := len(asArr(asObj(m["config"])["metrics"])); n > 0 {
				x["config"].(obj)["metrics_selected"] = n
			}
			if ag := asObj(m["agent"]); len(ag) > 0 {
				x["agent"] = pick(ag, "version", "platform", "push", "auto", "state", "busy", "latest", "tried", "next", "node", "disabled")
			}
			if er := str(m, "error"); er != "" {
				x["untrusted"] = obj{"error": c.m64Text(er, 300)}
			}
			acc = append(acc, x)
		}
		svcRows := func(v any) []any {
			out := []any{}
			for _, e := range asArr(v) {
				m := asObj(e)
				x := pick(m, "uid", "key", "kind", "via", "adopted", "vanished_at", "host_rule", "soll", "report")
				x["untrusted"] = obj{"name": c.m64Text(str(m, "name"), 200)}
				out = append(out, x)
				if len(out) >= 300 {
					break
				}
			}
			return out
		}
		return obj{"part": part, "host_id": uid, "accesses": acc, "discovered_waiting": svcRows(d["new"]), "ignored": svcRows(d["ignored"])}, nil
	case "smart":
		key := argStr(a, "service")
		if key == "" {
			return nil, errors.New("parameter service is required for part smart")
		}
		d, err := c.getObj(base+"/smart", url.Values{"key": {key}})
		if err != nil {
			return nil, err
		}
		s := asObj(d["smart"])
		out := pick(s, "type", "size", "passed", "at", "partial")
		out["part"], out["host_id"], out["service"] = part, uid, clean(str(d, "key"), 200)
		out["untrusted"] = obj{"model": clean(str(s, "model"), 120), "serial": clean(str(s, "serial"), 80), "firmware": clean(str(s, "firmware"), 60)}
		out["attributes"] = pickList(s["attrs"], 100, "id", "name", "value", "worst", "thresh", "raw", "failed")
		out["values"] = pickList(s["values"], 100, "key", "name", "value", "unit", "text")
		return out, nil
	case "traps":
		d, err := c.getObj(base+"/traps", nil)
		if err != nil {
			return nil, err
		}
		out := pick(d, "pending", "total", "rejected", "reject_reason", "rejected_at")
		out["part"], out["host_id"] = part, uid
		list := []any{}
		for _, e := range asArr(d["list"]) {
			m := asObj(e)
			x := pick(m, "time", "version", "inform", "kind", "handled", "truncated")
			var vb []any
			for _, v := range asArr(m["varbinds"]) {
				vm := asObj(v)
				vb = append(vb, obj{"oid": clean(str(vm, "oid"), 120), "type": clean(str(vm, "type"), 20), "value": clean(str(vm, "value"), 200)})
				if len(vb) >= 20 {
					break
				}
			}
			x["untrusted"] = obj{"user": clean(str(m, "user"), 64), "trap_oid": clean(str(m, "trap_oid"), 120), "trap_name": clean(str(m, "trap_name"), 120), "varbinds": vb}
			list = append(list, x)
			if len(list) >= 50 {
				break
			}
		}
		out["traps"] = list
		return out, nil
	case "series":
		spec := argStr(a, "series")
		if spec == "" {
			return nil, errors.New("parameter series is required for part series ('service_key|metric', see monitor64_host)")
		}
		q := url.Values{"host": {uid}, "points": {strconv.Itoa(argInt(a, "points", 60, 2, 300))}}
		if r := argStr(a, "range"); r != "" {
			q.Set("range", r)
		} else {
			q.Set("range", "24h")
		}
		for i, s := range strings.Split(spec, ",") {
			if s = strings.TrimSpace(s); s != "" && i < 8 {
				q.Add("s", s)
			}
		}
		d, err := c.getObj("/api/monitor64/series", q)
		if err != nil {
			return nil, err
		}
		series := []any{}
		for _, e := range asArr(d["series"]) {
			m := asObj(e)
			x := pick(m, "s", "res", "step")
			pts := []any{}
			for _, p := range asArr(m["points"]) {
				pm := asObj(p)
				pts = append(pts, obj{"t": ts(pm["t"]), "min": round(num(pm, "min"), 3), "avg": round(num(pm, "avg"), 3), "max": round(num(pm, "max"), 3)})
			}
			x["points"] = pts
			series = append(series, x)
		}
		return obj{"part": part, "host_id": uid, "from": ts(d["from"]), "to": ts(d["to"]), "series": series,
			"cluster": pickList(d["cluster"], 20, "node", "name", "ok", "missing")}, nil
	}
	// cluster_host
	d, err := c.getObj("/api/monitor64/cluster/hosts/"+url.PathEscape(uid), nil)
	if err != nil {
		return nil, err
	}
	out := pick(d, "active", "self", "majority")
	out["part"], out["host_id"] = part, uid
	out["nodes"] = pickList(d["nodes"], 0, "id", "name", "self", "online", "stable")
	out["host"] = pick(asObj(d["host"]), "uid", "name", "owner", "owner_name", "preferred", "backups", "role", "reachable")
	out["responsible"] = pick(asObj(d["ref"]), "node", "name", "here", "reporting", "reachable", "note", "at")
	events := []any{}
	for _, e := range asArr(d["events"]) {
		m := asObj(e)
		events = append(events, obj{"at": ts(m["at"]), "kind": str(m, "kind"), "untrusted": obj{"text": c.m64Text(str(m, "text"), 300)}})
	}
	out["events"] = events
	return out, nil
}
