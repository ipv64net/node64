package mcp

import (
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Tools liefert alle Werkzeuge (M1: nur lesen).
func Tools() []Tool {
	var out []Tool
	out = append(out, coreTools()...)
	out = append(out, healthTools()...)
	out = append(out, networkTools()...)
	out = append(out, honeypotTools()...)
	return out
}

func coreTools() []Tool {
	return []Tool{
		{Name: "node_status", Area: AreaNode, Title: "Node status", Untrusted: true,
			Desc:   "Node64 overview: version, uptime, database size, modules on/off, link to ipv64.net and a summary per module.",
			Schema: noArgs, Run: nodeStatus},
		{Name: "list_modules", Area: AreaNode, Title: "List modules",
			Desc:   "All modules with version, enabled/running state and last error.",
			Schema: noArgs, Run: listModules},
		{Name: "list_certs", Area: AreaCerts, Title: "List certificates", Untrusted: true,
			Desc:   "Certificates managed by the node: names, issuer, expiry, status, renewal. Never includes private keys.",
			Schema: noArgs, Run: listCerts},
		{Name: "recent_notifications", Area: AreaNotifications, Title: "Recent notifications", Untrusted: true,
			Desc: "Notification deliveries (newest first): channel, kind, delivered or failed, plus the configured channels without credentials. Error texts (responses of the remote services) are under untrusted.",
			Schema: schema(nil, pInt("limit", "Maximum number of deliveries.", 30, 1, 200), pBool("failed_only", "Only failed deliveries."),
				pIntOpt("channel_id", "Only deliveries of this channel.", 1, 1<<30)),
			Run: recentNotifications},
		{Name: "audit_log", Area: AreaAudit, Title: "Audit log", Untrusted: true,
			Desc: "Audit log of the node (who changed what, logins, MCP calls), newest first. The actor is under untrusted (for failed logins it is the name typed by the visitor).",
			Schema: schema(nil, pEnum("area", "Filter by area.", "", "login", "settings", "healthchecks", "dyndns", "cdn64", "dns64", "certs", "sync", "honeypot", "mcp"),
				pInt("limit", "Maximum number of entries.", 50, 1, 200), pIntOpt("before", "Only entries with an id lower than this (paging).", 1, maxID)),
			Run: auditLog},
		{Name: "node_logs", Area: AreaAudit, Title: "Node logs", Untrusted: true,
			Desc: "Recent log lines of the node (shortened, secrets masked), optionally filtered by level, module or text.",
			Schema: schema(nil, pInt("lines", "Maximum number of lines returned.", 100, 1, 500),
				pEnum("level", "Minimum level.", "", "debug", "info", "warn", "error"), pStr("module", "Only lines of this module (e.g. dns64, cdn64, healthchecks).", 40),
				pStr("contains", "Only lines containing this text (case-insensitive).", 100)),
			Run: nodeLogs},
	}
}

func nodeStatus(c *call, _ map[string]any) (map[string]any, error) {
	st, err := c.getObj("/api/status", nil)
	if err != nil {
		return nil, err
	}
	n := asObj(st["node"])
	node := obj{"name": str(n, "name"), "location": str(n, "location"), "timezone": str(n, "timezone"), "version": str(n, "version"),
		"started_at": ts(n["started_at"]), "uptime_seconds": i64(n, "uptime_seconds"), "database_bytes": i64(n, "database_bytes"), "log_level": str(n, "log_level")}
	if v, err := c.getObj("/api/version", nil); err == nil {
		node["hostname"] = str(v, "hostname")
	}
	l := asObj(st["link"])
	link := obj{"linked": boolean(l, "linked"), "connected": boolean(l, "connected")}
	if boolean(l, "linked") {
		link["plan"], link["last_sync_at"], link["outbox"], link["conflicts"] = str(l, "plan"), ts(l["last_sync_at"]), i64(l, "outbox"), i64(l, "conflicts")
		link["online_checks_today"], link["online_checks_limit"] = i64(l, "checks_today"), i64(l, "checks_limit")
		link["untrusted"] = obj{"last_error": clean(str(l, "last_error"), 200)} // Antworttext des Servers
	}
	var mods []any
	for _, e := range asArr(st["modules"]) {
		m := asObj(e)
		if !boolean(m, "available") {
			continue
		}
		mods = append(mods, obj{"name": str(m, "name"), "version": str(m, "version"), "enabled": boolean(m, "enabled"), "running": boolean(m, "running"),
			"last_error": clean(str(m, "last_error"), 200)})
	}
	var sums []any
	for _, e := range asArr(st["summary"]) {
		m := asObj(e)
		sums = append(sums, obj{"module": str(m, "module"), "ok": i64(m, "ok"), "down": i64(m, "down"), "paused": i64(m, "paused"), "other": i64(m, "other")})
	}
	return obj{"node": node, "link": link, "modules": mods, "summary": sums}, nil
}

func listModules(c *call, _ map[string]any) (map[string]any, error) {
	list, err := c.getArr("/api/modules", nil)
	if err != nil {
		return nil, err
	}
	var out []any
	for _, e := range list {
		m := asObj(e)
		out = append(out, obj{"name": str(m, "name"), "version": str(m, "version"), "available": boolean(m, "available"), "enabled": boolean(m, "enabled"),
			"running": boolean(m, "running"), "last_error": clean(str(m, "last_error"), 200), "changed": str(m, "changed")})
	}
	return obj{"modules": out}, nil
}

func listCerts(c *call, _ map[string]any) (map[string]any, error) {
	list, err := c.getArr("/api/certs", nil)
	if err != nil {
		return nil, err
	}
	var out []any
	for _, e := range list {
		m := asObj(e)
		o := obj{"id": i64(m, "id"), "names": strs(m, "names"), "source": str(m, "source"), "status": str(m, "status"), "issuer": clean(str(m, "issuer"), 120),
			"not_before": ts(m["not_before"]), "not_after": ts(m["not_after"]), "auto_renew": boolean(m, "auto_renew"), "staging": boolean(m, "staging"),
			"key_type": str(m, "key_type"), "last_attempt": ts(m["last_attempt"]), "used_by": strs(m, "used_by"), "step": str(m, "step")}
		if t := parseTS(m["not_after"]); t.Year() > 1 {
			o["days_left"] = int(time.Until(t).Hours() / 24)
		}
		if e := str(m, "last_error"); e != "" {
			o["untrusted"] = obj{"last_error": clean(e, 300)}
		}
		out = append(out, o)
	}
	return obj{"certificates": out, "count": len(out)}, nil
}

func recentNotifications(c *call, a map[string]any) (map[string]any, error) {
	limit := argInt(a, "limit", 30, 1, 200)
	q := url.Values{"limit": {strconv.Itoa(limit)}}
	failed := argBool(a, "failed_only")
	if failed {
		q.Set("limit", "1000") // filtern wir selbst
	}
	if ch := argInt(a, "channel_id", 0, 0, 1<<30); ch > 0 {
		q.Set("channel", strconv.Itoa(ch))
	}
	list, err := c.getArr("/api/deliveries", q)
	if err != nil {
		return nil, err
	}
	var out []any
	for _, e := range list {
		m := asObj(e)
		if failed && boolean(m, "ok") {
			continue
		}
		o := obj{"time": ts(m["time"]), "channel_id": i64(m, "channel_id"), "channel": clean(str(m, "channel"), 80), "kind": str(m, "kind"), "ok": boolean(m, "ok")}
		if t := str(m, "check_token"); t != "" {
			o["check_id"] = shortID(t)
		}
		o["untrusted"] = obj{"subject": clean(str(m, "subject"), 200), "error": clean(str(m, "error"), 300)}
		out = append(out, o)
		if len(out) >= limit {
			break
		}
	}
	res := obj{"deliveries": out, "count": len(out)}
	if chans, err := c.getArr("/api/channels", nil); err == nil { // ohne include_secrets: Geheimnisse maskiert, wir geben die Konfiguration gar nicht aus
		var cl []any
		for _, e := range chans {
			m := asObj(e)
			cl = append(cl, obj{"id": i64(m, "id"), "name": clean(str(m, "name"), 80), "type": str(m, "type"), "enabled": boolean(m, "enabled"),
				"default": boolean(m, "default"), "last_used_at": ts(m["last_used_at"]), "untrusted": obj{"last_error": clean(str(m, "last_error"), 200)}})
		}
		res["channels"] = cl
	}
	return res, nil
}

func auditLog(c *call, a map[string]any) (map[string]any, error) {
	limit := argInt(a, "limit", 50, 1, 200)
	q := url.Values{"limit": {strconv.Itoa(limit)}}
	if ar := argStr(a, "area"); ar != "" {
		q.Set("area", ar)
	}
	if b := argInt(a, "before", 0, 0, maxID); b > 0 {
		q.Set("before", strconv.Itoa(b))
	}
	list, err := c.getArr("/api/audit", q)
	if err != nil {
		return nil, err
	}
	var out []any
	var last int64
	for _, e := range list {
		m := asObj(e)
		last = i64(m, "id")
		// actor ist bei login.failed der vom Besucher eingegebene Name (bzw. Name aus SSO): fremde Daten
		out = append(out, obj{"id": last, "time": ts(m["time"]), "action": str(m, "action"), "ip": str(m, "ip"), "origin": clean(str(m, "origin"), 80),
			"untrusted": obj{"actor": clean(str(m, "actor"), 64), "target": clean(str(m, "target"), 200), "details": clean(str(m, "details"), 300)}})
	}
	res := obj{"entries": out, "count": len(out)}
	if len(out) == limit && last > 1 {
		res["next_before"] = last
	}
	return res, nil
}

var levelRank = map[string]int{"debug": 0, "info": 1, "warn": 2, "error": 3}

// logLevel liest die Stufe aus einer Logzeile (Text- oder JSON-Format).
func logLevel(line string) string {
	l := strings.ToLower(line)
	for _, lv := range []string{"error", "warn", "info", "debug"} {
		if strings.Contains(l, "level="+lv) || strings.Contains(l, `"level":"`+lv) {
			return lv
		}
	}
	return "info"
}

func nodeLogs(c *call, a map[string]any) (map[string]any, error) {
	n := argInt(a, "lines", 100, 1, 500)
	level, module, contains := argStr(a, "level"), strings.ToLower(argStr(a, "module")), strings.ToLower(argStr(a, "contains"))
	fetch := n
	if level != "" || module != "" || contains != "" {
		fetch = 2000
	}
	m, err := c.getObj("/api/logs", url.Values{"lines": {strconv.Itoa(fetch)}})
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, e := range asArr(m["lines"]) {
		s, _ := e.(string)
		ls := strings.ToLower(s)
		if level != "" && levelRank[logLevel(s)] < levelRank[level] {
			continue
		}
		if module != "" && !strings.Contains(ls, "module="+module) && !strings.Contains(ls, `"module":"`+module+`"`) {
			continue
		}
		if contains != "" && !strings.Contains(ls, contains) {
			continue
		}
		lines = append(lines, clean(s, 500))
	}
	if len(lines) > n { // die neuesten
		lines = lines[len(lines)-n:]
	}
	return obj{"level": str(m, "level"), "count": len(lines), "untrusted": obj{"lines": lines}}, nil
}
