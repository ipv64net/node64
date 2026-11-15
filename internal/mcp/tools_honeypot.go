package mcp

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Werte von "part" je Werkzeug: eine Liste fuer Schema und Auswertung (vorher je dreifach gepflegt).
var (
	partsHoneypotConfig = partSet{def: "", list: []string{"config", "status", "catalog", "watch", "live"}} // honeypot_config
)

// Honeypot64: fast alles, was hier steht, schreiben Angreifer (Benutzer, Passwoerter, Pfade, User-Agents,
// Nutzdaten). Diese Felder stehen immer unter "untrusted".

func honeypotTools() []Tool {
	return []Tool{
		{Name: "honeypot_stats", Area: AreaHoneypot, Title: "Honeypot64 statistics", Untrusted: true,
			Desc:   "Honeypot64 statistics for a period: events, attacking IPs, logins, by service/port/kind/country, top sources and the most tried users, passwords, paths and user agents.",
			Schema: schema(nil, pStr("since", "Period: 24h, 7d or Nd (1-90 days) or a duration like 6h. Default 24h.", 10), pInt("top", "Length of the top lists.", 10, 1, 50)),
			Run:    honeypotStats},
		{Name: "honeypot_events", Area: AreaHoneypot, Title: "Honeypot64 events", Untrusted: true,
			Desc: "Latest Honeypot64 events (connections, login attempts, requests), newest first, filterable by source, country, service and kind.",
			Schema: schema(nil, pInt("limit", "Maximum number of events.", 50, 1, 200), pEnum("source", "Event source.", "", "honeypot", "log", "syslog"),
				pStr("country", "Two-letter country code.", 2), pStr("service", "Only this service (e.g. ssh, http, telnet).", 30), pStr("kind", "Only this event kind.", 30)),
			Run: honeypotEvents},
		{Name: "honeypot_lookup_ip", Area: AreaHoneypot, Title: "Look up an IP", Untrusted: true,
			Desc:   "Everything the node knows locally about one IP: Honeypot64 events (count, first/last seen, services, recent events) and, if allowed for this key, PROXY64 blocks and access-log entries.",
			Schema: schema([]string{"ip"}, pStr("ip", "IPv4 or IPv6 address.", 45)),
			Run:    honeypotLookupIP},
		{Name: "honeypot_config", Area: AreaHoneypot, Title: "Honeypot64 configuration", Untrusted: true,
			Desc:   "Honeypot64 configuration and state by part: config (profile, services, limits, retention, reporting, log sensor), status (trap services, warnings, counters, reporting to ipv64, log sensor state), catalog (all trap services with selection and state), watch (early warning: own networks and DynDNS IPs watched at ipv64, recent hits), live (attacks of the last minutes with country).",
			Schema: schema([]string{"part"}, partsHoneypotConfig.prop(), pInt("minutes", "Period for part live.", 15, 1, 60)),
			Run:    honeypotConfig},
	}
}

func countList(v any, keyName string, max int) []any {
	var out []any
	for _, e := range asArr(v) {
		m := asObj(e)
		o := obj{"count": i64(m, "count"), "last": ts(m["last"])}
		if c := str(m, "country"); c != "" {
			o["country"] = c
		}
		o[keyName] = clean(str(m, "key"), 200)
		if n := i64(m, "sources"); n > 0 {
			o["sources"] = n
		}
		out = append(out, o)
		if max > 0 && len(out) >= max {
			break
		}
	}
	return out
}

func honeypotStats(c *call, a map[string]any) (map[string]any, error) {
	since := argStr(a, "since")
	if since == "" {
		since = "24h"
	}
	top := argInt(a, "top", 10, 1, 50)
	s, err := c.getObj("/api/honeypot/stats", url.Values{"since": {since}, "top": {strconv.Itoa(top)}})
	if err != nil {
		return nil, err
	}
	out := obj{"since": ts(s["since"]), "events": i64(s, "events"), "attacking_ips": i64(s, "sources"), "login_attempts": i64(s, "logins"),
		"by_service": countList(s["by_service"], "service", 0), "by_port": countList(s["by_port"], "port", 0),
		"by_kind": countList(s["by_kind"], "kind", 0), "by_source": countList(s["by_source"], "source", 0),
		"by_country": countList(s["by_country"], "country", top), "country_unknown": i64(s, "country_unknown"),
		"top_ips": countList(s["top_sources"], "ip", top)}
	var tl []any
	for _, e := range asArr(s["timeline"]) {
		m := asObj(e)
		tl = append(tl, obj{"time": ts(m["time"]), "events": i64(m, "events")})
	}
	if len(tl) > 100 {
		tl = tl[len(tl)-100:]
	}
	out["timeline"] = tl
	out["untrusted"] = obj{"top_users": countList(s["top_users"], "user", top), "top_passwords": countList(s["top_passwords"], "password", top),
		"top_credentials": countList(s["top_credentials"], "credential", top), "top_paths": countList(s["top_paths"], "path", top),
		"top_user_agents": countList(s["top_user_agents"], "user_agent", top), "top_fingerprints": countList(s["top_fingerprints"], "fingerprint", top),
		"by_decoy": countList(s["by_decoy"], "decoy", top)}
	if st, err := c.getObj("/api/honeypot/status", nil); err == nil {
		var svc []any
		for _, e := range asArr(st["services"]) {
			m := asObj(e)
			svc = append(svc, obj{"service": str(m, "service"), "port": i64(m, "port"), "listening": boolean(m, "listen"), "connections": i64(m, "conns"),
				"error": clean(str(m, "error"), 200)})
		}
		out["sensor"] = obj{"running": boolean(st, "running"), "profile": str(st, "profile"), "services": svc}
	}
	return out, nil
}

// eventOutHP: ein Honeypot-Ereignis, Angreiferfelder unter "untrusted".
func eventOutHP(m obj) obj {
	o := obj{"time": ts(m["time"]), "service": str(m, "service"), "port": i64(m, "port"), "kind": str(m, "kind"), "ip": str(m, "src"),
		"src_port": i64(m, "src_port"), "country": str(m, "country"), "source": str(m, "source"), "rule": clean(str(m, "rule"), 80)}
	u := obj{}
	for _, k := range []string{"username", "password", "method", "path", "host", "user_agent", "client", "page", "detail", "fingerprint"} {
		if v := str(m, k); v != "" {
			u[k] = clean(v, 300)
		}
	}
	if v := str(m, "payload_text"); v != "" {
		u["payload"] = clean(v, 300)
	}
	o["untrusted"] = u
	return o
}

func honeypotEvents(c *call, a map[string]any) (map[string]any, error) {
	limit := argInt(a, "limit", 50, 1, 200)
	service, kind := strings.ToLower(argStr(a, "service")), strings.ToLower(argStr(a, "kind"))
	q := url.Values{"limit": {strconv.Itoa(limit)}}
	if service != "" || kind != "" {
		q.Set("limit", "1000")
	}
	if s := argStr(a, "source"); s != "" {
		q.Set("source", s)
	}
	if s := argStr(a, "country"); s != "" {
		q.Set("country", s)
	}
	list, err := c.getArr("/api/honeypot/events", q)
	if err != nil {
		return nil, err
	}
	var out []any
	for _, e := range list {
		m := asObj(e)
		if service != "" && strings.ToLower(str(m, "service")) != service {
			continue
		}
		if kind != "" && strings.ToLower(str(m, "kind")) != kind {
			continue
		}
		out = append(out, eventOutHP(m))
		if len(out) >= limit {
			break
		}
	}
	return obj{"events": out, "count": len(out)}, nil
}

func honeypotLookupIP(c *call, a map[string]any) (map[string]any, error) {
	ip, err := netip.ParseAddr(argStr(a, "ip"))
	if err != nil {
		return nil, errors.New("parameter ip must be an IPv4 or IPv6 address")
	}
	ip = ip.Unmap()
	want := ip.String()
	out := obj{"ip": want, "private": ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()}
	list, err := c.getArr("/api/honeypot/events", url.Values{"limit": {"1000"}})
	if err != nil {
		return nil, err
	}
	var recent []any
	services, kinds := map[string]int{}, map[string]int{}
	var n int
	var first, last, country string
	for _, e := range list {
		m := asObj(e)
		if a, err := netip.ParseAddr(str(m, "src")); err != nil || a.Unmap() != ip {
			continue
		}
		n++
		t := ts(m["time"])
		if last == "" {
			last = t // neueste zuerst
		}
		first = t
		if country == "" {
			country = str(m, "country")
		}
		services[str(m, "service")]++
		kinds[str(m, "kind")]++
		if len(recent) < 10 {
			recent = append(recent, eventOutHP(m))
		}
	}
	hp := obj{"events_in_latest_1000": n, "first_seen": first, "last_seen": last, "country": country, "services": services, "kinds": kinds, "recent_events": recent}
	out["honeypot"] = hp

	if c.can(AreaProxy64) {
		px := obj{}
		if h, err := c.getObj("/api/cdn64/honeypot", nil); err == nil {
			for _, e := range asArr(h["blocks"]) {
				m := asObj(e)
				if str(m, "ip") == want {
					px["instant_block"] = obj{"since": ts(m["since"]), "until": ts(m["until"]), "untrusted": obj{"reason": clean(str(m, "reason"), 120)}}
				}
			}
		}
		if l, err := c.getObj("/api/cdn64/limits", nil); err == nil {
			for _, e := range asArr(l["bans"]) {
				m := asObj(e)
				if b, err := netip.ParsePrefix(str(m, "ip")); err == nil && b.Contains(ip) || str(m, "ip") == want {
					px["rate_limit_ban_until"] = ts(m["until"])
				}
			}
		}
		if rows, err := c.getArr("/api/cdn64/log", url.Values{"q": {want}, "limit": {"500"}}); err == nil {
			var lr []any
			cnt := 0
			for _, e := range rows {
				m := asObj(e)
				if str(m, "client") != want {
					continue
				}
				cnt++
				if len(lr) < 10 {
					lr = append(lr, obj{"time": ts(m["time"]), "status": i64(m, "status"), "rejected_reason": str(m, "reason"),
						"untrusted": obj{"method": clean(str(m, "method"), 10), "host": clean(str(m, "host"), 253), "path": clean(stripQuery(str(m, "path")), 300),
							"user_agent": clean(str(m, "user_agent"), 200)}})
				}
			}
			px["access_log_rows"] = cnt
			px["recent_requests"] = lr
		}
		out["proxy64"] = px
	} else {
		out["proxy64"] = "not available for this key"
	}
	return out, nil
}

func honeypotConfig(c *call, a map[string]any) (map[string]any, error) {
	part, err := partsHoneypotConfig.arg(a)
	if err != nil {
		return nil, err
	}
	out := obj{"part": part}
	switch part {
	case "config":
		d, err := c.getObj("/api/honeypot/config", nil)
		if err != nil {
			return nil, err
		}
		for k, v := range pick(d, "profile", "scan", "max_conns_per_ip", "max_conns_total", "retention_days", "max_events", "notify_new", "report", "no_local_block",
			"country", "cert_id", "cert_ports") {
			out[k] = v
		}
		out["services"] = pickList(d["services"], 100, "service", "port", "page")
		lg := asObj(d["log"])
		out["log_sensor"] = obj{"files": pickList(lg["files"], 50, "path", "format"), "syslog_port": i64(lg, "syslog_port"), "syslog_allow": strs(lg, "syslog_allow")}
		out["login"] = plain(d["login"], 2)
	case "status":
		d, err := c.getObj("/api/honeypot/status", nil)
		if err != nil {
			return nil, err
		}
		for k, v := range pick(d, "version", "running", "started_at", "profile", "scan", "buffered", "dropped") {
			out[k] = v
		}
		out["services"] = pickList(d["services"], 100, "service", "port", "listen", "error", "conns")
		out["warnings"] = pickList(d["warnings"], 50, "service", "port", "owner", "purpose", "skipped")
		out["counters"] = plain(d["counters"], 2)
		rp := asObj(d["report"])
		rep := pick(rp, "enabled", "key_set", "active", "last_success", "last_end", "last_error_at", "next_attempt", "errors", "sources_today", "sources_total", "last_rejected")
		rep["last_rejected_reasons"] = plain(rp["last_rejected_reasons"], 2)
		if le := str(rp, "last_error"); le != "" {
			rep["untrusted"] = obj{"last_error": clean(le, 200)}
		}
		out["report_to_ipv64"] = rep
		lg := asObj(d["logs"])
		out["log_sensor"] = obj{"files": pickList(lg["files"], 50, "path", "format", "ok", "error", "lines", "last"),
			"syslog": pick(asObj(lg["syslog"]), "port", "udp", "tcp", "error", "messages", "denied"), "lines": i64(lg, "lines"), "hits": i64(lg, "hits"), "events": i64(lg, "events")}
	case "catalog":
		d, err := c.getObj("/api/honeypot/catalog", nil)
		if err != nil {
			return nil, err
		}
		keys := []string{"service", "port", "default_port", "page", "proto", "group", "profiles", "on", "state", "owner", "purpose", "error", "conns"}
		out["profile"], out["running"] = str(d, "profile"), boolean(d, "running")
		out["entries"], out["extra"] = pickList(d["entries"], 300, keys...), pickList(d["extra"], 100, keys...)
	case "watch":
		d, err := c.getObj("/api/honeypot/watch", nil)
		if err != nil {
			return nil, err
		}
		out["limits"], out["full"], out["running"] = plain(d["limits"], 2), boolean(d, "full"), boolean(d, "running")
		out["networks"] = pickList(d["networks"], 200, "id", "cidr", "label", "verified", "created_at")
		out["dyndns"] = pickList(d["dyndns"], 100, "ip", "domain")
		st := asObj(d["state"])
		state := pick(st, "total", "networks", "dyndns", "last_check", "last_success", "next_attempt", "last_error_at", "error_status")
		if le := str(st, "last_error"); le != "" {
			state["untrusted"] = obj{"last_error": clean(le, 200)}
		}
		state["hits"] = pickList(st["hits"], 50, "id", "ip", "cidr", "label", "source", "listed", "score", "kinds", "first_seen", "last_seen", "created_at")
		out["state"] = state
	case "live":
		d, err := c.getObj("/api/honeypot/live", url.Values{"minutes": {strconv.Itoa(argInt(a, "minutes", 15, 1, 60))}})
		if err != nil {
			return nil, err
		}
		out["minutes"], out["now"] = i64(d, "minutes"), ts(d["now"])
		out["target"] = pick(asObj(d["target"]), "cc", "name", "known", "manual")
		out["events"] = pickList(d["events"], 100, "t", "cc", "name", "ip", "kind", "group", "service", "port", "source")
	}
	return out, nil
}
