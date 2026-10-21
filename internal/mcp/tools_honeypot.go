package mcp

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
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
