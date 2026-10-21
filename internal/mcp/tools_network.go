package mcp

import (
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DNS64, PROXY64 (Modul cdn64) und DynDNS.

func networkTools() []Tool {
	rng := pEnum("range", "Time range.", "24h", "1h", "24h", "7d")
	return []Tool{
		{Name: "dns64_summary", Area: AreaDNS64, Title: "DNS64 summary",
			Desc:   "DNS64 key figures for a time range: queries, blocked share, cache, clients, blocklists and upstream servers (without URLs).",
			Schema: schema(nil, rng), Run: dns64Summary},
		{Name: "dns64_top", Area: AreaDNS64, Title: "DNS64 top lists", Untrusted: true,
			Desc: "Top domains (blocked or allowed) or top clients of DNS64 in a time range.",
			Schema: schema([]string{"kind"}, pEnum("kind", "Which list.", "", "blocked", "allowed", "clients"), rng,
				pInt("limit", "Number of entries.", 10, 1, 50)),
			Run: dns64Top},
		{Name: "dns64_query_log", Area: AreaDNS64, Title: "DNS64 query log", Untrusted: true,
			Desc: "Search the DNS64 query log (newest first) by client and/or domain, status and age.",
			Schema: schema(nil, pStr("client", "Client IP or part of it.", 64), pStr("domain", "Domain or part of it.", 253),
				pEnum("status", "Only this status.", "", "allowed", "cached", "blocked", "local", "error", "custom"),
				pInt("since_minutes", "Only queries of the last N minutes (0 = no limit).", 0, 0, 7*24*60), pInt("limit", "Maximum number of rows.", 50, 1, 200)),
			Run: dns64QueryLog},

		{Name: "proxy_hosts", Area: AreaProxy64, Title: "PROXY64 hosts", Untrusted: true,
			Desc:   "Reverse-proxy hosts of PROXY64: names, kind, target, reachability, certificate state and request counters (no header values, no credentials).",
			Schema: schema(nil, pEnum("kind", "Only this kind.", "", "proxy", "redirect", "dead", "passthrough", "status")), Run: proxyHosts},
		{Name: "proxy_access_log", Area: AreaProxy64, Title: "PROXY64 access log", Untrusted: true,
			Desc: "Search the PROXY64 access log (newest first) by host, status class, rejected requests or text (path, client, user agent). Query strings are removed.",
			Schema: schema(nil, pIntOpt("host_id", "Only this host id (from proxy_hosts).", 1, 1<<30), pEnum("status", "Status class or rejected requests.", "", "1xx", "2xx", "3xx", "4xx", "5xx", "rejected"),
				pStr("query", "Text search in path, client and user agent.", 100), pInt("limit", "Maximum number of rows.", 50, 1, 200),
				pIntOpt("before", "Only rows with an id lower than this (paging).", 1, maxID)),
			Run: proxyAccessLog},
		{Name: "proxy_blocked", Area: AreaProxy64, Title: "PROXY64 blocked IPs", Untrusted: true,
			Desc:   "IPs currently blocked by PROXY64 (instant blocks from Honeypot64, rate-limit bans) and the state of the ipv64 blocklists and country blocks.",
			Schema: noArgs, Run: proxyBlocked},

		{Name: "dyndns_status", Area: AreaDynDNS, Title: "DynDNS status", Untrusted: true,
			Desc:   "Public IPv4/IPv6 and prefix of the connection, connection type hints (CGNAT/DS-Lite), DynDNS targets with state (no tokens) and the ipv64 update limit.",
			Schema: noArgs, Run: dyndnsStatus},
		{Name: "dyndns_history", Area: AreaDynDNS, Title: "DynDNS history", Untrusted: true,
			Desc: "History of DynDNS updates sent to ipv64 or of the public IP checks.",
			Schema: schema(nil, pEnum("type", "Updates or IP checks.", "updates", "updates", "checks"), pInt("days", "Look back this many days.", 7, 1, 30),
				pIntOpt("target_id", "Only updates of this target id (from dyndns_status).", 1, 1<<30), pEnum("family", "Only IPv4 or IPv6 (checks).", "", "4", "6"),
				pInt("limit", "Maximum number of entries.", 50, 1, 300)),
			Run: dyndnsHistory},
	}
}

// ---------------------------------------------------------------- DNS64

func dns64Summary(c *call, a map[string]any) (map[string]any, error) {
	rng := argStr(a, "range")
	if rng == "" {
		rng = "24h"
	}
	s, err := c.getObj("/api/dns64/summary", url.Values{"range": {rng}})
	if err != nil {
		return nil, err
	}
	sum := asObj(s["summary"])
	total, blocked := num(sum, "total"), num(sum, "blocked")
	out := obj{"range": rng, "queries": i64(sum, "total"), "blocked": i64(sum, "blocked"), "blocked_percent": pct(blocked, total),
		"cached": i64(sum, "cached"), "clients": i64(sum, "clients"), "avg_upstream_ms": round(num(sum, "avgUpstreamMs"), 1),
		"blocklist_domains": i64(s, "blocklistSize"), "lists_loaded_at": ts(s["listsLoadedAt"]), "uptime_seconds": i64(s, "uptimeSeconds"), "version": str(s, "version")}
	if d := i64(sum, "droppedLogEntries"); d > 0 {
		out["dropped_log_entries"] = d
	}
	cache := asObj(s["cache"])
	hits, misses := num(cache, "hits"), num(cache, "misses")
	out["cache"] = obj{"entries": i64(cache, "entries"), "max": i64(cache, "max"), "hit_percent": pct(hits, hits+misses)}
	if st, err := c.getObj("/api/dns64/status", nil); err == nil {
		b := asObj(st["blocking"])
		out["blocking_paused"] = boolean(b, "paused")
		if t := ts(b["paused_until"]); t != "" {
			out["blocking_paused_until"] = t
		}
	}
	if up, err := c.getObj("/api/dns64/upstreams", nil); err == nil {
		var list []any
		for _, e := range asArr(up["servers"]) {
			m := asObj(e)
			u := obj{"name": clean(str(m, "name"), 60), "proto": str(m, "proto"), "requests": i64(m, "requests"), "wins": i64(m, "wins"),
				"errors": i64(m, "errors"), "avg_ms": round(num(m, "avgMs"), 1), "healthy": boolean(m, "healthy"), "active": boolean(m, "active")}
			if le := str(m, "lastError"); le != "" {
				u["untrusted"] = obj{"last_error": clean(le, 200)}
				u["last_error_at"] = ts(m["lastErrorAt"])
			}
			list = append(list, u)
		}
		out["upstreams"] = obj{"mode": str(up, "mode"), "servers": list}
	}
	return out, nil
}

func dns64Top(c *call, a map[string]any) (map[string]any, error) {
	kind, rng, limit := argStr(a, "kind"), argStr(a, "range"), argInt(a, "limit", 10, 1, 50)
	if rng == "" {
		rng = "24h"
	}
	list, err := c.getArr("/api/dns64/top", url.Values{"kind": {kind}, "range": {rng}, "limit": {strconv.Itoa(limit)}})
	if err != nil {
		return nil, err
	}
	var out []any
	for _, e := range list {
		m := asObj(e)
		o := obj{"count": i64(m, "count"), "blocked": i64(m, "blocked")}
		u := obj{}
		if kind == "clients" {
			o["client"] = clean(str(m, "name"), 64)
			if h := str(m, "hostname"); h != "" {
				u["hostname"] = clean(h, 120)
			}
		} else {
			u["domain"] = clean(str(m, "name"), 253)
		}
		o["untrusted"] = u
		out = append(out, o)
	}
	return obj{"kind": kind, "range": rng, "items": out}, nil
}

func dns64QueryLog(c *call, a map[string]any) (map[string]any, error) {
	client, domain := strings.ToLower(argStr(a, "client")), strings.ToLower(argStr(a, "domain"))
	limit, since := argInt(a, "limit", 50, 1, 200), argInt(a, "since_minutes", 0, 0, 7*24*60)
	q := url.Values{"limit": {strconv.Itoa(limit)}}
	if s := argStr(a, "status"); s != "" {
		q.Set("status", s)
	}
	// Die API sucht mit q in Domain ODER Client; genauer filtern wir hier.
	switch {
	case domain != "":
		q.Set("q", domain)
	case client != "":
		q.Set("q", client)
	}
	if (client != "" && domain != "") || since > 0 {
		q.Set("limit", "500")
	}
	res, err := c.getObj("/api/dns64/log", q)
	if err != nil {
		return nil, err
	}
	cutoff := int64(0)
	if since > 0 {
		cutoff = time.Now().Add(-time.Duration(since) * time.Minute).UnixMilli()
	}
	var out []any
	for _, e := range asArr(res["rows"]) {
		m := asObj(e)
		t := i64(m, "t")
		if cutoff > 0 && t < cutoff {
			break // neueste zuerst
		}
		if client != "" && !strings.Contains(strings.ToLower(str(m, "client")), client) {
			continue
		}
		if domain != "" && !strings.Contains(strings.ToLower(str(m, "domain")), domain) {
			continue
		}
		o := obj{"time": time.UnixMilli(t).UTC().Format(time.RFC3339), "client": clean(str(m, "client"), 64), "qtype": str(m, "qtype"), "status": str(m, "status"),
			"reason": clean(str(m, "reason"), 80), "rcode": str(m, "rcode"), "upstream": clean(str(m, "upstream"), 60), "ms": round(num(m, "ms"), 1),
			"proto": str(m, "proto"), "group": clean(str(m, "group"), 60)}
		u := obj{"domain": clean(str(m, "domain"), 253)}
		if n := str(m, "clientName"); n != "" {
			u["client_name"] = clean(n, 120)
		}
		o["untrusted"] = u
		out = append(out, o)
		if len(out) >= limit {
			break
		}
	}
	return obj{"rows": out, "count": len(out), "total_matching_in_api": i64(res, "total")}, nil
}

// ---------------------------------------------------------------- PROXY64 (cdn64)

func proxyHosts(c *call, a map[string]any) (map[string]any, error) {
	q := url.Values{}
	if k := argStr(a, "kind"); k != "" {
		q.Set("kind", k)
	}
	list, err := c.getArr("/api/cdn64/hosts", q)
	if err != nil {
		return nil, err
	}
	var out []any
	for _, e := range list {
		m := asObj(e)
		o := obj{"id": i64(m, "id"), "kind": str(m, "kind"), "names": strs(m, "names"), "enabled": boolean(m, "enabled"),
			"access_list": i64(m, "access_list_id") > 0, "force_ssl": boolean(m, "force_ssl"), "route_error": clean(str(m, "route_error"), 200)}
		switch str(m, "kind") {
		case "redirect":
			o["redirect_target"] = clean(str(m, "redirect_target"), 200)
			o["redirect_code"] = i64(m, "redirect_code")
		case "proxy", "passthrough":
			o["target"] = str(m, "scheme") + "://" + clean(str(m, "target_host"), 200) + ":" + strconv.FormatInt(i64(m, "target_port"), 10)
		}
		if adv := asObj(m["advanced"]); adv != nil && str(adv, "geo_mode") != "" {
			o["geo_mode"], o["geo_countries"] = str(adv, "geo_mode"), strs(adv, "geo_countries")
		}
		if r := asObj(m["reach"]); r != nil {
			ro := obj{"state": str(r, "state"), "ms": i64(r, "ms"), "checked_at": ts(r["checked_at"]), "since": ts(r["since"])}
			if er := str(r, "error"); er != "" {
				ro["untrusted"] = obj{"error": clean(er, 200)}
			}
			o["reach"] = ro
		}
		if ce := asObj(m["certificate"]); ce != nil {
			o["certificate"] = obj{"state": str(ce, "state"), "name": clean(str(ce, "name"), 120), "days_left": i64(ce, "days_left")}
		}
		if st := asObj(m["stats"]); st != nil {
			o["stats_since_start"] = obj{"requests": i64(st, "requests"), "errors": i64(st, "errors"), "blocked": i64(st, "blocked")}
		}
		var hc []any
		for _, w := range asArr(m["healthchecks"]) {
			wm := asObj(w)
			hc = append(hc, obj{"check_id": shortID(str(wm, "token")), "name": clean(str(wm, "name"), 120), "state": str(wm, "state")})
		}
		if len(hc) > 0 {
			o["healthchecks"] = hc
		}
		out = append(out, o)
	}
	return obj{"hosts": out, "count": len(out)}, nil
}

// stripQuery: Pfad ohne Query-String (darin stehen oft Tokens der Clients).
func stripQuery(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		return p[:i] + "?…"
	}
	return p
}

func proxyAccessLog(c *call, a map[string]any) (map[string]any, error) {
	limit := argInt(a, "limit", 50, 1, 200)
	q := url.Values{"limit": {strconv.Itoa(limit)}}
	if h := argInt(a, "host_id", 0, 0, 1<<30); h > 0 {
		q.Set("host", strconv.Itoa(h))
	}
	switch s := argStr(a, "status"); s {
	case "rejected":
		q.Set("rejected", "1")
	case "1xx", "2xx", "3xx", "4xx", "5xx":
		q.Set("status", s[:1])
	}
	if s := argStr(a, "query"); s != "" {
		q.Set("q", s)
	}
	if b := argInt(a, "before", 0, 0, maxID); b > 0 {
		q.Set("before", strconv.Itoa(b))
	}
	list, err := c.getArr("/api/cdn64/log", q)
	if err != nil {
		return nil, err
	}
	var out []any
	var last int64
	for _, e := range list {
		m := asObj(e)
		last = i64(m, "id")
		o := obj{"id": last, "time": ts(m["time"]), "host_id": i64(m, "host_id"), "client": clean(str(m, "client"), 64), "method": clean(str(m, "method"), 10),
			"status": i64(m, "status"), "bytes": i64(m, "bytes"), "ms": i64(m, "ms"), "rejected_reason": str(m, "reason")}
		o["untrusted"] = obj{"host": clean(str(m, "host"), 253), "path": clean(stripQuery(str(m, "path")), 300), "user_agent": clean(str(m, "user_agent"), 200)}
		out = append(out, o)
	}
	res := obj{"rows": out, "count": len(out)}
	if len(out) == limit && last > 1 {
		res["next_before"] = last
	}
	return res, nil
}

func proxyBlocked(c *call, _ map[string]any) (map[string]any, error) {
	out := obj{}
	hp, err := c.getObj("/api/cdn64/honeypot", nil)
	if err != nil {
		return nil, err
	}
	var blocks []any
	for _, e := range asArr(hp["blocks"]) {
		m := asObj(e)
		blocks = append(blocks, obj{"ip": str(m, "ip"), "since": ts(m["since"]), "until": ts(m["until"]), "untrusted": obj{"reason": clean(str(m, "reason"), 120)}})
	}
	set := asObj(hp["settings"])
	out["honeypot_instant_block"] = obj{"enabled": boolean(set, "block"), "block_hours": i64(set, "block_hours"), "blocked_ips": blocks,
		"rejected_since_start": i64(hp, "rejected")}
	if lim, err := c.getObj("/api/cdn64/limits", nil); err == nil {
		var bans []any
		for _, e := range asArr(lim["bans"]) {
			m := asObj(e)
			bans = append(bans, obj{"ip": str(m, "ip"), "until": ts(m["until"])})
		}
		out["rate_limit"] = obj{"enabled": boolean(asObj(lim["limits"]), "enabled"), "banned_ips": bans, "rejected_since_start": i64(lim, "rejected")}
	}
	if bl, err := c.getObj("/api/cdn64/blocklists", nil); err == nil {
		var lists []any
		for _, e := range asArr(bl["lists"]) {
			m := asObj(e)
			if !boolean(m, "enabled") {
				continue
			}
			lists = append(lists, obj{"id": str(m, "id"), "name": clean(str(m, "name"), 80), "entries": i64(m, "entries"), "updated": ts(m["updated"]),
				"error": clean(str(m, "error"), 200)})
		}
		var geo []any
		for _, e := range asArr(bl["countries"]) {
			m := asObj(e)
			geo = append(geo, obj{"country": str(m, "code"), "entries": i64(m, "entries"), "error": clean(str(m, "error"), 200)})
		}
		out["blocklists"] = obj{"active": boolean(bl, "active"), "enabled_lists": lists, "blocked_since_start": i64(bl, "blocked"),
			"blocked_countries": geo, "geo_blocked_since_start": i64(bl, "geo_blocked")}
	}
	return out, nil
}

// ---------------------------------------------------------------- DynDNS

func dyndnsStatus(c *call, _ map[string]any) (map[string]any, error) {
	st, err := c.getObj("/api/dyndns/status", nil)
	if err != nil {
		return nil, err
	}
	fam := func(m obj) obj {
		o := obj{"ip": str(m, "ip"), "source_host": clean(str(m, "source"), 120), "checked_at": ts(m["checked_at"]), "changed_at": ts(m["changed_at"]),
			"no_route": boolean(m, "no_route"), "prefix": str(m, "prefix")}
		if e := str(m, "error"); e != "" {
			o["untrusted"] = obj{"error": clean(e, 200)}
		}
		return o
	}
	out := obj{"ipv4": fam(asObj(st["ipv4"])), "ipv6": fam(asObj(st["ipv6"])), "interval_minutes": i64(st, "interval_minutes")}
	if cn := asObj(st["connection"]); cn != nil {
		out["connection"] = obj{"suspect": str(cn, "suspect"), "hop": str(cn, "hop"), "checked_at": ts(cn["checked_at"])}
	}
	if tg := asObj(st["targets"]); tg != nil {
		out["targets_total"], out["targets_by_status"] = i64(tg, "total"), tg["by_status"]
	}
	if l := asObj(st["limit"]); l != nil {
		out["ipv64_update_limit"] = obj{"known": boolean(l, "known"), "used": i64(l, "used"), "limit": i64(l, "limit"), "own_24h": i64(l, "own_24h")}
	}
	if list, err := c.getArr("/api/dyndns/targets", nil); err == nil {
		var tl []any
		for _, e := range list {
			m := asObj(e)
			en, _ := m["enabled"].(bool)
			o := obj{"id": i64(m, "id"), "fqdn": clean(str(m, "fqdn"), 253), "enabled": en, "status": str(m, "status"), "paused": str(m, "paused"),
				"mode4": str(m, "mode4"), "mode6": str(m, "mode6"), "last_ipv4": str(m, "last_ipv4"), "last_ipv6": str(m, "last_ipv6"),
				"last_prefix": str(m, "last_prefix"), "last_ok_at": ts(m["last_ok_at"]), "dns_state": str(m, "dns_state")}
			if e := str(m, "last_error"); e != "" {
				o["untrusted"] = obj{"last_error": clean(e, 200)}
				o["last_error_at"] = ts(m["last_error_at"])
			}
			tl = append(tl, o)
		}
		out["targets"] = tl
	}
	return out, nil
}

func dyndnsHistory(c *call, a map[string]any) (map[string]any, error) {
	typ := argStr(a, "type")
	if typ != "checks" {
		typ = "updates"
	}
	q := url.Values{"type": {typ}, "days": {strconv.Itoa(argInt(a, "days", 7, 1, 30))}}
	if t := argInt(a, "target_id", 0, 0, 1<<30); t > 0 && typ == "updates" {
		q.Set("target", strconv.Itoa(t))
	}
	if f := argStr(a, "family"); f != "" && typ == "checks" {
		q.Set("family", f)
	}
	res, err := c.getObj("/api/dyndns/history", q)
	if err != nil {
		return nil, err
	}
	limit := argInt(a, "limit", 50, 1, 300)
	var out []any
	for _, e := range asArr(res["items"]) {
		m := asObj(e)
		var o obj
		if typ == "checks" {
			o = obj{"time": ts(m["time"]), "family": str(m, "family"), "ip": str(m, "ip"), "changed": boolean(m, "changed"), "duration_ms": i64(m, "duration_ms"),
				"source_host": clean(str(m, "source"), 120)}
			if er := str(m, "error"); er != "" {
				o["untrusted"] = obj{"error": clean(er, 200)}
			}
		} else {
			o = obj{"time": ts(m["time"]), "target_id": i64(m, "target_id"), "target": clean(str(m, "target"), 253), "trigger": str(m, "trigger"),
				"sent_ipv4": str(m, "sent_ipv4"), "sent_ipv6": str(m, "sent_ipv6"), "sent_prefix": str(m, "sent_prefix"), "http_status": i64(m, "http_status"),
				"ok": boolean(m, "ok"), "duration_ms": i64(m, "duration_ms")}
			o["untrusted"] = obj{"status": clean(str(m, "status"), 80), "info": clean(str(m, "info"), 200), "error": clean(str(m, "error"), 200)}
		}
		out = append(out, o)
		if len(out) >= limit {
			break
		}
	}
	return obj{"type": typ, "items": out, "count": len(out), "truncated": boolean(res, "truncated") || len(asArr(res["items"])) > len(out)}, nil
}
