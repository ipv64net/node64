package mcp

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Werte von "part" je Werkzeug: eine Liste fuer Schema und Auswertung (vorher je dreifach gepflegt).
var (
	partsDns64Config  = partSet{def: "", list: []string{"settings", "records", "zones", "forwards", "rewrites", "groups", "devices", "lists", "own_lists", "services", "docker"}}    // dns64_config
	partsProxyConfig  = partSet{def: "", list: []string{"host", "streams", "access_lists", "limits", "protection", "settings", "online", "status", "stats", "docker", "geo_lookup"}} // proxy_config
	partsDyndnsConfig = partSet{def: "", list: []string{"targets", "settings", "account_names"}}                                                                                     // dyndns_config
)

// DNS64, PROXY64 und DynDNS: Konfiguration und Nachschlagen. Adressen von Upstreams und Listen nur mit Schema und
// Host (im Pfad stehen oft Profil-Kennungen), keine TSIG-Schluessel, keine Header-Werte und Seiten-HTML von PROXY64,
// keine Passwoerter der Zugriffslisten, keine DynDNS-Tokens.

func networkMoreTools() []Tool {
	return []Tool{
		{Name: "dns64_config", Area: AreaDNS64, Title: "DNS64 configuration", Untrusted: true,
			Desc: "DNS64 configuration by part: settings (ports, encrypted DNS, upstreams and block lists without URLs, cache, state), records (own DNS records), zones (local zones and the device names in them), forwards (conditional forwarding with state), rewrites, groups (device groups with members, lists, blocked services, schedules, current state), devices (devices of the last 24 h), lists (block and allow lists with state), own_lists (own allowed and blocked domains), services (services that can be blocked per click), docker (records from Docker labels). DHCP is in dns64_dhcp.",
			Schema: schema([]string{"part"}, partsDns64Config.prop(),
				pStr("find", "Only entries containing this text (records, zones, devices, own_lists, services).", 100), pInt("limit", "Maximum entries per list.", 200, 1, 1000)),
			Run: dns64Config},
		{Name: "dns64_lookup", Area: AreaDNS64, Title: "DNS64 domain lookup",
			Desc:   "Why a domain is blocked or allowed by DNS64: matching block lists, own lists, exceptions, blocked services/categories and device groups.",
			Schema: schema([]string{"domain"}, pStr("domain", "Domain name.", 253)), Run: dns64Lookup},
		{Name: "proxy_config", Area: AreaProxy64, Title: "PROXY64 configuration", Untrusted: true,
			Desc: "PROXY64 configuration and state by part: host (one host with all settings, locations, DNS records, linked checks and CDN64 servers; needs id from proxy_hosts), streams (TCP/UDP streams), access_lists (allowed networks and user names, never passwords), limits (overload protection: settings and bans), protection (what the CDN64 servers blocked per name: WAF, JA4, overload), settings (access log retention, default page for unknown names), online (CDN64 tunnel, servers, enabled names, quota), status (listeners, cache, hosts), stats (requests per host and per hour), docker (container sync), geo_lookup (country of an IP for country blocks, needs ip).",
			Schema: schema([]string{"part"}, partsProxyConfig.prop(),
				pIntOpt("id", "Host id (part host; optional filter for part stats).", 1, maxID), pInt("hours", "Period in hours (part stats).", 24, 1, 168),
				pEnum("days", "Period in days (part protection).", "1", "1", "7", "30"), pStr("ip", "IP address (part geo_lookup).", 45)),
			Run: proxyConfig},
		{Name: "dyndns_config", Area: AreaDynDNS, Title: "DynDNS configuration", Untrusted: true,
			Desc:   "DynDNS configuration by part: targets (all targets with mode for IPv4/IPv6, fixed values, interface, state; never tokens), settings (check interval, IP sources, retention, notifications), account_names (names of the ipv64 account that can be used as targets).",
			Schema: schema([]string{"part"}, partsDyndnsConfig.prop()),
			Run:    dyndnsConfig},
	}
}

// contains: Text enthaelt die Suche (ohne Gross-/Kleinschreibung; leere Suche passt immer).
func contains(find string, parts ...string) bool {
	if find == "" {
		return true
	}
	for _, p := range parts {
		if strings.Contains(strings.ToLower(p), find) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- DNS64

func dns64Config(c *call, a map[string]any) (map[string]any, error) {
	part, err := partsDns64Config.arg(a)
	if err != nil {
		return nil, err
	}
	find, limit := strings.ToLower(argStr(a, "find")), argInt(a, "limit", 200, 1, 1000)
	out := obj{"part": part}
	switch part {
	case "settings":
		s, err := c.getObj("/api/dns64/settings", nil)
		if err != nil {
			return nil, err
		}
		for k, v := range pick(s, "port", "bind", "router", "retention_days", "upstream_mode", "list_hours", "block_mode", "cache_size", "anonymize", "allow_nets",
			"doh", "dot", "doq", "doh_port", "dot_port", "names", "cert_mode", "cert_id", "notify_upstream", "notify_lists", "acme_domain", "acme_prefix", "acme_staging",
			"upstream_count", "firefox_canary", "rebind", "rebind_allow", "mdns", "docker", "docker_ip", "docker_domains") {
			out[k] = v
		}
		ups := []any{}
		for _, e := range asArr(s["upstreams"]) {
			m := asObj(e)
			x := pick(m, "name", "ips", "enabled", "custom")
			x["host"] = urlHost(str(m, "url"))
			ups = append(ups, x)
		}
		out["upstreams"] = ups
		lists := func(v any) []any {
			l := []any{}
			for _, e := range asArr(v) {
				m := asObj(e)
				x := pick(m, "name", "enabled", "custom")
				x["host"] = urlHost(str(m, "url"))
				l = append(l, x)
			}
			return l
		}
		out["block_lists"], out["allow_lists"] = lists(s["lists"]), lists(s["allow_lists"])
		if st, err := c.getObj("/api/dns64/status", nil); err == nil {
			out["status"] = pick(st, "version", "listen", "startedAt", "router", "routerSource", "retentionDays")
			out["blocking"] = pick(asObj(st["blocking"]), "paused", "until_resumed", "paused_until")
		}
		if up, err := c.getObj("/api/dns64/upstreams", nil); err == nil {
			out["local_resolution"] = obj{"local_dns": clean(str(up, "localDNS"), 120), "local_source": str(up, "localSource"), "local_domains": strs(up, "localDomains"),
				"mdns": pick(asObj(up["mdns"]), "on", "queries", "answered", "responders", "probed_at")}
		}
	case "records":
		list, err := c.getArr("/api/dns64/records", nil)
		if err != nil {
			return nil, err
		}
		rows := []any{}
		for _, e := range list {
			m := asObj(e)
			if !contains(find, str(m, "name"), str(m, "value"), str(m, "comment")) {
				continue
			}
			if len(rows) >= limit {
				out["truncated"] = true
				break
			}
			rows = append(rows, pick(m, "id", "name", "type", "value", "ttl", "enabled", "comment", "no_ptr", "local_only", "dynamic", "created_at"))
		}
		out["records"], out["total"] = rows, len(list)
	case "zones":
		list, err := c.getArr("/api/dns64/zones", nil)
		if err != nil {
			return nil, err
		}
		zones := []any{}
		for _, e := range list {
			m := asObj(e)
			if contains(find, str(m, "name"), str(m, "comment")) {
				// tsig_name ist nur der Name des Schluessels; den Schluessel selbst (GET .../tsig) liest MCP nie
				zones = append(zones, pick(m, "id", "name", "authoritative", "devices", "comment", "enabled", "ttl", "refresh", "retry", "expire", "minimum",
					"hostmaster", "dynamic", "tsig_name", "created_at"))
			}
		}
		out["zones"] = zones
		if dn, err := c.getArr("/api/dns64/device-names", nil); err == nil { // Namen melden die Geraete selbst (DHCP)
			names := []any{}
			for _, e := range dn {
				m := asObj(e)
				if !contains(find, str(m, "name"), strings.Join(strs(m, "ips"), " ")) {
					continue
				}
				if len(names) >= limit {
					break
				}
				names = append(names, obj{"ips": strs(m, "ips"), "untrusted": obj{"name": clean(str(m, "name"), 200)}})
			}
			out["device_names"] = names
		}
	case "forwards":
		list, err := c.getArr("/api/dns64/forwards", nil)
		if err != nil {
			return nil, err
		}
		fw := []any{}
		for _, e := range list {
			m := asObj(e)
			x := pick(m, "id", "domain", "servers", "comment", "enabled", "local_only", "created_at")
			var st []any
			for _, s := range asArr(m["state"]) {
				sm := asObj(s)
				y := pick(sm, "label", "requests", "errors", "avg_ms", "healthy", "last_error_at")
				if le := str(sm, "last_error"); le != "" {
					y["untrusted"] = obj{"last_error": clean(le, 200)}
				}
				st = append(st, y)
			}
			x["state"] = st
			fw = append(fw, x)
		}
		out["forwards"] = fw
	case "rewrites":
		list, err := c.getArr("/api/dns64/rewrites", nil)
		if err != nil {
			return nil, err
		}
		out["rewrites"] = pickList(list, limit, "id", "name", "target", "comment", "enabled", "created_at")
	case "groups":
		list, err := c.getArr("/api/dns64/groups", nil)
		if err != nil {
			return nil, err
		}
		groups := []any{}
		for _, e := range list {
			m := asObj(e)
			x := pick(m, "id", "uid", "name", "position", "lists_mode", "lists", "categories", "safesearch", "youtube", "bypass", "hold", "hold_until")
			x["members"] = pickList(m["members"], limit, "id", "kind", "value", "label", "tags")
			x["domains"] = pickList(m["domains"], limit, "id", "domain", "action")
			x["schedules"] = pickList(m["schedules"], 50, "id", "label", "days", "start", "end", "action", "categories", "enabled")
			x["state"] = plain(m["state"], 2)
			groups = append(groups, x)
		}
		out["groups"] = groups
	case "devices":
		list, err := c.getArr("/api/dns64/devices", nil)
		if err != nil {
			return nil, err
		}
		devs := []any{}
		for _, e := range list {
			m := asObj(e)
			if !contains(find, str(m, "ip"), str(m, "name"), str(m, "mac"), str(m, "group")) {
				continue
			}
			if len(devs) >= limit {
				out["truncated"] = true
				break
			}
			x := pick(m, "ip", "mac", "group", "group_id", "queries", "last_seen")
			x["untrusted"] = obj{"name": clean(str(m, "name"), 120)} // Name vom Router bzw. vom Geraet
			devs = append(devs, x)
		}
		out["devices"], out["total"] = devs, len(list)
	case "lists":
		status := func(v []any) []any {
			l := []any{}
			for _, e := range v {
				m := asObj(e)
				x := pick(m, "name", "rules", "updatedAt", "failures", "enabled")
				x["host"] = urlHost(str(m, "url"))
				if er := str(m, "error"); er != "" {
					x["untrusted"] = obj{"error": clean(er, 200)}
				}
				l = append(l, x)
			}
			return l
		}
		bl, err := c.getArr("/api/dns64/lists", nil)
		if err != nil {
			return nil, err
		}
		out["block_lists"] = status(bl)
		if al, err := c.getArr("/api/dns64/allowlists", nil); err == nil {
			out["allow_lists"] = status(al)
		}
	case "own_lists":
		own := func(path string) []any {
			l := []any{}
			list, _ := c.getArr(path, nil)
			for _, e := range list {
				m := asObj(e)
				if contains(find, str(m, "domain")) && len(l) < limit {
					l = append(l, pick(m, "domain", "addedAt"))
				}
			}
			return l
		}
		out["allowed_domains"], out["blocked_domains"] = own("/api/dns64/allowlist"), own("/api/dns64/denylist")
	case "services":
		s, err := c.getObj("/api/dns64/services", nil)
		if err != nil {
			return nil, err
		}
		svcs := []any{}
		for _, e := range asArr(s["services"]) {
			m := asObj(e)
			if contains(find, str(m, "key"), str(m, "name"), str(m, "group")) {
				x := pick(m, "key", "id", "name", "group")
				x["domains"] = len(asArr(m["domains"]))
				svcs = append(svcs, x)
			}
		}
		out["categories"], out["service_groups"], out["services"] = strs(s, "categories"), strs(s, "groups"), svcs
	case "docker":
		d, err := c.getObj("/api/dns64/docker", nil)
		if err != nil {
			return nil, err
		}
		for k, v := range pick(d, "enabled", "connected", "host", "synced") {
			out[k] = v
		}
		if er := str(d, "error"); er != "" {
			out["untrusted"] = obj{"error": clean(er, 200)}
		}
		out["containers"] = pickList(d["containers"], limit, "container", "state", "names", "addrs", "problem", "problem_name")
	}
	return out, nil
}

func dns64Lookup(c *call, a map[string]any) (map[string]any, error) {
	d := argStr(a, "domain")
	if d == "" {
		return nil, errors.New("parameter domain is required")
	}
	m, err := c.getObj("/api/dns64/lookup", url.Values{"domain": {d}})
	if err != nil {
		return nil, err
	}
	out := pick(m, "domain", "blocked", "reason", "excepted", "own", "allowed", "released", "services", "categories")
	out["lists"] = pickList(m["lists"], 50, "name", "global")
	out["groups"] = pickList(m["groups"], 50, "group", "kind", "entry")
	return out, nil
}

// dns64Timeline: Anfragen im Zeitverlauf (fuer dns64_summary).
func dns64Timeline(c *call, rng string) []any {
	t, err := c.getObj("/api/dns64/timeline", url.Values{"range": {rng}})
	if err != nil {
		return nil
	}
	out := []any{}
	for _, e := range asArr(t["buckets"]) {
		m := asObj(e)
		out = append(out, obj{"time": time.UnixMilli(i64(m, "t")).UTC().Format(time.RFC3339), "total": i64(m, "total"), "blocked": i64(m, "blocked")})
	}
	return out
}

// ---------------------------------------------------------------- PROXY64

func proxyConfig(c *call, a map[string]any) (map[string]any, error) {
	part, err := partsProxyConfig.arg(a)
	if err != nil {
		return nil, err
	}
	out := obj{"part": part}
	switch part {
	case "host":
		id, err := needID(a, "id", part)
		if err != nil {
			return nil, err
		}
		h, err := c.getObj("/api/cdn64/hosts/"+id, nil)
		if err != nil {
			return nil, err
		}
		for k, v := range pick(h, "id", "kind", "names", "enabled", "scheme", "target_host", "target_port", "websockets", "block_exploits", "cache_assets", "cert_id",
			"force_ssl", "http2", "http3", "hsts", "hsts_subdomains", "min_tls", "verify_target", "created_at", "updated_at", "route_error", "certificate_error",
			"redirect_target", "redirect_scheme", "redirect_code", "preserve_path", "access_list_id", "dns_error", "status_page_id") {
			out[k] = v
		}
		out["reach"] = pick(asObj(h["reach"]), "state", "ms", "checked_at", "since", "error")
		out["certificate"] = pick(asObj(h["certificate"]), "state", "name", "days_left", "missing")
		out["stats_since_start"] = pick(asObj(h["stats"]), "requests", "errors", "blocked")
		out["advanced"] = proxyAdvanced(asObj(h["advanced"]))
		locs := []any{}
		for _, e := range asArr(h["locations"]) {
			m := asObj(e)
			x := pick(m, "path", "scheme", "target_host", "target_port", "forward_path", "websockets", "access_list_id", "denied_redirect", "action", "status", "content_type")
			x["advanced"] = proxyAdvanced(asObj(m["advanced"]))
			locs = append(locs, x)
		}
		out["locations"] = locs
		out["dns_records"] = pickList(h["dns_records"], 20, "name", "result", "error")
		var hc []any
		for _, w := range asArr(h["healthchecks"]) {
			wm := asObj(w)
			x := pick(wm, "name", "type", "state", "paused", "local", "host_only", "last_check")
			x["check_id"] = shortID(str(wm, "token"))
			hc = append(hc, x)
		}
		out["healthchecks"] = hc
		if s, err := c.getObj("/api/cdn64/hosts/"+id+"/servers", nil); err == nil {
			out["cdn64_servers"] = pick(s, "count", "choice", "max", "all", "total", "selectable", "assigned", "active", "sessions", "sessions_max", "options", "session_options")
		}
	case "streams":
		list, err := c.getArr("/api/cdn64/streams", nil)
		if err != nil {
			return nil, err
		}
		streams := []any{}
		for _, e := range list {
			m := asObj(e)
			x := pick(m, "id", "name", "enabled", "listen_port", "tcp", "udp", "target_host", "target_port", "tls_cert_id", "cert_name", "running", "geo_mode",
				"geo_countries", "bw_down_mbit", "bw_up_mbit", "proxy_protocol", "created_at", "updated_at")
			x["reach"], x["listen_errors"] = plain(m["reach"], 2), plain(m["listen_errors"], 2)
			x["stats"] = pick(asObj(m["stats"]), "connections", "active", "bytes_in", "bytes_out")
			streams = append(streams, x)
		}
		out["streams"] = streams
	case "access_lists":
		list, err := c.getArr("/api/cdn64/access-lists", nil)
		if err != nil {
			return nil, err
		}
		acls := []any{}
		for _, e := range list {
			m := asObj(e)
			al := asObj(m["access_list"])
			x := pick(al, "id", "name", "satisfy_any", "pass_auth", "created_at", "updated_at")
			var users []string
			for _, u := range asArr(al["users"]) {
				users = append(users, clean(str(asObj(u), "username"), 64)) // nur Namen, nie Passwoerter bzw. Hashes
			}
			x["users"], x["rules"], x["used_by"] = users, pickList(al["rules"], 200, "action", "cidr"), strs(m, "used_by")
			acls = append(acls, x)
		}
		out["access_lists"] = acls
	case "limits":
		l, err := c.getObj("/api/cdn64/limits", nil)
		if err != nil {
			return nil, err
		}
		keys := []string{"enabled", "conns_per_ip", "conn_rate", "req_rate", "req_burst", "max_conns", "target_conns", "ban_after", "ban_minutes", "exempt_lan"}
		out["limits"], out["defaults"] = pick(asObj(l["limits"]), keys...), pick(asObj(l["defaults"]), keys...)
		out["bans"] = pickList(l["bans"], 200, "ip", "until")
		out["rejected_since_start"], out["connections"] = i64(l, "rejected"), plain(l["conns"], 2)
	case "protection":
		days := argStr(a, "days")
		if days == "" {
			days = "1"
		}
		p, err := c.getObj("/api/cdn64/protection", url.Values{"days": {days}})
		if err != nil {
			return nil, err
		}
		for k, v := range pick(p, "days", "ja4_global") {
			out[k] = v
		}
		out["totals"], out["daily"] = plain(p["totals"], 2), plain(p["daily"], 3)
		out["ja4_top"] = pickList(p["ja4_top"], 20, "ja4", "hits")
		out["hosts"] = pickList(p["hosts"], 200, "id", "fqdn", "mode", "host_id", "blocked", "overload", "waf", "ja4")
	case "settings":
		s, err := c.getObj("/api/cdn64/settings", nil)
		if err != nil {
			return nil, err
		}
		out["access_log"] = pick(s, "log_days", "anonymize", "access_file", "access_file_mb", "access_file_path")
		if d, err := c.getObj("/api/cdn64/default", nil); err == nil { // eigenes HTML der Standardseite gibt es nicht
			out["default_page"] = obj{"default": str(d, "default"), "default_url": urlHost(str(d, "default_url")), "custom_html": str(d, "default_html") != ""}
		}
		if hp, err := c.getObj("/api/cdn64/honeypot", nil); err == nil {
			hs := asObj(hp["settings"])
			out["honeypot"] = obj{"route": plain(hs["route"], 2), "decoy": boolean(hs, "decoy"), "access": boolean(hs, "access"), "block": boolean(hs, "block"),
				"block_hours": i64(hs, "block_hours"), "decoy_available": boolean(hp, "decoy_available"), "access_available": boolean(hp, "access_available")}
		}
	case "online":
		o, err := c.getObj("/api/cdn64/online", nil)
		if err != nil {
			return nil, err
		}
		for k, v := range pick(o, "configured", "tunnel", "api_ready", "synced", "udp_buffer", "udp_buffer_low") {
			out[k] = v
		}
		out["edges"] = pickList(o["edges"], 50, "name", "host", "connected", "transport", "total", "rtt_ms", "loss_pct")
		out["names"] = pickList(o["names"], 500, "name", "host_id", "remote_id", "mode", "check", "created_at")
		out["quota"] = plain(o["quota"], 3)
		if se := str(o, "sync_error"); se != "" {
			out["untrusted"] = obj{"sync_error": clean(se, 200)}
		}
		if s, err := c.getObj("/api/cdn64/online/servers", nil); err == nil {
			out["tunnel_servers"] = pick(s, "count", "choice", "max", "all", "total", "selectable", "assigned", "active", "sessions", "sessions_max", "options", "session_options")
		}
	case "status":
		s, err := c.getObj("/api/cdn64/status", nil)
		if err != nil {
			return nil, err
		}
		for k, v := range pick(s, "version", "started_at", "hosts", "enabled", "targets_down") {
			out[k] = v
		}
		out["cache"] = pick(asObj(s["cache"]), "entries", "bytes", "hits", "misses")
		out["listeners"] = pickList(s["listeners"], 50, "name", "proto", "port", "needed", "running", "addr", "error")
	case "stats":
		q := url.Values{"hours": {strconv.Itoa(argInt(a, "hours", 24, 1, 168))}}
		if id := argInt(a, "id", 0, 0, maxID); id > 0 {
			q.Set("host", strconv.Itoa(id))
		}
		s, err := c.getObj("/api/cdn64/stats", q)
		if err != nil {
			return nil, err
		}
		keys := []string{"requests", "2xx", "3xx", "4xx", "5xx", "bytes", "bytes_in", "blocked", "decoy"}
		hosts := obj{}
		for id, v := range asObj(s["hosts"]) {
			hosts[id] = pick(asObj(v), keys...)
		}
		out["hours"], out["by_host_id"], out["dropped"], out["decoy_active"] = i64(s, "hours"), hosts, i64(s, "dropped"), boolean(s, "decoy_active")
		out["timeline"] = pickList(s["timeline"], 168, append([]string{"hour", "conn_blocked"}, keys...)...)
	case "docker":
		d, err := c.getObj("/api/cdn64/docker", nil)
		if err != nil {
			return nil, err
		}
		for k, v := range pick(d, "enabled", "connected", "host", "synced") {
			out[k] = v
		}
		if er := str(d, "error"); er != "" {
			out["untrusted"] = obj{"error": clean(er, 200)}
		}
		out["settings"] = pick(asObj(d["settings"]), "enabled", "traefik", "docker_host", "certificate")
		out["containers"] = pickList(d["containers"], 200, "name", "state", "source", "router", "names", "target", "host_id", "access", "ignored", "problem", "problem_name")
	case "geo_lookup":
		ip := argStr(a, "ip")
		if _, err := netip.ParseAddr(ip); err != nil {
			return nil, errors.New("parameter ip must be an IPv4 or IPv6 address")
		}
		g, err := c.getObj("/api/cdn64/geo/lookup", url.Values{"ip": {ip}, "lang": {"en"}})
		if err != nil {
			return nil, err
		}
		for k, v := range pick(g, "ip", "country", "name", "source", "location_data") {
			out[k] = v
		}
	}
	return out, nil
}

// proxyAdvanced: erweiterte Einstellungen eines Hosts bzw. einer Location ohne Header-Werte (darin stehen oft
// Zugangsdaten) und ohne eigenes HTML (Wartungs- und Fehlerseite).
func proxyAdvanced(adv obj) obj {
	if len(adv) == 0 {
		return nil
	}
	out := pick(adv, "maintenance", "maintenance_style", "error_override", "target_path", "only_locations", "target_http", "proxy_protocol", "host_header",
		"timeout_seconds", "max_body_mb", "buffering", "bw_down_mbit", "bw_up_mbit", "no_buffering", "gzip", "trusted_proxies", "access_log", "no_limits",
		"geo_mode", "geo_countries", "ai_bots", "ai_bots_allow_user", "ai_robots", "nextcloud_dav", "no_probe", "label_headers", "request_remove", "response_remove")
	names := func(v any) []string {
		var n []string
		for _, e := range asArr(v) {
			n = append(n, clean(str(asObj(e), "name"), 80))
		}
		return n
	}
	if n := names(adv["request_headers"]); len(n) > 0 {
		out["request_header_names"] = n
	}
	if n := names(adv["response_headers"]); len(n) > 0 {
		out["response_header_names"] = n
	}
	out["custom_maintenance_html"] = str(adv, "maintenance_html") != ""
	out["custom_error_html"] = str(adv, "error_html") != ""
	return out
}

// ---------------------------------------------------------------- DynDNS

func dyndnsConfig(c *call, a map[string]any) (map[string]any, error) {
	part, err := partsDyndnsConfig.arg(a)
	if err != nil {
		return nil, err
	}
	out := obj{"part": part}
	switch part {
	case "targets":
		list, err := c.getArr("/api/dyndns/targets", nil)
		if err != nil {
			return nil, err
		}
		tl := []any{}
		for _, e := range list {
			m := asObj(e)
			x := pick(m, "id", "domain", "host", "fqdn", "record_id", "mode4", "fixed4", "mode6", "fixed6", "suffix6", "iface", "enabled", "paused", "status",
				"last_ipv4", "last_ipv6", "last_prefix", "last_ok_at", "last_error_at", "dns_state")
			x["auth_kind"] = str(m, "token_kind") // Art der Berechtigung, nie das Token selbst
			if le := str(m, "last_error"); le != "" {
				x["untrusted"] = obj{"last_error": clean(le, 200)}
			}
			tl = append(tl, x)
		}
		out["targets"] = tl
	case "settings":
		s, err := c.getObj("/api/dyndns/settings", nil)
		if err != nil {
			return nil, err
		}
		for k, v := range pick(s, "interval_minutes", "keep_checks_days", "keep_updates_days", "notify_ip", "notify_fail", "notify_limit") {
			out[k] = v
		}
		out["source4"], out["source6"] = urlHost(str(s, "source4")), urlHost(str(s, "source6"))
	case "account_names":
		list, err := c.getArr("/api/dyndns/account/names", nil)
		if err != nil {
			return nil, err
		}
		out["names"] = pickList(list, 500, "key", "domain", "host", "fqdn", "kind", "a", "aaaa", "suffix_of", "default_mode4", "default_mode6", "exists", "blocked")
	}
	return out, nil
}
