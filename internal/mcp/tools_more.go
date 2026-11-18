package mcp

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Weitere lesende Werkzeuge: DHCP-Server von DNS64, Statusseiten der Healthchecks und der Cluster. Hostnamen der
// DHCP-Geraete liefern die Geraete selbst (untrusted); Kopplungscode und Account-Kennung des Clusters gibt es nie.

func moreTools() []Tool {
	return []Tool{
		{Name: "dns64_dhcp", Area: AreaDNS64, Title: "DHCP leases", Untrusted: true,
			Desc: "DHCP server of DNS64: mode and role, networks (interface, subnet, range, used/size, errors), current leases with IP, MAC, hostname and expiry, fixed addresses, foreign DHCP servers seen in the network and recent events. Filter by network or search for an IP, MAC or hostname.",
			Schema: schema(nil, pStr("network", "Only this network (name, interface or subnet).", 60), pStr("find", "Only leases/reservations whose IP, MAC or hostname contains this text.", 60),
				pInt("limit", "Maximum leases per network.", 100, 1, 500)),
			Run: dhcpLeases},
		{Name: "list_status_pages", Area: AreaHealthchecks, Title: "Status pages",
			Desc:   "Status pages of the node: title, address, enabled/public, password protected, and what each page currently shows (overall state, sections and groups with the state of every entry, running maintenance and recent incidents).",
			Schema: schema(nil, pStr("page", "Only this page (slug or exact title).", 120)), Run: statusPages},
		{Name: "status_page_details", Area: AreaHealthchecks, Title: "Status page configuration",
			Desc:   "Configuration of one status page as stored (layout, theme, options, sections and entries with their check or Monitor64 source) and its notices (announcements with updates). Never includes the page password.",
			Schema: schema([]string{"page"}, pStr("page", "Page id, slug or exact title (from list_status_pages).", 120)), Run: statusPageDetails},
		{Name: "cluster_status", Area: AreaNode, Title: "Cluster status",
			Desc:   "Cluster of this node: members with name, address, online, state (active or suspended, with reason), version, last seen, last error and synced areas, plus the synced modules. Never includes pairing codes.",
			Schema: noArgs, Run: clusterStatus},
	}
}

func dhcpLeases(c *call, a map[string]any) (map[string]any, error) {
	st, err := c.getObj("/api/dns64/dhcp", nil)
	if err != nil {
		return nil, err
	}
	scopes, err := c.getArr("/api/dns64/dhcp/scopes", nil)
	if err != nil {
		return nil, err
	}
	resv, _ := c.getArr("/api/dns64/dhcp/reservations", nil)
	netF, find := strings.ToLower(strings.TrimSpace(argStr(a, "network"))), strings.ToLower(strings.TrimSpace(argStr(a, "find")))
	limit := argInt(a, "limit", 100, 1, 500)
	view := asObj(st["state"])
	live := map[string]obj{} // Scope-Id -> Zustand
	for _, e := range asArr(view["scopes"]) {
		m := asObj(e)
		live[strconv.FormatInt(i64(m, "id"), 10)] = m
	}
	hit := func(parts ...string) bool {
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
	nets := []any{}
	names := map[string]string{}
	for _, e := range scopes {
		s := asObj(e)
		id := strconv.FormatInt(i64(s, "id"), 10)
		names[id] = str(s, "name")
		if netF != "" && !strings.Contains(strings.ToLower(str(s, "name")+" "+str(s, "interface")+" "+str(s, "subnet")), netF) {
			continue
		}
		n := obj{"name": clean(str(s, "name"), 80), "interface": str(s, "interface"), "subnet": str(s, "subnet"),
			"range": str(s, "range_start") + " - " + str(s, "range_end"), "enabled": boolean(s, "enabled"), "relay": boolean(s, "relay")}
		lv := live[id]
		if len(lv) > 0 {
			n["size"], n["used"], n["reserved"] = i64(lv, "size"), i64(lv, "used"), i64(lv, "reserved")
			if er := str(lv, "error"); er != "" {
				n["error"] = clean(er, 200)
			}
		}
		var leases []any
		for _, x := range asArr(lv["leases"]) {
			l := asObj(x)
			if !hit(str(l, "ip"), str(l, "mac"), str(l, "hostname")) {
				continue
			}
			if len(leases) >= limit {
				n["leases_truncated"] = true
				break
			}
			leases = append(leases, obj{"ip": str(l, "ip"), "mac": str(l, "mac"), "state": str(l, "state"), "expires": ts(l["expires"]),
				"untrusted": obj{"hostname": clean(str(l, "hostname"), 120)}})
		}
		n["leases"] = leases
		var fixed []any
		for _, x := range resv {
			r := asObj(x)
			if strconv.FormatInt(i64(r, "scope_id"), 10) != id || !hit(str(r, "ip"), str(r, "mac"), str(r, "name")) {
				continue
			}
			fixed = append(fixed, obj{"ip": str(r, "ip"), "mac": str(r, "mac"), "name": clean(str(r, "name"), 120), "comment": clean(str(r, "comment"), 200), "origin": str(r, "origin")})
		}
		if len(fixed) > 0 {
			n["fixed"] = fixed
		}
		nets = append(nets, n)
	}
	var foreign []any
	for _, e := range asArr(view["foreign"]) {
		f := asObj(e)
		foreign = append(foreign, obj{"network": clean(names[strconv.FormatInt(i64(f, "scope"), 10)], 80), "server": str(f, "server"), "last_seen": ts(f["last_seen"])})
	}
	var events []any
	for _, e := range asArr(view["events"]) {
		if len(events) >= 30 {
			break
		}
		ev := asObj(e)
		if !hit(str(ev, "ip"), str(ev, "mac"), str(ev, "hostname")) {
			continue
		}
		events = append(events, obj{"time": ts(ev["time"]), "type": str(ev, "type"), "ip": str(ev, "ip"), "mac": str(ev, "mac"), "result": clean(str(ev, "result"), 120),
			"untrusted": obj{"hostname": clean(str(ev, "hostname"), 120)}})
	}
	out := obj{"mode": str(st, "mode"), "role": str(st, "role"), "running": boolean(st, "running"), "standby_networks": strs(st, "standby"),
		"networks": nets, "foreign_servers": foreign, "events": events}
	if v6, err := c.getObj("/api/dns64/dhcp/ipv6", nil); err == nil { // IPv6-DNS per Router Advertisement
		ra := obj{"config": plain(v6["config"], 3), "running": boolean(v6, "running"), "error": clean(str(v6, "error"), 200),
			"status": pickList(v6["status"], 20, "interface", "dns", "last_sent", "error", "error_kind")}
		var routers []any
		for _, e := range asArr(v6["routers"]) { // Router Advertisements anderer Geraete im Netz
			r := asObj(e)
			x := pick(r, "interface", "source", "router_lifetime", "managed", "other", "last_seen")
			x["prefixes"] = pickList(r["prefixes"], 10, "prefix", "slaac", "on_link", "valid_lifetime")
			x["untrusted"] = obj{"dns": strs(r, "dns"), "domains": strs(r, "domains")}
			routers = append(routers, x)
			if len(routers) >= 20 {
				break
			}
		}
		ra["routers_seen"] = routers
		out["ipv6_router_advertisement"] = ra
	}
	return out, nil
}

func statusPages(c *call, a map[string]any) (map[string]any, error) {
	list, err := c.getArr("/api/status-pages", nil)
	if err != nil {
		return nil, err
	}
	ref := strings.TrimSpace(argStr(a, "page"))
	out := []any{}
	for _, e := range list {
		p := asObj(e)
		if ref != "" && !strings.EqualFold(str(p, "slug"), ref) && !strings.EqualFold(str(p, "title"), ref) {
			continue
		}
		x := obj{"title": clean(str(p, "title"), 120), "slug": str(p, "slug"), "path": "/status/" + str(p, "slug"), "enabled": boolean(p, "enabled"),
			"public_on_node_port": boolean(p, "publish_node"), "pw_protected": boolean(p, "has_password"), "days": i64(p, "days")}
		v, err := c.getObj("/api/status-pages/"+strconv.FormatInt(i64(p, "id"), 10)+"/view", url.Values{"lang": {"en"}})
		if err == nil {
			x["overall"] = str(v, "overall")
			var groups []any
			for _, g := range asArr(v["groups"]) {
				gm := asObj(g)
				var items []any
				for _, it := range asArr(gm["items"]) {
					im := asObj(it)
					item := obj{"label": clean(str(im, "label"), 120), "state": str(im, "state")}
					if u := num(im, "uptime"); u >= 0 {
						item["uptime_percent"] = round(u, 2)
					}
					items = append(items, item)
				}
				grp := obj{"name": clean(str(gm, "name"), 120), "overall": str(gm, "overall"), "items": items}
				if sec := str(gm, "section"); sec != "" {
					grp["section"] = sec
				}
				groups = append(groups, grp)
			}
			x["groups"] = groups
			var maint []any
			for _, m := range asArr(v["maintenance"]) {
				mm := asObj(m)
				maint = append(maint, obj{"title": clean(str(mm, "title"), 120), "start": ts(mm["start"]), "end": ts(mm["end"]), "active": boolean(mm, "active")})
			}
			if len(maint) > 0 {
				x["maintenance"] = maint
			}
			var inc []any
			for _, i := range asArr(v["incidents"]) {
				if len(inc) >= 10 {
					break
				}
				im := asObj(i)
				inc = append(inc, obj{"item": clean(str(im, "item"), 120), "start": ts(im["start"]), "end": ts(im["end"]), "reason": clean(str(im, "reason"), 200)})
			}
			if len(inc) > 0 {
				x["recent_incidents"] = inc
			}
		}
		out = append(out, x)
	}
	return obj{"status_pages": out}, nil
}

func clusterStatus(c *call, _ map[string]any) (map[string]any, error) {
	g, err := c.getObj("/api/group", nil)
	if err != nil {
		return nil, err
	}
	members := []any{}
	for _, e := range asArr(g["members"]) {
		m := asObj(e)
		x := obj{"name": clean(str(m, "name"), 120), "url": clean(str(m, "url"), 200), "online": boolean(m, "online"), "state": str(m, "state"),
			"version": str(m, "version"), "last_seen": ts(m["last_seen"]), "linked_to_ipv64": boolean(m, "linked"), "synced_areas": strs(m, "sync")}
		if er := str(m, "last_error"); er != "" {
			x["last_error"] = clean(er, 300)
		}
		if r := str(m, "reason"); r != "" {
			x["reason"] = clean(r, 200)
		}
		members = append(members, x)
	}
	return obj{"members": members, "synced_modules": g["sync_modules"], "linked_to_ipv64": boolean(g, "linked")}, nil
}

// statusPageDetails: gespeicherte Konfiguration einer Statusseite und ihre Ankuendigungen (ohne Passwort).
func statusPageDetails(c *call, a map[string]any) (map[string]any, error) {
	list, err := c.getArr("/api/status-pages", nil)
	if err != nil {
		return nil, err
	}
	ref := strings.TrimSpace(argStr(a, "page"))
	var id string
	for _, e := range list {
		p := asObj(e)
		pid := strconv.FormatInt(i64(p, "id"), 10)
		if ref == pid || strings.EqualFold(str(p, "slug"), ref) || strings.EqualFold(str(p, "title"), ref) {
			id = pid
			break
		}
	}
	if id == "" {
		return nil, fmt.Errorf("status page %q not found (use list_status_pages)", clean(ref, 60))
	}
	p, err := c.getObj("/api/status-pages/"+id, nil)
	if err != nil {
		return nil, err
	}
	out := pick(p, "id", "slug", "title", "description", "footer", "enabled", "publish_node", "layout", "theme", "lang", "accent", "days",
		"show_uptime", "show_history", "refresh_sec", "noindex", "powered_by", "hc_groups", "has_logo", "created_at", "updated_at")
	out["pw_protected"] = boolean(p, "has_password")
	out["path"] = "/status/" + str(p, "slug")
	groups := []any{}
	for _, g := range asArr(p["groups"]) {
		gm := asObj(g)
		items := []any{}
		for _, it := range asArr(gm["items"]) {
			im := asObj(it)
			x := pick(im, "id", "label", "kind")
			// Quelle: Check (nur Kurz-Id, das Token ist bei Push-Checks die Berechtigung), Monitor64-Quelle oder Gliederung
			switch tok := str(im, "token"); {
			case tok == "":
			case strings.HasPrefix(tok, "m64:"), strings.HasPrefix(tok, "@"):
				x["source"] = clean(tok, 200)
			default:
				x["check_id"] = shortID(tok)
			}
			items = append(items, x)
		}
		groups = append(groups, obj{"id": i64(gm, "id"), "name": clean(str(gm, "name"), 120), "items": items})
	}
	out["groups"] = groups
	if ns, err := c.getArr("/api/status-pages/"+id+"/notices", nil); err == nil {
		notices := []any{}
		for _, e := range ns {
			n := asObj(e)
			x := pick(n, "id", "title", "level", "created_at", "updated_at", "resolved_at")
			x["updates"] = pickList(n["updates"], 20, "id", "time", "text")
			notices = append(notices, x)
			if len(notices) >= 30 {
				break
			}
		}
		out["notices"] = notices
	}
	return out, nil
}
