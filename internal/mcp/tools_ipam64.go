package mcp

import (
	"net/url"
	"strconv"
)

// IPAM64: Praefixe, Adressen, Konflikte, freie Adressen (nur lesen). Namen und Hersteller stammen teils von Geraeten
// (DHCP-Hostname, Nachbartabelle) - deshalb als fremde Daten markiert.

func ipam64Tools() []Tool {
	return []Tool{
		{Name: "ipam64_overview", Area: AreaIPAM64, Title: "IPAM64 overview", Untrusted: true,
			Desc:   "IPAM64 prefixes (IPv4/IPv6 tree with VLAN, status, DHCP range from DNS64, DNS zone, utilisation, conflicts), address ranges and the state of the network scan.",
			Schema: noArgs, Run: ipam64Overview},
		{Name: "ipam64_addresses", Area: AreaIPAM64, Title: "IPAM64 addresses", Untrusted: true,
			Desc: "Used addresses merged from IPAM64, DHCP, local DNS, Monitor64, Healthchecks, PROXY64 and the neighbour table: name, MAC, vendor, kind, status, state, sources, last seen.",
			Schema: schema(nil, pStr("prefix", "Only this prefix, e.g. 192.168.1.0/24.", 49), pStr("query", "Search in IP, name, MAC, description.", 64),
				pInt("limit", "Maximum number of addresses.", 100, 1, 1000)),
			Run: ipam64Addresses},
		{Name: "ipam64_conflicts", Area: AreaIPAM64, Title: "IPAM64 conflicts", Untrusted: true,
			Desc:   "Conflicts (duplicate address, foreign MAC on a fixed address, lease versus fixed address), hints and unknown devices found by IPAM64.",
			Schema: noArgs, Run: ipam64Conflicts},
		{Name: "ipam64_available", Area: AreaIPAM64, Title: "IPAM64 free addresses",
			Desc:   "Next free addresses in a prefix (not used, not in the DHCP range, not in ranges kept free).",
			Schema: schema([]string{"prefix"}, pStr("prefix", "Prefix, e.g. 192.168.1.0/24.", 49), pInt("count", "Number of addresses.", 5, 1, 50)),
			Run:    ipam64Available},
	}
}

func ipam64Overview(c *call, _ map[string]any) (map[string]any, error) {
	po, err := c.getObj("/api/ipam64/prefixes", nil)
	if err != nil {
		return nil, err
	}
	var prefixes []any
	for _, e := range asArr(po["prefixes"]) {
		p := asObj(e)
		prefixes = append(prefixes, obj{"prefix": str(p, "prefix"), "name": clean(str(p, "name"), 64), "status": str(p, "status"), "vlan": i64(p, "vlan"),
			"parent": str(p, "parent"), "dynamic": boolean(p, "dynamic"), "dhcp": boolean(p, "dhcp"), "pool": str(p, "pool_start") + "-" + str(p, "pool_end"),
			"dns_zone": str(p, "dns_zone"), "used": i64(p, "used"), "size": i64(p, "size"), "used_pct": p["used_pct"], "conflicts": i64(p, "conflicts"),
			"in_ipam": str(p, "uid") != ""})
	}
	out := obj{"prefixes": prefixes, "count": len(prefixes)}
	if ro, err := c.getObj("/api/ipam64/ranges", nil); err == nil {
		var ranges []any
		for _, e := range asArr(ro["ranges"]) {
			r := asObj(e)
			ranges = append(ranges, obj{"start": str(r, "start"), "end": str(r, "end"), "kind": str(r, "kind"), "name": clean(str(r, "name"), 64)})
		}
		out["ranges"] = ranges
	}
	if so, err := c.getObj("/api/ipam64/scan", nil); err == nil {
		out["scan"] = obj{"running": boolean(so, "running"), "prefix": str(so, "prefix"), "finished": ts(so["finished"]), "found": i64(so, "found")}
	}
	return out, nil
}

func ipam64Addresses(c *call, a map[string]any) (map[string]any, error) {
	q := url.Values{"limit": {strconv.Itoa(argInt(a, "limit", 100, 1, 1000))}}
	if p := argStr(a, "prefix"); p != "" {
		q.Set("prefix", p)
	}
	if s := argStr(a, "query"); s != "" {
		q.Set("q", s)
	}
	ao, err := c.getObj("/api/ipam64/addresses", q)
	if err != nil {
		return nil, err
	}
	var list []any
	for _, e := range asArr(ao["addresses"]) {
		x := asObj(e)
		list = append(list, obj{"prefix": str(x, "prefix"), "ip": str(x, "ip"), "mac": str(x, "mac"), "kind": str(x, "kind"), "status": str(x, "status"),
			"role": str(x, "role"), "state": str(x, "state"), "conflict": str(x, "conflict"), "sources": x["sources"], "last_seen": ts(x["last_seen"]),
			"untrusted": obj{"name": clean(str(x, "name"), 80), "vendor": clean(str(x, "vendor"), 80), "description": clean(str(x, "description"), 200)}})
	}
	return obj{"addresses": list, "total": i64(ao, "total")}, nil
}

func ipam64Conflicts(c *call, _ map[string]any) (map[string]any, error) {
	co, err := c.getObj("/api/ipam64/conflicts", nil)
	if err != nil {
		return nil, err
	}
	var found, unknown []any
	for _, e := range asArr(co["findings"]) {
		f := asObj(e)
		found = append(found, obj{"kind": str(f, "kind"), "severity": str(f, "severity"), "ip": str(f, "ip"), "prefix": str(f, "prefix"), "macs": f["macs"],
			"untrusted": obj{"name": clean(str(f, "name"), 80)}})
	}
	for _, e := range asArr(co["unknown"]) {
		d := asObj(e)
		unknown = append(unknown, obj{"ip": str(d, "ip"), "prefix": str(d, "prefix"), "mac": str(d, "mac"), "first_seen": ts(d["first_seen"]), "last_seen": ts(d["last_seen"]),
			"untrusted": obj{"vendor": clean(str(d, "vendor"), 80)}})
	}
	return obj{"findings": found, "unknown_devices": unknown}, nil
}

func ipam64Available(c *call, a map[string]any) (map[string]any, error) {
	q := url.Values{"prefix": {argStr(a, "prefix")}, "count": {strconv.Itoa(argInt(a, "count", 5, 1, 50))}}
	ao, err := c.getObj("/api/ipam64/available", q)
	if err != nil {
		return nil, err
	}
	return obj{"prefix": str(ao, "prefix"), "available": ao["available"]}, nil
}
