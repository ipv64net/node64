package mcp

import (
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Werte von "part" je Werkzeug: eine Liste fuer Schema und Auswertung (vorher je dreifach gepflegt).
var (
	partsNodeConfig           = partSet{def: "", list: []string{"settings", "update", "link", "ipv64", "overview", "ports", "logging", "retention"}}            // node_config
	partsNotificationChannels = partSet{def: "channels", list: []string{"channels", "ipv64", "types"}}                                                          // notification_channels
	partsCertsConfig          = partSet{def: "", list: []string{"cert", "account", "dns_accounts", "dns_providers", "domains", "cas", "acme_cas", "dns_check"}} // certs_config
	partsSonar64Status        = partSet{def: "status", list: []string{"status", "recent", "inbound", "settings"}}                                               // sonar64_status
)

// Kern: Einstellungen der Node, Selbst-Update, Verknuepfung mit ipv64, Ports, Benachrichtigungskanaele,
// Zertifikate und Sonar64. Nie: API-Key von ipv64, Kopplungscodes, Account-Kennung, Kanal-Zugangsdaten,
// Werte der DNS-Zugaenge, private Schluessel, EAB-Kennungen.

func nodeTools() []Tool {
	return []Tool{
		{Name: "node_config", Area: AreaNode, Title: "Node configuration", Untrusted: true,
			Desc:   "Node settings and state by part: settings (name, location, time zone, base URL, quiet hours and rate limits of notifications, update check), update (self-update: running version, mode, channel, window, latest check), link (connection to ipv64.net: plan, sync state, limits, open sync conflicts), ipv64 (state of the central ipv64 API key: plan, expiry; never the key), overview (dashboard figures: traffic, measuring nodes, account limits), ports (used ports with conflicts, shared entrance, listeners, UI name), logging (log levels), retention (data retention). Never includes keys, pairing codes or the account id.",
			Schema: schema([]string{"part"}, partsNodeConfig.prop()),
			Run:    nodeConfig},
		{Name: "notification_channels", Area: AreaNotifications, Title: "Notification channels", Untrusted: true,
			Desc:   "Notification channels by part: channels (channels of the node: type, enabled, default, language, down/up, names of the configured fields, last use and error; never their values), ipv64 (e-mail, SMS and app channels at ipv64.net), types (channel types with their fields, which fields are sensitive).",
			Schema: schema(nil, partsNotificationChannels.prop()),
			Run:    notificationChannels},
		{Name: "certs_config", Area: AreaCerts, Title: "Certificate configuration", Untrusted: true,
			Desc: "Certificate management by part: cert (one certificate with all settings, serial and fingerprint; needs id from list_certs), account (ACME account: e-mail, terms), dns_accounts (DNS accounts for DNS-01 with provider and names of the configured fields, never their values), dns_providers (supported DNS providers and their fields), domains (ipv64 domains of the account), cas (own certificate authorities), acme_cas (further ACME CAs), dns_check (own resolvers of the DNS-01 check). Never includes private keys.",
			Schema: schema([]string{"part"}, partsCertsConfig.prop(),
				pIntOpt("id", "Certificate id (part cert).", 1, maxID)),
			Run: certsConfig},
		{Name: "sonar64_status", Area: AreaSonar64, Title: "Sonar64", Untrusted: true,
			Desc:   "Sonar64 (latency measurements between ipv64 nodes) by part: status (participation, node state at ipv64, trust level), recent (own latest measurements and probes answered on UDP 6464), inbound (who measured this node), settings (participation, budget, quiet hours, profile).",
			Schema: schema(nil, partsSonar64Status.prop(), pInt("limit", "Maximum rows (recent, inbound).", 50, 1, 200)),
			Run:    sonar64Status},
	}
}

func nodeConfig(c *call, a map[string]any) (map[string]any, error) {
	part, err := partsNodeConfig.arg(a)
	if err != nil {
		return nil, err
	}
	out := obj{"part": part}
	switch part {
	case "settings":
		s, err := c.getObj("/api/settings", nil) // feste Liste unkritischer Schluessel (apiSettingKeys)
		if err != nil {
			return nil, err
		}
		set := obj{}
		for k, v := range s {
			if sv, ok := v.(string); ok {
				set[k] = clean(sv, 200)
			}
		}
		out["settings"] = set
	case "update":
		u, err := c.getObj("/api/update", nil)
		if err != nil {
			return nil, err
		}
		for k, v := range pick(u, "running", "origin", "image_version", "previous", "bad", "signing_key", "arch", "dev") {
			out[k] = v
		}
		for _, k := range []string{"mode", "channel", "window", "chosen", "modes", "channels"} { // Felder ohne JSON-Namen: grosse Anfangsbuchstaben
			if v, ok := scalar(first(u, k, strings.ToUpper(k[:1])+k[1:]), 100); ok {
				out[k] = v
			}
		}
		if rb := asObj(u["rollback"]); len(rb) > 0 {
			out["rollback"] = pick(rb, "from", "to", "at")
		}
		if tr := asObj(u["trial"]); len(tr) > 0 {
			out["trial"] = plain(tr, 2)
		}
		if l := asObj(first(u, "latest", "Latest")); len(l) > 0 {
			lt := pick(l, "version", "channel", "checked_at", "newer")
			lt["untrusted"] = obj{"error": clean(str(l, "error"), 200), "apply_error": clean(str(l, "apply_error"), 200)} // Antworten des Update-Servers
			out["latest"] = lt
		}
	case "link":
		l, err := c.getObj("/api/link", nil)
		if err != nil {
			return nil, err
		}
		for k, v := range pick(l, "linked", "connected", "plan", "node_name", "location", "remote_mgmt", "hub", "last_sync_at", "connected_at", "linked_at", "outbox",
			"conflicts", "requesting", "online_limit", "checks_today", "checks_limit", "locations_per_check", "local_notifications") {
			out[k] = v
		}
		if le := str(l, "last_error"); le != "" {
			out["untrusted"] = obj{"last_error": clean(le, 200)}
		}
		if cf, err := c.getArr("/api/link/conflicts", nil); err == nil { // ohne die beiden Fassungen (darin stehen u. a. Check-Parameter)
			list := pickList(cf, 100, "id", "entity", "entity_id", "name", "local_op", "server_revision", "created_at", "error")
			for i, e := range list { // Checks: kurze Kennung wie in list_checks statt Token (Berechtigung fuer die Push-Adresse)
				raw, x := asObj(asArr(cf)[i]), asObj(e)
				if tok := str(raw, "entity_id"); str(raw, "entity") == "check" && tok != "" {
					x["entity_id"] = shortID(tok)
					if n := str(raw, "name"); n != "" { // ohne Namen in den Fassungen: "check <token>"
						x["name"] = clean(strings.ReplaceAll(n, tok, shortID(tok)), 300)
					}
				}
			}
			out["open_conflicts"] = list
		}
	case "ipv64":
		k, err := c.getObj("/api/ipv64", nil)
		if err != nil {
			return nil, err
		}
		out["central_key"] = pick(k, "key_stored", "plan", "checked_at", "expires_at", "days_left")
	case "overview":
		o, err := c.getObj("/api/overview", nil)
		if err != nil {
			return nil, err
		}
		out["traffic"] = pick(asObj(o["traffic"]), "available", "rx_since_start", "tx_since_start", "rx_total", "tx_total", "since")
		hc := asObj(o["healthchecks"])
		out["healthchecks"] = obj{"checks_by_location": plain(hc["checks_by_location"], 2), "nodes": i64(hc, "nodes"), "nodes_online": i64(hc, "nodes_online")}
		ac := asObj(o["account"])
		acc := pick(ac, "plan", "plan_until", "checked_at")
		acc["limits"] = pickList(ac["limits"], 50, "key", "used", "max", "unlimited", "pct")
		if e := str(ac, "error"); e != "" {
			acc["untrusted"] = obj{"error": clean(e, 200)}
		}
		out["account"] = acc
	case "ports":
		p, err := c.getObj("/api/ports", nil)
		if err != nil {
			return nil, err
		}
		out["ports"] = pickList(p["ports"], 200, "owner", "purpose", "proto", "port", "bind", "active", "conflicts")
		if e, err := c.getObj("/api/edge", nil); err == nil {
			out["entrance"] = obj{"config": pick(asObj(e["config"]), "bind", "http_port", "https_port", "public_port", "http3", "default", "proxy_protocol", "proxy_protocol_peers"),
				"listeners": pickList(e["listeners"], 50, "name", "proto", "port", "needed", "running", "addr", "error"),
				"names":     pickList(e["names"], 200, "name", "path", "owner"), "proxy_peers": strs(e, "proxy_peers")}
		}
		if ui, err := c.getObj("/api/edge/ui", nil); err == nil {
			out["ui_name"] = pick(ui, "name", "public", "cert", "cert_from_env")
		}
	case "logging":
		l, err := c.getObj("/api/logging", nil)
		if err != nil {
			return nil, err
		}
		for k, v := range pick(l, "level", "known_modules", "api_log") {
			out[k] = v
		}
		out["modules"] = plain(l["modules"], 2)
	case "retention":
		r, err := c.getObj("/api/retention", nil)
		if err != nil {
			return nil, err
		}
		for k, v := range pick(r, "raw_days", "hourly_days", "chart_detail", "audit_days") {
			out[k] = v
		}
	}
	return out, nil
}

// channelOut: Kanal ohne Konfigurationswerte (auch nicht geheime Felder wie ntfy-Thema oder Webhook-Adresse sind
// oft selbst die Berechtigung) - nur die Namen der gesetzten Felder.
func channelOut(m obj, keys ...string) obj {
	x := pick(m, keys...)
	x["configured_fields"] = setKeys(m["config"])
	if le := str(m, "last_error"); le != "" {
		x["untrusted"] = obj{"last_error": clean(le, 200)}
	}
	return x
}

func notificationChannels(c *call, a map[string]any) (map[string]any, error) {
	part, err := partsNotificationChannels.arg(a)
	if err != nil {
		return nil, err
	}
	out := obj{"part": part}
	switch part {
	case "channels":
		list, err := c.getArr("/api/channels", nil) // ohne include_secrets
		if err != nil {
			return nil, err
		}
		chans := []any{}
		for _, e := range list {
			chans = append(chans, channelOut(asObj(e), "id", "name", "type", "enabled", "default", "lang", "notify_down", "notify_up", "execution", "last_used_at", "created_at", "updated_at"))
		}
		out["channels"] = chans
	case "ipv64":
		list, err := c.getArr("/api/ipv64/channels", nil)
		if err != nil {
			return nil, err
		}
		chans := []any{}
		for _, e := range list {
			chans = append(chans, channelOut(asObj(e), "id", "name", "type", "enabled", "default", "verified", "lang", "notify_down", "notify_up"))
		}
		out["channels"] = chans
	case "types":
		t, err := c.getObj("/api/channel-types", nil)
		if err != nil {
			return nil, err
		}
		types := asObj(t["types"])
		names := make([]string, 0, len(types))
		for k := range types {
			names = append(names, k)
		}
		sort.Strings(names)
		list := []any{}
		for _, n := range names {
			var fields []any
			for _, f := range asArr(types[n]) {
				fm := asObj(f)
				x := pick(fm, "key", "required", "kind", "default", "options")
				x["sensitive"] = boolean(fm, "secret") // Feldname ohne "secret", sonst filtert sanitize ihn
				fields = append(fields, x)
			}
			list = append(list, obj{"type": n, "fields": fields})
		}
		out["types"], out["planned"] = list, plain(t["planned"], 2)
	}
	return out, nil
}

func certsConfig(c *call, a map[string]any) (map[string]any, error) {
	part, err := partsCertsConfig.arg(a)
	if err != nil {
		return nil, err
	}
	out := obj{"part": part}
	switch part {
	case "cert":
		id, err := needID(a, "id", part)
		if err != nil {
			return nil, err
		}
		m, err := c.getObj("/api/certs/"+id, nil)
		if err != nil {
			return nil, err
		}
		for k, v := range pick(m, "id", "names", "source", "alias_zone", "alias_prefix", "staging", "auto_renew", "status", "step", "issuer", "not_before", "not_after",
			"last_attempt", "used_by", "created_at", "updated_at", "dns_account", "ca_id", "days", "acme_ca", "key_type") {
			out[k] = v
		}
		if t := parseTS(m["not_after"]); t.Year() > 1 {
			out["days_left"] = int(time.Until(t).Hours() / 24)
		}
		if le := str(m, "last_error"); le != "" {
			out["untrusted"] = obj{"last_error": clean(le, 300)}
		}
		if meta, err := c.getObj("/api/certs/"+id+"/meta", nil); err == nil { // ausgestelltes Zertifikat (oeffentlich)
			out["issued"] = pick(meta, "serial", "fingerprint_sha256", "not_before", "not_after", "days_left")
		}
	case "account":
		m, err := c.getObj("/api/certs/account", nil)
		if err != nil {
			return nil, err
		}
		for k, v := range pick(m, "email", "tos_accepted", "tos_at", "tos_url") {
			out[k] = v
		}
	case "dns_accounts":
		list, err := c.getArr("/api/certs/dns-accounts", nil)
		if err != nil {
			return nil, err
		}
		accs := []any{}
		for _, e := range list {
			m := asObj(e)
			x := pick(m, "id", "name", "provider", "provider_name", "used_by", "created_at", "updated_at")
			x["configured_fields"] = setKeys(m["values"]) // nur Namen der Felder, keine Werte
			accs = append(accs, x)
		}
		out["dns_accounts"] = accs
	case "dns_providers":
		list, err := c.getArr("/api/certs/dns-providers", nil)
		if err != nil {
			return nil, err
		}
		provs := []any{}
		for _, e := range list {
			m := asObj(e)
			var fields []any
			for _, f := range asArr(m["fields"]) {
				fm := asObj(f)
				x := pick(fm, "key", "label", "optional", "default")
				x["sensitive"] = boolean(fm, "secret")
				fields = append(fields, x)
			}
			provs = append(provs, obj{"id": str(m, "id"), "name": clean(str(m, "name"), 80), "docs": urlHost(str(m, "docs")), "fields": fields})
		}
		out["dns_providers"] = provs
	case "domains":
		list, err := c.getArr("/api/certs/domains", nil)
		if err != nil {
			return nil, err
		}
		v, _ := scalar(list, 253)
		out["domains"] = v
	case "cas":
		list, err := c.getArr("/api/cas", nil)
		if err != nil {
			return nil, err
		}
		out["cas"] = pickList(list, 100, "id", "name", "subject", "not_after", "imported", "root", "permitted_dns", "permitted_ip", "fingerprint_sha256", "certificates", "created_at")
	case "acme_cas":
		list, err := c.getArr("/api/acme-cas", nil)
		if err != nil {
			return nil, err
		}
		cas := []any{}
		for _, e := range list {
			m := asObj(e)
			x := pick(m, "id", "name", "eab", "custom_root", "certificates", "created_at") // ohne EAB-Kennung
			x["directory"] = urlHost(str(m, "directory"))
			cas = append(cas, x)
		}
		out["acme_cas"] = cas
	case "dns_check":
		m, err := c.getObj("/api/certs/dns-check", nil)
		if err != nil {
			return nil, err
		}
		out["resolvers"] = strs(m, "resolvers")
	}
	return out, nil
}

func sonar64Status(c *call, a map[string]any) (map[string]any, error) {
	part, err := partsSonar64Status.arg(a)
	if err != nil {
		return nil, err
	}
	limit := argInt(a, "limit", 50, 1, 200)
	out := obj{"part": part}
	switch part {
	case "status":
		s, err := c.getObj("/api/sonar64/status", nil)
		if err != nil {
			return nil, err
		}
		for k, v := range pick(s, "version", "running", "started_at", "key_set", "participate", "public_url", "port_error") {
			out[k] = v
		}
		n := asObj(s["node"])
		out["node"] = pick(n, "node_id", "registered", "mode", "measured", "budget", "responder", "plan_issued", "plan_expires", "anchors_only", "paused",
			"sent_today", "last_report", "buffered")
		out["trust"] = pick(asObj(s["trust"]), "level", "class", "next", "pct", "days", "need_days", "uptime", "need_uptime", "need_measured")
		out["untrusted"] = obj{"error": clean(str(s, "error"), 200), "me_error": clean(str(s, "me_error"), 200), "node_error": clean(str(n, "last_error"), 200)}
	case "recent":
		s, err := c.getObj("/api/sonar64/recent", url.Values{"n": {strconv.Itoa(limit)}})
		if err != nil {
			return nil, err
		}
		out["responder"] = boolean(s, "responder")
		out["results"] = pickList(s["results"], limit, "at", "target", "method", "fam", "sent", "recv", "min", "avg", "max", "loss", "err")
		inb := []any{}
		for _, e := range asArr(s["inbound"]) {
			m := asObj(e)
			x := pick(m, "from", "fam", "count", "at")
			x["untrusted"] = obj{"name": clean(str(m, "name"), 120)} // Name des fremden Knotens
			inb = append(inb, x)
			if len(inb) >= limit {
				break
			}
		}
		out["answered_probes"] = inb
	case "inbound":
		s, err := c.getObj("/api/sonar64/inbound", nil)
		if err != nil {
			return nil, err
		}
		out["ready"] = boolean(s, "ready")
		rows := []any{}
		for _, e := range asArr(s["rows"]) {
			m := asObj(e)
			x := pick(m, "from", "trust", "fam", "method", "avg", "loss", "at")
			x["untrusted"] = obj{"name": clean(str(m, "name"), 120), "asname": clean(str(m, "asname"), 120), "place": clean(str(m, "place"), 120)}
			rows = append(rows, x)
			if len(rows) >= limit {
				break
			}
		}
		out["rows"] = rows
	case "settings":
		s, err := c.getObj("/api/sonar64/settings", nil)
		if err != nil {
			return nil, err
		}
		for k, v := range pick(s, "participate", "measured", "budget", "quiet", "name", "lat", "lon", "access", "device") {
			out[k] = v
		}
	}
	return out, nil
}
