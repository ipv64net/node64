package mcp

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Healthchecks (Modul healthchecks).

func healthTools() []Tool {
	checkArg := pStr("check", "Check id (8 characters, from list_checks) or exact check name.", 200)
	return []Tool{
		{Name: "list_checks", Area: AreaHealthchecks, Title: "List health checks", Untrusted: true,
			Desc: "Health checks with current state (up/down/paused/...), last result and latency. Filter by state, group, type, tag or text.",
			Schema: schema(nil, pEnum("state", "Only checks in this state.", "", "up", "down", "pending", "paused", "degraded", "flapping", "stabilizing", "dependent"),
				pStr("group", "Only checks in this group (exact).", 100), pStr("type", "Only checks of this type (http, keyword, json, tcp, icmp, dns, cert, whois, push, ...).", 30),
				pStr("tag", "Only checks with this tag.", 60), pStr("query", "Text search in name, target and tags.", 100), pInt("limit", "Maximum number of checks.", 100, 1, 500)),
			Run: listChecks},
		{Name: "get_check", Area: AreaHealthchecks, Title: "Get health check", Untrusted: true,
			Desc:   "One health check: configuration summary, state, uptime for 24 h / 7 d / 30 d and the latest state changes.",
			Schema: schema([]string{"check"}, checkArg), Run: getCheck},
		{Name: "check_history", Area: AreaHealthchecks, Title: "Check history", Untrusted: true,
			Desc: "Measurements of a check summarized for a time range: availability, latency (avg/min/max) and a bucketed series; optionally the latest failed measurements.",
			Schema: schema([]string{"check"}, checkArg, pEnum("range", "Time range.", "24h", "1h", "24h", "7d", "30d", "1y"),
				pBool("include_failures", "Also return the latest failed measurements in the range (max 20).")),
			Run: checkHistory},
		{Name: "list_incidents", Area: AreaHealthchecks, Title: "List incidents", Untrusted: true,
			Desc: "Incidents (outages) of all checks or one check, newest first, with start, end and duration.",
			Schema: schema(nil, pStr("check", "Only incidents of this check (id or exact name).", 200), pBool("open_only", "Only incidents that are still open."),
				pInt("limit", "Maximum number of incidents.", 20, 1, 200)),
			Run: listIncidents},
		{Name: "list_maintenance", Area: AreaHealthchecks, Title: "List maintenance windows",
			Desc:   "Maintenance windows (times, repetition, affected checks, active now).",
			Schema: schema(nil, pBool("active_only", "Only windows that are active now.")), Run: listMaintenance},
	}
}

// ---------------------------------------------------------------- Checks

func (c *call) allChecks() ([]any, error) {
	if c.checks == nil {
		list, err := c.getArr("/api/checks", nil)
		if err != nil {
			return nil, err
		}
		c.checks = list
	}
	return c.checks, nil
}

// checkNames: Token -> (id, Name) fuer die Zuordnung in Ereignissen und Stoerungen.
func (c *call) checkNames() map[string][2]string {
	out := map[string][2]string{}
	list, err := c.allChecks()
	if err != nil {
		return out
	}
	for _, e := range list {
		m := asObj(e)
		out[str(m, "token")] = [2]string{shortID(str(m, "token")), str(m, "name")}
	}
	return out
}

// findCheck sucht einen Check nach Kurz-Id (genau die Id aus list_checks), ganzem Token oder genauem Namen. Kein
// beliebig langer Token-Anfang: sonst liesse sich der geheime Push-Token Zeichen fuer Zeichen erraten.
func (c *call) findCheck(ref string) (obj, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, errors.New("parameter check is required")
	}
	list, err := c.allChecks()
	if err != nil {
		return nil, err
	}
	var hits []obj
	for _, e := range list {
		m := asObj(e)
		if tok := str(m, "token"); tok != "" && (ref == tok || ref == shortID(tok)) {
			hits = append(hits, m)
		}
	}
	if len(hits) == 0 {
		for _, e := range list {
			m := asObj(e)
			if strings.EqualFold(str(m, "name"), ref) {
				hits = append(hits, m)
			}
		}
	}
	switch len(hits) {
	case 0:
		return nil, fmt.Errorf("check %q not found (use list_checks)", clean(ref, 60))
	case 1:
		return hits[0], nil
	}
	return nil, fmt.Errorf("check %q is ambiguous, use the id from list_checks", clean(ref, 60))
}

// checkOut: kompakte Darstellung eines Checks (ohne Token, Push-Adresse und Parameter).
func checkOut(m obj, full bool) obj {
	st := asObj(m["state"])
	o := obj{"id": shortID(str(m, "token")), "name": clean(str(m, "name"), 120), "type": str(m, "type"), "target": clean(str(m, "target"), 200),
		"group": clean(str(m, "group"), 80), "tags": strs(m, "tags"), "paused": boolean(m, "paused"), "critical": boolean(m, "critical"),
		"state": str(st, "state"), "since": ts(st["since"]), "last_check_at": ts(st["last_check_at"]), "last_latency_ms": round(num(st, "last_latency_ms"), 1),
		"last_reason": str(st, "last_reason"), "maintenance": boolean(st, "maintenance"), "interval_seconds": i64(m, "interval_seconds")}
	if str(m, "type") == "push" {
		delete(o, "target") // Ziel eines Push-Checks ist leer bzw. ohne Bedeutung
	}
	if boolean(st, "unchecked") {
		o["unchecked"] = true
	}
	if full {
		o["description"] = clean(str(m, "description"), 300)
		o["execution"], o["retries"], o["timeout_seconds"] = str(m, "execution"), i64(m, "retries"), num(m, "timeout_seconds")
		o["next_check_at"], o["down_since"] = ts(st["next_check_at"]), ts(st["down_since"])
		o["consecutive_fail"] = i64(st, "consecutive_fail")
		o["notify_down"], o["notify_up"] = boolean(m, "notify_down"), boolean(m, "notify_up")
		if p := str(m, "parent"); p != "" {
			o["parent_id"] = shortID(p)
		}
		if str(m, "type") == "push" {
			o["last_push_at"] = ts(st["last_push_at"])
		}
	}
	if msg := str(st, "last_message"); msg != "" {
		o["untrusted"] = obj{"last_message": clean(msg, 300)}
	}
	return o
}

func listChecks(c *call, a map[string]any) (map[string]any, error) {
	q := url.Values{}
	for _, k := range []string{"type", "state", "tag"} {
		if v := argStr(a, k); v != "" {
			q.Set(k, v)
		}
	}
	if v := argStr(a, "query"); v != "" {
		q.Set("q", v)
	}
	list, err := c.getArr("/api/checks", q)
	if err != nil {
		return nil, err
	}
	group, limit := argStr(a, "group"), argInt(a, "limit", 100, 1, 500)
	var out []any
	counts := map[string]int{}
	for _, e := range list {
		m := asObj(e)
		if group != "" && !strings.EqualFold(str(m, "group"), group) {
			continue
		}
		counts[str(asObj(m["state"]), "state")]++
		if len(out) < limit {
			out = append(out, checkOut(m, false))
		}
	}
	total := 0
	for _, n := range counts {
		total += n
	}
	return obj{"checks": out, "total": total, "by_state": counts, "truncated": total > len(out)}, nil
}

func eventOut(m obj) obj {
	o := obj{"time": ts(m["time"]), "kind": str(m, "kind"), "from": str(m, "from"), "to": str(m, "to"), "reason": str(m, "reason"),
		"duration_seconds": i64(m, "duration_seconds")}
	if boolean(m, "maintenance") {
		o["maintenance"] = true
	}
	if msg := str(m, "message"); msg != "" {
		o["untrusted"] = obj{"message": clean(msg, 300)}
	}
	return o
}

func getCheck(c *call, a map[string]any) (map[string]any, error) {
	m, err := c.findCheck(argStr(a, "check"))
	if err != nil {
		return nil, err
	}
	tok := url.PathEscape(str(m, "token"))
	cur, err := c.getObj("/api/checks/"+tok, nil)
	if err != nil {
		return nil, err
	}
	out := checkOut(cur, true)
	up := obj{}
	for _, r := range []string{"24h", "7d", "30d"} {
		if s, err := c.getObj("/api/checks/"+tok+"/stats", url.Values{"range": {r}}); err == nil && i64(s, "count") > 0 {
			up[r] = obj{"up_percent": round(num(s, "up_percent"), 2), "avg_ms": round(num(s, "avg_ms"), 1), "measurements": i64(s, "count")}
		}
	}
	out["uptime"] = up
	if evs, err := c.getArr("/api/checks/"+tok+"/events", url.Values{"limit": {"10"}}); err == nil {
		var el []any
		for _, e := range evs {
			el = append(el, eventOut(asObj(e)))
		}
		out["recent_events"] = el
	}
	return out, nil
}

func checkHistory(c *call, a map[string]any) (map[string]any, error) {
	m, err := c.findCheck(argStr(a, "check"))
	if err != nil {
		return nil, err
	}
	rng := argStr(a, "range")
	if rng == "" {
		rng = "24h"
	}
	tok := url.PathEscape(str(m, "token"))
	s, err := c.getObj("/api/checks/"+tok+"/stats", url.Values{"range": {rng}})
	if err != nil {
		return nil, err
	}
	out := obj{"check": obj{"id": shortID(str(m, "token")), "name": clean(str(m, "name"), 120)}, "range": rng, "from": ts(s["from"]), "to": ts(s["to"]),
		"measurements": i64(s, "count"), "up_count": i64(s, "up_count"), "up_percent": round(num(s, "up_percent"), 2),
		"avg_ms": round(num(s, "avg_ms"), 1), "min_ms": round(num(s, "min_ms"), 1), "max_ms": round(num(s, "max_ms"), 1), "bucket_seconds": i64(s, "bucket_seconds")}
	var series []any
	for _, e := range asArr(s["series"]) {
		b := asObj(e)
		if i64(b, "count") == 0 {
			continue
		}
		series = append(series, obj{"time": ts(b["time"]), "count": i64(b, "count"), "up_percent": round(num(b, "up_percent"), 1), "avg_ms": round(num(b, "avg_ms"), 1)})
	}
	if len(series) > 200 { // 1 Jahr: hoechstens 200 Punkte (die neuesten)
		series = series[len(series)-200:]
	}
	out["series"] = series
	if argBool(a, "include_failures") {
		from, to := parseTS(s["from"]), parseTS(s["to"])
		q := url.Values{"limit": {"1000"}}
		if from.Year() > 1 {
			q.Set("from", from.UTC().Format(time.RFC3339))
		}
		if to.Year() > 1 {
			q.Set("to", to.UTC().Add(time.Second).Format(time.RFC3339))
		}
		if list, err := c.getArr("/api/checks/"+tok+"/measurements", q); err == nil {
			var fails []any
			for _, e := range list {
				x := asObj(e)
				if str(x, "status") != "down" || boolean(x, "maintenance") {
					continue
				}
				f := obj{"time": ts(x["time"]), "reason": str(x, "reason"), "latency_ms": round(num(x, "latency_ms"), 1), "family": str(x, "family")}
				if msg := str(x, "message"); msg != "" {
					f["untrusted"] = obj{"message": clean(msg, 300)}
				}
				fails = append(fails, f)
				if len(fails) >= 20 {
					break
				}
			}
			out["latest_failures"] = fails
		}
	}
	return out, nil
}

func listIncidents(c *call, a map[string]any) (map[string]any, error) {
	limit := argInt(a, "limit", 20, 1, 200)
	path := "/api/incidents"
	if ref := argStr(a, "check"); ref != "" {
		m, err := c.findCheck(ref)
		if err != nil {
			return nil, err
		}
		path = "/api/checks/" + url.PathEscape(str(m, "token")) + "/incidents"
	}
	fetch := limit
	if argBool(a, "open_only") {
		fetch = 1000
	}
	list, err := c.getArr(path, url.Values{"limit": {strconv.Itoa(fetch)}})
	if err != nil {
		return nil, err
	}
	names := c.checkNames()
	var out []any
	for _, e := range list {
		m := asObj(e)
		if argBool(a, "open_only") && !boolean(m, "open") {
			continue
		}
		n := names[str(m, "token")]
		o := obj{"id": i64(m, "id"), "check": obj{"id": shortID(str(m, "token")), "name": clean(n[1], 120)}, "started_at": ts(m["started_at"]),
			"ended_at": ts(m["ended_at"]), "open": boolean(m, "open"), "reason": str(m, "reason")}
		start, end := parseTS(m["started_at"]), parseTS(m["ended_at"])
		if end.Year() <= 1 {
			end = time.Now()
		}
		if start.Year() > 1 {
			o["duration_seconds"] = int64(end.Sub(start).Seconds())
		}
		if msg := str(m, "message"); msg != "" {
			o["untrusted"] = obj{"message": clean(msg, 300)}
		}
		out = append(out, o)
		if len(out) >= limit {
			break
		}
	}
	return obj{"incidents": out, "count": len(out)}, nil
}

func listMaintenance(c *call, a map[string]any) (map[string]any, error) {
	list, err := c.getArr("/api/maintenance", nil)
	if err != nil {
		return nil, err
	}
	names := c.checkNames()
	var out []any
	for _, e := range list {
		m := asObj(e)
		if argBool(a, "active_only") && !boolean(m, "active") {
			continue
		}
		var checks []any
		for _, t := range strs(m, "tokens") {
			n := names[t]
			checks = append(checks, obj{"id": shortID(t), "name": clean(n[1], 120)})
		}
		o := obj{"id": i64(m, "id"), "name": clean(str(m, "name"), 120), "start_at": ts(m["start_at"]), "end_at": ts(m["end_at"]), "repeat": str(m, "repeat"),
			"repeat_until": ts(m["repeat_until"]), "active": boolean(m, "active")}
		if len(checks) == 0 {
			o["applies_to"] = "all checks"
		} else {
			o["checks"] = checks
		}
		out = append(out, o)
	}
	return obj{"maintenance": out, "count": len(out)}, nil
}
