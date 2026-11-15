package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// api_reference: Wegweiser zur REST-API der Node. MCP selbst aendert nichts; die KI erfaehrt hier aus der
// mitgelieferten API-Beschreibung (GET /api/openapi.json), welcher Endpunkt mit welchen Parametern und Feldern eine
// Aenderung macht. Bereich AreaAll: jeder Schluessel sieht das Werkzeug - es liest keine Daten der Node, nur die
// Beschreibung, die auch im oeffentlichen Repo steht.

func apiRefTools() []Tool {
	return []Tool{
		{Name: "api_reference", Area: AreaAll, Title: "REST API reference",
			Desc: "How to change things on this node: MCP is read-only, changes go through the node's REST API under /api with an API key of the node (not the MCP key). " +
				"Without tag: the modules (tags) of the API with their number of operations and how to authenticate. With tag (node, certs, cluster, link, healthchecks, notifications, dyndns, dns64, proxy64, honeypot, sonar64, monitor64) and/or search: the operations in short form " +
				"(method, path, summary, parameters, request body fields; * = required). With path (e.g. /api/dyndns/targets/{id}): full details of the operations on that path including field types, allowed values and descriptions.",
			Schema: schema(nil, pStr("tag", "Module of the API (see description); empty = overview.", 40), pStr("search", "Only operations whose path, summary or description contains this text.", 100),
				pEnum("method", "Only this HTTP method.", "", "GET", "POST", "PUT", "PATCH", "DELETE"), pStr("path", "Exact path of one endpoint for full details, with or without /api prefix.", 200),
				pInt("limit", "Maximum number of operations.", 60, 1, 200)),
			Run: apiReference},
	}
}

// apiTagAlias: kurze Namen fuer die (deutschen) Tags der API-Beschreibung.
var apiTagAlias = map[string]string{
	"node": "Node", "certs": "Ports & Zertifikate", "certificates": "Ports & Zertifikate", "ports": "Ports & Zertifikate", "cluster": "Cluster",
	"link": "Verknüpfung", "sync": "Verknüpfung", "healthchecks": "Healthchecks", "notifications": "Benachrichtigungen", "channels": "Benachrichtigungen",
	"dyndns": "DynDNS", "dns64": "DNS64", "dhcp": "DNS64", "proxy64": "PROXY64", "cdn64": "PROXY64", "honeypot": "Honeypot64", "honeypot64": "Honeypot64",
	"sonar64": "Sonar64", "monitor64": "Monitor64",
}

var apiMethods = []string{"get", "post", "put", "patch", "delete"}

// openAPI ist der benutzte Teil der Beschreibung.
type openAPI struct {
	Servers []struct {
		URL string `json:"url"`
	} `json:"servers"`
	Tags []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"tags"`
	Components struct {
		Schemas         map[string]any `json:"schemas"`
		SecuritySchemes map[string]any `json:"securitySchemes"`
	} `json:"components"`
	Paths map[string]map[string]json.RawMessage `json:"paths"`
}

type apiOp struct {
	Tags        []string         `json:"tags"`
	Summary     string           `json:"summary"`
	Description string           `json:"description"`
	Parameters  []map[string]any `json:"parameters"`
	RequestBody map[string]any   `json:"requestBody"`
	Responses   map[string]any   `json:"responses"`
}

// docCache haelt die geparste API-Beschreibung: openapi.json (rund 1 MB) aendert sich zur Laufzeit nicht, ohne Cache
// wurde sie bei jedem Aufruf von api_reference geladen und vollstaendig geparst. Gelesen wird sie nur (resolve kopiert,
// bevor es aendert).
type docCache struct {
	mu sync.Mutex
	d  *openAPI
}

func (c *call) openAPI() (*openAPI, error) {
	if dc := c.o.doc; dc != nil {
		dc.mu.Lock()
		defer dc.mu.Unlock()
		if dc.d != nil {
			return dc.d, nil
		}
		d, err := c.loadOpenAPI()
		if err == nil {
			dc.d = d
		}
		return d, err
	}
	return c.loadOpenAPI()
}

func (c *call) loadOpenAPI() (*openAPI, error) {
	status, body, err := c.o.Backend.Get(c.ctx, c.id, "/api/openapi.json", nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, &apiError{Status: status, Msg: "API description not available"}
	}
	var d openAPI
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, errors.New("invalid API description")
	}
	return &d, nil
}

// resolve folgt $ref (nur #/components/schemas/...) und fuegt allOf zusammen.
func (d *openAPI) resolve(s any, depth int) obj {
	m := asObj(s)
	if m == nil || depth > 8 {
		return m
	}
	if ref, ok := m["$ref"].(string); ok {
		name, ok := strings.CutPrefix(ref, "#/components/schemas/")
		if !ok {
			return obj{}
		}
		r := d.resolve(d.Components.Schemas[name], depth+1)
		if desc, ok := m["description"].(string); ok && r != nil { // Beschreibung am Verweis gilt vor der des Schemas
			r = copyObj(r)
			r["description"] = desc
		}
		return r
	}
	if all, ok := m["allOf"].([]any); ok {
		out := copyObj(m)
		delete(out, "allOf")
		props, req := obj{}, []any{}
		for k, v := range asObj(m["properties"]) {
			props[k] = v
		}
		req = append(req, asArr(m["required"])...)
		for _, part := range all {
			p := d.resolve(part, depth+1)
			for k, v := range asObj(p["properties"]) {
				props[k] = v
			}
			req = append(req, asArr(p["required"])...)
			for _, k := range []string{"type", "items", "description", "enum"} {
				if _, has := out[k]; !has && p[k] != nil {
					out[k] = p[k]
				}
			}
		}
		if len(props) > 0 {
			out["properties"], out["type"] = props, "object"
		}
		if len(req) > 0 {
			out["required"] = req
		}
		return out
	}
	return m
}

func copyObj(m obj) obj {
	out := make(obj, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// typeOf: Kurzform des Typs eines Felds (string, integer, array of object, string|null ...).
func (d *openAPI) typeOf(s any) string {
	m := d.resolve(s, 0)
	if m == nil {
		return ""
	}
	if one := asArr(m["oneOf"]); len(one) > 0 {
		var ts []string
		for _, x := range one {
			ts = append(ts, d.typeOf(x))
		}
		return strings.Join(ts, "|")
	}
	var t string
	switch x := m["type"].(type) {
	case string:
		t = x
	case []any:
		var ts []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				ts = append(ts, s)
			}
		}
		t = strings.Join(ts, "|")
	}
	if t == "array" {
		return "array of " + d.typeOf(m["items"])
	}
	if t == "" && m["properties"] != nil {
		t = "object"
	}
	return t
}

func enumOf(m obj) []any {
	e := asArr(m["enum"])
	if len(e) > 12 {
		e = append(e[:12:12], "…")
	}
	return e
}

// bodyFields: Felder des JSON-Rumpfs; short = nur Namen ("name*" = Pflicht), sonst mit Typ, Werten, Beschreibung.
func (d *openAPI) bodyFields(rb map[string]any, short bool) (string, []any, any) {
	if rb == nil {
		return "", nil, nil
	}
	content := asObj(rb["content"])
	ct := "application/json"
	sch := asObj(content[ct])["schema"]
	if sch == nil {
		for k, v := range content { // z. B. text/plain oder multipart
			ct, sch = k, asObj(v)["schema"]
			break
		}
	}
	m := d.resolve(sch, 0)
	kind := ""
	if d.typeOf(m) != "object" && asObj(m["properties"]) == nil {
		if it := d.resolve(m["items"], 0); m["type"] == "array" && asObj(it["properties"]) != nil {
			kind, m = "array of objects with", it
		} else {
			return ct, nil, obj{"type": d.typeOf(m), "description": clean(str(m, "description"), 300)}
		}
	}
	req := map[string]bool{}
	for _, r := range asArr(m["required"]) {
		if s, ok := r.(string); ok {
			req[s] = true
		}
	}
	props := asObj(m["properties"])
	names := make([]string, 0, len(props))
	for k := range props {
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool { // Pflichtfelder zuerst
		if req[names[i]] != req[names[j]] {
			return req[names[i]]
		}
		return names[i] < names[j]
	})
	var short1 []string
	var full []any
	for _, n := range names {
		p := d.resolve(props[n], 0)
		if b, _ := p["readOnly"].(bool); b {
			continue
		}
		if short {
			if req[n] {
				short1 = append(short1, n+"*")
			} else {
				short1 = append(short1, n)
			}
			continue
		}
		f := obj{"name": n, "type": d.typeOf(p), "required": req[n]}
		if e := enumOf(p); len(e) > 0 {
			f["enum"] = e
		}
		if desc := str(p, "description"); desc != "" {
			f["description"] = clean(desc, 300)
		}
		if p["default"] != nil {
			f["default"] = p["default"]
		}
		if sub := asObj(p["properties"]); len(sub) > 0 { // verschachteltes Objekt: Namen der Felder
			var sn []string
			for k := range sub {
				sn = append(sn, k)
			}
			sort.Strings(sn)
			f["fields"] = sn
		} else if it := d.resolve(p["items"], 0); len(asObj(it["properties"])) > 0 {
			var sn []string
			for k := range asObj(it["properties"]) {
				sn = append(sn, k)
			}
			sort.Strings(sn)
			f["item_fields"] = sn
		}
		full = append(full, f)
	}
	if short {
		s := strings.Join(short1, ", ")
		if kind != "" {
			s = kind + ": " + s
		}
		return ct, nil, s
	}
	var out any = full
	if kind != "" {
		out = obj{"kind": kind, "fields": full}
	}
	return ct, full, out
}

// params: Parameter einer Operation (Pfad-Ebene und Operation).
func paramsOf(pathParams, opParams []map[string]any, short bool) []any {
	var out []any
	seen := map[string]bool{}
	for _, list := range [][]map[string]any{opParams, pathParams} {
		for _, p := range list {
			name, in := str(p, "name"), str(p, "in")
			if seen[in+":"+name] {
				continue
			}
			seen[in+":"+name] = true
			req, _ := p["required"].(bool)
			if short {
				s := name + " (" + in
				if req {
					s += ", required"
				}
				out = append(out, s+")")
				continue
			}
			x := obj{"name": name, "in": in, "required": req}
			sch := asObj(p["schema"])
			if t := str(sch, "type"); t != "" {
				x["type"] = t
			}
			if e := enumOf(sch); len(e) > 0 {
				x["enum"] = e
			}
			if desc := str(p, "description"); desc != "" {
				x["description"] = clean(desc, 200)
			}
			out = append(out, x)
		}
	}
	return out
}

// tagOf: Tag der API zu einem Namen (Kurzname, genauer Tag oder Teil davon).
func (d *openAPI) tagOf(s string) (string, error) {
	if t, ok := apiTagAlias[strings.ToLower(s)]; ok {
		return t, nil
	}
	for _, t := range d.Tags {
		if strings.EqualFold(t.Name, s) {
			return t.Name, nil
		}
	}
	for _, t := range d.Tags {
		if strings.Contains(strings.ToLower(t.Name), strings.ToLower(s)) {
			return t.Name, nil
		}
	}
	return "", fmt.Errorf("unknown tag %q (call api_reference without tag for the list)", clean(s, 40))
}

func apiReference(c *call, a map[string]any) (map[string]any, error) {
	d, err := c.openAPI()
	if err != nil {
		return nil, err
	}
	base := "/api"
	if len(d.Servers) > 0 { // die Node setzt beim Ausliefern Schema und Host davor; gebraucht wird nur der Pfad
		if u, err := url.Parse(d.Servers[0].URL); err == nil && u.Path != "" {
			base = strings.TrimSuffix(u.Path, "/")
		}
	}
	auth := obj{"base_path": base, "header": "Authorization", "value_format": "Bearer + API key of the node (Settings > API keys, prefix node64_)",
		"note": "The MCP key (mcp64_) is not accepted by /api. Send JSON with Content-Type: application/json. Ids shown by MCP tools can be shortened (check ids are the first 8 characters of the token): read full ids via the REST API (e.g. GET /api/checks) before changing something. Confirm changes with the user first."}
	for name, sc := range d.Components.SecuritySchemes {
		m := asObj(sc)
		auth["scheme"] = obj{"name": name, "type": str(m, "type"), "scheme": str(m, "scheme"), "description": clean(str(m, "description"), 200)}
	}
	tagArg, search, method := argStr(a, "tag"), strings.ToLower(argStr(a, "search")), strings.ToLower(argStr(a, "method"))
	path := argStr(a, "path")
	if path != "" && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	path = strings.TrimPrefix(path, base)
	limit := argInt(a, "limit", 60, 1, 200)
	if tagArg == "" && search == "" && path == "" { // Ueberblick
		counts := map[string]int{}
		for _, ops := range d.Paths {
			for _, mth := range apiMethods {
				var op apiOp
				if raw, ok := ops[mth]; ok && json.Unmarshal(raw, &op) == nil && len(op.Tags) > 0 {
					counts[op.Tags[0]]++
				}
			}
		}
		alias := map[string][]string{}
		for k, v := range apiTagAlias {
			alias[v] = append(alias[v], k)
		}
		tags := []any{}
		for _, t := range d.Tags {
			sort.Strings(alias[t.Name])
			tags = append(tags, obj{"tag": t.Name, "use": alias[t.Name], "operations": counts[t.Name]})
		}
		return obj{"auth": auth, "tags": tags, "hint": "Call api_reference with tag (or search) for the operations, then with path for the request body details."}, nil
	}
	tag := ""
	if tagArg != "" {
		if tag, err = d.tagOf(tagArg); err != nil {
			return nil, err
		}
	}
	paths := make([]string, 0, len(d.Paths))
	for p := range d.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	detail := path != ""
	ops := []any{}
	total := 0
	for _, p := range paths {
		if detail && p != path {
			continue
		}
		raw := d.Paths[p]
		var pathParams []map[string]any
		if pp, ok := raw["parameters"]; ok {
			_ = json.Unmarshal(pp, &pathParams)
		}
		for _, mth := range apiMethods {
			r, ok := raw[mth]
			if !ok || (method != "" && method != mth) {
				continue
			}
			var op apiOp
			if json.Unmarshal(r, &op) != nil {
				continue
			}
			if tag != "" && !containsStr(op.Tags, tag) {
				continue
			}
			if search != "" && !strings.Contains(strings.ToLower(p+" "+op.Summary+" "+op.Description), search) {
				continue
			}
			total++
			if len(ops) >= limit {
				continue
			}
			x := obj{"method": strings.ToUpper(mth), "path": base + p, "summary": clean(op.Summary, 300)}
			if pr := paramsOf(pathParams, op.Parameters, !detail); len(pr) > 0 {
				x["params"] = pr
			}
			ct, _, body := d.bodyFields(op.RequestBody, !detail)
			if body != nil && body != "" {
				x["body"] = body
				if ct != "application/json" {
					x["content_type"] = ct
				}
			}
			if detail {
				if op.Description != "" {
					x["description"] = clean(op.Description, 1500)
				}
				x["responses"] = d.responsesOf(op.Responses)
			}
			ops = append(ops, x)
		}
	}
	if detail && total == 0 {
		return nil, fmt.Errorf("no operation for path %q (use tag or search to find the path)", clean(path, 100))
	}
	res := obj{"auth": auth, "operations": ops, "count": len(ops), "total": total}
	if tag != "" {
		res["tag"] = tag
	}
	if total > len(ops) {
		res["truncated"] = true
		res["hint"] = "More operations match: narrow with search or method, or raise limit."
	}
	return res, nil
}

// responsesOf: Status mit Beschreibung und, fuer Erfolge, den Feldern der Antwort (oberste Ebene).
func (d *openAPI) responsesOf(rs map[string]any) []any {
	codes := make([]string, 0, len(rs))
	for k := range rs {
		codes = append(codes, k)
	}
	sort.Strings(codes)
	var out []any
	for _, code := range codes {
		r := asObj(rs[code])
		x := obj{"status": code, "description": clean(str(r, "description"), 200)}
		if strings.HasPrefix(code, "2") {
			m := d.resolve(asObj(asObj(r["content"])["application/json"])["schema"], 0)
			if str(m, "type") == "array" {
				m = d.resolve(m["items"], 0)
				x["array"] = true
			}
			var names []string
			for k := range asObj(m["properties"]) {
				names = append(names, k)
			}
			sort.Strings(names)
			if len(names) > 0 {
				x["fields"] = names
			}
		}
		out = append(out, x)
	}
	return out
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
