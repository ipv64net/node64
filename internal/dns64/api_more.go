package dns64

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/dns64/filter"
	"github.com/ipv64net/node64/internal/dns64/upstream"
	"github.com/ipv64net/node64/internal/module"
)

// Weitere Endpunkte der lokalen API (alles, was die Oberflaeche kann) und die Logik, die Oberflaeche und API
// gemeinsam nutzen.

// importAllow uebernimmt Freigaben (eine Domain je Zeile; Kommentare und Zeitstempel werden ignoriert).
func (m *Module) importAllow(lines []string) (n, bad int, err error) {
	a, err := m.allowlist()
	if err != nil {
		return 0, 0, err
	}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if i := strings.IndexAny(line, "#\t "); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if _, err := a.Add(line); err != nil {
			bad++
			continue
		}
		n++
	}
	m.clChanged(context.Background(), ItemAllow)
	return n, bad, nil
}

func (c *config) addUpstream(s upstream.Server) error {
	for _, u := range c.Upstreams {
		if u.URL == strings.TrimSpace(s.URL) {
			return errCfg("err_up_dup")
		}
	}
	c.Upstreams = append(c.Upstreams, upstreamSetting{Server: s, Enabled: true, Custom: true})
	return nil
}

func (c *config) addList(name, url string) error {
	url, name = strings.TrimSpace(url), strings.TrimSpace(name)
	if err := checkListURL(url); err != nil {
		return err
	}
	for _, l := range c.Lists {
		if l.URL == url {
			return errCfg("err_list_dup")
		}
	}
	if name == "" {
		name = url
	}
	c.Lists = append(c.Lists, listSetting{List: filter.List{Name: name, URL: url}, Enabled: true, Custom: true})
	return nil
}

// addAllowList legt eine Freigabe-Liste an (eingeschaltet).
func (c *config) addAllowList(name, url string) error {
	url, name = strings.TrimSpace(url), strings.TrimSpace(name)
	if err := checkListURL(url); err != nil {
		return err
	}
	for _, l := range c.AllowLst {
		if l.URL == url {
			return errCfg("err_list_dup")
		}
	}
	if len(c.AllowLst) >= filter.MaxLists {
		return errCfg("err_list_max", "n", filter.MaxLists)
	}
	if name == "" {
		name = listName(url)
	}
	c.AllowLst = append(c.AllowLst, listSetting{List: filter.List{Name: name, URL: url}, Enabled: true, Custom: true})
	return nil
}

// listName: Anzeigename aus der URL (Host und letzter Pfadteil), wenn keiner angegeben ist.
func listName(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	name := strings.TrimPrefix(u.Host, "www.")
	if p := strings.Trim(u.Path, "/"); p != "" {
		if i := strings.LastIndexByte(p, '/'); i >= 0 {
			p = p[i+1:]
		}
		name += " · " + p
	}
	return name
}

// BulkResult: Ergebnis beim Eintragen mehrerer Listen auf einmal.
type BulkResult struct {
	Added      []string `json:"added"`      // URLs
	Duplicates []string `json:"duplicates"` // schon vorhanden bzw. doppelt im Text
	Invalid    []string `json:"invalid"`    // keine gueltige http(s)-URL
}

// addListsBulk traegt mehrere Listen ein: je Zeile eine URL, optional davor ein Name ("Name | URL" oder
// "Name URL"); Kommentare mit "#" am Zeilenanfang. allow = Freigabe-Listen statt Blocklisten.
func (c *config) addListsBulk(lines []string, allow bool) BulkResult {
	res := BulkResult{Added: []string{}, Duplicates: []string{}, Invalid: []string{}}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		name, u := "", line
		if i := strings.LastIndexAny(line, " \t|"); i >= 0 {
			name, u = strings.TrimSpace(strings.Trim(strings.TrimSpace(line[:i]), "|")), strings.TrimSpace(line[i+1:])
		}
		var err error
		if allow {
			err = c.addAllowList(name, u)
		} else {
			if name == "" {
				name = listName(u)
			}
			err = c.addList(name, u)
		}
		var ce *cfgError
		switch {
		case err == nil:
			res.Added = append(res.Added, u)
		case errors.As(err, &ce) && ce.Key == "err_list_dup":
			res.Duplicates = append(res.Duplicates, u)
		default:
			res.Invalid = append(res.Invalid, line)
		}
	}
	return res
}

// removeCustom entfernt einen eigenen Upstream bzw. eine eigene Liste per URL (Vorlagen lassen sich nur abschalten).
func (c *config) removeCustom(url string) bool {
	for i, u := range c.Upstreams {
		if u.URL == url && u.Custom {
			c.Upstreams = append(c.Upstreams[:i], c.Upstreams[i+1:]...)
			return true
		}
	}
	for i, l := range c.Lists {
		if l.URL == url && l.Custom {
			c.Lists = append(c.Lists[:i], c.Lists[i+1:]...)
			return true
		}
	}
	return false
}

// ---- API ----

func (m *Module) apiMoreRoutes(mux *http.ServeMux, g module.Guards) {
	plain := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("POST /api/dns64/records/{id}/enable", plain(m.apiRecordToggle(true)))
	mux.Handle("POST /api/dns64/records/{id}/disable", plain(m.apiRecordToggle(false)))
	mux.Handle("POST /api/dns64/allowlist/import", plain(m.apiAllowImport))
	mux.Handle("GET /api/dns64/ca.crt", plain(m.pageCA))
	mux.Handle("GET /api/dns64/mobileconfig", plain(m.pageProfile))
	mux.Handle("POST /api/dns64/upstreams", plain(m.apiUpstreamAdd))
	mux.Handle("DELETE /api/dns64/upstreams", plain(m.apiCustomRemove("upstream")))
	mux.Handle("POST /api/dns64/lists", plain(m.apiListAdd))
	mux.Handle("DELETE /api/dns64/lists", plain(m.apiCustomRemove("list")))
	m.apiListRoutes(mux, plain)
}

// apiSave speichert eine geaenderte Konfiguration, startet neu und antwortet mit dem neuen Stand.
func (m *Module) apiSave(w http.ResponseWriter, r *http.Request, c config, status int) {
	ctx := r.Context()
	if err := m.saveConfig(ctx, c); err != nil {
		writeErr(w, http.StatusBadRequest, m.errText(r, err))
		return
	}
	if err := m.restart(ctx); err != nil {
		writeErr(w, http.StatusConflict, m.g.T(r, "dns64.err.restart", "err", err.Error()))
		return
	}
	writeJSON(w, status, m.loadConfig(ctx))
}

func (m *Module) apiRecordToggle(on bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		err := m.SetRecordEnabled(r.Context(), id, on)
		if errors.Is(err, errNotFound) {
			writeErr(w, http.StatusNotFound, m.errText(r, err))
			return
		}
		if err != nil {
			m.fail(w, err)
			return
		}
		m.audit(r, "dns64.record."+map[bool]string{true: "enable", false: "disable"}[on], r.PathValue("id"), "")
		w.WriteHeader(http.StatusNoContent)
	}
}

func (m *Module) apiAllowImport(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Domains []string `json:"domains"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	n, bad, err := m.importAllow(in.Domains)
	if err != nil {
		m.fail(w, err)
		return
	}
	m.audit(r, "dns64.allowlist.import", strconv.Itoa(n)+" domains", strconv.Itoa(bad)+" invalid")
	writeJSON(w, http.StatusOK, map[string]int{"imported": n, "invalid": bad})
}

func (m *Module) apiUpstreamAdd(w http.ResponseWriter, r *http.Request) {
	var in upstream.Server
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	c := m.loadConfig(r.Context())
	if err := c.addUpstream(in); err != nil {
		writeErr(w, http.StatusBadRequest, m.errText(r, err))
		return
	}
	m.audit(r, "dns64.upstream.add", in.URL, "")
	m.apiSave(w, r, c, http.StatusCreated)
}

func (m *Module) apiListAdd(w http.ResponseWriter, r *http.Request) {
	m.apiListAddKind(w, r, false)
}

// apiListAddKind legt eine Liste ({name, url}) oder mehrere auf einmal ({urls: ["…", "Name | …"]}) an;
// allow = Freigabe-Listen. Bei mehreren antwortet die API mit dem Ergebnis je URL.
func (m *Module) apiListAddKind(w http.ResponseWriter, r *http.Request, allow bool) {
	var in struct {
		Name string   `json:"name"`
		URL  string   `json:"url"`
		URLs []string `json:"urls"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	kind := map[bool]string{false: "list", true: "allowlists"}[allow]
	c := m.loadConfig(r.Context())
	if len(in.URLs) > 0 {
		res := c.addListsBulk(in.URLs, allow)
		if len(res.Added) == 0 {
			writeJSON(w, http.StatusUnprocessableEntity, res)
			return
		}
		ctx := r.Context()
		if err := m.saveConfig(ctx, c); err != nil {
			writeErr(w, http.StatusBadRequest, m.errText(r, err))
			return
		}
		m.audit(r, "dns64."+kind+".add", strconv.Itoa(len(res.Added))+" lists", "")
		if err := m.restart(ctx); err != nil {
			writeErr(w, http.StatusConflict, m.g.T(r, "dns64.err.restart", "err", err.Error()))
			return
		}
		writeJSON(w, http.StatusCreated, res)
		return
	}
	var err error
	if allow {
		err = c.addAllowList(in.Name, in.URL)
	} else {
		err = c.addList(in.Name, in.URL)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, m.errText(r, err))
		return
	}
	m.audit(r, "dns64."+kind+".add", in.URL, "")
	m.apiSave(w, r, c, http.StatusCreated)
}

// apiCustomRemove entfernt einen eigenen Upstream bzw. eine eigene Liste (?url=...).
func (m *Module) apiCustomRemove(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Query().Get("url")
		c := m.loadConfig(r.Context())
		before := len(c.Upstreams) + len(c.Lists)
		if !c.removeCustom(url) || len(c.Upstreams)+len(c.Lists) == before {
			writeErr(w, http.StatusNotFound, m.errText(r, errNotFound))
			return
		}
		m.audit(r, "dns64."+kind+".remove", url, "")
		m.apiSave(w, r, c, http.StatusOK)
	}
}
