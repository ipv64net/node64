package dns64

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/dns64/filter"
	"github.com/ipv64net/node64/internal/dns64/groups"
)

// Freigabe-Listen aus dem Netz, eigene Sperrliste als Textfeld, Dienste zum Sperren per Klick und Tags der
// Geraete in Gruppen (Seiten und lokale API).

// serviceGroup: Dienste einer Art fuer die Seite Gruppen.
type serviceGroup struct {
	Key      string // ai, social ...
	Services []filter.Service
}

func serviceGroups() []serviceGroup {
	var out []serviceGroup
	for _, g := range filter.ServiceGroups {
		sg := serviceGroup{Key: g}
		for _, s := range filter.Services {
			if s.Group == g {
				sg.Services = append(sg.Services, s)
			}
		}
		out = append(out, sg)
	}
	return out
}

// allTags: alle Tags der Geraete aller Gruppen (alphabetisch, ohne Doppelte) fuer den Filter.
func allTags(list []groups.Group) []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range list {
		for _, x := range g.Members {
			for _, t := range x.Tags {
				if k := strings.ToLower(t); !seen[k] {
					seen[k] = true
					out = append(out, t)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out
}

// ---- Seiten ----

func (m *Module) listUIRoutes(mux *http.ServeMux, page func(http.HandlerFunc) http.Handler) {
	mux.Handle("POST /dns64/allowlists", page(m.pageAllowListsSave))
	mux.Handle("POST /dns64/allowlists/add", page(m.pageAllowListAdd))
	mux.Handle("POST /dns64/allowlists/remove", page(m.pageAllowListRemove))
	mux.Handle("POST /dns64/denylist/save", page(m.pageDenySave))
	mux.Handle("POST /dns64/rules/save", page(m.pageRulesSave)) // eigene Filterregeln (rules_ui.go)
	mux.Handle("POST /dns64/groups/members/{id}/edit", page(m.pageMemberEdit))
}

func (m *Module) pageAllowListsSave(w http.ResponseWriter, r *http.Request) {
	c := m.loadConfig(r.Context())
	for i := range c.AllowLst {
		c.AllowLst[i].Enabled = r.PostFormValue("aon_"+strconv.Itoa(i)) != ""
	}
	m.apply(w, r, "/dns64/lists#freigabe-listen", c, "dns64.allowlists", "")
}

func (m *Module) pageAllowListAdd(w http.ResponseWriter, r *http.Request) {
	m.pageListAddKind(w, r, true)
}

// pageListAddKind traegt eine oder mehrere Listen aus dem Textfeld ein (eine URL je Zeile, optional "Name | URL").
func (m *Module) pageListAddKind(w http.ResponseWriter, r *http.Request, allow bool) {
	back, kind := "/dns64/lists", "dns64.list.add"
	if allow {
		back, kind = "/dns64/lists#freigabe-listen", "dns64.allowlists.add"
	}
	c := m.loadConfig(r.Context())
	lines := strings.Split(r.PostFormValue("urls"), "\n")
	if name, u := strings.TrimSpace(r.PostFormValue("name")), strings.TrimSpace(r.PostFormValue("url")); u != "" {
		lines = append(lines, name+" | "+u) // einzelnes Feld (alte Formulare, Zusatzname)
	}
	res := c.addListsBulk(lines, allow)
	if len(res.Added) == 0 {
		msg := m.g.T(r, "dns64.lists.bulk_none")
		if len(res.Duplicates) > 0 || len(res.Invalid) > 0 || len(res.Full) > 0 {
			msg += " " + m.bulkText(r, res)
		}
		m.g.Flash(w, r, "danger", msg)
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	ctx := r.Context()
	if err := m.saveConfig(ctx, c); err != nil {
		m.g.Flash(w, r, "danger", m.errText(r, err))
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	m.audit(r, kind, strings.Join(res.Added, " "), "")
	if err := m.restart(ctx); err != nil {
		m.g.Flash(w, r, "danger", m.g.T(r, "dns64.err.restart", "err", err.Error()))
	} else {
		m.g.Flash(w, r, "success", m.bulkText(r, res))
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// bulkText: "3 Listen hinzugefuegt · 1 schon vorhanden · 1 ungueltig: … · 2 nicht hinzugefuegt (hoechstens 64)".
func (m *Module) bulkText(r *http.Request, res BulkResult) string {
	parts := []string{m.g.T(r, "dns64.lists.bulk_added", "n", len(res.Added))}
	if len(res.Duplicates) > 0 {
		parts = append(parts, m.g.T(r, "dns64.lists.bulk_dup", "n", len(res.Duplicates)))
	}
	if len(res.Invalid) > 0 {
		inv := res.Invalid
		if len(inv) > 5 {
			inv = inv[:5]
		}
		parts = append(parts, m.g.T(r, "dns64.lists.bulk_invalid", "n", len(res.Invalid), "list", strings.Join(inv, ", ")))
	}
	if len(res.Full) > 0 {
		parts = append(parts, m.g.T(r, "dns64.lists.bulk_full", "n", len(res.Full), "max", filter.MaxLists))
	}
	return strings.Join(parts, " · ")
}

func (m *Module) pageAllowListRemove(w http.ResponseWriter, r *http.Request) {
	c := m.loadConfig(r.Context())
	url := ""
	if i := formInt(r, "remove"); i >= 0 && i < len(c.AllowLst) {
		url = c.AllowLst[i].URL
		c.AllowLst = append(c.AllowLst[:i], c.AllowLst[i+1:]...)
	}
	m.apply(w, r, "/dns64/lists#freigabe-listen", c, "dns64.allowlists.remove", url)
}

// replaceDeny setzt die eigene Sperrliste auf die Zeilen des Textfelds; wie beim Sperren einzelner Domains faellt
// eine gleichlautende Freigabe einer neuen Domain weg (sonst gewinnt sie und die Sperre wirkt nicht).
func (m *Module) replaceDeny(r *http.Request, lines []string) (filter.ReplaceResult, error) {
	dl, err := m.denylist()
	if err != nil {
		return filter.ReplaceResult{}, err
	}
	res, err := dl.Replace(lines)
	if err != nil {
		return res, err
	}
	if len(res.New) > 0 {
		if a, err := m.allowlist(); err == nil {
			freed := false
			for _, d := range res.New {
				if x, ok := a.Match(d); ok && x == d {
					_ = a.Remove(d)
					freed = true
				}
			}
			if freed {
				m.clChanged(r.Context(), ItemAllow)
			}
		}
		if e := m.running(); e != nil {
			e.cache.Flush() // wie apiDenyAdd
		}
	}
	m.clChanged(r.Context(), ItemDeny)
	m.audit(r, "dns64.denylist.replace", strconv.Itoa(res.Total)+" domains", "+"+strconv.Itoa(res.Added)+" -"+strconv.Itoa(res.Removed))
	return res, nil
}

func (m *Module) pageDenySave(w http.ResponseWriter, r *http.Request) {
	res, err := m.replaceDeny(r, strings.Split(r.PostFormValue("domains"), "\n"))
	switch {
	case errors.Is(err, filter.ErrInvalidDomain):
		m.g.Flash(w, r, "danger", m.g.T(r, "dns64.deny.text_invalid_all", "list", strings.Join(res.Invalid, ", ")))
	case err != nil:
		m.g.Flash(w, r, "danger", err.Error())
	default:
		msg := m.g.T(r, "dns64.deny.text_saved", "n", res.Total, "added", res.Added, "removed", res.Removed)
		if res.Duplicates > 0 {
			msg += " · " + m.g.T(r, "dns64.deny.text_dup", "n", res.Duplicates)
		}
		level := "success"
		if len(res.Invalid) > 0 {
			msg += " · " + m.g.T(r, "dns64.deny.text_invalid", "n", len(res.Invalid), "list", strings.Join(res.Invalid, ", "))
			level = "warning"
		}
		m.log.Info("denylist replaced", "domains", res.Total, "added", res.Added, "removed", res.Removed, "by", m.g.Actor(r))
		m.g.Flash(w, r, level, msg)
	}
	http.Redirect(w, r, "/dns64/lists#eigene-sperrliste", http.StatusSeeOther)
}

func (m *Module) pageMemberEdit(w http.ResponseWriter, r *http.Request) {
	x, err := m.UpdateMember(r.Context(), pathID(r), r.PostFormValue("label"), groups.SplitTags(r.PostFormValue("tags")))
	if err == nil {
		m.audit(r, "dns64.group.member.edit", strconv.FormatInt(x.GroupID, 10), x.Kind+" "+x.Value+" "+strings.Join(x.Tags, ","))
	}
	m.groupBack(w, r, err, "")
}

// ---- API ----

func (m *Module) apiListRoutes(mux *http.ServeMux, plain func(http.HandlerFunc) http.Handler) {
	mux.Handle("GET /api/dns64/allowlists", plain(m.apiAllowLists))
	mux.Handle("POST /api/dns64/allowlists", plain(func(w http.ResponseWriter, r *http.Request) { m.apiListAddKind(w, r, true) }))
	mux.Handle("DELETE /api/dns64/allowlists", plain(m.apiAllowListRemove))
	mux.Handle("PUT /api/dns64/denylist", plain(m.apiDenyReplace))
	mux.Handle("GET /api/dns64/rules", plain(m.apiRules)) // eigene Filterregeln (rules_ui.go)
	mux.Handle("PUT /api/dns64/rules", plain(m.apiRulesReplace))
	mux.Handle("GET /api/dns64/lookup", plain(m.apiLookup)) // In welcher Liste steht diese Domain?
	mux.Handle("GET /api/dns64/services", plain(m.apiServices))
	mux.Handle("PATCH /api/dns64/groups/members/{id}", plain(m.apiMemberUpdate)) // PUT kollidiert mit /groups/{id}/rules
}

// apiAllowLists: Freigabe-Listen mit Stand (Eintraege, Aktualisierung, Fehler; ohne laufenden Dienst nur die
// Einstellungen).
func (m *Module) apiAllowLists(w http.ResponseWriter, r *http.Request) {
	c := m.loadConfig(r.Context())
	type row struct {
		filter.ListStatus
		Enabled bool `json:"enabled"`
	}
	st := map[string]filter.ListStatus{}
	if e := m.running(); e != nil && e.lists.Release != nil {
		list, _ := e.lists.Release.Status()
		for _, s := range list {
			st[s.URL] = s
		}
	}
	out := []row{}
	for _, l := range c.AllowLst {
		s, ok := st[l.URL]
		if !ok {
			s = filter.ListStatus{List: l.List}
		}
		out = append(out, row{ListStatus: s, Enabled: l.Enabled})
	}
	writeJSON(w, http.StatusOK, out)
}

func (m *Module) apiAllowListRemove(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	c := m.loadConfig(r.Context())
	for i, l := range c.AllowLst {
		if l.URL == url {
			c.AllowLst = append(c.AllowLst[:i], c.AllowLst[i+1:]...)
			m.audit(r, "dns64.allowlists.remove", url, "")
			m.apiSave(w, r, c, http.StatusOK)
			return
		}
	}
	writeErr(w, http.StatusNotFound, m.errText(r, errNotFound))
}

// apiDenyReplace ersetzt die eigene Sperrliste ({"domains": ["…"]}); Antwort mit Zahlen und ungueltigen Zeilen.
func (m *Module) apiDenyReplace(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Domains []string `json:"domains"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&in); err != nil || in.Domains == nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON (domains)")
		return
	}
	res, err := m.replaceDeny(r, in.Domains)
	if errors.Is(err, filter.ErrInvalidDomain) {
		writeJSON(w, http.StatusUnprocessableEntity, res)
		return
	}
	if err != nil {
		m.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// apiServices: Dienste zum Sperren per Klick (Schluessel fuer die Kategorien einer Gruppe: "svc:<id>").
func (m *Module) apiServices(w http.ResponseWriter, r *http.Request) {
	type svc struct {
		Key string `json:"key"`
		filter.Service
	}
	out := []svc{}
	for _, s := range filter.Services {
		out = append(out, svc{filter.ServicePrefix + s.ID, s})
	}
	writeJSON(w, http.StatusOK, map[string]any{"categories": filter.GroupCategories, "groups": filter.ServiceGroups, "services": out})
}

// apiMemberUpdate aendert Bezeichnung und Tags eines Mitglieds ({"label": "…", "tags": ["…"]}; fehlende Felder
// bleiben).
func (m *Module) apiMemberUpdate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Label *string   `json:"label"`
		Tags  *[]string `json:"tags"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	id := pathID(r)
	cur, err := m.member(r, id)
	if err != nil {
		writeErr(w, http.StatusNotFound, m.errText(r, err))
		return
	}
	label, tags := cur.Label, cur.Tags
	if in.Label != nil {
		label = *in.Label
	}
	if in.Tags != nil {
		tags = *in.Tags
	}
	x, err := m.UpdateMember(r.Context(), id, label, tags)
	if errors.Is(err, errNotFound) {
		writeErr(w, http.StatusNotFound, m.errText(r, err))
		return
	}
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, m.errText(r, err))
		return
	}
	m.audit(r, "dns64.group.member.edit", strconv.FormatInt(x.GroupID, 10), x.Kind+" "+x.Value+" "+strings.Join(x.Tags, ","))
	writeJSON(w, http.StatusOK, x)
}

// member liefert ein Mitglied samt Tags.
func (m *Module) member(r *http.Request, id int64) (groups.Member, error) {
	list, err := m.Groups(r.Context())
	if err != nil {
		return groups.Member{}, err
	}
	for _, g := range list {
		for _, x := range g.Members {
			if x.ID == id {
				return x, nil
			}
		}
	}
	return groups.Member{}, errNotFound
}
