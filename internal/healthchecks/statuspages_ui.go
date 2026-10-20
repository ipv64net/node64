package healthchecks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Statusseiten: Verwaltung (Liste, Formular mit Gruppen und Eintraegen, Ankuendigungen, Vorschau).
// Das Formular kommt ohne JavaScript aus: Gruppen und Eintraege stehen als Felder im Formular, Knoepfe mit
// name="op" aendern den Stand und zeigen das Formular erneut (gespeichert wird erst mit "Speichern").
// statuspages.js schlaegt nur den Slug vor und filtert die Auswahl der Checks.

const statusPagesPath = "/healthchecks/status-pages"

type statusPageRow struct {
	*StatusPage
	Items   int
	Open    int    // offene Ankuendigungen
	URL     string // oeffentlich auf dem Node-Port (nur eingeschaltet + veroeffentlicht)
	Preview string
}

type statusPagesData struct {
	Pages []statusPageRow
}

// statusCheckOpt ist ein Check in der Auswahl.
type statusCheckOpt struct {
	Token  string
	Name   string
	Tags   string // durch Komma getrennt (Filter)
	Group  string // Healthchecks-Gruppe
	Paused bool
	OnPage bool // schon auf der Seite
}

type statusFormData struct {
	Page     *StatusPage
	Edit     bool
	Dirty    bool // Gruppen/Eintraege geaendert, noch nicht gespeichert
	Errors   map[string]string
	Error    string
	Checks   []statusCheckOpt
	Names    map[string]string // Token -> Name des Checks ("" = geloescht)
	Tags     []string
	HCGroups []string
	AddTo    int
	Layouts  []string
	Themes   []string
	DaysOpts []int
	Items    int
}

// Crumb: letzte Stufe der Brotkrumen.
func (d statusFormData) Crumb() string {
	if d.Edit && d.Page != nil {
		return d.Page.Title
	}
	return ""
}

type statusNoticesData struct {
	Page     *StatusPage
	Open     []StatusNotice
	Resolved []StatusNotice
	Form     map[string]string
	Error    string
}

func (d statusNoticesData) Crumb() string { return d.Page.Title }

func (m *Module) statusPagesRoutes(mux *http.ServeMux, page func(http.HandlerFunc) http.Handler) {
	mux.Handle("GET "+statusPagesPath, page(m.pageStatusPages))
	mux.Handle("GET "+statusPagesPath+"/new", page(m.pageStatusForm))
	mux.Handle("POST "+statusPagesPath+"/new", page(m.pageStatusSave))
	mux.Handle("GET "+statusPagesPath+"/{id}/edit", page(m.pageStatusForm))
	mux.Handle("POST "+statusPagesPath+"/{id}/edit", page(m.pageStatusSave))
	mux.Handle("POST "+statusPagesPath+"/{id}/delete", page(m.pageStatusDelete))
	// Vorschau (auch ausgeschaltete Seiten); Unterpfade (z. B. status.json, Details) reicht statusPreview selbst weiter
	mux.Handle("GET "+statusPagesPath+"/{id}/preview", page(m.pageStatusPreview))
	mux.Handle("GET "+statusPagesPath+"/{id}/preview/{rest...}", page(m.pageStatusPreview))
	mux.Handle("GET "+statusPagesPath+"/{id}/notices", page(m.pageStatusNotices))
	mux.Handle("POST "+statusPagesPath+"/{id}/notices", page(m.pageStatusNoticeAdd))
	mux.Handle("POST "+statusPagesPath+"/{id}/notices/{nid}/update", page(m.pageStatusNoticeUpdate))
	mux.Handle("POST "+statusPagesPath+"/{id}/notices/{nid}/delete", page(m.pageStatusNoticeDelete))
}

// ---------------------------------------------------------------- Liste

func (m *Module) pageStatusPages(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	list, err := m.st.StatusPages(ctx)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	items, open := m.statusCounts(ctx)
	d := statusPagesData{}
	for _, p := range list {
		row := statusPageRow{StatusPage: p, Items: items[p.ID], Open: open[p.ID], Preview: statusPagesPath + "/" + strconv.FormatInt(p.ID, 10) + "/preview"}
		if p.Enabled && p.PublishNode {
			row.URL = "/status/" + p.Slug
		}
		d.Pages = append(d.Pages, row)
	}
	m.g.Render(w, r, http.StatusOK, Name+"/status_pages", "nav.status_pages", d)
}

// statusCounts: Eintraege und offene Ankuendigungen je Seite.
func (m *Module) statusCounts(ctx context.Context) (items, open map[int64]int) {
	items, open = map[int64]int{}, map[int64]int{}
	for _, q := range []struct {
		sql string
		out map[int64]int
	}{
		{`SELECT g.page_id, COUNT(i.id) FROM hc_status_groups g JOIN hc_status_items i ON i.group_id = g.id GROUP BY g.page_id`, items},
		{`SELECT page_id, COUNT(*) FROM hc_status_notices WHERE resolved_at = '' GROUP BY page_id`, open},
	} {
		rows, err := m.st.r.QueryContext(ctx, q.sql)
		if err != nil {
			continue
		}
		for rows.Next() {
			var id int64
			var n int
			if rows.Scan(&id, &n) == nil {
				q.out[id] = n
			}
		}
		rows.Close()
	}
	return items, open
}

// ---------------------------------------------------------------- Formular

// newStatusPage: Standardwerte einer neuen Seite (wie in der Migration).
func newStatusPage() *StatusPage {
	return &StatusPage{Layout: "list", Theme: "auto", Days: 90, ShowUptime: true, ShowHistory: true, RefreshSec: 60, NoIndex: true, PoweredBy: true,
		Groups: []StatusGroup{}}
}

// loadStatusPage liest die Seite aus dem Pfad ({id}); nil = schon beantwortet (404/500).
func (m *Module) loadStatusPage(w http.ResponseWriter, r *http.Request) *StatusPage {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	p, err := m.st.StatusPage(r.Context(), id)
	if errors.Is(err, ErrStatusPageNotFound) {
		m.g.Render(w, r, http.StatusNotFound, Name+"/missing", "hc.missing", nil)
		return nil
	}
	if err != nil {
		m.fail(w, r, err)
		return nil
	}
	return p
}

func (m *Module) pageStatusForm(w http.ResponseWriter, r *http.Request) {
	p := newStatusPage()
	edit := r.PathValue("id") != ""
	if edit {
		if p = m.loadStatusPage(w, r); p == nil {
			return
		}
	}
	m.renderStatusForm(w, r, http.StatusOK, statusFormData{Page: p, Edit: edit})
}

func (m *Module) renderStatusForm(w http.ResponseWriter, r *http.Request, status int, d statusFormData) {
	d.Layouts, d.Themes, d.DaysOpts = []string{"list", "tiles", "compact"}, []string{"auto", "light", "dark"}, []int{30, 60, 90}
	d.Names = map[string]string{}
	on := map[string]bool{}
	for _, g := range d.Page.Groups {
		for _, it := range g.Items {
			on[it.Token] = true
			d.Items++
		}
	}
	tags, groups := map[string]bool{}, map[string]bool{}
	if list, err := m.st.Checks(r.Context()); err == nil {
		for _, c := range list {
			d.Names[c.Token] = c.Name
			d.Checks = append(d.Checks, statusCheckOpt{Token: c.Token, Name: c.Name, Tags: strings.Join(c.Tags, ","), Group: c.Group, Paused: c.Paused, OnPage: on[c.Token]})
			for _, t := range c.Tags {
				tags[t] = true
			}
			if c.Group != "" {
				groups[c.Group] = true
			}
		}
	}
	sort.Slice(d.Checks, func(i, j int) bool { return strings.ToLower(d.Checks[i].Name) < strings.ToLower(d.Checks[j].Name) })
	d.Tags, d.HCGroups = sortedKeys(tags), sortedKeys(groups)
	if d.AddTo < 0 || d.AddTo >= len(d.Page.Groups) {
		d.AddTo = 0
	}
	title := "hc.status.new"
	if d.Edit {
		title = "hc.status.edit"
	}
	m.g.Render(w, r, status, Name+"/status_page_form", title, d)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out
}

// statusPageFromForm uebernimmt die Felder des Formulars in p (Gruppen und Eintraege in der Reihenfolge des Formulars).
func statusPageFromForm(r *http.Request, p *StatusPage) {
	v := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	on := func(k string) bool { return r.PostFormValue(k) == "on" }
	p.Title, p.Slug = v("title"), strings.ToLower(v("slug"))
	p.Description, p.Footer = strings.TrimSpace(r.PostFormValue("description")), strings.TrimSpace(r.PostFormValue("footer"))
	p.Enabled, p.PublishNode, p.ShowUptime, p.ShowHistory, p.NoIndex, p.PoweredBy = on("enabled"), on("publish_node"), on("show_uptime"), on("show_history"), on("noindex"), on("powered_by")
	p.Layout, p.Theme, p.Lang = v("layout"), v("theme"), v("lang")
	p.Accent = ""
	if on("accent_on") {
		p.Accent = v("accent")
	}
	p.Days, _ = strconv.Atoi(v("days"))
	if n, err := strconv.Atoi(v("refresh_sec")); err == nil {
		p.RefreshSec = n
	}
	names := r.PostForm["gr_name"]
	p.Groups = make([]StatusGroup, len(names))
	for i, n := range names {
		p.Groups[i] = StatusGroup{Name: strings.TrimSpace(n), Items: []StatusItem{}}
	}
	gs, toks, lbls := r.PostForm["it_g"], r.PostForm["it_tok"], r.PostForm["it_lbl"]
	for i, tok := range toks {
		if i >= len(gs) || i >= len(lbls) || tok == "" {
			continue
		}
		gi, err := strconv.Atoi(gs[i])
		if err != nil || gi < 0 || gi >= len(p.Groups) {
			continue
		}
		p.Groups[gi].Items = append(p.Groups[gi].Items, StatusItem{Token: tok, Label: strings.TrimSpace(lbls[i])})
	}
}

// statusFormOp wendet einen Knopf des Formulars auf die Gruppen und Eintraege an (ohne zu speichern).
func (m *Module) statusFormOp(ctx context.Context, r *http.Request, p *StatusPage, op string) {
	parts := strings.Split(op, "-")
	num := func(i int) int {
		if i >= len(parts) {
			return -1
		}
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return -1
		}
		return n
	}
	gi := num(1)
	okG := gi >= 0 && gi < len(p.Groups)
	switch parts[0] {
	case "gadd":
		p.Groups = append(p.Groups, StatusGroup{Name: strings.TrimSpace(r.PostFormValue("new_group")), Items: []StatusItem{}})
	case "gup":
		if okG && gi > 0 {
			p.Groups[gi-1], p.Groups[gi] = p.Groups[gi], p.Groups[gi-1]
		}
	case "gdown":
		if okG && gi < len(p.Groups)-1 {
			p.Groups[gi+1], p.Groups[gi] = p.Groups[gi], p.Groups[gi+1]
		}
	case "gdel":
		if okG {
			p.Groups = append(p.Groups[:gi], p.Groups[gi+1:]...)
		}
	case "gsort":
		if okG {
			names := m.checkNames(ctx)
			label := func(it StatusItem) string {
				if it.Label != "" {
					return strings.ToLower(it.Label)
				}
				return strings.ToLower(names[it.Token])
			}
			items := p.Groups[gi].Items
			sort.SliceStable(items, func(a, b int) bool { return label(items[a]) < label(items[b]) })
		}
	case "iup", "idown", "idel":
		if !okG {
			return
		}
		items, ii := p.Groups[gi].Items, num(2)
		if ii < 0 || ii >= len(items) {
			return
		}
		switch {
		case parts[0] == "iup" && ii > 0:
			items[ii-1], items[ii] = items[ii], items[ii-1]
		case parts[0] == "idown" && ii < len(items)-1:
			items[ii+1], items[ii] = items[ii], items[ii+1]
		case parts[0] == "idel":
			p.Groups[gi].Items = append(items[:ii], items[ii+1:]...)
		}
	case "add", "addtag", "addhcg":
		list, err := m.st.Checks(ctx)
		if err != nil {
			return
		}
		want := map[string]bool{}
		for _, t := range r.PostForm["add_tok"] {
			want[t] = true
		}
		tag, hcg := r.PostFormValue("add_tag"), r.PostFormValue("add_hcg")
		var toks []string
		for _, c := range list {
			switch {
			case parts[0] == "add" && want[c.Token]:
			case parts[0] == "addtag" && tag != "" && containsStr(c.Tags, tag):
			case parts[0] == "addhcg" && hcg != "" && c.Group == hcg:
			default:
				continue
			}
			toks = append(toks, c.Token)
		}
		if len(toks) == 0 {
			return
		}
		if len(p.Groups) == 0 {
			p.Groups = append(p.Groups, StatusGroup{Items: []StatusItem{}})
		}
		to, _ := strconv.Atoi(r.PostFormValue("add_to"))
		if to < 0 || to >= len(p.Groups) {
			to = 0
		}
		g := &p.Groups[to]
		has := map[string]bool{}
		for _, it := range g.Items {
			has[it.Token] = true
		}
		for _, t := range toks {
			if !has[t] {
				g.Items, has[t] = append(g.Items, StatusItem{Token: t}), true
			}
		}
	}
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (m *Module) checkNames(ctx context.Context) map[string]string {
	out := map[string]string{}
	if list, err := m.st.Checks(ctx); err == nil {
		for _, c := range list {
			out[c.Token] = c.Name
		}
	}
	return out
}

// statusPasswordArg macht aus der Eingabe das Argument fuer SaveStatusPage: "" = unveraendert, "-" = entfernen,
// sonst bcrypt-Hash (Kosten wie bei PROXY64).
func statusPasswordArg(pw string) (string, error) {
	switch {
	case pw == "" || pw == "-":
		return pw, nil
	case len(pw) < 4 || len(pw) > 72:
		return "", fieldErr("password", "hc.status.err.password")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// statusSlugSuggest macht aus dem Titel einen Slug (a-z0-9-); ist er zu kurz, ein zufaelliger.
func statusSlugSuggest(title string) string {
	s := strings.NewReplacer("ä", "ae", "ö", "oe", "ü", "ue", "ß", "ss", "Ä", "ae", "Ö", "oe", "Ü", "ue").Replace(strings.ToLower(title))
	var b strings.Builder
	dash := false
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 50 {
		out = strings.Trim(out[:50], "-")
	}
	if len(out) < 2 || out == "assets" {
		buf := make([]byte, 3)
		_, _ = rand.Read(buf)
		out = "status-" + hex.EncodeToString(buf)
	}
	return out
}

// statusAutoSlug setzt bei leerem Slug einen Vorschlag aus dem Titel, der noch frei ist.
func (m *Module) statusAutoSlug(ctx context.Context, p *StatusPage) {
	if strings.TrimSpace(p.Slug) != "" {
		return
	}
	base := statusSlugSuggest(p.Title)
	p.Slug = base
	for i := 2; i < 50; i++ {
		var n int
		if m.st.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM hc_status_pages WHERE slug = ? AND id <> ?`, p.Slug, p.ID).Scan(&n) != nil || n == 0 {
			return
		}
		p.Slug = base + "-" + strconv.Itoa(i)
	}
}

// saveStatusPage prueft das Passwort, setzt bei Bedarf den Slug und speichert (Formular und API).
func (m *Module) saveStatusPage(ctx context.Context, p *StatusPage) error {
	hash, err := statusPasswordArg(p.Password)
	p.Password = ""
	if err != nil {
		return err
	}
	m.statusAutoSlug(ctx, p)
	return m.st.SaveStatusPage(ctx, p, hash)
}

func (m *Module) pageStatusSave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_ = r.ParseForm()
	p := newStatusPage()
	edit := r.PathValue("id") != ""
	if edit {
		if p = m.loadStatusPage(w, r); p == nil {
			return
		}
	}
	statusPageFromForm(r, p)
	d := statusFormData{Page: p, Edit: edit}
	d.AddTo, _ = strconv.Atoi(r.PostFormValue("add_to"))
	if op := r.PostFormValue("op"); op != "" && op != "save" {
		m.statusFormOp(ctx, r, p, op)
		d.Dirty = true
		if strings.HasPrefix(op, "gadd") {
			d.AddTo = len(p.Groups) - 1
		}
		m.renderStatusForm(w, r, http.StatusOK, d)
		return
	}
	switch {
	case r.PostFormValue("password_remove") == "on":
		p.Password = "-"
	default:
		p.Password = r.PostFormValue("password")
	}
	if err := m.saveStatusPage(ctx, p); err != nil {
		var fe *StatusFieldError
		if !errors.As(err, &fe) {
			m.fail(w, r, err)
			return
		}
		d.Errors = map[string]string{fe.Field: m.g.T(r, fe.Key)}
		d.Error = m.g.T(r, fe.Key)
		d.Dirty = true
		m.renderStatusForm(w, r, http.StatusUnprocessableEntity, d)
		return
	}
	m.auditText(r, map[bool]string{true: "status_page.update", false: "status_page.create"}[edit], p.Title+" ("+p.Slug+")")
	m.g.Flash(w, r, "success", m.g.T(r, "common.saved"))
	http.Redirect(w, r, statusPagesPath+"/"+strconv.FormatInt(p.ID, 10)+"/edit", http.StatusSeeOther)
}

func (m *Module) pageStatusDelete(w http.ResponseWriter, r *http.Request) {
	p := m.loadStatusPage(w, r)
	if p == nil {
		return
	}
	if err := m.st.DeleteStatusPage(r.Context(), p.ID); err != nil {
		m.fail(w, r, err)
		return
	}
	m.auditText(r, "status_page.delete", p.Title+" ("+p.Slug+")")
	m.g.Flash(w, r, "success", m.g.T(r, "hc.status.deleted"))
	http.Redirect(w, r, statusPagesPath, http.StatusSeeOther)
}

func (m *Module) pageStatusPreview(w http.ResponseWriter, r *http.Request) {
	if p := m.loadStatusPage(w, r); p != nil {
		m.statusPreview(w, r, p)
	}
}

// ---------------------------------------------------------------- Ankuendigungen

// noticePage liefert die Seite einer Ankuendigung (0 = unbekannt).
func (m *Module) noticePage(ctx context.Context, nid int64) int64 {
	var pid int64
	_ = m.st.r.QueryRowContext(ctx, `SELECT page_id FROM hc_status_notices WHERE id = ?`, nid).Scan(&pid)
	return pid
}

func (m *Module) pageStatusNotices(w http.ResponseWriter, r *http.Request) {
	p := m.loadStatusPage(w, r)
	if p == nil {
		return
	}
	m.renderStatusNotices(w, r, http.StatusOK, statusNoticesData{Page: p, Form: map[string]string{"level": "info"}})
}

func (m *Module) renderStatusNotices(w http.ResponseWriter, r *http.Request, status int, d statusNoticesData) {
	list, err := m.st.StatusNotices(r.Context(), d.Page.ID, time.Now().AddDate(0, 0, -90))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	for _, n := range list {
		if n.ResolvedAt.IsZero() {
			d.Open = append(d.Open, n)
		} else {
			d.Resolved = append(d.Resolved, n)
		}
	}
	m.g.Render(w, r, status, Name+"/status_page_notices", "hc.status.notices", d)
}

func (m *Module) noticesURL(p *StatusPage) string {
	return statusPagesPath + "/" + strconv.FormatInt(p.ID, 10) + "/notices"
}

func (m *Module) pageStatusNoticeAdd(w http.ResponseWriter, r *http.Request) {
	p := m.loadStatusPage(w, r)
	if p == nil {
		return
	}
	_ = r.ParseForm()
	title, level, text := r.PostFormValue("title"), r.PostFormValue("level"), r.PostFormValue("text")
	if _, err := m.st.AddStatusNotice(r.Context(), p.ID, title, level, text); err != nil {
		var fe *StatusFieldError
		if !errors.As(err, &fe) {
			m.fail(w, r, err)
			return
		}
		m.renderStatusNotices(w, r, http.StatusUnprocessableEntity, statusNoticesData{Page: p, Error: m.g.T(r, fe.Key),
			Form: map[string]string{"title": title, "level": level, "text": text}})
		return
	}
	m.auditText(r, "status_notice.create", p.Slug+": "+strings.TrimSpace(title))
	m.g.Flash(w, r, "success", m.g.T(r, "common.saved"))
	http.Redirect(w, r, m.noticesURL(p), http.StatusSeeOther)
}

// loadNotice liefert die ID der Ankuendigung im Pfad, wenn sie zur Seite gehoert (sonst 404, 0).
func (m *Module) loadNotice(w http.ResponseWriter, r *http.Request, p *StatusPage) int64 {
	nid, _ := strconv.ParseInt(r.PathValue("nid"), 10, 64)
	if nid == 0 || m.noticePage(r.Context(), nid) != p.ID {
		m.g.Render(w, r, http.StatusNotFound, Name+"/missing", "hc.missing", nil)
		return 0
	}
	return nid
}

func (m *Module) pageStatusNoticeUpdate(w http.ResponseWriter, r *http.Request) {
	p := m.loadStatusPage(w, r)
	if p == nil {
		return
	}
	nid := m.loadNotice(w, r, p)
	if nid == 0 {
		return
	}
	_ = r.ParseForm()
	resolve := r.PostFormValue("resolve") == "on"
	if err := m.st.UpdateStatusNotice(r.Context(), nid, r.PostFormValue("level"), r.PostFormValue("text"), resolve); err != nil {
		var fe *StatusFieldError
		if !errors.As(err, &fe) {
			m.fail(w, r, err)
			return
		}
		m.renderStatusNotices(w, r, http.StatusUnprocessableEntity, statusNoticesData{Page: p, Error: m.g.T(r, fe.Key), Form: map[string]string{"level": "info"}})
		return
	}
	m.auditText(r, map[bool]string{true: "status_notice.resolve", false: "status_notice.update"}[resolve], p.Slug+": #"+strconv.FormatInt(nid, 10))
	m.g.Flash(w, r, "success", m.g.T(r, "common.saved"))
	http.Redirect(w, r, m.noticesURL(p), http.StatusSeeOther)
}

func (m *Module) pageStatusNoticeDelete(w http.ResponseWriter, r *http.Request) {
	p := m.loadStatusPage(w, r)
	if p == nil {
		return
	}
	nid := m.loadNotice(w, r, p)
	if nid == 0 {
		return
	}
	if err := m.st.DeleteStatusNotice(r.Context(), nid); err != nil {
		m.fail(w, r, err)
		return
	}
	m.auditText(r, "status_notice.delete", p.Slug+": #"+strconv.FormatInt(nid, 10))
	m.g.Flash(w, r, "success", m.g.T(r, "hc.status.notice_deleted"))
	http.Redirect(w, r, m.noticesURL(p), http.StatusSeeOther)
}
