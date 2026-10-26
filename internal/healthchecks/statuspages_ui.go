package healthchecks

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/proxmox"
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
	Sub    string // Proxmox-System bzw. Docker-Host
	Paused bool
	OnPage bool // schon auf der Seite
	// Node, Gast oder Container ohne Check: Value "<System-ID>|<Key>" (add_res), der Check wird beim Hinzufuegen angelegt
	Res   bool
	Value string
	Type  string // i18n-Schluessel des Typs (pve.type.*)
}

// statusPageItem ist ein Eintrag der Seite im Formular (eine Liste, gruppiert wird nach den Healthchecks-Gruppen).
type statusPageItem struct {
	Token, Name, Label, Group string
}

// statusResSys ist ein System bzw. Docker-Host mit Nodes, Gaesten bzw. Containern.
type statusResSys struct {
	Name  string
	Items []statusResOpt
}

// statusResOpt ist ein Node, Gast oder Container; ohne Token wird der Check beim Hinzufuegen angelegt.
type statusResOpt struct {
	ID     string // fuer id/for im Formular
	Value  string // "<System-ID>|<Key>"
	Name   string
	Type   string // i18n-Schluessel des Typs
	Token  string // Check („auch als Check fuehren“), "" = noch keiner
	OnPage bool
}

type statusFormData struct {
	Page     *StatusPage
	Edit     bool
	Dirty    bool // Gruppen/Eintraege geaendert, noch nicht gespeichert
	Errors   map[string]string
	Error    string
	Checks   []statusCheckOpt  // Auswahl: Checks und Nodes/Gaeste/Container ohne Check
	PageList []statusPageItem  // Eintraege der Seite
	Names    map[string]string // Token -> Name des Checks ("" = geloescht)
	Tags     []string
	HCGroups []string
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
	mux.Handle("POST "+statusPagesPath+"/{id}/logo/delete", page(m.pageStatusLogoDelete))
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

// newStatusPage: Standardwerte einer neuen Seite (wie in der Migration; abweichend davon auf dem Node-Port
// veroeffentlicht, das ist der normale Weg, PROXY64 der optionale).
func newStatusPage() *StatusPage {
	return &StatusPage{PublishNode: true, Layout: "list", Theme: "auto", Days: 90, ShowUptime: true, ShowHistory: true, RefreshSec: 60, NoIndex: true, PoweredBy: true,
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
	tags, groups := map[string]bool{}, map[string]bool{}
	list, err := m.st.Checks(r.Context())
	byTok := map[string]*Check{}
	if err == nil {
		for _, c := range list {
			d.Names[c.Token], byTok[c.Token] = c.Name, c
		}
	}
	for _, g := range d.Page.Groups {
		for _, it := range g.Items {
			if on[it.Token] {
				continue
			}
			on[it.Token] = true
			pi := statusPageItem{Token: it.Token, Name: d.Names[it.Token], Label: it.Label}
			if c := byTok[it.Token]; c != nil {
				pi.Group = statusGroupName(c)
			}
			d.PageList = append(d.PageList, pi)
		}
	}
	d.Items = len(d.PageList)
	// Nodes, Gaeste und Container ohne Check (mit Check stehen sie unten als Check in der Liste)
	linked := map[string]bool{}
	for _, docker := range []bool{false, true} {
		group := pveCheckGroup
		if docker {
			group = dockerCheckGroup
		}
		for _, sys := range m.statusResources(r.Context(), docker, d.Names, on, linked) {
			for _, o := range sys.Items {
				if o.Token != "" {
					continue
				}
				d.Checks = append(d.Checks, statusCheckOpt{Name: o.Name, Group: group, Sub: sys.Name, Res: true, Value: o.Value, Type: o.Type})
				groups[group] = true
			}
		}
	}
	if err == nil {
		for _, c := range list {
			d.Checks = append(d.Checks, statusCheckOpt{Token: c.Token, Value: c.Token, Name: c.Name, Tags: strings.Join(c.Tags, ","), Group: c.Group,
				Sub: checkSystemOf(c), Paused: c.Paused, OnPage: on[c.Token]})
			for _, t := range c.Tags {
				tags[t] = true
			}
			if c.Group != "" {
				groups[c.Group] = true
			}
		}
	}
	sort.SliceStable(d.Checks, func(i, j int) bool { return strings.ToLower(d.Checks[i].Name) < strings.ToLower(d.Checks[j].Name) })
	d.Tags, d.HCGroups = sortedKeys(tags), sortedKeys(groups)
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

// statusPageFromForm uebernimmt die Felder des Formulars in p. Die Eintraege stehen in einer Liste; die Seite gruppiert
// nach den Gruppen der Healthchecks (statusGroupsFor), eigene Gruppen der Seite gibt es in der Oberflaeche nicht mehr.
func statusPageFromForm(r *http.Request, p *StatusPage) {
	v := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	on := func(k string) bool { return r.PostFormValue(k) == "on" }
	p.Title, p.Slug = v("title"), strings.ToLower(v("slug"))
	p.Description, p.Footer = strings.TrimSpace(r.PostFormValue("description")), strings.TrimSpace(r.PostFormValue("footer"))
	p.Enabled, p.PublishNode, p.ShowUptime, p.ShowHistory, p.NoIndex, p.PoweredBy = on("enabled"), on("publish_node"), on("show_uptime"), on("show_history"), on("noindex"), on("powered_by")
	p.HCGroups = true
	p.Layout, p.Theme, p.Lang = v("layout"), v("theme"), v("lang")
	p.Accent = ""
	if on("accent_on") {
		p.Accent = v("accent")
	}
	p.Days, _ = strconv.Atoi(v("days"))
	if n, err := strconv.Atoi(v("refresh_sec")); err == nil {
		p.RefreshSec = n
	}
	g := StatusGroup{Items: []StatusItem{}}
	toks, lbls := r.PostForm["it_tok"], r.PostForm["it_lbl"]
	for i, tok := range toks {
		if i >= len(lbls) || tok == "" {
			continue
		}
		g.Items = append(g.Items, StatusItem{Token: tok, Label: strings.TrimSpace(lbls[i])})
	}
	p.Groups = []StatusGroup{g}
}

// statusFormOp wendet einen Knopf des Formulars auf die Gruppen und Eintraege an (ohne zu speichern).
// statusResources liefert die Proxmox-Systeme (docker=false) bzw. Docker-Hosts mit Nodes, Gaesten bzw. Containern aus
// dem letzten Abruf, dazu Eintraege, die schon als Check gefuehrt werden, aber gerade nicht abgerufen sind. linked
// sammelt die Checks dieser Eintraege.
func (m *Module) statusResources(ctx context.Context, docker bool, names map[string]string, on, linked map[string]bool) []statusResSys {
	list, err := m.pve.st.Systems(ctx)
	if err != nil {
		return nil
	}
	sort.Slice(list, func(i, j int) bool { return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name) })
	var out []statusResSys
	for _, sys := range list {
		if sys.IsDocker() != docker {
			continue
		}
		set, _ := m.pve.st.Settings(ctx, sys.ID)
		g := statusResSys{Name: sys.Name}
		add := func(key, name string) {
			o := statusResOpt{ID: strconv.FormatInt(sys.ID, 10) + "-" + strconv.Itoa(len(g.Items)), Value: strconv.FormatInt(sys.ID, 10) + "|" + key, Name: name}
			typ, _, _ := strings.Cut(key, "/")
			o.Type = "pve.type." + typ
			if it := set.Item(key); it != nil && it.AsCheck && names[it.CheckToken] != "" {
				o.Token, o.OnPage = it.CheckToken, on[it.CheckToken]
				linked[it.CheckToken] = true
			}
			g.Items = append(g.Items, o)
		}
		seen := map[string]bool{}
		if s := m.pveLast(sys.ID); s != nil {
			for i := range s.Resources {
				res := &s.Resources[i]
				if res.Excluded() {
					continue
				}
				key := res.Key()
				seen[key] = true
				name := res.Name
				if name == "" {
					name = key
				}
				add(key, name)
			}
		}
		if set != nil {
			keys := make([]string, 0, len(set.Items))
			for key, it := range set.Items {
				if key != "" && !seen[key] && it.AsCheck && names[it.CheckToken] != "" {
					keys = append(keys, key)
				}
			}
			sort.Strings(keys)
			for _, key := range keys {
				add(key, names[set.Items[key].CheckToken])
			}
		}
		// Nodes zuerst, dann nach Name
		sort.SliceStable(g.Items, func(i, j int) bool {
			ni, nj := g.Items[i].Type == "pve.type.node", g.Items[j].Type == "pve.type.node"
			if ni != nj {
				return ni
			}
			return strings.ToLower(g.Items[i].Name) < strings.ToLower(g.Items[j].Name)
		})
		out = append(out, g)
	}
	return out
}

// statusResTokens liefert die Checks zu ausgewaehlten Nodes, Gaesten bzw. Containern ("<System-ID>|<Key>"). Fehlt der
// Check, wird er angelegt wie mit „auch als Check fuehren“ (Kanaele der Regeln, keine doppelte Meldung).
func (m *Module) statusResTokens(r *http.Request, vals []string) ([]string, error) {
	ctx := r.Context()
	var toks []string
	for _, v := range vals {
		ids, key, ok := strings.Cut(v, "|")
		id, err := strconv.ParseInt(ids, 10, 64)
		if !ok || err != nil || !proxmox.ValidKey(key) {
			continue
		}
		sys, err := m.pve.st.System(ctx, id)
		if err != nil || sys == nil {
			continue
		}
		token := func() string {
			set, _ := m.pve.st.Settings(ctx, id)
			if it := set.Item(key); it != nil && it.AsCheck && it.CheckToken != "" {
				if c, _ := m.st.Check(ctx, it.CheckToken); c != nil {
					return c.Token
				}
			}
			return ""
		}
		t := token()
		if t == "" {
			if err := m.pveSetAsCheck(r, sys, key, true); err != nil {
				return toks, err
			}
			t = token()
		}
		if t != "" {
			toks = append(toks, t)
		}
	}
	return toks, nil
}

func (m *Module) statusFormOp(ctx context.Context, r *http.Request, p *StatusPage, op string) error {
	if len(p.Groups) == 0 {
		p.Groups = []StatusGroup{{Items: []StatusItem{}}}
	}
	g := &p.Groups[0]
	if n, ok := strings.CutPrefix(op, "rm-"); ok { // Eintrag entfernen
		if i, err := strconv.Atoi(n); err == nil && i >= 0 && i < len(g.Items) {
			g.Items = append(g.Items[:i], g.Items[i+1:]...)
		}
		return nil
	}
	if op != "add" {
		return nil
	}
	toks, opErr := m.statusResTokens(r, r.PostForm["add_res"]) // Nodes, Gaeste, Container: fehlende Checks anlegen
	list, err := m.st.Checks(ctx)
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, t := range append(r.PostForm["add_tok"], toks...) {
		want[t] = true
	}
	has := map[string]bool{}
	for _, it := range g.Items {
		has[it.Token] = true
	}
	for _, c := range list {
		if want[c.Token] && !has[c.Token] {
			g.Items, has[c.Token] = append(g.Items, StatusItem{Token: c.Token}), true
		}
	}
	return opErr
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
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
	perr := parseStatusForm(r)
	p := newStatusPage()
	edit := r.PathValue("id") != ""
	if edit {
		if p = m.loadStatusPage(w, r); p == nil {
			return
		}
	}
	if perr != nil { // z. B. Datei groesser als das Limit der Oberflaeche: Eingaben sind weg, Hinweis am Logo
		msg := m.g.T(r, "hc.status.err.logo")
		m.renderStatusForm(w, r, http.StatusUnprocessableEntity, statusFormData{Page: p, Edit: edit, Errors: map[string]string{"logo": msg}, Error: msg})
		return
	}
	statusPageFromForm(r, p)
	d := statusFormData{Page: p, Edit: edit}
	if op := r.PostFormValue("op"); op != "" && op != "save" {
		if err := m.statusFormOp(ctx, r, p, op); err != nil {
			d.Error = m.pveErrText(r, err)
		}
		d.Dirty = true
		m.renderStatusForm(w, r, http.StatusOK, d)
		return
	}
	switch {
	case r.PostFormValue("password_remove") == "on":
		p.Password = "-"
	default:
		p.Password = r.PostFormValue("password")
	}
	// Logo vor dem Speichern pruefen (Fehler am Feld, nichts gespeichert); gesetzt wird es nach dem Speichern,
	// damit auch eine neue Seite es gleich bekommt
	logo, ltype, err := statusLogoUpload(r)
	if err == nil {
		err = m.saveStatusPage(ctx, p)
	}
	if err == nil && logo != nil {
		if err = m.st.SetStatusLogo(ctx, p.ID, logo, ltype); err == nil {
			m.auditText(r, "status_page.logo", p.Title+" ("+p.Slug+")")
		}
	}
	if err != nil {
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

// parseStatusForm liest das Formular (multipart wegen des Logos, sonst urlencoded).
func parseStatusForm(r *http.Request) error {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
		return r.ParseMultipartForm(StatusLogoMax + 1<<20)
	}
	return r.ParseForm()
}

// statusLogoUpload liest ein hochgeladenes Logo (Feld "logo"); nil = keins hochgeladen.
func statusLogoUpload(r *http.Request) ([]byte, string, error) {
	if r.MultipartForm == nil || len(r.MultipartForm.File["logo"]) == 0 {
		return nil, "", nil
	}
	fh := r.MultipartForm.File["logo"][0]
	if fh.Size == 0 {
		return nil, "", nil // leeres Dateifeld
	}
	if fh.Size > StatusLogoMax {
		return nil, "", fieldErr("logo", "hc.status.err.logo")
	}
	f, err := fh.Open()
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, StatusLogoMax+1))
	if err != nil {
		return nil, "", err
	}
	ctype, ok := statusLogoType(data)
	if !ok || len(data) > StatusLogoMax {
		return nil, "", fieldErr("logo", "hc.status.err.logo")
	}
	return data, ctype, nil
}

// statusLogoType bestimmt das Format nach dem Inhalt (nicht nach Name oder Header): PNG, JPEG, WebP oder SVG.
func statusLogoType(data []byte) (string, bool) {
	if len(data) == 0 {
		return "", false
	}
	if ct := http.DetectContentType(data); StatusLogoTypes[ct] && ct != "image/svg+xml" {
		return ct, true
	}
	// SVG: nach Leerraum, XML-Kopf, Kommentaren und DOCTYPE muss <svg kommen
	s := bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	for n := 0; n < 20; n++ {
		s = bytes.TrimLeft(s, " \t\r\n")
		var end []byte
		switch {
		case bytes.HasPrefix(s, []byte("<?xml")):
			end = []byte("?>")
		case bytes.HasPrefix(s, []byte("<!--")):
			end = []byte("-->")
		case bytes.HasPrefix(s, []byte("<!DOCTYPE")), bytes.HasPrefix(s, []byte("<!doctype")):
			end = []byte(">")
		default:
			if len(s) > 4 && bytes.HasPrefix(s, []byte("<svg")) && strings.IndexByte(" \t\r\n>/", s[4]) >= 0 {
				return "image/svg+xml", true
			}
			return "", false
		}
		i := bytes.Index(s, end)
		if i < 0 {
			return "", false
		}
		s = s[i+len(end):]
	}
	return "", false
}

// pageStatusLogoDelete entfernt das Logo einer Seite.
func (m *Module) pageStatusLogoDelete(w http.ResponseWriter, r *http.Request) {
	p := m.loadStatusPage(w, r)
	if p == nil {
		return
	}
	if err := m.st.SetStatusLogo(r.Context(), p.ID, nil, ""); err != nil {
		m.fail(w, r, err)
		return
	}
	m.auditText(r, "status_page.logo_remove", p.Title+" ("+p.Slug+")")
	m.g.Flash(w, r, "success", m.g.T(r, "hc.status.logo_removed"))
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
