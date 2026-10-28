package healthchecks

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"time"
)

// Statusseiten (Plan docs/PLAN-NODE64-STATUSSEITE.md): Datenmodell und Speicher. Die Berechnung der Anzeige steht in
// statusview.go, die oeffentlichen Routen in statuspublic.go, die Verwaltung in statuspages_ui.go.

// StatusPage ist eine Statusseite mit ihren Gruppen.
type StatusPage struct {
	ID          int64         `json:"id"`
	Slug        string        `json:"slug"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Footer      string        `json:"footer"`
	Enabled     bool          `json:"enabled"`      // aus = nirgends erreichbar
	PublishNode bool          `json:"publish_node"` // auch direkt auf dem Node-Port
	Layout      string        `json:"layout"`       // list | tiles | compact
	Theme       string        `json:"theme"`        // auto | light | dark
	Lang        string        `json:"lang"`         // "" = Browser, de, en
	Accent      string        `json:"accent"`       // #rrggbb oder ""
	Days        int           `json:"days"`         // 30 | 60 | 90
	ShowUptime  bool          `json:"show_uptime"`
	ShowHistory bool          `json:"show_history"`
	RefreshSec  int           `json:"refresh_sec"`
	HasPassword bool          `json:"has_password"`       // nur Anzeige
	Password    string        `json:"password,omitempty"` // Eingabe: neues Passwort im Klartext; "-" = entfernen; leer = unveraendert
	NoIndex     bool          `json:"noindex"`
	PoweredBy   bool          `json:"powered_by"`
	Groups      []StatusGroup `json:"groups"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
	hash        string        // gespeicherter bcrypt-Hash
	UID         string        `json:"-"` // Kennung im Cluster (gleich auf allen Nodes, statuscluster.go)

	HCGroups bool `json:"hc_groups"` // Eintraege nach den Gruppen der Healthchecks anzeigen (statt der Gruppen der Seite)

	HasLogo     bool      `json:"has_logo"`              // eigenes Logo hochgeladen (SetStatusLogo)
	LogoUpdated time.Time `json:"logo_updated,omitzero"` // fuer ?v= an der Logo-URL
}

// StatusGroup ist eine Gruppe auf der Seite.
type StatusGroup struct {
	ID    int64        `json:"id"`
	Name  string       `json:"name"`
	Items []StatusItem `json:"items"`
}

// StatusItem ist ein Check auf der Seite.
type StatusItem struct {
	ID    int64  `json:"id"`
	Token string `json:"token"`
	Label string `json:"label"` // "" = Name des Checks
}

// StatusNotice ist eine Ankuendigung von Hand.
type StatusNotice struct {
	ID         int64                `json:"id"`
	PageID     int64                `json:"page_id"`
	Title      string               `json:"title"`
	Level      string               `json:"level"` // info | warning | danger
	CreatedAt  time.Time            `json:"created_at"`
	UpdatedAt  time.Time            `json:"updated_at"`
	ResolvedAt time.Time            `json:"resolved_at,omitzero"`
	Updates    []StatusNoticeUpdate `json:"updates"`
}

// StatusNoticeUpdate ist ein Eintrag in der Zeitleiste einer Ankuendigung.
type StatusNoticeUpdate struct {
	ID   int64     `json:"id"`
	Time time.Time `json:"time"`
	Text string    `json:"text"`
}

var (
	statusSlugRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)
	statusAccentRe = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
	// ErrStatusPageNotFound: Seite unbekannt (oeffentlich immer 404, ohne Unterschied zu "aus")
	ErrStatusPageNotFound = errors.New("status page not found")
)

// normalize prueft eine Seite und setzt Standardwerte. Fehler als FieldError-Schluessel hc.status.err.<feld>.
func (p *StatusPage) normalize() error {
	p.Slug = strings.ToLower(strings.TrimSpace(p.Slug))
	if !statusSlugRe.MatchString(p.Slug) || p.Slug == "assets" {
		return fieldErr("slug", "hc.status.err.slug")
	}
	p.Title = strings.TrimSpace(p.Title)
	if p.Title == "" || len(p.Title) > 120 {
		return fieldErr("title", "hc.status.err.title")
	}
	if len(p.Description) > 5000 || len(p.Footer) > 2000 {
		return fieldErr("description", "hc.status.err.text")
	}
	switch p.Layout {
	case "list", "tiles", "compact":
	default:
		p.Layout = "list"
	}
	switch p.Theme {
	case "auto", "light", "dark":
	default:
		p.Theme = "auto"
	}
	if p.Lang != "de" && p.Lang != "en" {
		p.Lang = ""
	}
	if p.Accent != "" && !statusAccentRe.MatchString(p.Accent) {
		return fieldErr("accent", "hc.status.err.accent")
	}
	if p.Days != 30 && p.Days != 60 {
		p.Days = 90
	}
	if p.RefreshSec < 30 {
		p.RefreshSec = 30
	}
	if p.RefreshSec > 3600 {
		p.RefreshSec = 3600
	}
	n := 0
	for gi := range p.Groups {
		g := &p.Groups[gi]
		g.Name = strings.TrimSpace(g.Name)
		if len(g.Name) > 100 {
			return fieldErr("groups", "hc.status.err.group")
		}
		for ii := range g.Items {
			g.Items[ii].Label = strings.TrimSpace(g.Items[ii].Label)
			if g.Items[ii].Token == "" || len(g.Items[ii].Label) > 120 {
				return fieldErr("groups", "hc.status.err.item")
			}
			n++
		}
	}
	if len(p.Groups) > 50 || n > 1000 {
		return fieldErr("groups", "hc.status.err.many")
	}
	return nil
}

// fieldErr ist ein Feldfehler einer Statusseite (Formular, API 422).
func fieldErr(field, key string) error { return &StatusFieldError{Field: field, Key: key} }

// StatusFieldError ist ein Fehler in einem Feld einer Statusseite; Key ist der i18n-Schluessel.
type StatusFieldError struct{ Field, Key string }

func (e *StatusFieldError) Error() string { return e.Field + ": " + e.Key }

const statusPageCols = `id, slug, title, description, footer, enabled, publish_node, layout, theme, lang, accent, days, show_uptime,
	show_history, refresh_sec, password, noindex, powered_by, created_at, updated_at, hc_groups, logo_type, logo_updated, uid`

func scanStatusPage(row interface{ Scan(...any) error }) (*StatusPage, error) {
	var p StatusPage
	var ca, ua, lt, lu string
	if err := row.Scan(&p.ID, &p.Slug, &p.Title, &p.Description, &p.Footer, &p.Enabled, &p.PublishNode, &p.Layout, &p.Theme, &p.Lang,
		&p.Accent, &p.Days, &p.ShowUptime, &p.ShowHistory, &p.RefreshSec, &p.hash, &p.NoIndex, &p.PoweredBy, &ca, &ua, &p.HCGroups, &lt, &lu, &p.UID); err != nil {
		return nil, err
	}
	p.HasLogo, p.LogoUpdated = lt != "", pt(lu)
	p.HasPassword = p.hash != ""
	p.CreatedAt, p.UpdatedAt = pt(ca), pt(ua)
	return &p, nil
}

// StatusPages liefert alle Seiten (ohne Gruppen).
func (s *Store) StatusPages(ctx context.Context) ([]*StatusPage, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT `+statusPageCols+` FROM hc_status_pages ORDER BY title, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*StatusPage
	for rows.Next() {
		p, err := scanStatusPage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// StatusPage liefert eine Seite mit Gruppen und Eintraegen.
func (s *Store) StatusPage(ctx context.Context, id int64) (*StatusPage, error) {
	return s.statusPageWhere(ctx, `id = ?`, id)
}

// StatusPageBySlug liefert eine Seite nach Slug (mit Gruppen).
func (s *Store) StatusPageBySlug(ctx context.Context, slug string) (*StatusPage, error) {
	return s.statusPageWhere(ctx, `slug = ?`, strings.ToLower(slug))
}

func (s *Store) statusPageWhere(ctx context.Context, where string, arg any) (*StatusPage, error) {
	p, err := scanStatusPage(s.r.QueryRowContext(ctx, `SELECT `+statusPageCols+` FROM hc_status_pages WHERE `+where, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrStatusPageNotFound
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.r.QueryContext(ctx, `SELECT g.id, g.name, i.id, i.token, i.label FROM hc_status_groups g
		LEFT JOIN hc_status_items i ON i.group_id = g.id WHERE g.page_id = ? ORDER BY g.sort, g.id, i.sort, i.id`, p.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	p.Groups = []StatusGroup{}
	for rows.Next() {
		var gid int64
		var gname string
		var iid sql.NullInt64
		var tok, label sql.NullString
		if err := rows.Scan(&gid, &gname, &iid, &tok, &label); err != nil {
			return nil, err
		}
		if len(p.Groups) == 0 || p.Groups[len(p.Groups)-1].ID != gid {
			p.Groups = append(p.Groups, StatusGroup{ID: gid, Name: gname, Items: []StatusItem{}})
		}
		if iid.Valid {
			g := &p.Groups[len(p.Groups)-1]
			g.Items = append(g.Items, StatusItem{ID: iid.Int64, Token: tok.String, Label: label.String})
		}
	}
	return p, rows.Err()
}

// SaveStatusPage legt eine Seite an (ID 0) oder ersetzt sie samt Gruppen und Eintraegen. hash ist der neue
// bcrypt-Hash ("" = unveraendert lassen, "-" = Passwort entfernen); das Hashen macht der Aufrufer.
func (s *Store) SaveStatusPage(ctx context.Context, p *StatusPage, hash string) error {
	if err := p.normalize(); err != nil {
		return err
	}
	var taken int64
	_ = s.r.QueryRowContext(ctx, `SELECT id FROM hc_status_pages WHERE slug = ? AND id <> ?`, p.Slug, p.ID).Scan(&taken)
	if taken != 0 {
		return fieldErr("slug", "hc.status.err.slug_taken")
	}
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	now := ft(time.Now())
	args := []any{p.Slug, p.Title, p.Description, p.Footer, p.Enabled, p.PublishNode, p.Layout, p.Theme, p.Lang, p.Accent, p.Days,
		p.ShowUptime, p.ShowHistory, p.RefreshSec, p.NoIndex, p.PoweredBy, p.HCGroups}
	if p.ID == 0 {
		if p.UID == "" { // neu hier: eigene Kennung (aus dem Cluster: die der anderen Node)
			p.UID = newUID()
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO hc_status_pages (slug, title, description, footer, enabled, publish_node, layout, theme, lang,
			accent, days, show_uptime, show_history, refresh_sec, noindex, powered_by, hc_groups, created_at, updated_at, uid) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			append(args, now, now, p.UID)...)
		if err != nil {
			return err
		}
		p.ID, _ = res.LastInsertId()
	} else {
		res, err := tx.ExecContext(ctx, `UPDATE hc_status_pages SET slug=?, title=?, description=?, footer=?, enabled=?, publish_node=?, layout=?,
			theme=?, lang=?, accent=?, days=?, show_uptime=?, show_history=?, refresh_sec=?, noindex=?, powered_by=?, hc_groups=?, updated_at=? WHERE id=?`,
			append(args, now, p.ID)...)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrStatusPageNotFound
		}
	}
	switch hash {
	case "":
	case "-":
		if _, err := tx.ExecContext(ctx, `UPDATE hc_status_pages SET password = '' WHERE id = ?`, p.ID); err != nil {
			return err
		}
	default:
		if _, err := tx.ExecContext(ctx, `UPDATE hc_status_pages SET password = ? WHERE id = ?`, hash, p.ID); err != nil {
			return err
		}
	}
	// Gruppen und Eintraege ersetzen (die Seite ist klein; IDs der Eintraege aendern sich dabei)
	if _, err := tx.ExecContext(ctx, `DELETE FROM hc_status_items WHERE group_id IN (SELECT id FROM hc_status_groups WHERE page_id = ?)`, p.ID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM hc_status_groups WHERE page_id = ?`, p.ID); err != nil {
		return err
	}
	for gi := range p.Groups {
		g := &p.Groups[gi]
		res, err := tx.ExecContext(ctx, `INSERT INTO hc_status_groups (page_id, name, sort) VALUES (?,?,?)`, p.ID, g.Name, gi)
		if err != nil {
			return err
		}
		g.ID, _ = res.LastInsertId()
		for ii := range g.Items {
			it := &g.Items[ii]
			res, err := tx.ExecContext(ctx, `INSERT INTO hc_status_items (group_id, token, label, sort) VALUES (?,?,?,?)`, g.ID, it.Token, it.Label, ii)
			if err != nil {
				return err
			}
			it.ID, _ = res.LastInsertId()
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.statusChanged()
	s.statusCluster(ctx, p.ID)
	return nil
}

// statusPasswordHash liefert den gespeicherten Hash einer Seite ("" = ohne Passwort).
func (s *Store) statusPasswordHash(ctx context.Context, id int64) string {
	var h string
	_ = s.r.QueryRowContext(ctx, `SELECT password FROM hc_status_pages WHERE id = ?`, id).Scan(&h)
	return h
}

// DeleteStatusPage loescht eine Seite mit allem, was dazugehoert.
func (s *Store) DeleteStatusPage(ctx context.Context, id int64) error {
	uid := s.statusUID(ctx, id)
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	for _, q := range []string{
		`DELETE FROM hc_status_notice_updates WHERE notice_id IN (SELECT id FROM hc_status_notices WHERE page_id = ?)`,
		`DELETE FROM hc_status_notices WHERE page_id = ?`,
		`DELETE FROM hc_status_items WHERE group_id IN (SELECT id FROM hc_status_groups WHERE page_id = ?)`,
		`DELETE FROM hc_status_groups WHERE page_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM hc_status_pages WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrStatusPageNotFound
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.statusChanged()
	if s.OnStatusCluster != nil && uid != "" {
		s.OnStatusCluster(ctx, uid, true)
	}
	return nil
}

// AnyStatusPageEnabled: mindestens eine Seite ist eingeschaltet (sonst laeuft fuer Statusseiten nichts).
func (s *Store) AnyStatusPageEnabled(ctx context.Context) bool {
	var n int
	_ = s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM hc_status_pages WHERE enabled = 1`).Scan(&n)
	return n > 0
}

// ---------------------------------------------------------------- Ankuendigungen

// StatusNotices liefert die Ankuendigungen einer Seite seit since (neueste zuerst, mit Updates).
func (s *Store) StatusNotices(ctx context.Context, pageID int64, since time.Time) ([]StatusNotice, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT id, page_id, title, level, created_at, updated_at, resolved_at FROM hc_status_notices
		WHERE page_id = ? AND (resolved_at = '' OR resolved_at >= ?) ORDER BY created_at DESC LIMIT 100`, pageID, ft(since))
	if err != nil {
		return nil, err
	}
	var out []StatusNotice
	for rows.Next() {
		var n StatusNotice
		var ca, ua, ra string
		if err := rows.Scan(&n.ID, &n.PageID, &n.Title, &n.Level, &ca, &ua, &ra); err != nil {
			rows.Close()
			return nil, err
		}
		n.CreatedAt, n.UpdatedAt, n.ResolvedAt = pt(ca), pt(ua), pt(ra)
		n.Updates = []StatusNoticeUpdate{}
		out = append(out, n)
	}
	rows.Close()
	for i := range out {
		ur, err := s.r.QueryContext(ctx, `SELECT id, time, text FROM hc_status_notice_updates WHERE notice_id = ? ORDER BY time DESC`, out[i].ID)
		if err != nil {
			return nil, err
		}
		for ur.Next() {
			var u StatusNoticeUpdate
			var t string
			if err := ur.Scan(&u.ID, &t, &u.Text); err != nil {
				ur.Close()
				return nil, err
			}
			u.Time = pt(t)
			out[i].Updates = append(out[i].Updates, u)
		}
		ur.Close()
	}
	return out, nil
}

func validNoticeLevel(l string) bool { return l == "info" || l == "warning" || l == "danger" }

// AddStatusNotice legt eine Ankuendigung mit erstem Text an.
func (s *Store) AddStatusNotice(ctx context.Context, pageID int64, title, level, text string) (int64, error) {
	title, text = strings.TrimSpace(title), strings.TrimSpace(text)
	if title == "" || len(title) > 200 || len(text) > 5000 {
		return 0, fieldErr("title", "hc.status.err.notice")
	}
	if !validNoticeLevel(level) {
		level = "info"
	}
	now := ft(time.Now())
	res, err := s.w.ExecContext(ctx, `INSERT INTO hc_status_notices (page_id, title, level, created_at, updated_at) VALUES (?,?,?,?,?)`,
		pageID, title, level, now, now)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	if text != "" {
		if _, err := s.w.ExecContext(ctx, `INSERT INTO hc_status_notice_updates (notice_id, time, text) VALUES (?,?,?)`, id, now, text); err != nil {
			return 0, err
		}
	}
	s.statusChanged()
	s.statusCluster(ctx, pageID)
	return id, nil
}

// UpdateStatusNotice haengt ein Update an; level "" = unveraendert, resolve = erledigt.
func (s *Store) UpdateStatusNotice(ctx context.Context, id int64, level, text string, resolve bool) error {
	text = strings.TrimSpace(text)
	if len(text) > 5000 {
		return fieldErr("text", "hc.status.err.notice")
	}
	now := ft(time.Now())
	if level != "" && validNoticeLevel(level) {
		if _, err := s.w.ExecContext(ctx, `UPDATE hc_status_notices SET level = ? WHERE id = ?`, level, id); err != nil {
			return err
		}
	}
	if resolve {
		if _, err := s.w.ExecContext(ctx, `UPDATE hc_status_notices SET resolved_at = ? WHERE id = ? AND resolved_at = ''`, now, id); err != nil {
			return err
		}
	}
	if text != "" {
		if _, err := s.w.ExecContext(ctx, `INSERT INTO hc_status_notice_updates (notice_id, time, text) VALUES (?,?,?)`, id, now, text); err != nil {
			return err
		}
	}
	if _, err := s.w.ExecContext(ctx, `UPDATE hc_status_notices SET updated_at = ? WHERE id = ?`, now, id); err != nil {
		return err
	}
	s.statusChanged()
	s.statusCluster(ctx, s.noticePage(ctx, id))
	return nil
}

// DeleteStatusNotice loescht eine Ankuendigung.
func (s *Store) DeleteStatusNotice(ctx context.Context, id int64) error {
	page := s.noticePage(ctx, id)
	if _, err := s.w.ExecContext(ctx, `DELETE FROM hc_status_notice_updates WHERE notice_id = ?`, id); err != nil {
		return err
	}
	if _, err := s.w.ExecContext(ctx, `DELETE FROM hc_status_notices WHERE id = ?`, id); err != nil {
		return err
	}
	s.statusChanged()
	s.statusCluster(ctx, page)
	return nil
}

// statusChanged verwirft zwischengespeicherte Ansichten (statusview.go setzt OnStatusChange).
func (s *Store) statusChanged() {
	if s.OnStatusChange != nil {
		s.OnStatusChange()
	}
}

// statusCluster meldet eine geaenderte Seite an den Cluster (OnStatusCluster, statuscluster.go).
func (s *Store) statusCluster(ctx context.Context, pageID int64) {
	if s.OnStatusCluster == nil || pageID == 0 {
		return
	}
	if uid := s.statusUID(ctx, pageID); uid != "" {
		s.OnStatusCluster(ctx, uid, false)
	}
}

// statusUID liefert die Kennung einer Seite im Cluster ("" = unbekannt).
func (s *Store) statusUID(ctx context.Context, pageID int64) string {
	var uid string
	_ = s.w.QueryRowContext(ctx, `SELECT uid FROM hc_status_pages WHERE id = ?`, pageID).Scan(&uid)
	return uid
}

// noticePage liefert die Seite einer Ankuendigung (0 = unbekannt).
func (s *Store) noticePage(ctx context.Context, noticeID int64) int64 {
	var id int64
	_ = s.w.QueryRowContext(ctx, `SELECT page_id FROM hc_status_notices WHERE id = ?`, noticeID).Scan(&id)
	return id
}

// ---------------------------------------------------------------- Logo

// StatusLogoMax ist die groesste erlaubte Logo-Datei.
const StatusLogoMax = 256 << 10

// StatusLogoTypes sind die erlaubten Bildformate (SVG wird beim Ausliefern mit sandbox-CSP gesichert).
var StatusLogoTypes = map[string]bool{"image/png": true, "image/jpeg": true, "image/webp": true, "image/svg+xml": true}

// SetStatusLogo speichert das Logo einer Seite (data nil = entfernen). Das Format prueft der Aufrufer
// (StatusLogoTypes, StatusLogoMax, Inhalt passt zum Typ).
func (s *Store) SetStatusLogo(ctx context.Context, id int64, data []byte, ctype string) error {
	if data != nil && (!StatusLogoTypes[ctype] || len(data) > StatusLogoMax) {
		return fieldErr("logo", "hc.status.err.logo")
	}
	if data == nil {
		ctype = ""
	}
	res, err := s.w.ExecContext(ctx, `UPDATE hc_status_pages SET logo = ?, logo_type = ?, logo_updated = ?, updated_at = ? WHERE id = ?`,
		data, ctype, ft(time.Now()), ft(time.Now()), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrStatusPageNotFound
	}
	s.statusChanged()
	s.statusCluster(ctx, id)
	return nil
}

// StatusLogo liefert das Logo einer Seite (data nil = keins) und den Zeitpunkt der letzten Aenderung.
func (s *Store) StatusLogo(ctx context.Context, id int64) (data []byte, ctype string, updated time.Time, err error) {
	var u string
	err = s.r.QueryRowContext(ctx, `SELECT logo, logo_type, logo_updated FROM hc_status_pages WHERE id = ?`, id).Scan(&data, &ctype, &u)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", time.Time{}, ErrStatusPageNotFound
	}
	if len(data) == 0 {
		data, ctype = nil, ""
	}
	return data, ctype, pt(u), err
}
