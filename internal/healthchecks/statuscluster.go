package healthchecks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Statusseiten ueber den Cluster (Bereich healthchecks/statuspages, ohne Einstellung aus): eine Seite geht samt allem,
// was sie ausmacht, an die Nodes, bei denen der Bereich ebenfalls an ist - Titel, Slug, Texte, Optionen, Sichtbarkeit
// (an/aus, Node-Port, Passwort als bcrypt-Hash, noindex), Gruppen mit den Checks in ihrer Reihenfolge, Logo und
// Ankuendigungen. Kennung im Cluster ist StatusPage.UID (die lokale Nummer ist je Node verschieden und bleibt, PROXY64-
// Hosts verweisen weiter auf sie; die Hosts selbst gehoeren zu ihrer Node). Checks stehen ueber ihr Token auf der
// Seite, das auf allen Nodes gleich ist; ein Check, den es hier (noch) nicht gibt, faellt beim Anzeigen weg.
//
// Exakte Doppel: Gibt es hier schon eine Seite mit gleichem Slug unter anderer Kennung und gleichem Inhalt (alles oben,
// ausser dem Zeitpunkt des Logos), gilt die kleinere Kennung - ist sie die fremde, uebernimmt die Seite hier sie (die
// alte Kennung geht als geloescht hinaus), sonst bleibt alles und die andere Node uebernimmt unsere. Gleicher Slug mit
// anderem Inhalt wird nicht uebernommen (Meldung im Log), bis der Slug auf einer Node geaendert ist.

// ClusterItemStatusPages ist der Bereich der Statusseiten im Cluster (Modul healthchecks).
const ClusterItemStatusPages = "statuspages"

var statusUIDRe = regexp.MustCompile(`^[0-9a-f]{16,64}$`)

// clusterStatusPage ist eine Seite im Cluster.
type clusterStatusPage struct {
	Slug        string               `json:"slug"`
	Title       string               `json:"title"`
	Description string               `json:"description"`
	Footer      string               `json:"footer"`
	Enabled     bool                 `json:"enabled"`
	PublishNode bool                 `json:"publish_node"`
	Layout      string               `json:"layout"`
	Theme       string               `json:"theme"`
	Lang        string               `json:"lang"`
	Accent      string               `json:"accent"`
	Days        int                  `json:"days"`
	ShowUptime  bool                 `json:"show_uptime"`
	ShowHistory bool                 `json:"show_history"`
	RefreshSec  int                  `json:"refresh_sec"`
	Password    string               `json:"password,omitempty"` // bcrypt-Hash
	NoIndex     bool                 `json:"noindex"`
	PoweredBy   bool                 `json:"powered_by"`
	HCGroups    bool                 `json:"hc_groups"`
	Groups      []clusterStatusGroup `json:"groups"`
	Logo        []byte               `json:"logo,omitempty"`
	LogoType    string               `json:"logo_type,omitempty"`
	LogoUpdated time.Time            `json:"logo_updated,omitzero"`
	Notices     []clusterNotice      `json:"notices"`
}

type clusterStatusGroup struct {
	Name  string              `json:"name"`
	Items []clusterStatusItem `json:"items"`
}

type clusterStatusItem struct {
	Token string `json:"token"`
	Label string `json:"label,omitempty"`
}

type clusterNotice struct {
	Title      string               `json:"title"`
	Level      string               `json:"level"`
	CreatedAt  time.Time            `json:"created_at"`
	UpdatedAt  time.Time            `json:"updated_at"`
	ResolvedAt time.Time            `json:"resolved_at,omitzero"`
	Updates    []clusterNoticeEntry `json:"updates"`
}

type clusterNoticeEntry struct {
	Time time.Time `json:"time"`
	Text string    `json:"text"`
}

// statusClusterOf liefert eine Seite in der Form fuer den Cluster (mit Logo und Ankuendigungen).
func (m *Module) statusClusterOf(ctx context.Context, p *StatusPage) (*clusterStatusPage, error) {
	out := &clusterStatusPage{Slug: p.Slug, Title: p.Title, Description: p.Description, Footer: p.Footer, Enabled: p.Enabled,
		PublishNode: p.PublishNode, Layout: p.Layout, Theme: p.Theme, Lang: p.Lang, Accent: p.Accent, Days: p.Days, ShowUptime: p.ShowUptime,
		ShowHistory: p.ShowHistory, RefreshSec: p.RefreshSec, Password: p.hash, NoIndex: p.NoIndex, PoweredBy: p.PoweredBy, HCGroups: p.HCGroups,
		Groups: []clusterStatusGroup{}, Notices: []clusterNotice{}}
	for _, g := range p.Groups {
		cg := clusterStatusGroup{Name: g.Name, Items: []clusterStatusItem{}}
		for _, it := range g.Items {
			cg.Items = append(cg.Items, clusterStatusItem{Token: it.Token, Label: it.Label})
		}
		out.Groups = append(out.Groups, cg)
	}
	logo, ctype, upd, err := m.st.StatusLogo(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	out.Logo, out.LogoType, out.LogoUpdated = logo, ctype, upd
	notices, err := m.st.StatusNotices(ctx, p.ID, time.Time{})
	if err != nil {
		return nil, err
	}
	for _, n := range notices {
		cn := clusterNotice{Title: n.Title, Level: n.Level, CreatedAt: n.CreatedAt, UpdatedAt: n.UpdatedAt, ResolvedAt: n.ResolvedAt, Updates: []clusterNoticeEntry{}}
		for _, u := range n.Updates {
			cn.Updates = append(cn.Updates, clusterNoticeEntry{Time: u.Time, Text: u.Text})
		}
		out.Notices = append(out.Notices, cn)
	}
	return out, nil
}

// sameStatusPage: exakt gleicher Inhalt (ohne den Zeitpunkt des Logos, der nur das Zwischenspeichern steuert).
func sameStatusPage(a, b *clusterStatusPage) bool {
	x, y := *a, *b
	x.LogoUpdated, y.LogoUpdated = time.Time{}, time.Time{}
	xb, err1 := json.Marshal(x)
	yb, err2 := json.Marshal(y)
	return err1 == nil && err2 == nil && bytes.Equal(xb, yb)
}

func (m *Module) statusClusterIDs(ctx context.Context) ([]string, error) {
	rows, err := m.st.r.QueryContext(ctx, `SELECT uid FROM hc_status_pages WHERE uid <> '' ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var uid string
		if err := rows.Scan(&uid); err != nil {
			return nil, err
		}
		out = append(out, uid)
	}
	return out, rows.Err()
}

func (m *Module) statusClusterGet(ctx context.Context, uid string) (json.RawMessage, bool, error) {
	p, err := m.st.statusPageWhere(ctx, `uid = ?`, uid)
	if errors.Is(err, ErrStatusPageNotFound) || uid == "" {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	cp, err := m.statusClusterOf(ctx, p)
	if err != nil {
		return nil, false, err
	}
	b, err := json.Marshal(cp)
	return b, err == nil, err
}

var errStatusSlug = errors.New("cluster: status page with this slug exists here with other content")

// statusClusterApply uebernimmt eine Seite einer anderen Node (anlegen, aendern, loeschen). Die Aenderung geht ueber
// den Hook des Stores mit ihrer Herkunft (ctx) weiter an den Cluster.
func (m *Module) statusClusterApply(ctx context.Context, uid string, data json.RawMessage, deleted bool) error {
	if !statusUIDRe.MatchString(uid) {
		return errClusterSystem
	}
	cur, err := m.st.statusPageWhere(ctx, `uid = ?`, uid)
	if errors.Is(err, ErrStatusPageNotFound) {
		cur, err = nil, nil
	}
	if err != nil {
		return err
	}
	if deleted {
		if cur == nil {
			return nil
		}
		return m.st.DeleteStatusPage(ctx, cur.ID)
	}
	var in clusterStatusPage
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	if in.Logo != nil && (!StatusLogoTypes[in.LogoType] || len(in.Logo) > StatusLogoMax) {
		return fieldErr("logo", "hc.status.err.logo")
	}
	if cur == nil {
		other, err := m.st.StatusPageBySlug(ctx, in.Slug)
		switch {
		case errors.Is(err, ErrStatusPageNotFound):
		case err != nil:
			return err
		default:
			mine, err := m.statusClusterOf(ctx, other)
			if err != nil {
				return err
			}
			if !sameStatusPage(mine, &in) {
				return fmt.Errorf("%w: %s", errStatusSlug, in.Slug)
			}
			if other.UID != "" && other.UID < uid {
				return nil // exaktes Doppel: hier gilt die kleinere Kennung, die andere Node uebernimmt sie
			}
			// exaktes Doppel mit kleinerer fremder Kennung: die Seite hier uebernimmt sie (lokale Nummer bleibt)
			if _, err := m.st.w.ExecContext(ctx, `UPDATE hc_status_pages SET uid = ? WHERE id = ?`, uid, other.ID); err != nil {
				return err
			}
			if h := m.st.OnStatusCluster; h != nil && other.UID != "" {
				h(context.Background(), other.UID, true) // alte Kennung: von hier aus geloescht (neuer Zeitpunkt)
			}
			cur = other
		}
	}
	p := &StatusPage{Slug: in.Slug, Title: in.Title, Description: in.Description, Footer: in.Footer, Enabled: in.Enabled, PublishNode: in.PublishNode,
		Layout: in.Layout, Theme: in.Theme, Lang: in.Lang, Accent: in.Accent, Days: in.Days, ShowUptime: in.ShowUptime, ShowHistory: in.ShowHistory,
		RefreshSec: in.RefreshSec, NoIndex: in.NoIndex, PoweredBy: in.PoweredBy, HCGroups: in.HCGroups, Groups: []StatusGroup{}, UID: uid}
	for _, g := range in.Groups {
		sg := StatusGroup{Name: g.Name, Items: []StatusItem{}}
		for _, it := range g.Items {
			sg.Items = append(sg.Items, StatusItem{Token: it.Token, Label: it.Label})
		}
		p.Groups = append(p.Groups, sg)
	}
	if cur != nil {
		p.ID = cur.ID
	}
	hash := in.Password
	if hash == "" {
		hash = "-"
	}
	if err := m.st.SaveStatusPage(ctx, p, hash); err != nil {
		return err
	}
	return m.st.replaceStatusExtras(ctx, p.ID, &in)
}

// replaceStatusExtras ersetzt Logo und Ankuendigungen einer Seite (Uebernahme aus dem Cluster, ohne Hook: die
// Aenderung der Seite ist schon gemeldet).
func (s *Store) replaceStatusExtras(ctx context.Context, pageID int64, in *clusterStatusPage) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	ctype := in.LogoType
	if len(in.Logo) == 0 {
		in.Logo, ctype = nil, ""
	}
	if _, err := tx.ExecContext(ctx, `UPDATE hc_status_pages SET logo = ?, logo_type = ?, logo_updated = ? WHERE id = ?`, in.Logo, ctype, ft(in.LogoUpdated), pageID); err != nil {
		return err
	}
	for _, q := range []string{
		`DELETE FROM hc_status_notice_updates WHERE notice_id IN (SELECT id FROM hc_status_notices WHERE page_id = ?)`,
		`DELETE FROM hc_status_notices WHERE page_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, pageID); err != nil {
			return err
		}
	}
	for _, n := range in.Notices {
		if !validNoticeLevel(n.Level) {
			n.Level = "info"
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO hc_status_notices (page_id, title, level, created_at, updated_at, resolved_at) VALUES (?,?,?,?,?,?)`,
			pageID, n.Title, n.Level, ft(n.CreatedAt), ft(n.UpdatedAt), ft(n.ResolvedAt))
		if err != nil {
			return err
		}
		nid, _ := res.LastInsertId()
		for _, u := range n.Updates {
			if _, err := tx.ExecContext(ctx, `INSERT INTO hc_status_notice_updates (notice_id, time, text) VALUES (?,?,?)`, nid, ft(u.Time), u.Text); err != nil {
				return err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.statusChanged()
	return nil
}
