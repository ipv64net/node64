package web

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"

	"github.com/ipv64net/node64/internal/module"
)

// Dashboard nach Wunsch: Jeder Benutzer waehlt, welche Kacheln er sieht, in welcher Reihenfolge und wie breit.
// Gespeichert wird je Benutzer unter dashboard.layout.<id> (nur Kennung, Groesse, ausgeblendet); neue Kacheln
// (z. B. ein spaeter eingeschaltetes Modul) erscheinen hinten mit ihrer Voreinstellung.

const settingDashLayout = "dashboard.layout."

// Breiten der Kacheln (Bootstrap-Spalten): s = vier je Zeile, m = drei, l = zwei, xl = ganze Breite.
var dashCols = map[string]string{"s": "col-md-6 col-xl-3", "m": "col-md-6 col-xl-4", "l": "col-lg-6", "xl": "col-12"}

var dashIDRe = regexp.MustCompile(`^[a-z0-9_]{1,20}(:[a-z0-9_]{1,40})?$`)

// dashItem ist eine Kachel des Dashboards.
type dashItem struct {
	ID     string `json:"id"`
	Size   string `json:"size"`
	Hidden bool   `json:"hidden"`
	// nur fuer die Anzeige
	Kind  string                `json:"-"` // board, incidents, card, chart, node, storage, modules, account, link
	Board *module.DashboardInfo `json:"-"`
	Card  *module.Card          `json:"-"`
	Chart string                `json:"-"` // dns64, cdn64
}

// Col: Bootstrap-Spalten fuer die Groesse.
func (i dashItem) Col() string { return dashCols[i.Size] }

// dashAvailable: die Kacheln, die es auf dieser Node gerade gibt, mit Voreinstellung (Reihenfolge, Groesse, sichtbar).
func dashAvailable(boards []module.DashboardInfo, cards []namedCard, dns64On, cdn64On bool) []dashItem {
	var out []dashItem
	for i := range boards {
		b := &boards[i]
		out = append(out, dashItem{ID: "board:" + b.Module, Size: "xl", Kind: "board", Board: b},
			dashItem{ID: "incidents:" + b.Module, Size: "l", Kind: "incidents", Board: b})
	}
	for i := range cards {
		out = append(out, dashItem{ID: "card:" + cards[i].Module, Size: "s", Kind: "card", Card: &cards[i].Card})
	}
	if dns64On {
		out = append(out, dashItem{ID: "chart:dns64", Size: "l", Hidden: true, Kind: "chart", Chart: "dns64"})
	}
	if cdn64On {
		out = append(out, dashItem{ID: "chart:cdn64", Size: "l", Hidden: true, Kind: "chart", Chart: "cdn64"})
	}
	for _, k := range []string{"node", "storage", "modules", "account", "link"} {
		out = append(out, dashItem{ID: k, Size: "s", Kind: k})
	}
	return out
}

// namedCard ist die Karte eines Moduls mit dessen Namen (Kennung der Kachel).
type namedCard struct {
	Module string
	Card   module.Card
}

// dashMerge legt die gespeicherte Einstellung ueber die vorhandenen Kacheln: gespeicherte Reihenfolge, Groesse und
// Sichtbarkeit; was es nicht mehr gibt, faellt weg; neue Kacheln kommen hinten dazu.
func dashMerge(avail []dashItem, saved []dashItem) []dashItem {
	byID := make(map[string]int, len(avail))
	for i, a := range avail {
		byID[a.ID] = i
	}
	used := make(map[string]bool, len(avail))
	out := make([]dashItem, 0, len(avail))
	for _, s := range saved {
		i, ok := byID[s.ID]
		if !ok || used[s.ID] {
			continue
		}
		it := avail[i]
		if _, ok := dashCols[s.Size]; ok {
			it.Size = s.Size
		}
		it.Hidden = s.Hidden
		out = append(out, it)
		used[s.ID] = true
	}
	for _, a := range avail {
		if !used[a.ID] {
			out = append(out, a)
		}
	}
	return out
}

func (s *Server) dashSaved(ctx context.Context, userID int64) []dashItem {
	var saved []dashItem
	if raw := s.Store.SettingOr(ctx, settingDashLayout+strconv.FormatInt(userID, 10), ""); raw != "" {
		_ = json.Unmarshal([]byte(raw), &saved)
	}
	return saved
}

// ---------------------------------------------------------------- API (auch fuer die Oberflaeche)

func (s *Server) apiDashLayoutGet(w http.ResponseWriter, r *http.Request) {
	saved := s.dashSaved(r.Context(), currentUser(r).ID)
	if saved == nil {
		saved = []dashItem{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": saved, "sizes": []string{"s", "m", "l", "xl"}})
}

// apiDashLayoutPut speichert Reihenfolge, Groesse und Sichtbarkeit der Kacheln des angemeldeten Benutzers.
func (s *Server) apiDashLayoutPut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Items []dashItem `json:"items"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if len(in.Items) > 200 {
		writeErr(w, http.StatusUnprocessableEntity, "at most 200 items")
		return
	}
	clean := make([]dashItem, 0, len(in.Items))
	seen := map[string]bool{}
	for _, it := range in.Items {
		if !dashIDRe.MatchString(it.ID) || seen[it.ID] {
			writeErr(w, http.StatusUnprocessableEntity, "invalid or duplicate id: "+it.ID)
			return
		}
		if _, ok := dashCols[it.Size]; !ok {
			writeErr(w, http.StatusUnprocessableEntity, "size must be s, m, l or xl")
			return
		}
		seen[it.ID] = true
		clean = append(clean, dashItem{ID: it.ID, Size: it.Size, Hidden: it.Hidden})
	}
	b, _ := json.Marshal(clean)
	if err := s.Store.SetSetting(r.Context(), settingDashLayout+strconv.FormatInt(currentUser(r).ID, 10), string(b)); err != nil {
		s.log.Error("dashboard layout", "err", err)
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": clean})
}

// apiDashLayoutDelete setzt das Dashboard auf die Voreinstellung zurueck.
func (s *Server) apiDashLayoutDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.Store.SetSetting(r.Context(), settingDashLayout+strconv.FormatInt(currentUser(r).ID, 10), ""); err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
