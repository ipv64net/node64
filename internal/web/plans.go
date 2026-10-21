package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/ipv64api"
)

// Seite "Account-Klassen": Uebersicht der Klassen von ipv64.net mit Preis und Grenzen, die eigene Klasse markiert,
// die beliebteste (Home / Supporter) hervorgehoben. Werte mit Einheit (GB/TB, Mbit/s, Sekunden, Tage).
// Daten ueber GET /plans der ipv64-API (einmal am Tag), sonst der eingebaute Stand der Preisseite.

type plansData struct {
	Plans      []ipv64api.Plan
	Live       bool
	Current    string // Klasse im Account (leer = nicht verbunden)
	CurrentKey string // passende Spalte (leer = Klasse nicht in der Uebersicht, z. B. VIP)
	PopularKey string // hervorgehobene Spalte
	Rows       [][2]string
	Cells      map[string]map[string]string // Klasse -> Grenze -> Anzeige ("∞" = unbegrenzt, "–" = nicht enthalten)
	Groups     map[string]map[string]bool   // Klasse -> Gruppe -> enthalten (mindestens eine Grenze > 0)
	Icons      map[string]string            // Gruppe -> Bootstrap-Icon
	PricingURL string
}

var planIcons = map[string]string{"dyndns": "bi-globe2", "healthchecks": "bi-heart-pulse", "failover": "bi-signpost-split", "cdn": "bi-diagram-3",
	"vpn": "bi-shield-lock", "other": "bi-three-dots"}

// planValue: Grenze lesbar mit Einheit (nach dem Schluessel: _gb, _mbit, _s, _days).
func planValue(v *View, key string, n *int) string {
	if n == nil {
		return "∞"
	}
	x := *n
	if x == 0 {
		return "–"
	}
	trim := func(f float64) string { return strings.TrimSuffix(strconv.FormatFloat(f, 'f', 1, 64), ".0") }
	switch {
	case strings.HasSuffix(key, "_gb"):
		if x >= 1024 {
			return v.T("plans.unit.tb", "n", trim(float64(x)/1024))
		}
		return v.T("plans.unit.gb", "n", v.Int(int64(x)))
	case strings.HasSuffix(key, "_mbit"):
		if x >= 1000 {
			return v.T("plans.unit.gbit", "n", trim(float64(x)/1000))
		}
		return v.T("plans.unit.mbit", "n", v.Int(int64(x)))
	case strings.HasSuffix(key, "_s"):
		return v.T("plans.unit.s", "n", v.Int(int64(x)))
	case strings.HasSuffix(key, "_days"):
		return v.T("plans.unit.days", "n", v.Int(int64(x)))
	}
	return v.Int(int64(x))
}

func (s *Server) plansPage(w http.ResponseWriter, r *http.Request) {
	v := s.view(r, "plans.title")
	d := plansData{Rows: ipv64api.PlanOrder, PricingURL: ipv64api.PricingURL, Current: currentPlan(v), PopularKey: ipv64api.PopularKey, Icons: planIcons}
	if s.IPv64 != nil {
		d.Plans, d.Live = s.IPv64.Plans(r.Context())
	}
	if p := ipv64api.PlanFor(d.Plans, d.Current); p != nil {
		d.CurrentKey = p.Key
	}
	d.Cells, d.Groups = map[string]map[string]string{}, map[string]map[string]bool{}
	for _, p := range d.Plans {
		c, g := map[string]string{}, map[string]bool{}
		for _, row := range d.Rows {
			n := p.Limits[row[1]]
			c[row[1]] = planValue(v, row[1], n)
			if n == nil || *n > 0 {
				g[row[0]] = true
			}
		}
		d.Cells[p.Key], d.Groups[p.Key] = c, g
	}
	v.Data = d
	s.render(w, r, http.StatusOK, "plans", v)
}

// Plan: Account-Klasse fuer die Seitenleiste (leer = nicht mit ipv64 verbunden).
func (v *View) Plan() string { return currentPlan(v) }

// currentPlan: Account-Klasse aus dem API-Key, sonst aus der Healthchecks-Verknuepfung (leer = nicht verbunden).
func currentPlan(v *View) string {
	if v.APIOk && v.API.Plan != "" {
		return v.API.Plan
	}
	if v.Sync.Linked {
		return v.Sync.Plan
	}
	return ""
}
