package web

import (
	"net/http"

	"github.com/ipv64net/node64/internal/ipv64api"
)

// Seite "Account-Klassen": Uebersicht der Klassen von ipv64.net mit Preis und Grenzen, die eigene Klasse markiert.
// Daten ueber GET /plans der ipv64-API (einmal am Tag), sonst der eingebaute Stand der Preisseite.

type plansData struct {
	Plans      []ipv64api.Plan
	Live       bool
	Current    string // Klasse im Account (leer = nicht verbunden)
	CurrentKey string // passende Spalte (leer = Klasse nicht in der Uebersicht, z. B. VIP)
	Rows       [][2]string
	Cells      map[string]map[string]string // Klasse -> Grenze -> Anzeige ("∞" = unbegrenzt)
	PricingURL string
}

func (s *Server) plansPage(w http.ResponseWriter, r *http.Request) {
	v := s.view(r, "plans.title")
	d := plansData{Rows: ipv64api.PlanOrder, PricingURL: ipv64api.PricingURL, Current: currentPlan(v)}
	if s.IPv64 != nil {
		d.Plans, d.Live = s.IPv64.Plans(r.Context())
	}
	if p := ipv64api.PlanFor(d.Plans, d.Current); p != nil {
		d.CurrentKey = p.Key
	}
	d.Cells = map[string]map[string]string{}
	for _, p := range d.Plans {
		c := map[string]string{}
		for _, row := range d.Rows {
			if n := p.Limits[row[1]]; n != nil {
				c[row[1]] = v.Int(int64(*n))
			} else {
				c[row[1]] = "∞"
			}
		}
		d.Cells[p.Key] = c
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
