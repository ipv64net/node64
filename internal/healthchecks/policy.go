package healthchecks

import "github.com/ipv64net/node64/internal/scheduler"

// Bewertungsregeln fuer den Gesamtzustand eines Checks mit mehreren
// Messstellen (Node innen, ipv64-Standorte aussen). Standalone hat ein Check
// genau eine Messstelle, dann ist der Gesamtzustand ihr Zustand. Dieselbe
// Regel laeuft auf dem ipv64-Server (Sync-Plan 3.12).
const (
	PolicyAll      = "all"      // down nur, wenn alle Messstellen down sind (Standard)
	PolicyAny      = "any"      // down, sobald eine Messstelle down ist
	PolicyMajority = "majority" // down, wenn mehr als die Haelfte down ist
)

var Policies = []string{PolicyAll, PolicyAny, PolicyMajority}

// KnownLocations sind die ipv64-Standorte fuer Online-Messungen. Die Liste
// kommt spaeter vom Server; bis dahin fest.
var KnownLocations = []string{"nbg", "fsn"}

func ValidPolicy(p string) bool {
	for _, x := range Policies {
		if x == p {
			return true
		}
	}
	return false
}

// Overall berechnet den Gesamtzustand aus den Zustaenden der Messstellen.
// Messstellen ohne frische Daten (offline, pausiert, abhaengig, noch kein
// Ergebnis) zaehlen nicht mit. Sind alle ohne Daten, ist das Ergebnis pending.
func Overall(policy string, sources []scheduler.SourceState) scheduler.State {
	return scheduler.Overall(policy, sources)
}
