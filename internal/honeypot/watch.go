package honeypot

import (
	"context"
	"net/http"

	"github.com/ipv64net/node64/internal/module"
)

// Platzhalter (H5 Vertrag): wird vom Teil „Fruehwarnung“ ersetzt. Signaturen bleiben.
// Fruehwarnung fuer eigene Netze (Plan Abschnitt 11): Netze werden bei ipv64 gespeichert und dort bewertet
// (GET/POST/DELETE /api/v2/threat/watch, GET /api/v2/threat/watch/alerts); die Node verwaltet sie in der Oberflaeche
// und holt Treffer als Benachrichtigung ab.

// watchRoutes haengt Seite und API der Fruehwarnung ein (aus Routes).
func (m *Module) watchRoutes(mux *http.ServeMux, g module.Guards) {}

// watchLoop holt Treffer der Fruehwarnung ab (aus Start, laeuft bis ctx endet).
func (m *Module) watchLoop(ctx context.Context) { <-ctx.Done() }
