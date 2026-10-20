package healthchecks

import (
	"context"
	"errors"
	"net/http"

	"github.com/ipv64net/node64/internal/module"
)

// Statusseiten: Berechnung der oeffentlichen Sicht (Cache 30 s, nur auf Abruf) und oeffentliche Routen.
// PLATZHALTER: wird von der Sitzung "Statusseite Kern" ersetzt (Signaturen bleiben).

var errStatusTODO = errors.New("status pages: not implemented yet")

// StatusPageRef ist eine Seite zur Auswahl (PROXY64-Hostart "Statusseite").
type StatusPageRef struct {
	ID      int64
	Slug    string
	Title   string
	Enabled bool
}

// statusView berechnet die oeffentliche Sicht einer Seite (zwischengespeichert, lang "de"/"en").
func (m *Module) statusView(ctx context.Context, p *StatusPage, lang string) (*StatusView, error) {
	return nil, errStatusTODO
}

// statusItemDetail liefert die Details eines Eintrags der Seite.
func (m *Module) statusItemDetail(ctx context.Context, p *StatusPage, itemID int64, lang string) (*StatusItemDetail, error) {
	return nil, errStatusTODO
}

// statusRoutes meldet die oeffentlichen Routen /status/{slug}... an (nur eingeschaltete Seiten mit publish_node).
func (m *Module) statusRoutes(mux *http.ServeMux, g module.Guards) {}

// statusPreview zeigt eine Seite in der Verwaltung (angemeldet), auch wenn sie aus ist.
func (m *Module) statusPreview(w http.ResponseWriter, r *http.Request, p *StatusPage) {
	http.Error(w, errStatusTODO.Error(), http.StatusNotImplemented)
}

// StatusSite liefert die Seite mit dieser ID als eigene Website (Pfade relativ zu "/"), fuer PROXY64.
// Ist die Seite aus oder unbekannt, antwortet der Handler mit 404.
func (m *Module) StatusSite(id int64) http.Handler {
	return http.NotFoundHandler()
}

// StatusPageRefs liefert alle Seiten zur Auswahl (PROXY64).
func (m *Module) StatusPageRefs(ctx context.Context) []StatusPageRef {
	return nil
}
