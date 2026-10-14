package dyndns

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/ipv64net/node64/internal/module"
)

//go:embed templates
var templateFS embed.FS

// Templates liefert die Seiten des Moduls (module.Templater).
func (m *Module) Templates() fs.FS {
	sub, _ := fs.Sub(templateFS, "templates")
	return sub
}

// uiRoutes registriert die Seiten.
func (m *Module) uiRoutes(mux *http.ServeMux, g module.Guards) {
	m.g = g
	page := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /dyndns", page(m.pageOverview))
}

type overviewData struct {
	Targets int
}

func (m *Module) pageOverview(w http.ResponseWriter, r *http.Request) {
	var d overviewData
	_ = m.core.Reader().QueryRowContext(r.Context(), `SELECT count(*) FROM dyn_targets`).Scan(&d.Targets)
	m.g.Render(w, r, http.StatusOK, Name+"/overview", "dyn.title", d)
}
