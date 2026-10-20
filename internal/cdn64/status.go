package cdn64

import (
	"context"
	"net/http"
)

// Hostart "status": eine Domain zeigt eine Statusseite der Healthchecks. Die Seite kommt ueber StatusPages
// (main.go verdrahtet das Modul Healthchecks, kein Import hier); davor greift alles aus handlerFor
// (Blocklisten, Laendersperre, Limits, Exploit-Sperre, Zugriffsliste, Statistik, Zugriffs-Log).

// StatusPageInfo ist eine Statusseite zur Auswahl im Formular.
type StatusPageInfo struct {
	ID      int64
	Slug    string
	Title   string
	Enabled bool
}

// StatusPages liefert die Statusseiten der Healthchecks.
type StatusPages interface {
	// StatusSite liefert die Seite als eigene Website (Pfade relativ zu "/"); aus oder unbekannt -> 404.
	// Wird je Anfrage aufgerufen; nil = Healthchecks nicht verfuegbar (ausgeschaltet).
	StatusSite(id int64) http.Handler
	// StatusPageList liefert alle Seiten (nil = Healthchecks nicht verfuegbar).
	StatusPageList(ctx context.Context) []StatusPageInfo
}

// SetStatusPages haengt die Statusseiten der Healthchecks an (Hostart "status").
func (m *Module) SetStatusPages(sp StatusPages) { m.status = sp }

// statusHandler liefert die Statusseite eines Hosts; ohne Healthchecks 503.
func (m *Module) statusHandler(h *Host) http.Handler {
	id := h.StatusPageID
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var site http.Handler
		if m.status != nil {
			site = m.status.StatusSite(id)
		}
		if site == nil {
			page(w, http.StatusServiceUnavailable)
			return
		}
		site.ServeHTTP(w, r)
	})
}

// statusPages: alle Statusseiten (nil ohne Healthchecks).
func (m *Module) statusPages(ctx context.Context) []StatusPageInfo {
	if m.status == nil {
		return nil
	}
	return m.status.StatusPageList(ctx)
}
