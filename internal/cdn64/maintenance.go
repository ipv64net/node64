package cdn64

import (
	_ "embed"
	"html"
	"net/http"
	"strings"
	"unicode/utf8"
)

// Wartungsmodus je Proxy-Host: der Name bleibt erreichbar, statt des Ziels antwortet PROXY64 mit einer Wartungsseite
// (503, Retry-After, nie zwischenspeichern). Nur Proxy-Hosts: beim Durchreichen (TLS beim Ziel) und bei Streams sieht
// PROXY64 keine Anfragen. Gilt auch fuer CDN64 Modus 1 und 2 (beide kommen beim Handler der Node an), nicht fuer
// Modus 3 (die Edge geht dort direkt zum Ziel). ACME-HTTP-01 und die Pruefung der CDN-Bruecke beantwortet der Eingang
// vor dem Host, sie laufen auch in der Wartung.

// Gestaltung der Wartungsseite (Advanced.MaintenanceStyle).
const (
	MaintMatrix = "matrix" // Terminal im Matrix-Stil (wie die Startseite des Honeypots), Standard
	MaintGear   = "gear"   // schlicht mit drehendem Zahnrad, hell/dunkel nach System
	MaintCustom = "custom" // eigenes HTML
)

// MaintStyles: Auswahl im Formular (Standard zuerst).
var MaintStyles = []string{MaintMatrix, MaintGear, MaintCustom}

const (
	maintMaxHTML    = 64 << 10 // eigenes HTML hoechstens 64 KB
	maintRetryAfter = "600"    // Sekunden: Hinweis an Browser und Suchmaschinen
	rejMaintenance  = "maintenance"
)

//go:embed maint_matrix.html
var maintMatrixHTML string

//go:embed maint_gear.html
var maintGearHTML string

// normalizeMaint prueft die Einstellungen des Wartungsmodus (nur Proxy-Hosts).
func (a *Advanced) normalizeMaint(kind string) error {
	if kind != KindProxy {
		a.Maintenance, a.MaintenanceStyle, a.MaintenanceHTML = false, "", ""
		return nil
	}
	switch a.MaintenanceStyle {
	case MaintGear, MaintCustom:
	default:
		a.MaintenanceStyle = MaintMatrix
	}
	if len(a.MaintenanceHTML) > maintMaxHTML || !utf8.ValidString(a.MaintenanceHTML) {
		return ferr("maintenance_html", "cdn64.err.maint_html_size")
	}
	if a.Maintenance && a.MaintenanceStyle == MaintCustom && strings.TrimSpace(a.MaintenanceHTML) == "" {
		return ferr("maintenance_html", "cdn64.err.maint_html_empty")
	}
	return nil
}

// maintPage liefert die Seite fuer einen Stil; {{HOST}} wird durch den angefragten Namen ersetzt (eigenes HTML bleibt
// unveraendert).
func maintPage(style, custom, host string) string {
	switch style {
	case MaintCustom:
		return custom
	case MaintGear:
		return strings.ReplaceAll(maintGearHTML, "{{HOST}}", html.EscapeString(host))
	}
	return strings.ReplaceAll(maintMatrixHTML, "{{HOST}}", html.EscapeString(host))
}

// serveMaint beantwortet eine Anfrage im Wartungsmodus.
func serveMaint(w http.ResponseWriter, r *http.Request, a *Advanced) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Retry-After", maintRetryAfter)
	h.Set("X-Robots-Tag", "noindex")
	w.WriteHeader(http.StatusServiceUnavailable)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(maintPage(a.MaintenanceStyle, a.MaintenanceHTML, hostOnly(r.Host))))
	}
}
