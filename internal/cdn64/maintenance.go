package cdn64

import (
	_ "embed"
	"html"
	"io"
	"net/http"
	"strconv"
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

// keepPage: Kopf an den CDN64-Server (Modus 2), die 5xx-Seite der Node nicht durch seine eigene zu ersetzen
// (internal/cdnedge/errorpage.go) - Wartungsseite und eigene Fehlerseite sollen beim Besucher ankommen.
const keepPage = "CDN64-Error-Page"

// keepOwnPage: selbst erzeugte Seite (Wartung, eigene Fehlerseite, feste 5xx einer Location) nicht ersetzen lassen.
func keepOwnPage(h http.Header) { h.Set(keepPage, "off") }

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

// normalizeErrPage prueft die eigene Fehlerseite (nur Proxy-Hosts; ohne Seite nichts zu ersetzen).
func (a *Advanced) normalizeErrPage(kind string) error {
	if kind != KindProxy {
		a.ErrorHTML, a.ErrorOverride = "", false
		return nil
	}
	if len(a.ErrorHTML) > maintMaxHTML || !utf8.ValidString(a.ErrorHTML) {
		return ferr("error_html", "cdn64.err.error_html_size")
	}
	if strings.TrimSpace(a.ErrorHTML) == "" {
		a.ErrorHTML, a.ErrorOverride = "", false
	}
	return nil
}

// errPageFor: eigene Fehlerseite fuer einen Status ("" = keine bzw. Status ohne eigene Seite).
func errPageFor(a *Advanced, status int, host string) string {
	if a == nil || a.ErrorHTML == "" || status < 500 || status > 599 {
		return ""
	}
	s := strings.ReplaceAll(a.ErrorHTML, "{{STATUS}}", strconv.Itoa(status))
	return strings.ReplaceAll(s, "{{HOST}}", html.EscapeString(host))
}

// hostPage: Fehlerseite eines Proxy-Hosts - eigene Seite bei 502/503/504 von PROXY64, sonst die neutrale.
func hostPage(w http.ResponseWriter, r *http.Request, a *Advanced, status int) {
	body := ""
	if status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout {
		body = errPageFor(a, status, hostOnly(r.Host))
	}
	if body == "" {
		page(w, status)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	keepOwnPage(w.Header())
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, body)
	}
}

// overrideErr ersetzt eine 5xx-Antwort des Ziels durch die eigene Fehlerseite (Status bleibt).
func overrideErr(a *Advanced, resp *http.Response) {
	if !a.ErrorOverride || resp.StatusCode < 500 || resp.StatusCode > 599 {
		return
	}
	host := ""
	if in := visitorReq(resp); in != nil { // Name beim Besucher, nicht der Host-Kopf zum Ziel
		host = hostOnly(in.Host)
	}
	body := errPageFor(a, resp.StatusCode, host)
	if body == "" {
		return
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	resp.Body = io.NopCloser(strings.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.TransferEncoding = nil
	for _, k := range []string{"Content-Encoding", "Content-Range", "Etag", "Last-Modified", "Content-Disposition", "Content-Security-Policy"} {
		resp.Header.Del(k)
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Set("Cache-Control", "no-store")
	keepOwnPage(resp.Header)
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
	keepOwnPage(h)
	w.WriteHeader(http.StatusServiceUnavailable)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(maintPage(a.MaintenanceStyle, a.MaintenanceHTML, hostOnly(r.Host))))
	}
}
