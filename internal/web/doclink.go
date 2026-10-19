package web

import (
	"html/template"
	"net/url"
	"strings"
)

// docsBase ist die Online-Dokumentation (Webseite node64.de, Seiten unter /docs/, Englisch unter /en/docs/).
const docsBase = "https://node64.de"

// DocURL liefert den Link in die Online-Dokumentation in der Sprache der Oberflaeche.
// ref = "<seite>#<sprungmarke>", z. B. "dyndns#ziele" -> https://node64.de/docs/dyndns/#ziele; leer = Uebersicht.
func (v *View) DocURL(ref string) string {
	page, anchor, _ := strings.Cut(ref, "#")
	u := docsBase
	if v.Lang != "de" {
		u += "/en"
	}
	u += "/docs/"
	if page = strings.Trim(page, "/"); page != "" {
		u += (&url.URL{Path: page}).EscapedPath() + "/"
	}
	if anchor != "" {
		u += "#" + url.PathEscape(anchor)
	}
	return u
}

// Doc ist ein kleines Hilfe-Symbol, das die passende Stelle der Online-Dokumentation in einem neuen Tab oeffnet.
// Im Template: {{.Doc "dyndns#ziele"}}
func (v *View) Doc(ref string) template.HTML {
	title := template.HTMLEscapeString(v.T("common.docs"))
	return template.HTML(`<a href="` + template.HTMLEscapeString(v.DocURL(ref)) + `" target="_blank" rel="noopener" class="doc-link link-secondary text-decoration-none ms-1 small" title="` +
		title + `" aria-label="` + title + `"><i class="bi bi-question-circle"></i></a>`)
}
