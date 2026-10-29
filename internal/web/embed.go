package web

import (
	"embed"
	"io/fs"
	"path"
	"strings"
)

// Alle Assets und Templates liegen im Binary. Nichts wird von aussen geladen,
// die Oberflaeche funktioniert komplett offline.

//go:embed static
var staticFS embed.FS

//go:embed templates
var templateFS embed.FS

// darkImage: Bild fuer das dunkle Design (name_dark.ext unter static/img), sonst das Bild selbst.
func darkImage(name string) string {
	ext := path.Ext(name)
	dark := strings.TrimSuffix(name, ext) + "_dark" + ext
	if _, err := fs.Stat(staticFS, "static/img/"+dark); err == nil {
		return dark
	}
	return name
}

// dict: Werte fuer einen Baustein ({{template "x" (dict "A" 1 "B" .)}}); Schluessel und Wert im Wechsel.
func dict(kv ...any) map[string]any {
	m := make(map[string]any, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		if k, ok := kv[i].(string); ok {
			m[k] = kv[i+1]
		}
	}
	return m
}
