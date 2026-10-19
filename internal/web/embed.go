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
