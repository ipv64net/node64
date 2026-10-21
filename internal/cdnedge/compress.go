package cdnedge

import (
	"net/http"
	"path"
	"strings"
)

// Komprimierung in Modus 3 (Server direkt zum Ziel): liefert das Ziel Text unkomprimiert, komprimiert der Server mit
// zstd, Brotli oder gzip, je nach Browser (internal/httpcompress). Das spart Bandbreite und Traffic-Kontingent. Der
// Cache legt die fertig komprimierte Fassung ab; statische Dateien bekommen die staerkere Stufe. Modus 1 geht nicht
// (verschluesselt), Modus 2 komprimiert die Node (PROXY64).

// compressOn: Standard an, "off" in der Konfiguration schaltet ab.
func (s *Server) compressOn() bool { return !strings.EqualFold(strings.TrimSpace(s.cfg.Compression), "off") }

var staticExt = map[string]bool{".css": true, ".js": true, ".mjs": true, ".svg": true, ".json": true, ".map": true, ".txt": true,
	".xml": true, ".wasm": true, ".ttf": true, ".otf": true, ".eot": true, ".ico": true}

// staticAsset: Datei, die sich zum Ablegen im Cache eignet (staerkere Komprimierung).
func staticAsset(r *http.Request) bool { return staticExt[strings.ToLower(path.Ext(r.URL.Path))] }
