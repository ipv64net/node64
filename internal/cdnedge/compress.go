package cdnedge

import (
	"net/http"
	"strings"

	"github.com/ipv64net/node64/internal/httpcompress"
)

// Komprimierung in Modus 3 (Server direkt zum Ziel): liefert das Ziel Text unkomprimiert, komprimiert der Server mit
// zstd, Brotli oder gzip, je nach Browser (internal/httpcompress). Das spart Bandbreite und Traffic-Kontingent. Der
// Cache legt die fertig komprimierte Fassung ab; was er ablegt, bekommt die staerkere Stufe. Modus 1 geht nicht
// (verschluesselt), Modus 2 komprimiert die Node (PROXY64).

// compressOn: Standard an, "off" in der Konfiguration schaltet ab.
func (s *Server) compressOn() bool {
	return !strings.EqualFold(strings.TrimSpace(s.cfg.Compression), "off")
}

// staticCached: staerkere Komprimierung nur, wenn die Antwort danach im Cache liegt - Datei mit Text-Endung
// (httpcompress.StaticExt), Cache des Namens an, nicht umgangen (serveCached) und die Antwort cachebar.
func staticCached(r *http.Request, h http.Header) bool {
	cw, _ := r.Context().Value(captureKey{}).(*captureWriter)
	if cw == nil || !httpcompress.StaticExt(r.URL.Path) {
		return false
	}
	_, ok := cw.storable(http.StatusOK, h)
	return ok
}
