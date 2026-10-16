package certsui

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/certs"
)

// Downloads: PEM-Dateien wie bei certbot, alles in einer Datei, ZIP und PKCS#12. Formate mit Schluessel stehen
// im Audit. Seite und API teilen sich ServeFile (ETag = Fingerabdruck, damit Skripte nur bei Aenderung laden).

// ServeFile schreibt ein Format eines Zertifikats als Datei (304 bei passendem If-None-Match, sent = false).
func ServeFile(w http.ResponseWriter, r *http.Request, b *certs.Bundle, format string) (sent bool, err error) {
	data, name, ctype, err := b.File(format)
	if err != nil {
		return false, err
	}
	etag := `"` + b.Fingerprint + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Cert-Not-After", b.Leaf.NotAfter.UTC().Format("2006-01-02T15:04:05Z"))
	if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, etag) {
		w.WriteHeader(http.StatusNotModified)
		return false, nil
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
	return true, nil
}

// ServeP12 schreibt die PKCS#12-Datei.
func ServeP12(w http.ResponseWriter, b *certs.Bundle, password string, legacy bool) error {
	data, err := b.P12(password, legacy)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/x-pkcs12")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.p12"`, b.FileBase()))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
	return nil
}

func (u *UI) bundleFromPath(w http.ResponseWriter, r *http.Request) (*certs.Bundle, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		b, err := u.m.Bundle(r.Context(), id)
		if err == nil {
			return b, true
		}
	}
	http.NotFound(w, r)
	return nil, false
}

func (u *UI) pageCertDownload(w http.ResponseWriter, r *http.Request) {
	b, ok := u.bundleFromPath(w, r)
	if !ok {
		return
	}
	format := r.URL.Query().Get("f")
	sent, err := ServeFile(w, r, b, format)
	if err != nil {
		http.Error(w, u.certError(r, err), http.StatusBadRequest)
		return
	}
	if sent && certs.HasKey(format) {
		u.g.Audit(r, "cert.download", strconv.FormatInt(b.ID, 10), "format="+format+" names="+b.Name)
	}
}

func (u *UI) pageCertP12(w http.ResponseWriter, r *http.Request) {
	b, ok := u.bundleFromPath(w, r)
	if !ok {
		return
	}
	legacy := r.PostFormValue("legacy") == "on"
	if err := ServeP12(w, b, r.PostFormValue("password"), legacy); err != nil {
		u.g.Flash(w, r, "danger", u.certError(r, err))
		http.Redirect(w, r, Base, http.StatusSeeOther)
		return
	}
	u.g.Audit(r, "cert.download", strconv.FormatInt(b.ID, 10), fmt.Sprintf("format=p12 legacy=%v names=%s", legacy, b.Name))
}
