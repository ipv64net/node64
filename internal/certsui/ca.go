package certsui

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/certs"
)

// Eigene CAs (erzeugen, importieren, verteilen) und weitere ACME-Stellen (ZeroSSL, Google, step-ca …).

func (u *UI) caRoutes(mux *http.ServeMux, page func(http.HandlerFunc) http.Handler) {
	mux.Handle("GET "+Base+"/ca/new", page(u.pageCANew))
	mux.Handle("POST "+Base+"/ca", page(u.pageCACreate))
	mux.Handle("POST "+Base+"/ca/import", page(u.pageCAImport))
	mux.Handle("GET "+Base+"/ca/{id}/file", page(u.pageCAFile))
	mux.Handle("POST "+Base+"/ca/{id}/delete", page(u.pageCADelete))
	mux.Handle("GET "+Base+"/acme/new", page(u.pageACMENew))
	mux.Handle("POST "+Base+"/acme", page(u.pageACMECreate))
	mux.Handle("POST "+Base+"/acme/{id}/delete", page(u.pageACMEDelete))
}

type caForm struct {
	Name, Domains, ImportName string
	KeyType                   string
	Constrained               bool
	Error, ImportErr          string
}

func (u *UI) pageCANew(w http.ResponseWriter, r *http.Request) {
	u.g.Render(w, r, http.StatusOK, Name+"/ca_new", "certs.ca.new", caForm{KeyType: "ecdsa", Constrained: true})
}

func (u *UI) pageCACreate(w http.ResponseWriter, r *http.Request) {
	f := caForm{Name: r.PostFormValue("name"), Domains: r.PostFormValue("domains"), KeyType: r.PostFormValue("key_type"), Constrained: r.PostFormValue("constrained") == "on"}
	on := f.Constrained
	ca, err := u.m.CreateCA(r.Context(), certs.CAInput{Name: f.Name, KeyType: f.KeyType, Constrained: &on, Domains: ParseNames(f.Domains)})
	if err != nil {
		f.Error = u.certError(r, err)
		u.g.Render(w, r, http.StatusUnprocessableEntity, Name+"/ca_new", "certs.ca.new", f)
		return
	}
	u.g.Audit(r, "cert.ca.create", strconv.FormatInt(ca.ID, 10), fmt.Sprintf("name=%s constrained=%v", ca.Name, on))
	u.g.Flash(w, r, "success", u.g.T(r, "certs.ca.created", "name", ca.Name))
	http.Redirect(w, r, Base, http.StatusSeeOther)
}

func (u *UI) pageCAImport(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	name := r.PostFormValue("import_name")
	certPEM, keyPEM := readPEMFields(r)
	ca, err := u.m.ImportCA(r.Context(), name, certPEM, keyPEM)
	if err != nil {
		u.g.Render(w, r, http.StatusUnprocessableEntity, Name+"/ca_new", "certs.ca.new", caForm{KeyType: "ecdsa", Constrained: true, ImportName: name,
			ImportErr: u.certError(r, err)})
		return
	}
	u.g.Audit(r, "cert.ca.import", strconv.FormatInt(ca.ID, 10), "name="+ca.Name)
	u.g.Flash(w, r, "success", u.g.T(r, "certs.ca.imported", "name", ca.Name))
	http.Redirect(w, r, Base, http.StatusSeeOther)
}

func (u *UI) pageCAFile(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	data, name, ctype, err := u.m.CAFile(r.Context(), id, r.URL.Query().Get("f"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	_, _ = w.Write(data)
}

func (u *UI) pageCADelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	ca, err := u.m.GetCA(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := u.m.DeleteCA(r.Context(), id); errors.Is(err, certs.ErrInUse) {
		u.g.Flash(w, r, "danger", u.g.T(r, "certs.ca.in_use", "name", ca.Name))
	} else if err != nil {
		u.g.Flash(w, r, "danger", u.certError(r, err))
	} else {
		u.g.Audit(r, "cert.ca.delete", strconv.FormatInt(id, 10), "name="+ca.Name)
		u.g.Flash(w, r, "success", u.g.T(r, "certs.ca.deleted", "name", ca.Name))
	}
	http.Redirect(w, r, Base, http.StatusSeeOther)
}

type acmeForm struct {
	Presets                       []certs.ACMEPreset
	Name, Directory, KID, RootPEM string
	Error                         string
}

func (u *UI) pageACMENew(w http.ResponseWriter, r *http.Request) {
	u.g.Render(w, r, http.StatusOK, Name+"/acme_new", "certs.acme.new", acmeForm{Presets: certs.ACMEPresets})
}

func (u *UI) pageACMECreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	in := certs.ACMECAInput{Name: r.PostFormValue("name"), Directory: r.PostFormValue("directory"), EABKID: r.PostFormValue("eab_kid"),
		EABHMAC: r.PostFormValue("eab_hmac"), RootPEM: r.PostFormValue("root_pem"), AcceptTOS: r.PostFormValue("accept_tos") == "on"}
	a, err := u.m.AddACMECA(r.Context(), in)
	if err != nil {
		u.g.Render(w, r, http.StatusUnprocessableEntity, Name+"/acme_new", "certs.acme.new", acmeForm{Presets: certs.ACMEPresets, Name: in.Name,
			Directory: in.Directory, KID: in.EABKID, RootPEM: in.RootPEM, Error: u.certError(r, err)})
		return
	}
	u.g.Audit(r, "cert.acme_ca.create", strconv.FormatInt(a.ID, 10), fmt.Sprintf("name=%s directory=%s eab=%v", a.Name, a.Directory, a.HasEAB))
	u.g.Flash(w, r, "success", u.g.T(r, "certs.acme.created", "name", a.Name))
	http.Redirect(w, r, Base, http.StatusSeeOther)
}

func (u *UI) pageACMEDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	a, err := u.m.ACMECA(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := u.m.DeleteACMECA(r.Context(), id); errors.Is(err, certs.ErrInUse) {
		u.g.Flash(w, r, "danger", u.g.T(r, "certs.acme.in_use", "name", a.Name))
	} else if err != nil {
		u.g.Flash(w, r, "danger", u.certError(r, err))
	} else {
		u.g.Audit(r, "cert.acme_ca.delete", strconv.FormatInt(id, 10), "name="+a.Name)
		u.g.Flash(w, r, "success", u.g.T(r, "certs.acme.deleted", "name", a.Name))
	}
	http.Redirect(w, r, Base, http.StatusSeeOther)
}

// readPEMFields liest Zertifikat und Schluessel aus Datei-Feldern (cert_file, key_file) oder Textfeldern.
func readPEMFields(r *http.Request) (certPEM, keyPEM string) {
	certPEM, keyPEM = r.PostFormValue("cert"), r.PostFormValue("key")
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
		if err := r.ParseMultipartForm(1 << 20); err == nil {
			read := func(name, fallback string) string {
				f, _, err := r.FormFile(name)
				if err != nil {
					return r.FormValue(fallback)
				}
				defer f.Close()
				b, _ := io.ReadAll(io.LimitReader(f, 1<<20))
				if strings.TrimSpace(string(b)) == "" {
					return r.FormValue(fallback)
				}
				return string(b)
			}
			certPEM, keyPEM = read("cert_file", "cert"), read("key_file", "key")
		}
	}
	return certPEM, keyPEM
}
