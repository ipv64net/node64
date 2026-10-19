// Package certsui ist die Seite „Zertifikate“ des Kerns: Oberflaeche fuer die Zertifikatsverwaltung
// (internal/certs) mit eigenem Menuepunkt, unabhaengig davon, welche Module laufen. Let's Encrypt ueber ipv64,
// Alias per CNAME, DNS-Anbieter (lego), HTTP-01 und eigene Zertifikate. Die JSON-API dazu ist /api/certs (web).
package certsui

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/module"
)

// Name ist das Praefix der Seiten-Templates ("certs/<seite>").
const Name = "certs"

// Base ist der Pfad der Seite.
const Base = "/certificates"

//go:embed templates
var templateFS embed.FS

// UI ist die Zertifikatsseite.
type UI struct {
	m *certs.Manager
	g module.Guards
}

// New baut die Seite fuer die Verwaltung m.
func New(m *certs.Manager) *UI { return &UI{m: m} }

// Templates liefert die Seiten-Templates (pages/*.html).
func (u *UI) Templates() fs.FS {
	sub, _ := fs.Sub(templateFS, "templates")
	return sub
}

// Routes registriert die Seiten (alle mit Anmeldung).
func (u *UI) Routes(mux *http.ServeMux, g module.Guards) {
	u.g = g
	page := func(h http.HandlerFunc) http.Handler { return g.Auth(h) }
	mux.Handle("GET "+Base, page(u.pageCerts))
	mux.Handle("GET "+Base+"/new", page(u.pageCertNew))
	mux.Handle("POST "+Base, page(u.pageCertCreate))
	mux.Handle("POST "+Base+"/upload", page(u.pageCertUpload))
	mux.Handle("POST "+Base+"/account", page(u.pageCertAccount))
	mux.Handle("POST "+Base+"/{id}/renew", page(u.pageCertRenew))
	mux.Handle("POST "+Base+"/{id}/autorenew", page(u.pageCertAutoRenew))
	mux.Handle("POST "+Base+"/{id}/delete", page(u.pageCertDelete))
	mux.Handle("GET "+Base+"/{id}/chain.pem", page(u.pageCertChain))
	mux.Handle("GET "+Base+"/{id}/download", page(u.pageCertDownload))
	mux.Handle("POST "+Base+"/{id}/p12", page(u.pageCertP12))
	// DNS-Zugaenge: vier Stufen, damit sich die Pfade nicht mit /certificates/{id}/... ueberschneiden
	mux.Handle("GET "+Base+"/dns-accounts/new", page(u.pageDNSNew))
	mux.Handle("POST "+Base+"/dns-accounts", page(u.pageDNSSave))
	mux.Handle("GET "+Base+"/dns-accounts/{id}/edit", page(u.pageDNSEdit))
	mux.Handle("POST "+Base+"/dns-accounts/{id}/edit", page(u.pageDNSSave))
	mux.Handle("POST "+Base+"/dns-accounts/{id}/delete", page(u.pageDNSDelete))
	u.caRoutes(mux, page)
}

type cnamePair struct{ From, To string }

type certRow struct {
	*certs.Cert
	Pill   string // ok, soon, expired, none
	CNAMEs []cnamePair
}

type certsData struct {
	Rows      []certRow
	Account   certs.Account
	DNSReady  bool
	HTTPReady bool
	Issuing   bool
	DNS       []*certs.DNSAccount
	CAs       []*certs.CA
	ACME      []*certs.ACMECA
	ACMENames map[int64]string
}

func certPill(c *certs.Cert) string {
	switch {
	case c.NotAfter.IsZero():
		return "none"
	case time.Now().After(c.NotAfter):
		return "expired"
	case c.DaysLeft() < 7:
		return "expired" // rot: unter 7 Tagen
	case c.DaysLeft() < 30:
		return "soon"
	}
	return "ok"
}

func (u *UI) pageCerts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	list, err := u.m.List(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	d := certsData{Account: u.m.Account(ctx), DNSReady: u.m.DNSReady(ctx), HTTPReady: u.m.HTTPReady(), ACMENames: map[int64]string{}}
	d.DNS, _ = u.m.DNSAccounts(ctx)
	d.CAs, _ = u.m.CAs(ctx)
	d.ACME, _ = u.m.ACMECAs(ctx)
	for _, a := range d.ACME {
		d.ACMENames[a.ID] = a.Name
	}
	for _, c := range list {
		row := certRow{Cert: c, Pill: certPill(c)}
		if c.Source == certs.SourceAlias {
			for _, n := range c.Names {
				from, to := certs.AliasCNAME(n, c.AliasZone, c.AliasPrefix)
				row.CNAMEs = append(row.CNAMEs, cnamePair{From: from, To: to})
			}
		}
		d.Issuing = d.Issuing || c.Step != ""
		d.Rows = append(d.Rows, row)
	}
	u.g.Render(w, r, http.StatusOK, Name+"/certs", "certs.title", d)
}

type certNewData struct {
	Account    certs.Account
	DNSReady   bool
	HTTPReady  bool
	Domains    []string
	DomainsErr string
	Names      string
	Source     string
	AliasZone  string
	AliasPref  string
	Staging    bool
	Error      string
	UploadErr  string
	DNS        []*certs.DNSAccount
	DNSAccount int64
	CAs        []*certs.CA
	ACME       []*certs.ACMECA
	CAID       int64
	Days       int
	ACMECA     int64
	KeyType    string
}

func (u *UI) certNewData(ctx context.Context) certNewData {
	d := certNewData{Account: u.m.Account(ctx), DNSReady: u.m.DNSReady(ctx), HTTPReady: u.m.HTTPReady(), Source: "auto", Days: 397}
	d.DNS, _ = u.m.DNSAccounts(ctx)
	d.CAs, _ = u.m.CAs(ctx)
	d.ACME, _ = u.m.ACMECAs(ctx)
	if d.DNSReady {
		dctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		if list, err := u.m.Domains(dctx); err != nil {
			d.DomainsErr = err.Error()
		} else {
			d.Domains = list
		}
	}
	return d
}

// ParseNames trennt eine Eingabe mit Namen (Komma, Leerzeichen, Zeilen, Semikolon).
func ParseNames(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' || r == ';' })
}

func (u *UI) pageCertNew(w http.ResponseWriter, r *http.Request) {
	d := u.certNewData(r.Context())
	d.Names = strings.Join(ParseNames(r.URL.Query().Get("names")), "\n")
	u.g.Render(w, r, http.StatusOK, Name+"/cert_new", "certs.new", d)
}

// ErrorText: verstaendliche Meldung fuer Fehler der Verwaltung (t uebersetzt in der Sprache des Aufrufers).
func ErrorText(t func(key string, args ...any) string, err error) string {
	var ve *certs.ValidationError
	switch {
	case errors.As(err, &ve):
		return t("certs.err."+ve.Field) + " (" + ve.Msg + ")"
	case errors.Is(err, certs.ErrTOS):
		return t("certs.err.tos")
	case errors.Is(err, certs.ErrNoKey):
		return t("certs.err.nokey")
	case errors.Is(err, certs.ErrInUse):
		return t("certs.err.in_use")
	case errors.Is(err, certs.ErrBusy):
		return t("certs.err.busy")
	case errors.Is(err, certs.ErrUpload):
		return t("certs.err.upload_renew")
	case errors.Is(err, certs.ErrNoCert):
		return t("certs.err.no_cert")
	case errors.Is(err, certs.ErrKeyPassword):
		return t("certs.err.key_password")
	}
	return err.Error()
}

func (u *UI) certError(r *http.Request, err error) string {
	return ErrorText(func(key string, args ...any) string { return u.g.T(r, key, args...) }, err)
}

// AuditCreate schreibt das Anlegen eines Zertifikats ins Audit.
func AuditCreate(g module.Guards, r *http.Request, c *certs.Cert) {
	g.Audit(r, "cert.create", strconv.FormatInt(c.ID, 10), fmt.Sprintf("names=%s source=%s staging=%v", strings.Join(c.Names, ","), c.Source, c.Staging))
}

func (u *UI) pageCertCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d := u.certNewData(ctx)
	d.Names, d.Source = r.PostFormValue("names"), r.PostFormValue("source")
	d.AliasZone, d.AliasPref, d.Staging = r.PostFormValue("alias_zone"), r.PostFormValue("alias_prefix"), r.PostFormValue("staging") == "on"
	if r.PostFormValue("accept_tos") == "on" && !d.Account.TOSAccepted {
		if err := u.m.SetAccount(ctx, d.Account.Email, true); err == nil {
			u.g.Audit(r, "cert.account", "", "accept_tos=true")
			d.Account = u.m.Account(ctx)
		}
	}
	d.DNSAccount, _ = strconv.ParseInt(r.PostFormValue("dns_account"), 10, 64)
	d.CAID, _ = strconv.ParseInt(r.PostFormValue("ca_id"), 10, 64)
	d.ACMECA, _ = strconv.ParseInt(r.PostFormValue("acme_ca"), 10, 64)
	d.Days, _ = strconv.Atoi(r.PostFormValue("days"))
	if d.Source == certs.SourceSelf { // eigenes Feld, damit es nicht mit der Laufzeit der CA kollidiert
		d.Days, _ = strconv.Atoi(r.PostFormValue("self_days"))
	}
	d.KeyType = r.PostFormValue("key_type")
	names := ParseNames(d.Names)
	source := d.Source
	if source == "" || source == "auto" {
		source = u.m.AutoSource(ctx, names)
	}
	c, err := u.m.Create(ctx, certs.Request{Names: names, Source: source, AliasZone: d.AliasZone, AliasPrefix: d.AliasPref, DNSAccount: d.DNSAccount, Staging: d.Staging,
		CAID: d.CAID, Days: d.Days, ACMECA: d.ACMECA, KeyType: d.KeyType})
	if err != nil {
		d.Error = u.certError(r, err)
		u.g.Render(w, r, http.StatusUnprocessableEntity, Name+"/cert_new", "certs.new", d)
		return
	}
	AuditCreate(u.g, r, c)
	u.g.Flash(w, r, "success", u.g.T(r, "certs.requested", "name", c.Title()))
	http.Redirect(w, r, Base, http.StatusSeeOther)
}

func (u *UI) pageCertUpload(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	certPEM, keyPEM, err := certs.PrepareUpload(readPEMFields(r, r.PostFormValue("key_password")))
	var c *certs.Cert
	if err == nil {
		c, err = u.m.Upload(ctx, certPEM, keyPEM)
	}
	if err != nil {
		d := u.certNewData(ctx)
		d.UploadErr = u.certError(r, err)
		u.g.Render(w, r, http.StatusUnprocessableEntity, Name+"/cert_new", "certs.new", d)
		return
	}
	u.g.Audit(r, "cert.upload", strconv.FormatInt(c.ID, 10), "names="+strings.Join(c.Names, ","))
	u.g.Flash(w, r, "success", u.g.T(r, "certs.uploaded", "name", c.Title()))
	http.Redirect(w, r, Base, http.StatusSeeOther)
}

func (u *UI) pageCertAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	email, accept := strings.TrimSpace(r.PostFormValue("email")), r.PostFormValue("accept_tos") == "on"
	if err := u.m.SetAccount(ctx, email, accept); err != nil {
		u.g.Flash(w, r, "danger", u.g.T(r, "certs.err.email"))
	} else {
		u.g.Audit(r, "cert.account", "", fmt.Sprintf("email_set=%v accept_tos=%v", email != "", accept))
		u.g.Flash(w, r, "success", u.g.T(r, "common.saved"))
	}
	http.Redirect(w, r, Base, http.StatusSeeOther)
}

func (u *UI) certFromPath(w http.ResponseWriter, r *http.Request) (*certs.Cert, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		if c, err := u.m.Get(r.Context(), id); err == nil {
			return c, true
		}
	}
	http.NotFound(w, r)
	return nil, false
}

func (u *UI) pageCertRenew(w http.ResponseWriter, r *http.Request) {
	c, ok := u.certFromPath(w, r)
	if !ok {
		return
	}
	if err := u.m.Renew(r.Context(), c.ID); err != nil {
		u.g.Flash(w, r, "danger", u.certError(r, err))
	} else {
		u.g.Audit(r, "cert.renew", strconv.FormatInt(c.ID, 10), "")
		u.g.Flash(w, r, "success", u.g.T(r, "certs.renewing", "name", c.Title()))
	}
	http.Redirect(w, r, Base, http.StatusSeeOther)
}

func (u *UI) pageCertAutoRenew(w http.ResponseWriter, r *http.Request) {
	c, ok := u.certFromPath(w, r)
	if !ok {
		return
	}
	on := r.PostFormValue("on") == "1"
	if err := u.m.SetAutoRenew(r.Context(), c.ID, on); err != nil {
		u.g.Flash(w, r, "danger", u.certError(r, err))
	} else {
		u.g.Audit(r, "cert.update", strconv.FormatInt(c.ID, 10), fmt.Sprintf("auto_renew=%v", on))
	}
	http.Redirect(w, r, Base, http.StatusSeeOther)
}

func (u *UI) pageCertDelete(w http.ResponseWriter, r *http.Request) {
	c, ok := u.certFromPath(w, r)
	if !ok {
		return
	}
	force := r.PostFormValue("force") == "1"
	if err := u.m.Delete(r.Context(), c.ID, force); err != nil {
		u.g.Flash(w, r, "danger", u.certError(r, err))
	} else {
		u.g.Audit(r, "cert.delete", strconv.FormatInt(c.ID, 10), fmt.Sprintf("names=%s force=%v", strings.Join(c.Names, ","), force))
		u.g.Flash(w, r, "success", u.g.T(r, "certs.deleted", "name", c.Title()))
	}
	http.Redirect(w, r, Base, http.StatusSeeOther)
}

func (u *UI) pageCertChain(w http.ResponseWriter, r *http.Request) {
	c, ok := u.certFromPath(w, r)
	if !ok {
		return
	}
	chain, err := u.m.Chain(r.Context(), c.ID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.pem"`, strings.ReplaceAll(strings.TrimPrefix(c.Names[0], "*."), "*", "_")))
	_, _ = io.WriteString(w, chain)
}

// ---------------------------------------------------------------- DNS-Zugaenge

type dnsForm struct {
	A         *certs.DNSAccount
	New       bool
	Providers []certs.ProviderInfo
	Error     string
}

func (u *UI) pageDNSNew(w http.ResponseWriter, r *http.Request) {
	u.g.Render(w, r, http.StatusOK, Name+"/dns_form", "certs.dns.new", dnsForm{A: &certs.DNSAccount{Provider: "cloudflare", Values: map[string]string{}}, New: true,
		Providers: certs.ProvidersFor(u.g.Lang(r))})
}

func (u *UI) pageDNSEdit(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	a, err := u.m.DNSAccount(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	u.g.Render(w, r, http.StatusOK, Name+"/dns_form", "certs.dns.edit", dnsForm{A: a, Providers: certs.ProvidersFor(u.g.Lang(r))})
}

func (u *UI) pageDNSSave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_ = r.ParseForm()
	a := &certs.DNSAccount{Name: r.PostFormValue("name"), Provider: r.PostFormValue("provider")}
	isNew := true
	if v := r.PathValue("id"); v != "" {
		id, _ := strconv.ParseInt(v, 10, 64)
		old, err := u.m.DNSAccount(ctx, id)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		a.ID, a.Provider, isNew = id, old.Provider, false
	}
	values := map[string]string{}
	for k, v := range r.PostForm { // Felder heissen f_<anbieter>_<feld>
		if rest, ok := strings.CutPrefix(k, "f_"+a.Provider+"_"); ok && len(v) > 0 {
			values[rest] = v[0]
		}
	}
	if err := u.m.SaveDNSAccount(ctx, a, values); err != nil {
		a.Values = map[string]string{}
		u.g.Render(w, r, http.StatusUnprocessableEntity, Name+"/dns_form", "certs.dns.new", dnsForm{A: a, New: isNew, Providers: certs.ProvidersFor(u.g.Lang(r)),
			Error: u.certError(r, err)})
		return
	}
	action := "cert.dns.update"
	if isNew {
		action = "cert.dns.create"
	}
	u.g.Audit(r, action, strconv.FormatInt(a.ID, 10), "name="+a.Name+" provider="+a.Provider)
	u.g.Flash(w, r, "success", u.g.T(r, "common.saved"))
	http.Redirect(w, r, Base, http.StatusSeeOther)
}

func (u *UI) pageDNSDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	a, err := u.m.DNSAccount(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := u.m.DeleteDNSAccount(r.Context(), id); err != nil {
		u.g.Flash(w, r, "danger", u.certError(r, err))
	} else {
		u.g.Audit(r, "cert.dns.delete", strconv.FormatInt(id, 10), "name="+a.Name)
		u.g.Flash(w, r, "success", u.g.T(r, "certs.dns.deleted", "name", a.Name))
	}
	http.Redirect(w, r, Base, http.StatusSeeOther)
}
