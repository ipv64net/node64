package cdn64

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/certs"
)

// Reiter SSL-Zertifikate: Oberflaeche fuer die Zertifikatsverwaltung des Kerns (Let's Encrypt ueber ipv64,
// Alias per CNAME, HTTP-01, eigene Zertifikate). Die JSON-API dazu ist die des Kerns unter /api/certs.

func (m *Module) certRoutes(mux *http.ServeMux, page func(http.HandlerFunc) http.Handler) {
	mux.Handle("GET /cdn64/certificates", page(m.pageCerts))
	mux.Handle("GET /cdn64/certificates/new", page(m.pageCertNew))
	mux.Handle("POST /cdn64/certificates", page(m.pageCertCreate))
	mux.Handle("POST /cdn64/certificates/upload", page(m.pageCertUpload))
	mux.Handle("POST /cdn64/certificates/account", page(m.pageCertAccount))
	mux.Handle("POST /cdn64/certificates/{id}/renew", page(m.pageCertRenew))
	mux.Handle("POST /cdn64/certificates/{id}/autorenew", page(m.pageCertAutoRenew))
	mux.Handle("POST /cdn64/certificates/{id}/delete", page(m.pageCertDelete))
	mux.Handle("GET /cdn64/certificates/{id}/chain.pem", page(m.pageCertChain))
	mux.Handle("GET /cdn64/dns-accounts/new", page(m.pageDNSNew))
	mux.Handle("POST /cdn64/dns-accounts", page(m.pageDNSSave))
	mux.Handle("GET /cdn64/dns-accounts/{id}", page(m.pageDNSEdit))
	mux.Handle("POST /cdn64/dns-accounts/{id}", page(m.pageDNSSave))
	mux.Handle("POST /cdn64/dns-accounts/{id}/delete", page(m.pageDNSDelete))
}

type cnamePair struct{ From, To string }

type certRow struct {
	*certs.Cert
	Pill   string // ok, soon, expired, none
	CNAMEs []cnamePair
}

type certsData struct {
	Tabs      []tab
	Rows      []certRow
	Account   certs.Account
	DNSReady  bool
	HTTPReady bool
	Issuing   bool
	DNS       []*certs.DNSAccount
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

func (m *Module) pageCerts(w http.ResponseWriter, r *http.Request) {
	if m.certs == nil {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	list, err := m.certs.List(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	d := certsData{Tabs: tabs("/cdn64/certificates"), Account: m.certs.Account(ctx), DNSReady: m.certs.DNSReady(ctx), HTTPReady: m.certs.HTTPReady()}
	d.DNS, _ = m.certs.DNSAccounts(ctx)
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
	m.g.Render(w, r, http.StatusOK, Name+"/certs", "cdn64.certs.title", d)
}

type certNewData struct {
	Tabs       []tab
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
}

func (m *Module) certNewData(ctx context.Context) certNewData {
	d := certNewData{Tabs: tabs("/cdn64/certificates"), Account: m.certs.Account(ctx), DNSReady: m.certs.DNSReady(ctx), HTTPReady: m.certs.HTTPReady(), Source: "auto"}
	d.DNS, _ = m.certs.DNSAccounts(ctx)
	if d.DNSReady {
		dctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		if list, err := m.certs.Domains(dctx); err != nil {
			d.DomainsErr = err.Error()
		} else {
			d.Domains = list
		}
	}
	return d
}

func (m *Module) pageCertNew(w http.ResponseWriter, r *http.Request) {
	if m.certs == nil {
		http.NotFound(w, r)
		return
	}
	d := m.certNewData(r.Context())
	d.Names = strings.Join(ParseNames(r.URL.Query().Get("names")), "\n")
	m.g.Render(w, r, http.StatusOK, Name+"/cert_new", "cdn64.certs.new", d)
}

// certError: verstaendliche Meldung fuer Fehler der Verwaltung.
func (m *Module) certError(r *http.Request, err error) string {
	var ve *certs.ValidationError
	switch {
	case errors.As(err, &ve):
		return m.g.T(r, "cdn64.certs.err."+ve.Field) + " (" + ve.Msg + ")"
	case errors.Is(err, certs.ErrTOS):
		return m.g.T(r, "cdn64.certs.err.tos")
	case errors.Is(err, certs.ErrNoKey):
		return m.g.T(r, "cdn64.certs.err.nokey")
	case errors.Is(err, certs.ErrInUse):
		return m.g.T(r, "cdn64.certs.err.in_use")
	case errors.Is(err, certs.ErrBusy):
		return m.g.T(r, "cdn64.certs.err.busy")
	case errors.Is(err, certs.ErrUpload):
		return m.g.T(r, "cdn64.certs.err.upload_renew")
	}
	return err.Error()
}

// autoSource: ipv64, wenn alle Namen in Domains des Accounts liegen, sonst HTTP-01.
func (m *Module) autoSource(ctx context.Context, names []string) string {
	if !m.certs.DNSReady(ctx) {
		return certs.SourceHTTP
	}
	domains, err := m.certs.Domains(ctx)
	if err != nil {
		return certs.SourceHTTP
	}
	for _, n := range names {
		base := strings.TrimPrefix(strings.ToLower(strings.TrimSuffix(n, ".")), "*.")
		found := false
		for _, d := range domains {
			if base == d || strings.HasSuffix(base, "."+d) {
				found = true
				break
			}
		}
		if !found {
			return certs.SourceHTTP
		}
	}
	return certs.SourceIPv64
}

// requestCert legt ein Zertifikat an (aus dem Formular oder beim Speichern eines Hosts).
func (m *Module) requestCert(ctx context.Context, names []string, source, zone, prefix string, dnsAccount int64, staging bool) (*certs.Cert, error) {
	if source == "" || source == "auto" {
		source = m.autoSource(ctx, names)
	}
	return m.certs.Create(ctx, certs.Request{Names: names, Source: source, AliasZone: zone, AliasPrefix: prefix, DNSAccount: dnsAccount, Staging: staging})
}

func (m *Module) auditCert(r *http.Request, c *certs.Cert) {
	m.g.Audit(r, "cert.create", strconv.FormatInt(c.ID, 10), fmt.Sprintf("names=%s source=%s staging=%v", strings.Join(c.Names, ","), c.Source, c.Staging))
}

func (m *Module) pageCertCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d := m.certNewData(ctx)
	d.Names, d.Source = r.PostFormValue("names"), r.PostFormValue("source")
	d.AliasZone, d.AliasPref, d.Staging = r.PostFormValue("alias_zone"), r.PostFormValue("alias_prefix"), r.PostFormValue("staging") == "on"
	if r.PostFormValue("accept_tos") == "on" && !d.Account.TOSAccepted {
		if err := m.certs.SetAccount(ctx, d.Account.Email, true); err == nil {
			m.g.Audit(r, "cert.account", "", "accept_tos=true")
			d.Account = m.certs.Account(ctx)
		}
	}
	d.DNSAccount, _ = strconv.ParseInt(r.PostFormValue("dns_account"), 10, 64)
	c, err := m.requestCert(ctx, ParseNames(d.Names), d.Source, d.AliasZone, d.AliasPref, d.DNSAccount, d.Staging)
	if err != nil {
		d.Error = m.certError(r, err)
		m.g.Render(w, r, http.StatusUnprocessableEntity, Name+"/cert_new", "cdn64.certs.new", d)
		return
	}
	m.auditCert(r, c)
	m.g.Flash(w, r, "success", m.g.T(r, "cdn64.certs.requested", "name", c.Title()))
	http.Redirect(w, r, "/cdn64/certificates", http.StatusSeeOther)
}

func (m *Module) pageCertUpload(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	certPEM, keyPEM := r.PostFormValue("cert"), r.PostFormValue("key")
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
		if err := r.ParseMultipartForm(1 << 20); err == nil {
			read := func(name, fallback string) string {
				f, _, err := r.FormFile(name)
				if err != nil {
					return r.FormValue(fallback)
				}
				defer f.Close()
				b, _ := io.ReadAll(f)
				if len(strings.TrimSpace(string(b))) == 0 {
					return r.FormValue(fallback)
				}
				return string(b)
			}
			certPEM, keyPEM = read("cert_file", "cert"), read("key_file", "key")
		}
	}
	c, err := m.certs.Upload(ctx, certPEM, keyPEM)
	if err != nil {
		d := m.certNewData(ctx)
		d.UploadErr = m.certError(r, err)
		m.g.Render(w, r, http.StatusUnprocessableEntity, Name+"/cert_new", "cdn64.certs.new", d)
		return
	}
	m.g.Audit(r, "cert.upload", strconv.FormatInt(c.ID, 10), "names="+strings.Join(c.Names, ","))
	m.g.Flash(w, r, "success", m.g.T(r, "cdn64.certs.uploaded", "name", c.Title()))
	http.Redirect(w, r, "/cdn64/certificates", http.StatusSeeOther)
}

func (m *Module) pageCertAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	email, accept := strings.TrimSpace(r.PostFormValue("email")), r.PostFormValue("accept_tos") == "on"
	if err := m.certs.SetAccount(ctx, email, accept); err != nil {
		m.g.Flash(w, r, "danger", m.g.T(r, "cdn64.certs.err.email"))
	} else {
		m.g.Audit(r, "cert.account", "", fmt.Sprintf("email_set=%v accept_tos=%v", email != "", accept))
		m.g.Flash(w, r, "success", m.g.T(r, "common.saved"))
	}
	http.Redirect(w, r, "/cdn64/certificates", http.StatusSeeOther)
}

func (m *Module) certFromPath(w http.ResponseWriter, r *http.Request) (*certs.Cert, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil && m.certs != nil {
		if c, err := m.certs.Get(r.Context(), id); err == nil {
			return c, true
		}
	}
	http.NotFound(w, r)
	return nil, false
}

func (m *Module) pageCertRenew(w http.ResponseWriter, r *http.Request) {
	c, ok := m.certFromPath(w, r)
	if !ok {
		return
	}
	if err := m.certs.Renew(r.Context(), c.ID); err != nil {
		m.g.Flash(w, r, "danger", m.certError(r, err))
	} else {
		m.g.Audit(r, "cert.renew", strconv.FormatInt(c.ID, 10), "")
		m.g.Flash(w, r, "success", m.g.T(r, "cdn64.certs.renewing", "name", c.Title()))
	}
	http.Redirect(w, r, "/cdn64/certificates", http.StatusSeeOther)
}

func (m *Module) pageCertAutoRenew(w http.ResponseWriter, r *http.Request) {
	c, ok := m.certFromPath(w, r)
	if !ok {
		return
	}
	on := r.PostFormValue("on") == "1"
	if err := m.certs.SetAutoRenew(r.Context(), c.ID, on); err != nil {
		m.g.Flash(w, r, "danger", m.certError(r, err))
	} else {
		m.g.Audit(r, "cert.update", strconv.FormatInt(c.ID, 10), fmt.Sprintf("auto_renew=%v", on))
	}
	http.Redirect(w, r, "/cdn64/certificates", http.StatusSeeOther)
}

func (m *Module) pageCertDelete(w http.ResponseWriter, r *http.Request) {
	c, ok := m.certFromPath(w, r)
	if !ok {
		return
	}
	force := r.PostFormValue("force") == "1"
	if err := m.certs.Delete(r.Context(), c.ID, force); err != nil {
		m.g.Flash(w, r, "danger", m.certError(r, err))
	} else {
		m.g.Audit(r, "cert.delete", strconv.FormatInt(c.ID, 10), fmt.Sprintf("names=%s force=%v", strings.Join(c.Names, ","), force))
		m.g.Flash(w, r, "success", m.g.T(r, "cdn64.certs.deleted", "name", c.Title()))
	}
	http.Redirect(w, r, "/cdn64/certificates", http.StatusSeeOther)
}

func (m *Module) pageCertChain(w http.ResponseWriter, r *http.Request) {
	c, ok := m.certFromPath(w, r)
	if !ok {
		return
	}
	chain, err := m.certs.Chain(r.Context(), c.ID)
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
	Tabs      []tab
	A         *certs.DNSAccount
	New       bool
	Providers []certs.ProviderInfo
	Error     string
}

func (m *Module) pageDNSNew(w http.ResponseWriter, r *http.Request) {
	m.g.Render(w, r, http.StatusOK, Name+"/dns_form", "cdn64.dns.new", dnsForm{Tabs: tabs("/cdn64/certificates"), A: &certs.DNSAccount{Provider: "cloudflare",
		Values: map[string]string{}}, New: true, Providers: certs.Providers()})
}

func (m *Module) pageDNSEdit(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	a, err := m.certs.DNSAccount(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	m.g.Render(w, r, http.StatusOK, Name+"/dns_form", "cdn64.dns.edit", dnsForm{Tabs: tabs("/cdn64/certificates"), A: a, Providers: certs.Providers()})
}

func (m *Module) pageDNSSave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_ = r.ParseForm()
	a := &certs.DNSAccount{Name: r.PostFormValue("name"), Provider: r.PostFormValue("provider")}
	isNew := true
	if v := r.PathValue("id"); v != "" {
		id, _ := strconv.ParseInt(v, 10, 64)
		old, err := m.certs.DNSAccount(ctx, id)
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
	if err := m.certs.SaveDNSAccount(ctx, a, values); err != nil {
		a.Values = map[string]string{}
		m.g.Render(w, r, http.StatusUnprocessableEntity, Name+"/dns_form", "cdn64.dns.new", dnsForm{Tabs: tabs("/cdn64/certificates"), A: a, New: isNew,
			Providers: certs.Providers(), Error: m.certError(r, err)})
		return
	}
	action := "cert.dns.update"
	if isNew {
		action = "cert.dns.create"
	}
	m.g.Audit(r, action, strconv.FormatInt(a.ID, 10), "name="+a.Name+" provider="+a.Provider)
	m.g.Flash(w, r, "success", m.g.T(r, "common.saved"))
	http.Redirect(w, r, "/cdn64/certificates", http.StatusSeeOther)
}

func (m *Module) pageDNSDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	a, err := m.certs.DNSAccount(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := m.certs.DeleteDNSAccount(r.Context(), id); err != nil {
		m.g.Flash(w, r, "danger", m.certError(r, err))
	} else {
		m.g.Audit(r, "cert.dns.delete", strconv.FormatInt(id, 10), "name="+a.Name)
		m.g.Flash(w, r, "success", m.g.T(r, "cdn64.deleted", "name", a.Name))
	}
	http.Redirect(w, r, "/cdn64/certificates", http.StatusSeeOther)
}
