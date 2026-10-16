package cdn64

import (
	"context"
	"net/http"

	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/certsui"
)

// Die Zertifikatsseiten liegen im Kern (Menuepunkt „Zertifikate“, internal/certsui). CDN64 leitet die alten
// Pfade dorthin weiter und fordert beim Speichern eines Hosts auf Wunsch ein Zertifikat an.

func (m *Module) certRoutes(mux *http.ServeMux, page func(http.HandlerFunc) http.Handler) {
	moved := func(to func(r *http.Request) string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			u := to(r)
			if r.URL.RawQuery != "" {
				u += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, u, http.StatusMovedPermanently)
		}
	}
	mux.Handle("GET /cdn64/certificates", page(moved(func(*http.Request) string { return certsui.Base })))
	mux.Handle("GET /cdn64/certificates/new", page(moved(func(*http.Request) string { return certsui.Base + "/new" })))
	mux.Handle("GET /cdn64/certificates/{id}/chain.pem", page(moved(func(r *http.Request) string { return certsui.Base + "/" + r.PathValue("id") + "/chain.pem" })))
	mux.Handle("GET /cdn64/dns-accounts/new", page(moved(func(*http.Request) string { return certsui.Base + "/dns-accounts/new" })))
	mux.Handle("GET /cdn64/dns-accounts/{id}", page(moved(func(r *http.Request) string { return certsui.Base + "/dns-accounts/" + r.PathValue("id") + "/edit" })))
}

// certError: verstaendliche Meldung fuer Fehler der Verwaltung.
func (m *Module) certError(r *http.Request, err error) string {
	return certsui.ErrorText(func(key string, args ...any) string { return m.g.T(r, key, args...) }, err)
}

// autoSource: ipv64, wenn alle Namen in Domains des Accounts liegen, sonst HTTP-01.
func (m *Module) autoSource(ctx context.Context, names []string) string {
	return m.certs.AutoSource(ctx, names)
}

// requestCert legt ein Zertifikat an (beim Speichern eines Hosts).
func (m *Module) requestCert(ctx context.Context, names []string, source, zone, prefix string, dnsAccount int64, staging bool) (*certs.Cert, error) {
	if source == "" || source == "auto" {
		source = m.autoSource(ctx, names)
	}
	return m.certs.Create(ctx, certs.Request{Names: names, Source: source, AliasZone: zone, AliasPrefix: prefix, DNSAccount: dnsAccount, Staging: staging})
}

func (m *Module) auditCert(r *http.Request, c *certs.Cert) { certsui.AuditCreate(m.g, r, c) }
