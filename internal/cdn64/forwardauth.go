package cdn64

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// Forward-Auth wie Traefik (forwardAuth): Vor jeder Anfrage fragt PROXY64 den Anmeldedienst der Zugriffsliste
// (authentik, Authelia, oauth2-proxy oder ein eigener). 2xx = durch, die eingestellten Antwort-Header gehen ans Ziel;
// sonst geht die Antwort des Dienstes (meist die Weiterleitung zur Anmeldung) an den Besucher. Der Rueckweg des
// Dienstes (z. B. /outpost.goauthentik.io/) geht ohne Pruefung an den Dienst. Plan: docs/PLAN-PROXY64-FORWARDAUTH.md.

// Anmeldedienste (AccessList.Auth).
const (
	AuthUsers     = ""             // Benutzer der Liste (Basic Auth bzw. Login-Seite)
	AuthAuthentik = "authentik"    // authentik (Proxy-Provider, Forward auth)
	AuthAuthelia  = "authelia"     // Authelia
	AuthOAuth2    = "oauth2-proxy" // oauth2-proxy
	AuthCustom    = "custom"       // eigener Dienst mit Traefik-kompatiblem Endpunkt
)

const (
	fwdTimeout  = 5 * time.Second
	fwdMaxBody  = 64 << 10 // Antwort des Dienstes an den Besucher (Anmeldeseite, Fehlermeldung)
	fwdMaxHdrs  = 20
	oauth2Start = "/oauth2/start?rd="
)

// ForwardAuth ist die Einstellung des Anmeldedienstes einer Zugriffsliste.
type ForwardAuth struct {
	Address  string   `json:"address"`            // Pruef-Adresse, z. B. http://authentik-server:9000/outpost.goauthentik.io/auth/traefik
	Headers  []string `json:"headers,omitempty"`  // Antwort-Header, die ans Ziel gehen (Traefik authResponseHeaders)
	Callback string   `json:"callback,omitempty"` // Pfad des Rueckwegs auf dem Host, geht direkt an den Dienst ("" = keiner)
}

// fwdPreset: Vorgaben je Dienst (Beispiel-Adresse, Antwort-Header, Rueckweg).
type fwdPreset struct {
	Example  string
	Headers  []string
	Callback string
}

var fwdPresets = map[string]fwdPreset{
	AuthAuthentik: {Example: "http://authentik-server:9000/outpost.goauthentik.io/auth/traefik",
		Headers: []string{"X-authentik-username", "X-authentik-groups", "X-authentik-email", "X-authentik-name", "X-authentik-uid",
			"X-authentik-entitlements", "X-authentik-jwt", "X-authentik-meta-jwks", "X-authentik-meta-outpost", "X-authentik-meta-provider",
			"X-authentik-meta-app", "X-authentik-meta-version"},
		Callback: "/outpost.goauthentik.io/"},
	AuthAuthelia: {Example: "http://authelia:9091/api/authz/forward-auth",
		Headers: []string{"Remote-User", "Remote-Groups", "Remote-Email", "Remote-Name"}},
	AuthOAuth2: {Example: "http://oauth2-proxy:4180/oauth2/auth",
		Headers:  []string{"X-Auth-Request-User", "X-Auth-Request-Email", "X-Auth-Request-Groups", "X-Auth-Request-Preferred-Username"},
		Callback: "/oauth2/"},
	AuthCustom: {},
}

// Kennung des Benutzers aus der Antwort des Dienstes, erster Treffer gilt (fuer "Benutzer an das Ziel melden").
var (
	idUser   = []string{"Remote-User", "X-authentik-username", "X-Auth-Request-Preferred-Username", "X-Auth-Request-User", "X-Forwarded-User"}
	idEmail  = []string{"Remote-Email", "X-authentik-email", "X-Auth-Request-Email", "X-Forwarded-Email"}
	idGroups = []string{"Remote-Groups", "X-authentik-groups", "X-Auth-Request-Groups", "X-Forwarded-Groups"}
	idName   = []string{"Remote-Name", "X-authentik-name"}
)

// identityHeaders setzt PROXY64 selbst ans Ziel; vom Besucher mitgeschickt werden sie immer entfernt.
var identityHeaders = []string{"Remote-User", "Remote-Email", "Remote-Groups", "Remote-Name"}

// normalize prueft die Einstellung; ohne Header bzw. Rueckweg gelten die Vorgaben des Dienstes.
func (f *ForwardAuth) normalize(kind string) error {
	p, ok := fwdPresets[kind]
	if !ok {
		return ferr("auth", "cdn64.err.fwd_kind")
	}
	f.Address = strings.TrimSpace(f.Address)
	u, err := url.Parse(f.Address)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return ferr("fwd_address", "cdn64.err.fwd_address")
	}
	var hs []string
	seen := map[string]bool{}
	for _, h := range f.Headers {
		h = strings.TrimSpace(h)
		if h == "" || seen[strings.ToLower(h)] {
			continue
		}
		if !validHeaderName(h) || fixedHeaders[strings.ToLower(h)] || len(hs) >= fwdMaxHdrs {
			return &FieldError{Field: "fwd_headers", Key: "cdn64.err.fwd_header", Name: h}
		}
		seen[strings.ToLower(h)] = true
		hs = append(hs, h)
	}
	if len(hs) == 0 {
		hs = append(hs, p.Headers...)
	}
	f.Headers = hs
	f.Callback = strings.TrimSpace(f.Callback)
	if f.Callback == "" {
		f.Callback = p.Callback
	}
	if f.Callback != "" {
		if !strings.HasPrefix(f.Callback, "/") || f.Callback == "/" || strings.ContainsAny(f.Callback, " ?#\\") || strings.HasPrefix(f.Callback, "/.node64/") {
			return ferr("fwd_callback", "cdn64.err.fwd_callback")
		}
		if !strings.HasSuffix(f.Callback, "/") {
			f.Callback += "/"
		}
	}
	return nil
}

// fwdAuth ist der vorbereitete Anmeldedienst einer Liste (in newGuard).
type fwdAuth struct {
	kind     string
	cfg      ForwardAuth
	client   *http.Client
	callback http.Handler // Rueckweg an den Dienst (nil = keiner)
}

func newFwdAuth(kind string, cfg ForwardAuth) *fwdAuth {
	u, err := url.Parse(cfg.Address)
	if err != nil || u.Host == "" {
		return nil
	}
	f := &fwdAuth{kind: kind, cfg: cfg, client: &http.Client{Timeout: fwdTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if cfg.Callback != "" {
		base := &url.URL{Scheme: u.Scheme, Host: u.Host}
		f.callback = &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(base)
				pr.Out.Host = pr.In.Host // der Dienst baut seine Weiterleitungen mit dem Namen des Hosts
				pr.SetXForwarded()
				pr.Out.Header.Set("X-Forwarded-Proto", fwdScheme(pr.In))
				if ip := clientOf(pr.In); ip.IsValid() {
					pr.Out.Header.Set("X-Forwarded-For", ip.String())
				}
			},
			ErrorLog:     log.New(io.Discard, "", 0),
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) { page(w, http.StatusBadGateway) },
		}
	}
	return f
}

// isCallback: Pfad gehoert dem Dienst (Rueckweg nach der Anmeldung).
func (f *fwdAuth) isCallback(path string) bool {
	return f.callback != nil && (strings.HasPrefix(path, f.cfg.Callback) || path == strings.TrimSuffix(f.cfg.Callback, "/"))
}

// fwdResult: Ergebnis der Pruefung beim Dienst.
type fwdResult struct {
	ok     bool
	header http.Header // Antwort des Dienstes (bei ok: Quelle der Antwort-Header und der Kennung)
	err    error       // Dienst nicht erreichbar
}

// check fragt den Dienst: Header des Besuchers und X-Forwarded-* wie Traefik. Bei nicht ok ist die Antwort schon an
// den Besucher geschrieben (ausser err != nil).
func (f *fwdAuth) check(w http.ResponseWriter, r *http.Request) fwdResult {
	ctx, cancel := context.WithTimeout(r.Context(), fwdTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.cfg.Address, nil)
	if err != nil {
		return fwdResult{err: err}
	}
	for k, vs := range r.Header {
		if !fixedHeaders[strings.ToLower(k)] {
			req.Header[k] = vs
		}
	}
	req.Header.Del("Accept-Encoding") // Antwort unkomprimiert (Go entpackt selbst), sonst zerschnitte die Grenze den Datenstrom
	scheme := fwdScheme(r)
	req.Header.Set("X-Forwarded-Method", r.Method)
	req.Header.Set("X-Forwarded-Proto", scheme)
	req.Header.Set("X-Forwarded-Host", r.Host)
	req.Header.Set("X-Forwarded-Uri", r.URL.RequestURI())
	if ip := clientOf(r); ip.IsValid() {
		req.Header.Set("X-Forwarded-For", ip.String())
		req.Header.Set("X-Real-IP", ip.String())
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return fwdResult{err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, fwdMaxBody))
		return fwdResult{ok: true, header: resp.Header}
	}
	// oauth2-proxy antwortet mit 401: Browser zur Anmeldung schicken (wie die errors-Middleware bei Traefik)
	if f.kind == AuthOAuth2 && resp.StatusCode == http.StatusUnauthorized && strings.Contains(r.Header.Get("Accept"), "text/html") {
		http.Redirect(w, r, oauth2Start+url.QueryEscape(scheme+"://"+r.Host+r.URL.RequestURI()), http.StatusFound)
		return fwdResult{}
	}
	for k, vs := range resp.Header {
		if !fixedHeaders[strings.ToLower(k)] {
			w.Header()[k] = vs
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, fwdMaxBody))
	return fwdResult{}
}

// fwdScheme: Schema des Besuchers; endet TLS schon beim vertrauenswuerdigen Proxy davor (z. B. Cloudflare), dessen
// X-Forwarded-Proto (Authelia und authentik verlangen https).
func fwdScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if p := peerIP(r); p.IsValid() && clientOf(r) != p && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return "https"
	}
	return "http"
}

// first liefert den ersten gesetzten Header aus names.
func first(h http.Header, names []string) string {
	for _, n := range names {
		if v := h.Get(n); v != "" {
			return v
		}
	}
	return ""
}

// identity ist der angemeldete Benutzer (fuer "Benutzer an das Ziel melden").
type identity struct{ user, email, groups, name string }

func (id identity) set(h http.Header) {
	for _, kv := range [][2]string{{"Remote-User", id.user}, {"Remote-Email", id.email}, {"Remote-Groups", id.groups}, {"Remote-Name", id.name}} {
		if kv[1] != "" {
			h.Set(kv[0], kv[1])
		}
	}
}

func identityOf(h http.Header) identity {
	return identity{user: first(h, idUser), email: first(h, idEmail), groups: first(h, idGroups), name: first(h, idName)}
}
