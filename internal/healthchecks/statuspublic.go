package healthchecks

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/text/language"

	"github.com/ipv64net/node64/internal/module"
)

// Oeffentliche Routen der Statusseiten. Drei Wege fuehren zur selben Implementierung (serveStatus):
//   - Node-Port: /status/<slug>/... (nur eingeschaltet UND publish_node, sonst 404 wie "gibt es nicht")
//   - StatusSite(id): eigene Website fuer PROXY64/CDN64, Pfade relativ zu "/" (nur eingeschaltet)
//   - statusPreview: Vorschau in der Verwaltung (angemeldet, auch ausgeschaltet, ohne Passwort und Zwischenspeicher)
// Pfade unter der Basis: "" (HTML), status.json, item/<id>[.json], badge.svg, badge/<id>[.svg]?type=status|uptime,
// feed.atom und POST login. Kein Login und keine Sitzung der Verwaltung; nur GET/HEAD und das Login-POST.

const (
	statusCookiePrefix = "node64_status_"
	statusCookieAge    = 30 * 24 * time.Hour
	statusLoginFails   = 10 // Fehlversuche je IP ...
	statusLoginWindow  = 5 * time.Minute
	statusBodyLimit    = 4 << 10
	statusMaxAge       = 30 // Sekunden (Cache-Control fuer JSON, Badges und Feed; wie der Zwischenspeicher)
)

// statusFail zaehlt Passwort-Fehlversuche einer IP.
type statusFail struct {
	n     int
	since time.Time
}

// statusRoutes meldet die oeffentlichen Routen /status/{slug}... an (nur eingeschaltete Seiten mit publish_node).
func (m *Module) statusRoutes(mux *http.ServeMux, g module.Guards) {
	h := g.Enabled(http.HandlerFunc(m.statusNode))
	mux.Handle("GET /status/{slug}", h)
	mux.Handle("GET /status/{slug}/{rest...}", h)
	mux.Handle("POST /status/{slug}/login", h) // CSRF-Ausnahme in internal/web/middleware.go, eigene Drosselung
}

// statusNode bedient /status/<slug>/... auf dem Node-Port. Unbekannter Slug: hoechstens eine Abfrage.
func (m *Module) statusNode(w http.ResponseWriter, r *http.Request) {
	slug := strings.ToLower(r.PathValue("slug"))
	if !statusSlugRe.MatchString(slug) {
		http.NotFound(w, r)
		return
	}
	p, err := m.st.StatusPageBySlug(r.Context(), slug)
	if err != nil || !p.Enabled || !p.PublishNode {
		http.NotFound(w, r)
		return
	}
	rest := r.PathValue("rest")
	if r.Method == http.MethodPost {
		rest = "login"
	}
	m.serveStatus(w, r, p, "/status/"+p.Slug, rest, false)
}

// StatusSite liefert die Seite mit dieser ID als eigene Website (Pfade relativ zu "/"), fuer PROXY64.
// Ist die Seite aus oder unbekannt (oder das Modul aus), antwortet der Handler mit 404; publish_node spielt keine Rolle.
// Billig je Aufruf (PROXY64 ruft es bei jeder Anfrage): kein Mux, kein DB-Zugriff beim Erzeugen.
func (m *Module) StatusSite(id int64) http.Handler { return statusSite{m, id} }

type statusSite struct {
	m  *Module
	id int64
}

func (s statusSite) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.m.g.Enabled != nil {
		s.m.g.Enabled(http.HandlerFunc(s.serve)).ServeHTTP(w, r)
		return
	}
	s.serve(w, r)
}

func (s statusSite) serve(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/")
	if r.Method != http.MethodGet && r.Method != http.MethodHead && !(r.Method == http.MethodPost && rest == "login") {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	p, err := s.m.st.StatusPage(r.Context(), s.id)
	if err != nil || !p.Enabled {
		http.NotFound(w, r)
		return
	}
	s.m.serveStatus(w, r, p, "", rest, false)
}

// statusPreview zeigt eine Seite in der Verwaltung (angemeldet), auch wenn sie aus ist. Basis ist der Pfad der
// Vorschau selbst (ohne {rest...}); die Verwaltung leitet ".../preview/{rest...}" ebenfalls hierher, so funktionieren
// Details und Nachladen auch in der Vorschau. Gerechnet wird ohne Zwischenspeicher, das Passwort gilt nicht.
func (m *Module) statusPreview(w http.ResponseWriter, r *http.Request, p *StatusPage) {
	rest := strings.Trim(r.PathValue("rest"), "/")
	base := strings.TrimSuffix(strings.TrimSuffix(r.URL.Path, rest), "/")
	if rest == "login" || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		http.NotFound(w, r)
		return
	}
	m.serveStatus(w, r, p, base, rest, true)
}

// serveStatus verteilt auf HTML, JSON, Badges, Feed und Login.
func (m *Module) serveStatus(w http.ResponseWriter, r *http.Request, p *StatusPage, base, rest string, preview bool) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Del("X-Frame-Options") // die Oberflaeche setzt DENY; hier entscheidet frame-ancestors (siehe statusHTML)
	if p.NoIndex || preview {
		h.Set("X-Robots-Tag", "noindex, nofollow")
	}
	lang := statusLang(r, p)
	if p.Lang == "" {
		h.Add("Vary", "Accept-Language")
	}
	rest = strings.Trim(rest, "/")
	if r.Method == http.MethodPost {
		if rest != "login" || preview {
			http.NotFound(w, r)
			return
		}
		m.statusLogin(w, r, p, base, lang)
		return
	}
	if rest == "logo" || rest == "favicon" || rest == "favicon.ico" {
		m.statusLogo(w, r, p, preview, rest != "logo") // auch ohne Passwort: steht auf dem Passwortformular
		return
	}
	locked := !preview && p.hash != "" && !statusAuthorized(r, p)
	switch {
	case rest == "" || rest == "index.html":
		m.statusHTML(w, r, p, base, lang, locked, locked && r.URL.Query().Get("pw") == "wrong", preview, http.StatusOK)
		return
	case rest == "status.json", strings.HasPrefix(rest, "item/"), rest == "badge.svg", strings.HasPrefix(rest, "badge/"), rest == "feed.atom":
	default:
		http.NotFound(w, r)
		return
	}
	if locked {
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		writeJSON(w, http.StatusUnauthorized, apiError{Error: "password required"})
		return
	}
	ctx := r.Context()
	if strings.HasPrefix(rest, "item/") {
		id, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(rest, "item/"), ".json"), 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		d, err := m.statusItemDetail(ctx, p, id, lang)
		if errors.Is(err, ErrStatusPageNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			m.statusFail(w, r, err)
			return
		}
		statusJSON(w, p, preview, d)
		return
	}
	v, err := m.statusViewFor(ctx, p, lang, preview)
	if err != nil {
		m.statusFail(w, r, err)
		return
	}
	switch {
	case rest == "status.json" && !preview:
		raw, gz, err := m.statusJSONBytes(ctx, p, lang)
		if err != nil {
			m.statusFail(w, r, err)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		statusCache(w, p, preview)
		statusWrite(w, r, http.StatusOK, raw, gz)
	case rest == "status.json":
		statusJSON(w, p, preview, v)
	case rest == "badge.svg":
		tr := m.translator(lang)
		statusBadge(w, p, preview, statusBadgeSVG(p.Title, tr("hc.status.pub.badge."+v.Overall), v.Overall))
	case strings.HasPrefix(rest, "badge/"):
		id, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(rest, "badge/"), ".svg"), 10, 64)
		it := statusFindItem(v, id)
		if err != nil || it == nil {
			http.NotFound(w, r)
			return
		}
		tr := m.translator(lang)
		value, color := tr("hc.status.pub.badge."+it.State), it.State
		if r.URL.Query().Get("type") == "uptime" {
			value, color = statusUptimeBadge(tr, it.Uptime)
		}
		statusBadge(w, p, preview, statusBadgeSVG(it.Label, value, color))
	case rest == "feed.atom":
		m.statusFeed(w, r, p, base, lang, preview, v)
	}
}

// statusFaviconFallback liefert das Node64-Logo (SVG, statushtml.go) fuer favicon ohne eigenes Logo; nil = 404 (Tests).
var statusFaviconFallback = statusNode64Favicon

// statusLogo liefert das eigene Logo (logo, favicon) bzw. fuer favicon ersatzweise das Node64-Logo. Mit ?v= (die
// Sicht haengt den Zeitpunkt der letzten Aenderung an) lange cachebar, sonst eine Stunde; bei Passwort privat.
func (m *Module) statusLogo(w http.ResponseWriter, r *http.Request, p *StatusPage, preview, favicon bool) {
	data, ctype, _, err := m.st.StatusLogo(r.Context(), p.ID)
	if err != nil && !errors.Is(err, ErrStatusPageNotFound) {
		m.statusFail(w, r, err)
		return
	}
	if data == nil {
		if !favicon || statusFaviconFallback == nil {
			http.NotFound(w, r)
			return
		}
		data, ctype = statusFaviconFallback(), "image/svg+xml"
		if len(data) == 0 {
			http.NotFound(w, r)
			return
		}
	}
	sum := sha256.Sum256(data)
	etag := `"` + hex.EncodeToString(sum[:12]) + `"`
	h := w.Header()
	h.Set("ETag", etag)
	age := "3600"
	if r.URL.Query().Get("v") != "" {
		age = "31536000"
	}
	switch {
	case preview:
		h.Set("Cache-Control", "no-cache")
	case p.hash != "":
		h.Set("Cache-Control", "private, max-age="+age)
	default:
		h.Set("Cache-Control", "public, max-age="+age)
	}
	if ctype == "image/svg+xml" {
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox") // SVG kann Skripte enthalten
	} else {
		h.Set("Content-Security-Policy", "default-src 'none'")
	}
	if inm := r.Header.Get("If-None-Match"); inm != "" && strings.Contains(inm, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Type", ctype)
	h.Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// statusViewFor: oeffentlich aus dem Zwischenspeicher, die Vorschau immer frisch (ungespeicherte Aenderungen).
func (m *Module) statusViewFor(ctx context.Context, p *StatusPage, lang string, preview bool) (*StatusView, error) {
	if preview {
		return m.buildStatusView(ctx, p, lang)
	}
	return m.statusView(ctx, p, lang)
}

func (m *Module) statusFail(w http.ResponseWriter, r *http.Request, err error) {
	m.log.Error("status page failed", "path", r.URL.Path, "err", err)
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// statusHTML rendert die Seite bzw. (gesperrt) das Passwortformular.
func (m *Module) statusHTML(w http.ResponseWriter, r *http.Request, p *StatusPage, base, lang string, locked, wrong, preview bool, code int) {
	var v *StatusView
	if !locked {
		var err error
		if v, err = m.statusViewFor(r.Context(), p, lang, preview); err != nil {
			m.statusFail(w, r, err)
			return
		}
	}
	nonce := statusNonce()
	var buf bytes.Buffer
	if err := renderStatusHTML(&buf, v, statusRenderOpts{Base: base, Lang: lang, Nonce: nonce, NoIndex: p.NoIndex || preview,
		NeedPassword: locked, PasswordWrong: wrong, Preview: preview, T: m.translator(lang)}); err != nil {
		m.statusFail(w, r, err)
		return
	}
	// Einbetten (iframe, z. B. Ansicht Kompakt) ist erlaubt; mit Passwort und in der Vorschau nur von hier selbst
	frame := "*"
	if p.hash != "" || preview {
		frame = "'self'"
	}
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+nonce+"'; style-src-attr 'unsafe-inline'; script-src 'nonce-"+nonce+
		"'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors "+frame)
	if preview {
		h.Set("X-Frame-Options", "SAMEORIGIN")
	}
	switch {
	case preview || locked || p.hash != "":
		h.Set("Cache-Control", "private, no-store")
	default:
		h.Set("Cache-Control", "no-cache")
	}
	h.Set("Content-Type", "text/html; charset=utf-8")
	statusWrite(w, r, code, buf.Bytes(), nil) // je Abruf komprimiert: das HTML traegt eine eigene Nonce
}

// statusWrite schreibt body, gzip-komprimiert, wenn der Client es annimmt (gz = fertige Fassung oder nil).
func statusWrite(w http.ResponseWriter, r *http.Request, code int, body, gz []byte) {
	h := w.Header()
	h.Add("Vary", "Accept-Encoding")
	if statusAcceptsGzip(r) && len(body) > 512 {
		if gz == nil {
			gz = statusGzip(body)
		}
		body = gz
		h.Set("Content-Encoding", "gzip")
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// statusAcceptsGzip: Accept-Encoding enthaelt gzip (nicht mit q=0).
func statusAcceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if strings.EqualFold(strings.TrimSpace(name), "gzip") {
			q := strings.ReplaceAll(strings.TrimSpace(params), " ", "")
			return q != "q=0" && q != "q=0.0" && q != "q=0.00" && q != "q=0.000"
		}
	}
	return false
}

func statusGzip(b []byte) []byte {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.DefaultCompression)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return buf.Bytes()
}

// statusCache setzt Cache-Control und CORS fuer JSON, Badges und Feed.
func statusCache(w http.ResponseWriter, p *StatusPage, preview bool) {
	h := w.Header()
	switch {
	case preview:
		h.Set("Cache-Control", "no-store")
	case p.hash != "":
		h.Set("Cache-Control", "private, max-age="+strconv.Itoa(statusMaxAge))
	default:
		h.Set("Cache-Control", "public, max-age="+strconv.Itoa(statusMaxAge))
		h.Set("Access-Control-Allow-Origin", "*") // eigene Widgets auf anderen Seiten (nur ohne Passwort)
	}
}

func statusJSON(w http.ResponseWriter, p *StatusPage, preview bool, v any) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	statusCache(w, p, preview)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}

func statusBadge(w http.ResponseWriter, p *StatusPage, preview bool, svg []byte) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.Header().Set("Content-Type", "image/svg+xml")
	statusCache(w, p, preview)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(svg)
}

// statusUptimeBadge: Wert und Farbe fuer type=uptime (ab 99 % gruen, ab 95 % gelb, darunter rot, ohne Daten grau).
func statusUptimeBadge(tr func(string, ...any) string, up float64) (string, string) {
	switch {
	case up < 0:
		return tr("hc.status.pub.badge.nodata"), "unknown"
	case up >= 99:
		return strconv.FormatFloat(up, 'f', 2, 64) + "%", "up"
	case up >= statusDownUptime:
		return strconv.FormatFloat(up, 'f', 2, 64) + "%", "degraded"
	}
	return strconv.FormatFloat(up, 'f', 2, 64) + "%", "down"
}

func statusFindItem(v *StatusView, id int64) *StatusViewItem {
	for gi := range v.Groups {
		for ii := range v.Groups[gi].Items {
			if v.Groups[gi].Items[ii].ID == id {
				return &v.Groups[gi].Items[ii]
			}
		}
	}
	return nil
}

// statusLang: feste Sprache der Seite, sonst ?lang=, sonst Accept-Language (de/en, Standard en).
func statusLang(r *http.Request, p *StatusPage) string {
	if p.Lang == "de" || p.Lang == "en" {
		return p.Lang
	}
	if q := r.URL.Query().Get("lang"); q == "de" || q == "en" {
		return q
	}
	tags, _, _ := language.ParseAcceptLanguage(r.Header.Get("Accept-Language"))
	for _, t := range tags {
		if b, _ := t.Base(); b.String() == "de" || b.String() == "en" {
			return b.String()
		}
	}
	return "en"
}

func statusNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// ---------------------------------------------------------------- Passwort

// statusCookieValue: HMAC ueber die Seiten-ID mit dem gespeicherten bcrypt-Hash als Schluessel. Ein neues Passwort
// (neuer Hash) macht alle Cookies ungueltig; der Hash selbst verlaesst die Node nie.
func statusCookieValue(p *StatusPage) string {
	mac := hmac.New(sha256.New, []byte(p.hash))
	mac.Write([]byte("node64-status:" + strconv.FormatInt(p.ID, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

func statusAuthorized(r *http.Request, p *StatusPage) bool {
	c, err := r.Cookie(statusCookiePrefix + strconv.FormatInt(p.ID, 10))
	return err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(statusCookieValue(p))) == 1
}

func statusSecure(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// statusLogin prueft das Passwort (bcrypt), setzt das Cookie und leitet zur Seite. Fehlversuche je IP gedrosselt.
func (m *Module) statusLogin(w http.ResponseWriter, r *http.Request, p *StatusPage, base, lang string) {
	home := base
	if home == "" {
		home = "/"
	}
	if p.hash == "" {
		http.Redirect(w, r, home, http.StatusSeeOther)
		return
	}
	ip := m.statusClientIP(r)
	if !m.statusLoginAllowed(ip) {
		w.Header().Set("Retry-After", strconv.Itoa(int(statusLoginWindow.Seconds())))
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, m.translator(lang)("hc.status.pub.too_many"), http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, statusBodyLimit)
	if err := r.ParseForm(); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	pw := r.PostFormValue("password")
	if pw == "" || len(pw) > 72 || bcrypt.CompareHashAndPassword([]byte(p.hash), []byte(pw)) != nil {
		m.statusLoginFailed(ip)
		m.log.Info("status page password wrong", "page", p.Slug, "ip", ip)
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, home+"?pw=wrong", http.StatusSeeOther) // PRG: Neuladen schickt das Formular nicht erneut
		return
	}
	http.SetCookie(w, &http.Cookie{Name: statusCookiePrefix + strconv.FormatInt(p.ID, 10), Value: statusCookieValue(p), Path: home,
		HttpOnly: true, Secure: statusSecure(r), SameSite: http.SameSiteLaxMode, MaxAge: int(statusCookieAge.Seconds())})
	http.Redirect(w, r, home, http.StatusSeeOther)
}

func (m *Module) statusClientIP(r *http.Request) string {
	if m.g.ClientIP != nil {
		return m.g.ClientIP(r)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// statusFailKey liefert den Schluessel der Sperre: IPv4 (auch v4-gemappt) je Adresse, IPv6 je /64.
func statusFailKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap().WithZone("")
	if a.Is4() {
		return a.String()
	}
	return netip.PrefixFrom(a, 64).Masked().String()
}

func (m *Module) statusLoginAllowed(ip string) bool {
	ip = statusFailKey(ip)
	s := m.statusState()
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.fails[ip]
	return f == nil || time.Since(f.since) > statusLoginWindow || f.n < statusLoginFails
}

func (m *Module) statusLoginFailed(ip string) {
	ip = statusFailKey(ip)
	s := m.statusState()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.fails) >= 10000 {
		// Tabelle voll: erst abgelaufene Eintraege entfernen, reicht das nicht, den aeltesten
		var oldest string
		for k, f := range s.fails {
			if time.Since(f.since) > statusLoginWindow {
				delete(s.fails, k)
			} else if oldest == "" || f.since.Before(s.fails[oldest].since) {
				oldest = k
			}
		}
		if len(s.fails) >= 10000 && oldest != "" {
			delete(s.fails, oldest)
		}
	}
	f := s.fails[ip]
	if f == nil || time.Since(f.since) > statusLoginWindow {
		f = &statusFail{since: time.Now()}
		s.fails[ip] = f
	}
	f.n++
}

// ---------------------------------------------------------------- Feed

type atomFeed struct {
	XMLName xml.Name    `xml:"http://www.w3.org/2005/Atom feed"`
	Title   string      `xml:"title"`
	ID      string      `xml:"id"`
	Updated string      `xml:"updated"`
	Author  atomAuthor  `xml:"author"`
	Links   []atomLink  `xml:"link"`
	Entries []atomEntry `xml:"entry"`
}

type atomAuthor struct {
	Name string `xml:"name"`
}

type atomLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr,omitempty"`
}

type atomEntry struct {
	Title     string   `xml:"title"`
	ID        string   `xml:"id"`
	Updated   string   `xml:"updated"`
	Published string   `xml:"published,omitempty"`
	Link      atomLink `xml:"link"`
	Content   atomText `xml:"content"`
}

type atomText struct {
	Type string `xml:"type,attr"`
	Body string `xml:",chardata"`
}

// statusFeed: Atom mit den Stoerungen und Ankuendigungen der Sicht (also nur, was die Seite auch zeigt).
func (m *Module) statusFeed(w http.ResponseWriter, r *http.Request, p *StatusPage, base, lang string, preview bool, v *StatusView) {
	tr := m.translator(lang)
	loc := m.statusLocation(r.Context())
	when := func(t time.Time) string {
		if lang == "de" {
			return t.In(loc).Format("02.01.2006 15:04")
		}
		return t.In(loc).Format("2006-01-02 15:04")
	}
	scheme := "http"
	if statusSecure(r) {
		scheme = "https"
	}
	home := scheme + "://" + r.Host + base + "/"
	urn := "urn:node64:status:" + strconv.FormatInt(p.ID, 10)
	f := atomFeed{Title: p.Title, ID: urn, Author: atomAuthor{Name: p.Title},
		Links: []atomLink{{Href: home}, {Href: scheme + "://" + r.Host + base + "/feed.atom", Rel: "self"}}}
	var latest time.Time
	for _, i := range v.Incidents {
		title, upd := tr("hc.status.pub.feed.incident", "item", i.Item), i.Start
		lines := []string{tr("hc.status.pub.feed.since", "time", when(i.Start))}
		if !i.End.IsZero() {
			title, upd = tr("hc.status.pub.feed.resolved", "item", i.Item), i.End
			lines = append(lines, tr("hc.status.pub.feed.until", "time", when(i.End)))
		}
		if i.Reason != "" {
			lines = append(lines, i.Reason)
		}
		sum := sha256.Sum256([]byte(i.Item + "|" + i.Start.UTC().Format(time.RFC3339Nano)))
		f.Entries = append(f.Entries, atomEntry{Title: title, ID: urn + ":incident:" + hex.EncodeToString(sum[:8]), Updated: upd.UTC().Format(time.RFC3339),
			Published: i.Start.UTC().Format(time.RFC3339), Link: atomLink{Href: home}, Content: atomText{Type: "text", Body: strings.Join(lines, "\n")}})
	}
	for _, n := range v.Notices {
		var lines []string
		if !n.ResolvedAt.IsZero() {
			lines = append(lines, tr("hc.status.pub.feed.done", "time", when(n.ResolvedAt)))
		}
		for _, u := range n.Updates {
			lines = append(lines, when(u.Time)+": "+u.Text)
		}
		f.Entries = append(f.Entries, atomEntry{Title: n.Title, ID: urn + ":notice:" + strconv.FormatInt(n.ID, 10), Updated: n.UpdatedAt.UTC().Format(time.RFC3339),
			Published: n.CreatedAt.UTC().Format(time.RFC3339), Link: atomLink{Href: home}, Content: atomText{Type: "text", Body: strings.Join(lines, "\n\n")}})
	}
	sort.SliceStable(f.Entries, func(i, j int) bool { return f.Entries[i].Updated > f.Entries[j].Updated })
	if len(f.Entries) > 50 {
		f.Entries = f.Entries[:50]
	}
	for _, e := range f.Entries {
		if t, err := time.Parse(time.RFC3339, e.Updated); err == nil && t.After(latest) {
			latest = t
		}
	}
	if latest.IsZero() {
		latest = v.Generated
	}
	f.Updated = latest.UTC().Format(time.RFC3339)
	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	if err := xml.NewEncoder(&buf).Encode(f); err != nil {
		m.statusFail(w, r, err)
		return
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	w.Header().Set("Content-Type", "application/atom+xml; charset=utf-8")
	statusCache(w, p, preview)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}
