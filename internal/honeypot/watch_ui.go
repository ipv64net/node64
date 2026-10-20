package honeypot

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/module"
)

// Seite „Fruehwarnung“ (Reiter des Honeypot-Moduls): eigene Netze bei ipv64 verwalten, automatisch ueberwachte
// DynDNS-IPs und Grenzen anzeigen, letzte Treffer (lokal) und Zustand des Abrufs. Ohne JavaScript bedienbar.

const (
	watchLabelMax   = 64               // Zeichen der Bezeichnung
	watchAPITimeout = 15 * time.Second // Aufrufe aus der Oberflaeche
)

// Reiter „Fruehwarnung“ an die Reiter des Moduls haengen (ui.go bleibt unberuehrt; doppelt wird er nicht).
func init() {
	for _, t := range uiTabs {
		if t.Key == "watch" {
			return
		}
	}
	uiTabs = append(uiTabs, uiTab{Key: "watch", Path: "/honeypot/watch", TitleKey: "honeypot.tab.watch", Icon: "bi-shield-exclamation"})
}

// watchRoutes haengt Seite und Formulare der Fruehwarnung ein (aus Routes). CSRF prueft der Kern fuer alle POST.
func (m *Module) watchRoutes(mux *http.ServeMux, g module.Guards) {
	page := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /honeypot/watch", page(m.pageWatch))
	mux.Handle("POST /honeypot/watch", page(m.pageWatchAdd))
	mux.Handle("POST /honeypot/watch/check", page(m.pageWatchCheck))
	mux.Handle("POST /honeypot/watch/{id}/delete", page(m.pageWatchDelete))
}

// watchNetView ist ein Netz fuer die Seite.
type watchNetView struct {
	ipv64api.ThreatWatchNetwork
	Created time.Time // Zero = unbekannt
}

// watchHitView ist ein Treffer fuer die Seite.
type watchHitView struct {
	watchHit
	At time.Time // Zeitpunkt bei ipv64 (sonst Abholung)
}

type watchData struct {
	Tabs     []uiTab
	Running  bool // Modul laeuft (sonst kein automatischer Abruf)
	KeySet   bool
	Loaded   bool // Liste von ipv64 geholt
	Limits   ipv64api.ThreatWatchLimits
	Networks []watchNetView
	DynDNS   []ipv64api.ThreatWatchDynDNS
	Full     bool   // Limit der Netze erreicht
	Err      string // Fehler beim Laden der Liste
	AuthErr  bool   // Key abgelehnt (401/403)
	State    watchState
	Hits     []watchHitView
	CIDR     string // Formular
	Label    string
	FormErr  string
}

// parseWatchTime liest einen Zeitpunkt der API (RFC 3339, notfalls MySQL-Form in UTC).
func parseWatchTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return t
	}
	return time.Time{}
}

// watchView baut die Daten der Seite; die Liste kommt live von ipv64.
func (m *Module) watchView(r *http.Request) watchData {
	ctx := r.Context()
	d := watchData{Tabs: tabsFor("watch"), Running: m.running() != nil, State: m.watchLoad(ctx)}
	for _, h := range d.State.Hits {
		v := watchHitView{watchHit: h, At: parseWatchTime(h.Created)}
		if v.At.IsZero() {
			v.At = h.Fetched
		}
		d.Hits = append(d.Hits, v)
	}
	c, key := m.api(ctx)
	d.KeySet = c != nil && key != ""
	if !d.KeySet {
		return d
	}
	lctx, cancel := context.WithTimeout(ctx, watchAPITimeout)
	defer cancel()
	list, err := c.ThreatWatchList(lctx, key)
	if err != nil {
		m.log.Warn("honeypot watch: list failed", "err", err)
		d.Err, d.AuthErr = err.Error(), watchAuthErr(err)
		return d
	}
	d.Loaded, d.Limits, d.DynDNS = true, list.Limits, list.DynDNS
	for _, n := range list.Networks {
		d.Networks = append(d.Networks, watchNetView{ThreatWatchNetwork: n, Created: parseWatchTime(n.CreatedAt)})
	}
	d.Full = d.Limits.Max > 0 && len(d.Networks) >= d.Limits.Max
	return d
}

func watchAuthErr(err error) bool {
	var ae *ipv64api.APIError
	return errors.As(err, &ae) && (ae.Status == http.StatusUnauthorized || ae.Status == http.StatusForbidden)
}

func (m *Module) pageWatch(w http.ResponseWriter, r *http.Request) {
	m.g.Render(w, r, http.StatusOK, Name+"/watch", "honeypot.watch.title", m.watchView(r))
}

// normalizeCIDR: Netz oder einzelne IP (dann /32 bzw. /128) in Normalform; liefert sonst einen Fehlercode wie die
// API (invalid_cidr, not_public). Die Grenzen der Praefixe prueft ipv64.
func normalizeCIDR(s string) (string, string) {
	s = strings.TrimSpace(s)
	var p netip.Prefix
	if strings.Contains(s, "/") {
		x, err := netip.ParsePrefix(s)
		if err != nil {
			return "", "invalid_cidr"
		}
		p = x
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return "", "invalid_cidr"
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	if !p.IsValid() {
		return "", "invalid_cidr"
	}
	p = p.Masked()
	a := p.Addr()
	if !a.IsGlobalUnicast() || a.IsPrivate() {
		return "", "not_public"
	}
	return p.String(), ""
}

// cleanLabel: Bezeichnung ohne Steuerzeichen, hoechstens watchLabelMax Zeichen (ok = false: zu lang).
func cleanLabel(s string) (string, bool) {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s))
	return s, utf8.RuneCountInString(s) <= watchLabelMax
}

// watchErrText uebersetzt einen Fehlercode der API (honeypot.watch.err.<code>, mit Grenzen); unbekannt = Text des
// Fehlers.
func (m *Module) watchErrText(r *http.Request, code string, lim ipv64api.ThreatWatchLimits, err error) string {
	if code != "" {
		key := "honeypot.watch.err." + code
		if t := m.g.T(r, key, "max", lim.Max, "v4", lim.MinPrefixV4, "v6", lim.MinPrefixV6, "chars", watchLabelMax); t != key {
			return t
		}
	}
	if err != nil {
		return m.g.T(r, "honeypot.watch.err.api", "error", err.Error())
	}
	return code
}

// pageWatchAdd traegt ein Netz bei ipv64 ein. Fehler zeigen die Seite mit dem Formular erneut.
func (m *Module) pageWatchAdd(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rawCIDR := strings.TrimSpace(r.PostFormValue("cidr"))
	label, okLabel := cleanLabel(r.PostFormValue("label"))
	fail := func(status int, code string, err error) {
		d := m.watchView(r)
		d.CIDR, d.Label = rawCIDR, label
		d.FormErr = m.watchErrText(r, code, d.Limits, err)
		m.g.Render(w, r, status, Name+"/watch", "honeypot.watch.title", d)
	}
	c, key := m.api(ctx)
	if c == nil || key == "" {
		m.g.Flash(w, r, "danger", m.g.T(r, "honeypot.watch.nokey"))
		http.Redirect(w, r, "/honeypot/watch", http.StatusSeeOther)
		return
	}
	cidr, code := normalizeCIDR(rawCIDR)
	if code == "" && !okLabel {
		code = "label"
	}
	if code != "" {
		fail(http.StatusUnprocessableEntity, code, nil)
		return
	}
	actx, cancel := context.WithTimeout(ctx, watchAPITimeout)
	defer cancel()
	n, err := c.ThreatWatchAdd(actx, key, cidr, label)
	if err != nil {
		m.log.Warn("honeypot watch: add failed", "cidr", cidr, "err", err)
		status := http.StatusBadGateway
		var ae *ipv64api.APIError
		if errors.As(err, &ae) && ae.Status >= 400 && ae.Status < 500 {
			status = ae.Status
		}
		fail(status, ipv64api.ErrorCode(err), err)
		return
	}
	m.log.Info("watch network added", "cidr", n.CIDR, "id", n.ID, "via", "ui", "by", m.g.Actor(r))
	m.g.Audit(r, "honeypot.watch.add", n.CIDR, label)
	m.g.Flash(w, r, "success", m.g.T(r, "honeypot.watch.added", "cidr", n.CIDR))
	http.Redirect(w, r, "/honeypot/watch", http.StatusSeeOther)
}

// pageWatchDelete entfernt ein Netz bei ipv64 (404 = schon weg).
func (m *Module) pageWatchDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer http.Redirect(w, r, "/honeypot/watch", http.StatusSeeOther)
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		m.g.Flash(w, r, "danger", m.g.T(r, "honeypot.watch.err.invalid_id"))
		return
	}
	c, key := m.api(ctx)
	if c == nil || key == "" {
		m.g.Flash(w, r, "danger", m.g.T(r, "honeypot.watch.nokey"))
		return
	}
	cidr := strings.TrimSpace(r.PostFormValue("cidr")) // nur fuer Audit und Meldung
	if cidr == "" {
		cidr = "#" + strconv.FormatInt(id, 10)
	}
	actx, cancel := context.WithTimeout(ctx, watchAPITimeout)
	defer cancel()
	err = c.ThreatWatchDelete(actx, key, id)
	var ae *ipv64api.APIError
	switch {
	case err == nil:
		m.log.Info("watch network removed", "cidr", cidr, "id", id, "via", "ui", "by", m.g.Actor(r))
		m.g.Audit(r, "honeypot.watch.delete", cidr, strconv.FormatInt(id, 10))
		m.g.Flash(w, r, "success", m.g.T(r, "honeypot.watch.deleted", "cidr", cidr))
	case errors.As(err, &ae) && ae.Status == http.StatusNotFound:
		m.g.Flash(w, r, "warning", m.g.T(r, "honeypot.watch.gone", "cidr", cidr))
	default:
		m.log.Warn("honeypot watch: delete failed", "id", id, "err", err)
		m.g.Flash(w, r, "danger", m.watchErrText(r, ipv64api.ErrorCode(err), ipv64api.ThreatWatchLimits{}, err))
	}
}

// pageWatchCheck ruft die Treffer sofort ab (auch nach 401/403, z. B. nach neuem Key).
func (m *Module) pageWatchCheck(w http.ResponseWriter, r *http.Request) {
	n, _, err := m.watchCheck(r.Context(), true)
	switch {
	case errors.Is(err, errWatchNoKey):
		m.g.Flash(w, r, "danger", m.g.T(r, "honeypot.watch.nokey"))
	case err != nil:
		m.g.Flash(w, r, "danger", m.g.T(r, "honeypot.watch.err.api", "error", err.Error()))
	default:
		m.log.Info("watch checked", "hits", n, "via", "ui", "by", m.g.Actor(r))
		m.g.Flash(w, r, "success", m.g.T(r, "honeypot.watch.checked", "count", n))
	}
	http.Redirect(w, r, "/honeypot/watch", http.StatusSeeOther)
}
