package healthchecks

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/ipv64net/node64/internal/checks"
)

// Proxmox VE und Docker sind ab 3.0.0 nicht mehr Teil der Healthchecks, sondern des Moduls Monitor64 (ohne
// Uebernahme: dort neu einrichten). Die Typen docker und proxmox gibt es in internal/checks weiter (hubs, aeltere
// Nodes); diese Node legt solche Checks nicht mehr an, misst und zeigt sie nicht und uebernimmt sie von nirgends
// (hub, Cluster, Import). Beim Update loescht die Migration 0022 alle Daten dazu. Eigene Checks (owner self) muessen
// auch der hub und die anderen Nodes des Clusters loeschen: ihre Tokens merkt sich die Migration, die Loeschmeldung
// geht einmal nach dem Start ueber die Hooks des Stores hinaus (announceRemoved). Checks anderer Nodes (vielleicht
// noch alt) verschwinden nur hier.

const (
	// settingRemovedNotice: Hinweis in der Uebersicht (von der Migration gesetzt, wenn es etwas gab; Schliessen loescht ihn)
	settingRemovedNotice = "hc.notice.monitor64"
	// settingRemovedTokens: eigene entfernte Checks (Komma-Liste), deren Loeschung hub und Cluster noch erfahren
	settingRemovedTokens = "hc.removed_tokens"
)

// errRemovedType: Anlegen bzw. Aendern eines Checks vom Typ docker oder proxmox.
var errRemovedType = errors.New("type: Proxmox VE and Docker have moved to the module Monitor64 – set them up there")

// removedType: Typ, den diese Node nicht mehr fuehrt (nach Monitor64 umgezogen).
func removedType(t checks.Type) bool { return t == checks.TypeDocker || t == checks.TypeProxmox }

// removedNotice: Hinweis in der Uebersicht zeigen.
func (m *Module) removedNotice(ctx context.Context) bool {
	return m.core != nil && m.core.SettingOr(ctx, settingRemovedNotice, "") != ""
}

// announceRemoved meldet die Loeschung der von der Migration entfernten eigenen Checks an hub (Outbox, nur
// verknuepft) und Cluster (Protokoll der Gruppe) und nimmt ihre Tokens aus den Wartungsfenstern (ein Fenster nur fuer
// sie faellt weg, leer hiesse „alle Checks“). Laeuft einmal, die Liste wird danach geloescht.
func (m *Module) announceRemoved(ctx context.Context) {
	raw := m.core.SettingOr(ctx, settingRemovedTokens, "")
	if raw == "" {
		return
	}
	own := map[string]bool{}
	for _, t := range strings.Split(raw, ",") {
		if tokenRe.MatchString(t) {
			own[t] = true
		}
	}
	for t := range own {
		if c, err := m.st.Check(ctx, t); err != nil || c != nil {
			continue // nicht lesbar bzw. wieder da: nichts melden
		}
		m.st.changed(ctx, "check", t, "delete")
	}
	if list, err := m.st.MaintenanceList(ctx); err == nil {
		for _, mw := range list {
			keep := slices.DeleteFunc(slices.Clone(mw.Tokens), func(t string) bool { return own[t] })
			switch {
			case len(keep) == len(mw.Tokens):
				continue
			case len(keep) == 0:
				err = m.st.MaintenanceDelete(ctx, mw.ID)
			default:
				mw.Tokens = keep
				err = m.st.MaintenanceUpdate(ctx, &mw)
			}
			if err != nil {
				m.log.Warn("removed checks: maintenance", "err", err)
			}
		}
	}
	if err := m.core.DeleteSetting(ctx, settingRemovedTokens); err != nil {
		m.log.Warn("removed checks: setting", "err", err)
		return
	}
	m.log.Info("proxmox/docker checks removed (moved to monitor64)", "own", len(own))
}

// removedRoutes: Hinweis schliessen; alte Seiten von Proxmox VE und Docker fuehren zur Uebersicht (mit Hinweis).
func (m *Module) removedRoutes(mux *http.ServeMux, page func(http.HandlerFunc) http.Handler) {
	mux.Handle("POST /healthchecks/notice/monitor64", page(m.pageRemovedDismiss))
	for _, p := range []string{"/healthchecks/proxmox", "/healthchecks/docker"} {
		mux.Handle("GET "+p, page(m.pageRemoved))
		mux.Handle("GET "+p+"/new", page(m.pageRemoved))
		mux.Handle("GET "+p+"/system/{rest...}", page(m.pageRemoved))
	}
}

func (m *Module) pageRemoved(w http.ResponseWriter, r *http.Request) {
	m.g.Flash(w, r, "info", m.g.T(r, "hc.moved.page"))
	http.Redirect(w, r, "/healthchecks", http.StatusSeeOther)
}

func (m *Module) pageRemovedDismiss(w http.ResponseWriter, r *http.Request) {
	if err := m.core.DeleteSetting(r.Context(), settingRemovedNotice); err != nil {
		m.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/healthchecks", http.StatusSeeOther)
}

// removedAPIRoutes: die frueheren Endpunkte unter /api/healthchecks/proxmox und /api/healthchecks/docker antworten
// mit 410 Gone.
func (m *Module) removedAPIRoutes(mux *http.ServeMux, api func(http.HandlerFunc) http.Handler) {
	gone := func(w http.ResponseWriter, _ *http.Request) {
		writeErr(w, http.StatusGone, "Proxmox VE and Docker have moved to the module Monitor64 – set them up there")
	}
	for _, p := range []string{"/api/healthchecks/proxmox", "/api/healthchecks/docker"} {
		mux.Handle(p, api(gone))
		mux.Handle(p+"/", api(gone))
	}
}
