package cdn64

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/ipv64api"
)

// Server je Tunnel: wie viele CDN64-Server der Tunnel dieser Node und seine Namen nutzen und wie viele Verbindungen je
// Server. Die Klasse legt die Grenzen fest, Business und Company waehlen darunter (Knopf in der Spalte CDN64, Portal: PUT
// /cdn64o/tunnels/{id}/servers). Die Node uebernimmt beides beim naechsten Abgleich, ohne bleibende Verbindungen zu
// trennen.

type serversAPI interface {
	SetServers(ctx context.Context, tunnel string, count, sessions int) (*ipv64api.CDN64Servers, error)
}

// serversView: Knopf und Dialog in der Spalte CDN64.
type serversView struct {
	*ipv64api.CDN64Servers
	Names   string // zugeteilte Server, z. B. "srv07, srv08"
	Options []int  // waehlbare Anzahlen; 0 = alle (auch kuenftige)
	Current int    // gewaehlte Option
	// Verbindungen je Server: waehlbare Werte (leer = fest) und der gewaehlte
	SessionOptions []int
	CurSessions    int
}

func newServersView(s *ipv64api.CDN64Servers) *serversView {
	if s == nil {
		return nil
	}
	v := &serversView{CDN64Servers: s, Names: strings.Join(s.Assigned, ", "), Current: s.Count, CurSessions: max(s.Sessions, 1)}
	if !s.Selectable {
		return v
	}
	top := s.Max
	if s.All || top <= 0 {
		top = s.Total // die Liste waechst mit den Servern, dazu "alle (auch kuenftige)"
	}
	for n := 1; n <= top; n++ {
		v.Options = append(v.Options, n)
	}
	if s.All {
		v.Options = append(v.Options, 0)
		if s.Choice == 0 {
			v.Current = 0
		}
	}
	for n := 1; s.SessionsMax > 1 && n <= s.SessionsMax; n++ {
		v.SessionOptions = append(v.SessionOptions, n)
	}
	return v
}

// onlineServers: Server des eigenen Tunnels aus dem letzten Abgleich (nil = kein Tunnel oder Portal ohne Server je
// Tunnel).
func (m *Module) onlineServers(ctx context.Context, ov *ipv64api.CDN64Overview) *serversView {
	c, _, err := m.onlineConf(ctx)
	if err != nil || c == nil || ov == nil {
		return nil
	}
	for _, t := range ov.Tunnels {
		if t.ID == c.Tunnel {
			return newServersView(t.Servers)
		}
	}
	return nil
}

// POST /cdn64/online/servers: Server und Verbindungen je Server des eigenen Tunnels setzen.
func (m *Module) pageOnlineServers(w http.ResponseWriter, r *http.Request) {
	back := listPath(KindProxy)
	a, ok := m.online.api.(serversAPI)
	n, err := strconv.Atoi(r.PostFormValue("count"))
	ses, serr := strconv.Atoi(r.PostFormValue("sessions"))
	c, _, cerr := m.onlineConf(r.Context())
	if !ok || m.online.api == nil || !m.online.api.Ready(r.Context()) || err != nil || n < 0 || serr != nil || ses < 1 || cerr != nil || c == nil {
		m.g.Flash(w, r, "danger", m.g.T(r, "cdn64.online.servers_failed", "error", "invalid"))
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	s, err := a.SetServers(r.Context(), c.Tunnel, n, ses)
	if err != nil {
		m.g.Flash(w, r, "danger", m.g.T(r, "cdn64.online.servers_failed", "error", err.Error()))
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	m.g.Audit(r, "cdn64.online.servers", strconv.Itoa(n)+"x"+strconv.Itoa(ses), strings.Join(s.Assigned, ","))
	if rm := m.online.remote.Load(); rm != nil && rm.Data != nil { // Anzeige sofort, Abgleich gleich danach
		ov := *rm.Data
		ov.Tunnels = slices.Clone(ov.Tunnels)
		for i := range ov.Tunnels {
			if ov.Tunnels[i].ID == c.Tunnel {
				ov.Tunnels[i].Servers, ov.Tunnels[i].Sessions = s, s.Sessions
			}
		}
		m.onlineSetRemote(&ov, nil)
	}
	m.onlineKick()
	m.g.Flash(w, r, "success", m.g.T(r, "cdn64.online.servers_saved", "list", strings.Join(s.Assigned, ", "), "n", s.Sessions))
	http.Redirect(w, r, back, http.StatusSeeOther)
}
