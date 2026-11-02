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
	if t := ownTunnel(m, ctx, ov); t != nil {
		return newServersView(t.Servers)
	}
	return nil
}

// ownTunnel: der Tunnel dieser Node in einer Uebersicht von ipv64 (nil = keiner).
func ownTunnel(m *Module, ctx context.Context, ov *ipv64api.CDN64Overview) *ipv64api.CDN64Tunnel {
	c, _, err := m.onlineConf(ctx)
	if err != nil || c == nil || ov == nil {
		return nil
	}
	for i := range ov.Tunnels {
		if ov.Tunnels[i].ID == c.Tunnel {
			return &ov.Tunnels[i]
		}
	}
	return nil
}

// onlineOwnTunnel: der eigene Tunnel aus dem letzten Abgleich.
func (m *Module) onlineOwnTunnel(ctx context.Context) *ipv64api.CDN64Tunnel {
	if rm := m.online.remote.Load(); rm != nil {
		return ownTunnel(m, ctx, rm.Data)
	}
	return nil
}

// onlineFailover: Server des Tunnels, die ipv64 als ausgefallen meldet -> Ersatz ("" = noch keiner, die anderen Server
// tragen; der Ersatz kommt nach 3 Minuten).
func onlineFailover(t *ipv64api.CDN64Tunnel) map[string]string {
	out := map[string]string{}
	if t == nil {
		return out
	}
	for _, e := range t.Edges {
		if e.Standby || e.ReplacedBy != "" {
			out[e.Name] = e.ReplacedBy
		}
	}
	return out
}

// onlineFailoverLog: Ausfall, Einspringen des Ersatzes und Rueckkehr je Server ins Log (beim Abgleich, unter op).
func (m *Module) onlineFailoverLog(fo map[string]string) {
	for g, s := range fo {
		old, had := m.online.fo[g]
		switch {
		case !had && s == "":
			m.log.Warn("cdn64 online: server not reachable (ipv64), the other servers carry the tunnel", "edge", g)
		case s != "" && old != s:
			m.log.Warn("cdn64 online: failover, stand-in server for the failed one", "edge", g, "stand_in", s)
		}
	}
	for g, s := range m.online.fo {
		if _, still := fo[g]; !still {
			m.log.Info("cdn64 online: server back, failover ended", "edge", g, "stand_in", s)
		}
	}
	m.online.fo = fo
}

// onlineBalanceLog: Lastausgleich der Server (ipv64 zieht den Tunnel auf einen weniger belasteten um) ins Log - Beginn,
// sobald der neue Server dazukommt, Ende, wenn der alte weggefallen ist (beim Abgleich, unter op).
func (m *Module) onlineBalanceLog(t *ipv64api.CDN64Tunnel) {
	now := map[string]string{}
	have := map[string]bool{}
	if t != nil {
		for _, e := range t.Edges {
			have[e.Name] = true
			if e.BalanceFrom != "" {
				now[e.Name] = e.BalanceFrom
			}
		}
	}
	for to, from := range now {
		if m.online.bal[to] != from {
			m.log.Info("cdn64 online: load balancing, tunnel moves to a less loaded server", "from", from, "to", to)
		}
	}
	for to, from := range m.online.bal {
		if _, still := now[to]; !still {
			if have[from] {
				m.log.Info("cdn64 online: load balancing cancelled, tunnel stays", "edge", from)
			} else {
				m.log.Info("cdn64 online: load balancing done", "from", from, "to", to)
			}
		}
	}
	m.online.bal = now
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
