package cdn64

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/ipv64api"
)

// Server je Name: wie viele CDN64-Server ein Proxy-Host (seine Namen bei ipv64) nutzt und wie viele Verbindungen je
// Server. Die Klasse legt die Grenzen fest, Business und Company waehlen darunter (Knopf in der Spalte CDN64, Portal: PUT
// /cdn64o/hosts/{id}/servers). Der Tunnel verbindet zu den Servern aller Namen, je Server mit dem Hoechstwert der
// Verbindungen der Namen dort; die Node uebernimmt das beim naechsten Abgleich, ohne bleibende Verbindungen zu trennen.
// Ein Portal ohne Server je Name (hosts[].servers fehlt): Auswahl je Tunnel wie bis PROXY64 1.47 (PUT
// /cdn64o/tunnels/{id}/servers).

type serversAPI interface {
	SetServers(ctx context.Context, tunnel string, count, sessions int) (*ipv64api.CDN64Servers, error)
	SetHostServers(ctx context.Context, hostID int64, count, sessions int) (*ipv64api.CDN64Servers, error)
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
	// vorgewaehlt ist die Wahl, nicht die Zahl der Zuteilungen (beim Lastausgleich kurz eine mehr): sonst schreibt ein
	// Speichern nur der Verbindungen eine andere Anzahl fest
	switch {
	case s.Choice > 0:
		v.Current = min(s.Choice, top)
	case s.All:
		v.Current = 0
	default:
		v.Current = top // 0 = Hoechstwert der Klasse
	}
	if s.All {
		v.Options = append(v.Options, 0)
	}
	for n := 1; s.SessionsMax > 1 && n <= s.SessionsMax; n++ {
		v.SessionOptions = append(v.SessionOptions, n)
	}
	return v
}

// onlineServers: Server des eigenen Tunnels aus dem letzten Abgleich (nil = kein Tunnel oder Portal ohne Server je
// Tunnel); gilt fuer Zeilen ohne eigene Auswahl (Portal ohne Server je Name).
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

// onlineBalanceLog: Lastausgleich der Server (ipv64 zieht einen Namen auf einen weniger belasteten um) ins Log - Beginn,
// sobald der neue Server dazukommt, Ende, wenn die Markierung wegfaellt: der neue bleibt (fertig; der alte bleibt nur,
// wenn andere Namen ihn nutzen) oder ist wieder weg (abgebrochen) (beim Abgleich, unter op).
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
			m.log.Info("cdn64 online: load balancing, a name moves to a less loaded server", "from", from, "to", to)
		}
	}
	for to, from := range m.online.bal {
		if _, still := now[to]; !still {
			if !have[to] {
				m.log.Info("cdn64 online: load balancing cancelled, the name stays", "edge", from)
			} else {
				m.log.Info("cdn64 online: load balancing done", "from", from, "to", to)
			}
		}
	}
	m.online.bal = now
}

// onlineRemoteIDs: die Namen eines Proxy-Hosts bei ipv64 - von hier eingeschaltete, sonst die des Accounts mit seinen
// Namen (Modus 3 von ipv64.net, andere Nodes).
func (m *Module) onlineRemoteIDs(ctx context.Context, hostID int64) []int64 {
	var out []int64
	if list, err := m.onlineNames(ctx); err == nil {
		for _, x := range list {
			if x.HostID == hostID && x.RemoteID > 0 {
				out = append(out, x.RemoteID)
			}
		}
	}
	if len(out) > 0 {
		return out
	}
	foreign := m.onlineForeign(ctx)
	if hl, err := m.hosts(ctx); err == nil {
		for _, h := range hl {
			if h.ID != hostID {
				continue
			}
			for _, n := range h.Names {
				if rh, ok := foreign[strings.ToLower(n)]; ok {
					out = append(out, rh.ID)
				}
			}
		}
	}
	return out
}

// POST /cdn64/online/servers: Server und Verbindungen je Server eines Proxy-Hosts (host, alle seine Namen) setzen;
// ohne host die des eigenen Tunnels (Portal ohne Server je Name).
func (m *Module) pageOnlineServers(w http.ResponseWriter, r *http.Request) {
	back := listPath(KindProxy)
	a, ok := m.online.api.(serversAPI)
	n, err := strconv.Atoi(r.PostFormValue("count"))
	ses, serr := strconv.Atoi(r.PostFormValue("sessions"))
	hid, herr := int64(0), error(nil)
	if v := r.PostFormValue("host"); v != "" {
		hid, herr = strconv.ParseInt(v, 10, 64)
	}
	c, _, cerr := m.onlineConf(r.Context())
	var ids []int64
	if hid > 0 {
		ids = m.onlineRemoteIDs(r.Context(), hid)
	}
	if !ok || m.online.api == nil || !m.online.api.Ready(r.Context()) || err != nil || n < 0 || serr != nil || ses < 1 || herr != nil ||
		(hid > 0 && len(ids) == 0) || (hid == 0 && (cerr != nil || c == nil)) {
		m.g.Flash(w, r, "danger", m.g.T(r, "cdn64.online.servers_failed", "error", "invalid"))
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	if hid > 0 {
		m.pageHostServers(w, r, a, hid, ids, n, ses)
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

// pageHostServers: Auswahl fuer alle Namen eines Proxy-Hosts (ids) setzen, Anzeige sofort, Abgleich gleich danach.
func (m *Module) pageHostServers(w http.ResponseWriter, r *http.Request, a serversAPI, hostID int64, ids []int64, n, ses int) {
	back := listPath(KindProxy)
	got := map[int64]*ipv64api.CDN64Servers{}
	var last *ipv64api.CDN64Servers
	for _, id := range ids {
		s, err := a.SetHostServers(r.Context(), id, n, ses)
		if err != nil {
			m.g.Flash(w, r, "danger", m.g.T(r, "cdn64.online.servers_failed", "error", err.Error()))
			http.Redirect(w, r, back, http.StatusSeeOther)
			return
		}
		got[id], last = s, s
	}
	m.g.Audit(r, "cdn64.online.servers", strconv.FormatInt(hostID, 10)+": "+strconv.Itoa(n)+"x"+strconv.Itoa(ses), strings.Join(last.Assigned, ","))
	if rm := m.online.remote.Load(); rm != nil && rm.Data != nil {
		ov := *rm.Data
		ov.Hosts = slices.Clone(ov.Hosts)
		for i := range ov.Hosts {
			if s, ok := got[ov.Hosts[i].ID]; ok {
				ov.Hosts[i].Servers = s
			}
		}
		m.onlineSetRemote(&ov, nil)
	}
	m.onlineKick()
	m.g.Flash(w, r, "success", m.g.T(r, "cdn64.online.servers_saved", "list", strings.Join(last.Assigned, ", "), "n", last.Sessions))
	http.Redirect(w, r, back, http.StatusSeeOther)
}
